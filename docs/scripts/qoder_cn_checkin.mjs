#!/usr/bin/env node
/** Qoder CN campaign claims. See ../reverse-note/qoder-cn-daily-checkin_CN.md. */
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

const BASE = 'https://openapi.qoder.com.cn';
const CAMPAIGNS = '/sash/api/v1/me/campaigns';
const HELP = `Usage: node docs/scripts/qoder_cn_checkin.mjs --auth <file> [--claim] [--json]

Requires Node.js 18+; no dependencies.
Default: query only. --claim submits all claimable CLAIM_BENEFIT campaigns.
The credential file must contain access_token; machine_id is optional.
No automatic token refresh, retries, or scheduling. Credentials are never printed.`;

export function parseArgs(args) {
  const options = { claim: false, json: false, help: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--claim') options.claim = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--auth') {
      if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error('--auth requires a file path');
      options.auth = args[++i];
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!options.help && !options.auth) throw new Error('--auth is required');
  return options;
}

export async function run(credential, options, fetchImpl = fetch) {
  const token = credential.access_token ?? credential.accessToken;
  const machineId = credential.machine_id ?? credential.machineId;
  if (typeof token !== 'string' || !token.trim()) throw new Error('Missing access_token');
  const headers = {
    Accept: 'application/json',
    Authorization: `Bearer ${token.trim()}`,
    'User-Agent': 'Qoder',
    'Cosy-ClientType': '10',
    'Cosy-Business-Product': 'app',
    'Cosy-Version': '0.2.5',
  };
  if (typeof machineId === 'string' && machineId.trim()) headers['Cosy-MachineId'] = machineId.trim();

  async function request(endpoint, method = 'GET') {
    // Refuse redirects so the bearer cannot be forwarded to another endpoint.
    // Do not emit raw response bodies or network errors containing credentials.
    let response;
    try {
      response = await fetchImpl(BASE + endpoint, { method, headers, redirect: 'error' });
    } catch {
      throw new Error('Network request failed; no automatic retry performed');
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    let payload;
    try { payload = await response.json(); } catch { throw new Error('Invalid JSON response'); }
    return payload?.data ?? payload;
  }

  const payload = await request(CAMPAIGNS);
  const campaigns = Array.isArray(payload) ? payload : payload?.campaigns;
  if (!Array.isArray(campaigns)) throw new Error('Invalid campaigns response: expected an array');
  const result = {
    dryRun: !options.claim,
    campaigns: campaigns.filter(c => c && typeof c === 'object').map(c => ({
      campaignId: c.campaignId, campaignKey: c.campaignKey,
      actionType: c.actionType, claimStatus: c.claimStatus, benefit: c.benefit,
    })),
    claimed: [], skipped: [], errors: [],
  };
  const seen = new Set();
  for (const c of result.campaigns) {
    if (c.actionType !== 'CLAIM_BENEFIT' || c.claimStatus !== 'CLAIMABLE') continue;
    if (typeof c.campaignId !== 'string' || !c.campaignId.trim()) {
      result.errors.push({ error: 'Claimable campaign has no valid campaignId' });
      continue;
    }
    if (seen.has(c.campaignId)) continue;
    seen.add(c.campaignId);
    if (!options.claim) { result.skipped.push(c.campaignId); continue; }
    try {
      // The official iframe submits a bodyless POST (not a JSON body).
      const response = await request(`${CAMPAIGNS}/${encodeURIComponent(c.campaignId)}/claim`, 'POST');
      if (response?.status !== 'CLAIMED') throw new Error('Unexpected claim response status');
      result.claimed.push({ campaignId: c.campaignId, campaignKey: c.campaignKey, amount: c.benefit?.amount });
    } catch (error) {
      result.errors.push({ campaignId: c.campaignId, error: error.message });
    }
  }
  return result;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { console.log(HELP); return; }
  let credential;
  try { credential = JSON.parse(fs.readFileSync(options.auth, 'utf8')); }
  catch { throw new Error('Cannot read or parse the credential JSON file'); }
  if (!credential || typeof credential !== 'object') throw new Error('Invalid credential object');
  const result = await run(credential, options);
  if (options.json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(result.dryRun ? 'Query only; no claims submitted.' : 'Claim mode.');
    for (const c of result.campaigns) console.log(`${c.claimStatus ?? '?'}  ${c.actionType ?? '?'}  ${c.campaignKey ?? c.campaignId ?? '?'}  ${c.benefit?.amount ?? ''}`);
    console.log(`Claimed: ${result.claimed.length}; skipped: ${result.skipped.length}; errors: ${result.errors.length}`);
    for (const e of result.errors) console.error(`${e.campaignId ?? 'campaign'}: ${e.error}`);
  }
  if (result.errors.length) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  });
}
