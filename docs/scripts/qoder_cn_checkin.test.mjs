import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, run } from './qoder_cn_checkin.mjs';

const credential = { access_token: 'test-only-token', machine_id: 'test-machine' };
const campaign = { campaignId: 'a/b', actionType: 'CLAIM_BENEFIT', claimStatus: 'CLAIMABLE' };
const response = data => ({ ok: true, status: 200, json: async () => data });

test('arguments require an explicit credential path', () => {
  assert.throws(() => parseArgs([]), /required/);
  assert.throws(() => parseArgs(['--auth']), /requires/);
  assert.throws(() => parseArgs(['--unknown']), /Unknown/);
  assert.equal(parseArgs(['--help']).help, true);
  assert.equal(parseArgs(['--auth', 'test.json', '--claim']).claim, true);
});

test('default mode only queries and does not expose credentials', async () => {
  let calls = 0;
  const result = await run(credential, {}, async (url, init) => {
    calls++;
    assert.equal(init.method, 'GET');
    assert.equal(init.redirect, 'error');
    assert.equal(init.headers['Cosy-ClientType'], '10');
    assert.ok(url.startsWith('https://openapi.qoder.com.cn/'));
    return response({ campaigns: [campaign] });
  });
  assert.equal(calls, 1);
  assert.deepEqual(result.skipped, ['a/b']);
  assert.ok(!JSON.stringify(result).includes(credential.access_token));
});

test('claim filters, deduplicates, URL-encodes and uses bodyless POST', async () => {
  const calls = [];
  const result = await run(credential, { claim: true }, async (url, init) => {
    calls.push({ url, init });
    if (calls.length === 1) return response({ data: { campaigns: [
      campaign, campaign, { ...campaign, campaignId: 'details', actionType: 'VIEW_DETAILS' },
      { ...campaign, campaignId: 'already', claimStatus: 'CLAIMED' },
    ] } });
    assert.ok(url.endsWith('/a%2Fb/claim'));
    assert.equal(init.method, 'POST');
    assert.equal(init.body, undefined);
    return response({ data: { status: 'CLAIMED' } });
  });
  assert.equal(calls.length, 2);
  assert.equal(result.claimed.length, 1);
  assert.equal(result.errors.length, 0);
});

test('HTTP failure and unexpected success body are not accepted as claims', async () => {
  for (const claimResponse of [
    { ok: false, status: 403, json: async () => ({ status: 'CLAIMED' }) },
    response({ status: 'UNKNOWN' }),
  ]) {
    let calls = 0;
    const result = await run(credential, { claim: true }, async () =>
      ++calls === 1 ? response({ campaigns: [campaign] }) : claimResponse);
    assert.equal(result.claimed.length, 0);
    assert.equal(result.errors.length, 1);
  }
});

test('malformed list fails rather than reporting no activities', async () => {
  await assert.rejects(run(credential, {}, async () => response({})), /Invalid campaigns/);
});

test('network errors are sanitized and never retried', async () => {
  let calls = 0;
  await assert.rejects(run(credential, {}, async () => {
    calls++;
    throw new Error(credential.access_token);
  }), error => !error.message.includes(credential.access_token));
  assert.equal(calls, 1);
});
