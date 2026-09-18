#!/usr/bin/env node
/**
 * decode-xor.mjs — decode XOR/base64-obfuscated string literals in JS bundles.
 *
 * Many CN vendor bundles ship a helper like:
 *     const _$d=(s,k="<16-char key>")=>{const b=Buffer.from(s,"base64");
 *        for(let i=0;i<b.length;i++)b[i]^=k.charCodeAt(i%k.length);
 *        return b.toString()}
 * and then hide every interesting literal (URLs, paths, headers, error text)
 * behind it. This script finds the helper, learns its key automatically (and
 * accepts an override), then dumps every decoded literal.
 *
 * Usage:
 *   node decode-xor.mjs <bundle.js> [--key <key>] [--min-len N] [--json]
 *
 * The default helper name regexp is intentionally broad: `_$d`, `_$d1`,
 * `_$dN`, `$dec`, `d`, ... Anything of the form
 *    <name>=(<param>,<keyParam>="....")=>{ ... base64 ... xor ... }
 * is detected by scanning for the base64+xor body shape rather than the name.
 */
import fs from 'node:fs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const getOpt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const minLen = Number(getOpt('--min-len', '0'));
const asJson = args.includes('--json');

if (!file) {
  console.error('usage: decode-xor.mjs <bundle.js> [--key K] [--min-len N] [--json]');
  process.exit(2);
}
const src = fs.readFileSync(file, 'utf8');

// 1. Locate the decode helper: bases64 -> xor -> toString, with a string key.
//    Capture (helperName, keyDefault).
let helper = null;
let key = getOpt('--key', null);
const helperRe =
  /([A-Za-z_$][\w$]*)\s*=\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*=\s*"([^"]{1,64})"\s*\)\s*=>\s*\{[^}]{0,400}base64[^}]{0,400}[\^][^}]{0,400}\}/g;
let m;
while ((m = helperRe.exec(src))) {
  helper = m[1];
  if (!key) key = m[4];
  break;
}
if (!helper) {
  // Fallback: any function whose body does Buffer.from(...,"base64") + xor + toString
  const alt = /([A-Za-z_$][\w$]*)\s*=\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*=\s*"([^"]{1,64})"\s*\)/.exec(src);
  if (alt && /base64/.test(src.slice(alt.index, alt.index + 600))) {
    helper = alt[1];
    if (!key) key = alt[4];
  }
}
if (!helper || !key) {
  console.error('could not locate an XOR/base64 decode helper (pass --key and inspect manually)');
  process.exit(1);
}

// 2. Decode every literal passed to the helper.
function decode(b64, k) {
  const b = Buffer.from(b64, 'base64');
  for (let i = 0; i < b.length; i++) b[i] ^= k.charCodeAt(i % k.length);
  return b.toString('utf8');
}

const callRe = new RegExp(
  `\\b${helper.replace(/\$/g, '\\$')}\\s*\\(\\s*"([A-Za-z0-9+/=]+)"`,
  'g'
);
const seen = new Map();
while ((m = callRe.exec(src))) {
  const enc = m[1];
  if (seen.has(enc)) continue;
  let dec;
  try {
    dec = decode(enc, key);
  } catch (err) {
    dec = `<<decode error: ${err.message}>>`;
  }
  seen.set(enc, dec);
}

const out = [...seen.values()].filter((s) => s.length >= minLen);
if (asJson) {
  console.log(JSON.stringify({ helper, key, count: out.length, strings: out }, null, 2));
} else {
  console.error(`# helper=${helper} key=${key} decoded=${out.length} unique literals`);
  console.log(out.join('\n'));
}
