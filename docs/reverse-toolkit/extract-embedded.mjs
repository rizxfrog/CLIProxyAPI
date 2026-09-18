#!/usr/bin/env node
/**
 * extract-embedded.mjs — carve native blobs (WASM / ELF / PE / Mach-O / zip /
 * gzip) out of base64 string literals inside a JS bundle.
 *
 * Bundlers inline prebuilt runtimes as huge base64 string literals. This walks
 * every long base64 literal, decodes it, sniffs the magic, and writes matching
 * blobs to disk. A byte offset < 64 also counts (some tools wrap the payload in
 * a small header before the `\0asm` magic).
 *
 * Usage:
 *   node extract-embedded.mjs <bundle.js> <outDir> [minB64Len=4096]
 *
 * Note: the whole file is read once and scanned with a bounded regexp. Very
 * large bundles (30 MB+) are fine.
 */
import fs from 'node:fs';
import path from 'node:path';

const [src, outDir, minLenArg] = process.argv.slice(2);
if (!src || !outDir) {
  console.error('usage: extract-embedded.mjs <bundle.js> <outDir> [minB64Len]');
  process.exit(2);
}
const minLen = Number(minLenArg || 4096);

const MAGIC = [
  [Buffer.from([0x00, 0x61, 0x73, 0x6d]), 'wasm', 0],
  [Buffer.from([0x7f, 0x45, 0x4c, 0x46]), 'elf', 0],
  [Buffer.from([0x4d, 0x5a]), 'pe', 0],
  [Buffer.from([0x1f, 0x8b]), 'gzip', 0],
  [Buffer.from('PK'), 'zip', 0],
  [Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), 'macho64', 0],
  [Buffer.from([0xca, 0xfe, 0xba, 0xbe]), 'macho32', 0],
  [Buffer.from([0x00, 0x61, 0x73, 0x6d]), 'wasm', 64],
];

const code = fs.readFileSync(src, 'utf8');
fs.mkdirSync(outDir, { recursive: true });

// A regexp like /"([A-Za-z0-9+/=]{1000,})"/g backtracks catastrophically on a
// one-line minified bundle. Scan for quote-delimited base64 runs manually instead
// (linear, no backtracking).
const B64 = (c) =>
  (c >= 0x41 && c <= 0x5a) || // A-Z
  (c >= 0x61 && c <= 0x7a) || // a-z
  (c >= 0x30 && c <= 0x39) || // 0-9
  c === 0x2b || // +
  c === 0x2f || // /
  c === 0x3d; // =

const candidates = [];
for (let i = 0; i < code.length; i++) {
  if (code.charCodeAt(i) !== 0x22) continue; // "
  let j = i + 1;
  while (j < code.length && B64(code.charCodeAt(j))) j++;
  const len = j - i - 1;
  if (len >= Math.max(minLen, 1000) && code.charCodeAt(j) === 0x22) {
    candidates.push(code.slice(i + 1, j));
  }
  i = j - 1;
}

let count = 0;
const seen = new Set();
for (const b64 of candidates) {
  if (seen.has(b64)) continue;
  seen.add(b64);

  let buf;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch {
    continue;
  }
  if (!buf.length) continue;

  let kind = null;
  for (const [sig, name, maxSkip] of MAGIC) {
    if (maxSkip === 0) {
      if (buf.subarray(0, sig.length).equals(sig)) {
        kind = name;
        break;
      }
    } else {
      const at = buf.indexOf(sig, 0);
      if (at > 0 && at <= maxSkip) {
        buf = buf.subarray(at);
        kind = `${name}-off${at}`;
        break;
      }
    }
  }
  if (!kind) continue;

  count += 1;
  const out = path.join(outDir, `${String(count).padStart(2, '0')}-${kind}-${buf.length}.bin`);
  fs.writeFileSync(out, buf);
  const head = buf.subarray(0, 12).toString('latin1').replace(/[^\x20-\x7e]/g, '.');
  console.log(`${out}  ${buf.length} bytes  "${head}"`);
}
console.log(`extracted ${count} blob(s) -> ${outDir}`);
