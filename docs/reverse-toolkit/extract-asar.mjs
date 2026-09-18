#!/usr/bin/env node
/**
 * extract-asar.mjs — dependency-free Electron `app.asar` extractor.
 *
 * Electron archives are: [pickle header][JSON directory][concatenated file data].
 *
 * Pickle header layout (all little-endian u32):
 *   +0  size of the length field itself (always 4)
 *   +4  payload size  = align4(jsonLen) + 4   ->  data starts at 8 + payload
 *   +8  payload size - 4
 *   +12 jsonLen       (JSON directory bytes, un-padded)
 * Every file entry carries an `offset` relative to the data start; entries flagged
 * `unpacked` live outside the archive in `app.asar.unpacked/` and are reported
 * rather than written.
 *
 * Usage:
 *   node extract-asar.mjs <app.asar> <outDir>
 *
 * Tip: if a JSON parse fails the header layout has changed — the error dumps the
 * first 64 bytes so you can re-derive the offsets before adjusting this script.
 */
import fs from 'node:fs';
import path from 'node:path';

const [asarPath, outDir] = process.argv.slice(2);
if (!asarPath || !outDir) {
  console.error('usage: extract-asar.mjs <app.asar> <outDir>');
  process.exit(2);
}

const fd = fs.openSync(asarPath, 'r');
const head = Buffer.alloc(16);
fs.readSync(fd, head, 0, 16, 0);
const payloadSize = head.readUInt32LE(4);
const jsonLen = head.readUInt32LE(12);
const all = fs.readFileSync(asarPath);

let json;
try {
  json = JSON.parse(all.subarray(16, 16 + jsonLen).toString('utf8'));
} catch (err) {
  console.error(
    `failed to parse asar directory JSON (jsonLen=${jsonLen}): ${err.message}\n` +
      `first 64 bytes: ${all.subarray(0, 64).toString('hex')}`
  );
  process.exit(1);
}
// Payload size already accounts for 4-byte padding of the JSON directory.
const dataOffset = 8 + payloadSize;

let packed = 0;
let unpacked = 0;

function walk(node, rel) {
  for (const [name, ent] of Object.entries(node.files || {})) {
    const r = path.posix.join(rel, name);
    if (ent.files) {
      fs.mkdirSync(path.join(outDir, r), { recursive: true });
      walk(ent, r);
    } else if (ent.unpacked) {
      unpacked++;
    } else {
      const dst = path.join(outDir, r);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      const size = Number(ent.size || 0);
      const b = Buffer.alloc(size);
      if (size) fs.readSync(fd, b, 0, size, dataOffset + Number(ent.offset || 0));
      fs.writeFileSync(dst, b);
      packed++;
    }
  }
}

fs.mkdirSync(outDir, { recursive: true });
walk(json, '');
fs.closeSync(fd);

console.log(`packed files written : ${packed}`);
console.log(`unpacked (external)  : ${unpacked}  (look in <name>.asar.unpacked/)`);
console.log(`archive bytes        : ${all.length}  json header: ${jsonLen}`);
console.log(`output               : ${outDir}`);
