#!/usr/bin/env node
/**
 * connect-proxy.mjs — record TLS ClientHellos through an HTTP CONNECT proxy,
 * WITHOUT man-in-the-middle and WITHOUT raw-capture privileges.
 *
 * Why this exists
 * ---------------
 * To fingerprint a client you need its ClientHello bytes. Requires-root captures
 * (tcpdump/tshark) are unavailable in many sandboxes, and a MITM proxy rewrites
 * the fingerprint you are trying to measure. A plain CONNECT proxy is ideal:
 * the client sends `CONNECT host:443`, we answer `200`, and the *client*
 * immediately writes its ClientHello in cleartext over the tunnel before the
 * TLS handshake proceeds. We parse that first flight, then blind-tunnel bytes.
 *
 * Usage:
 *   node connect-proxy.mjs                 # listens 127.0.0.1:8899
 *   PROXY_PORT=9000 PROXY_LOG=/tmp/c.log node connect-proxy.mjs
 *
 * Then point the client at it:
 *   HTTPS_PROXY=http://127.0.0.1:8899 <client>
 *   curl -x http://127.0.0.1:8899 https://host/
 *   openssl s_client -proxy 127.0.0.1:8899 -connect host:443 -servername host
 *   chromium --proxy-server=http://127.0.0.1:8899   (ELECTRON apps: see docs —
 *     Chromium often ignores --proxy-server, prefer the env vars above)
 *
 * Output: one JSON line per CONNECT and per parsed ClientHello, with a JA3 MD5
 * plus the raw JA3 components so it can be replayed by a uTLS/tls-client
 * implementation.
 */
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import fs from 'node:fs';

const PORT = Number(process.env.PROXY_PORT || 8899);
const HOST = process.env.PROXY_HOST || '127.0.0.1';
const LOG = process.env.PROXY_LOG || '/tmp/qoder-rev/tls/proxy.log';

// RFC 8701 GREASE values are ignored by JA3 and must be filtered out.
const GREASE = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);
const clean = (xs) => xs.filter((x) => !GREASE.has(x));

function parseClientHello(buf) {
  if (buf.length < 6 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
  const recLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recLen) return null;
  try {
    let p = 9; // record(5) + handshake type(1) + length(3)
    const legacyVersion = buf.readUInt16BE(p);
    p += 2 + 32; // version + random
    const sidLen = buf[p];
    p += 1 + sidLen;
    const csLen = buf.readUInt16BE(p);
    p += 2;
    const ciphers = [];
    for (let i = 0; i < csLen; i += 2) ciphers.push(buf.readUInt16BE(p + i));
    p += csLen;
    const compLen = buf[p];
    p += 1 + compLen;

    const extTotal = buf.readUInt16BE(p);
    p += 2;
    const extEnd = Math.min(p + extTotal, buf.length);
    const exts = [];
    const groups = [];
    const pointFormats = [];
    const sigAlgs = [];
    const alpn = [];
    const supportedVersions = [];
    let sni = null;

    while (p + 4 <= extEnd) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      p += 4;
      const body = buf.subarray(p, p + len);
      p += len;
      exts.push(type);
      if (type === 0) {
        const nl = body.readUInt16BE(3);
        sni = body.subarray(5, 5 + nl).toString('latin1');
      } else if (type === 16) {
        let q = 2;
        while (q < body.length) {
          const l = body[q];
          q += 1;
          alpn.push(body.subarray(q, q + l).toString('latin1'));
          q += l;
        }
      } else if (type === 43) {
        let q = 1;
        while (q + 2 <= body.length) {
          supportedVersions.push(body.readUInt16BE(q));
          q += 2;
        }
      } else if (type === 10) {
        let q = 2;
        while (q + 2 <= body.length) {
          groups.push(body.readUInt16BE(q));
          q += 2;
        }
      } else if (type === 11) {
        pointFormats.push(...body.subarray(1, 1 + body[0]));
      } else if (type === 13) {
        let q = 2;
        while (q + 2 <= body.length) {
          sigAlgs.push(body.readUInt16BE(q));
          q += 2;
        }
      }
    }

    const ja3str = [
      legacyVersion,
      clean(ciphers).join('-'),
      clean(exts).join('-'),
      clean(groups).join('-'),
      clean(pointFormats).join('-'),
    ].join(',');

    return {
      ja3: crypto.createHash('md5').update(ja3str).digest('hex'),
      ja3str,
      legacyVersion,
      ciphers: clean(ciphers),
      extensions: clean(exts),
      groups: clean(groups),
      pointFormats: clean(pointFormats),
      sigAlgs,
      sni,
      alpn,
      supportedVersions,
      grease: ciphers.length !== clean(ciphers).length,
    };
  } catch (err) {
    return { parseError: err.message };
  }
}

function record(obj) {
  const line = JSON.stringify(obj);
  fs.appendFileSync(LOG, line + '\n');
  process.stderr.write(line + '\n');
}

const proxy = http.createServer((req, res) => {
  res.writeHead(405);
  res.end();
});

proxy.on('connect', (req, clientSock, head) => {
  let host;
  let port;
  try {
    [host, port] = req.url.split(':');
  } catch {
    clientSock.destroy();
    return;
  }
  const target = Number(port || 443);
  record({ kind: 'connect', host, port: target });

  clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  const upstream = net.connect(target, host);
  let acc = Buffer.alloc(0);
  let logged = false;

  upstream.on('connect', () => {
    if (head && head.length) upstream.write(head);
  });

  clientSock.on('data', (d) => {
    if (!logged) {
      acc = Buffer.concat([acc, d]);
      const info = parseClientHello(acc);
      if (info && !info.parseError) {
        logged = true;
        record({ kind: 'clienthello', host, port: target, ...info });
      } else if (acc.length > 65536) {
        logged = true;
      }
    }
    upstream.write(d);
  });

  upstream.on('data', (d) => clientSock.write(d));
  clientSock.on('error', () => upstream.destroy());
  upstream.on('error', () => clientSock.destroy());
  clientSock.on('close', () => upstream.destroy());
  upstream.on('close', () => clientSock.destroy());
});

proxy.on('error', (e) => process.stderr.write(`proxy error: ${e.message}\n`));

proxy.listen(PORT, HOST, () =>
  process.stderr.write(`connect-proxy listening on ${HOST}:${PORT} log=${LOG}\n`)
);
