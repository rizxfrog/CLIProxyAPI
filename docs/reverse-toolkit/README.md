# Reverse-Engineering Toolkit (CN clients)

Reusable recipes and scripts for taking apart a closed-source CLI or Electron
desktop client — enough to add a new CLIProxyAPI provider: OAuth flow, upstream
API endpoints, TLS fingerprint, User-Agent, and request signing.

Everything here was validated against the Qoder CN packages; the resulting
findings live in [`../qoder-cn-client-analysis.md`](../qoder-cn-client-analysis.md).

## TL;DR workflow

```text
unpack ──► fingerprint ──► deobfuscate ──► trace auth ──► emulate
 .deb/.tgz   JA3/JA4        strings/URLs    OAuth+PKCE    uTLS + headers
 .asar       (proxy/strace) (xor/base64)    device flow   signing (WASM/core)
```

| Phase | Script | What you get |
|---|---|---|
| Unpack Electron | `extract-asar.mjs` | full app source + `main/index.js` |
| Unpack npm CLI | (plain `tar -xzf`) | minified JS bundle |
| TLS fingerprint | `fingerprint-client.sh` | JA3 + full ClientHello fields |
| Raw hello from strace | `extract-hello.py` | JA3 when no proxy/root capture |
| Raw hello via proxy | `connect-proxy.mjs` | ClientHello without MITM or root |
| Deobfuscate strings | `decode-xor.mjs` | hidden URLs, paths, headers, keys |
| Embedded binaries | `extract-embedded.mjs` | WASM / ELF / PE / Mach-O blobs |
| Native analysis | *idalib-mcp* | signing logic, machine identity |

---

## 1. Unpacking

### Electron `.deb` / `.dmg` / AppImage

```bash
dpkg-deb -R  "Qoder-CN-linux-amd64.deb" out/           # or: 7z x app.dmg
node extract-asar.mjs "out/opt/<App>/resources/app.asar" app/
```

`app.asar.unpacked/` (native `.node`, prebuilt runtimes, `keytar`) is **not** in
the archive — read it in place. `resources/product.json` and
`resources/app-update.yml` usually leak the product IDs, protocol scheme, and
update base URL before you read a single line of JS.

### npm CLI tarball

```bash
tar -xzf pkg.tgz       # -> package/{package.json,bundle/…}
```

`package.json` `bin` entries tell you the real entry point. A **~30 MB single
`.js`** is normal: it is a bundled esbuild/rollup output. Also check
`postinstall.cjs`, which often reveals a hidden `configure-path`-style
subcommand and the on-disk layout.

### First-pass recon (always ripgrep, never `grep -E '.{0,2000}'`)

Minified bundles are frequently **one line**. A context regex like
`grep -oE '.{0,2000}needle.{0,2000}'` backtracks catastrophically and appears to
hang. Use `rg -o` with a bounded window instead — it is ~1000× faster:

```bash
rg -o --no-filename -e '.{0,200}gateway\.[a-z.]+.{0,200}' main.js   # instant
```

Order of recon:

```bash
# 1. every URL, host, and API path
rg -o --no-filename 'https?://[A-Za-z0-9._~:/?#@!$&*+,;=%-]{4,200}' -g '*.js' -g '*.mjs' | sort -u
rg -o --no-filename '"/[a-z0-9]+/v[0-9]+/[A-Za-z0-9_./${}-]+"' -g '*.js' | sort -u

# 2. auth keywords
rg -oi 'device_?code|code_challenge|pkce|/authorize|/token|sso|sign-?in|oauth_callback|client_id' bundle.js

# 3. headers / UA / product ids
rg -o '"[Xx]-[A-Za-z0-9-]{2,40}"' bundle.js | sort | uniq -c | sort -rn
rg -o 'User-Agent"?\s*[:=]\s*[^,}]{0,120}' bundle.js | sort -u

# 4. TLS / transport hints
rg -oi 'ja3|ja4|utls|impersonat|fingerprint|cipher_?suite|http2|undici|bunVersion' bundle.js

# 5. feature flags & env overrides (how to redirect the client for tests!)
rg -o '[A-Z][A-Z0-9_]{3,}_?(BASE_?URL|ENDPOINT|HOST|DOMAIN|PROXY)' bundle.js | sort -u
```

That last group is gold: an `*_ENDPOINT` override lets you point the **real**
client at a local collector without patching it.

---

## 2. TLS fingerprinting

You want the client's ClientHello to reproduce it with `uTLS`/`tls-client`.
Three privilege-free methods, in order of fidelity:

### Method A — CONNECT proxy (best; no MITM, no root)

`connect-proxy.mjs` answers `CONNECT host:443` with `200`, then reads the
ClientHello the client writes over the tunnel *before* TLS completes, and
blind-tunnels the rest. **Because there is no MITM the fingerprint is genuine.**

```bash
PROXY_PORT=8899 node connect-proxy.mjs &
HTTPS_PROXY=http://127.0.0.1:8899 HTTP_PROXY=http://127.0.0.1:8899 <client>
# also: curl -x http://127.0.0.1:8899 https://host/    (proxy-honoring clients)
```

Caveats: **Node's global `fetch` ignores proxy env vars** until
`NODE_USE_ENV_PROXY=1` (or an undici `Agent`). Chromium/Electron frequently
ignores `--proxy-server` on Linux; prefer env vars or a system proxy.

### Method B — strace (works even when the client ignores proxies)

```bash
strace -f -qq -e trace=write,writev,sendto,sendmsg -s 8192 -xx \
    -o trace.txt ./client
python3 extract-hello.py trace.txt
```

`-xx` hex-escapes non-printables, making byte-accurate reconstruction possible.
A ClientHello is often split across several `sendmsg` calls, so
`extract-hello.py` concatenates payloads **per thread id** before scanning.
This is how the Qoder **desktop** app's fingerprint was recovered.

### Method C — Chromium net-log (negotiated params only)

`--log-net-log=net.json --net-log-capture-mode=Everything` records the
negotiated TLS version, cipher, ALPN and resolved hosts (useful to enumerate
endpoints), but **not** the ClientHello bytes, so it cannot yield a JA3. Note
the file is truncated on `SIGKILL` — copy it while the app still runs.

### One-shot runner

```bash
./fingerprint-client.sh --timeout 30 -- <client> [args...]
# tries proxy, then strace; prints JA3 + ja3str + SNI + ALPN + versions; writes summary.json
```

### Reading the result

The `ja3str` is `TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`.
Reproduce all five components **in order** — order matters — and filter GREASE
(`0x?a?a`) as JA3 requires:

```text
JA3 = md5("771,4866-4867-...,65281-0-11-...,4588-29-...,0-1-2")
```

A raw TLS stack bypasses both the client's fingerprint *and* any fingerprint-based
WAF. Map the field values to your library's names, e.g.

| Wire | Meaning | uTLS/tls-client |
|---|---|---|
| ext `65281` first | `renegotiation_info` | `UtlsGREASEExtension`-free order preserved |
| no ext `16` | **no ALPN** → HTTP/1.1 | `NextProtos=nil` |
| group `4588` | `X25519MLKEM768` | modern-Go only |
| ciphers `4866-4867-4865` | TLS1.3 first | `HelloGolang`/`HelloChrome` ordering |

---

## 3. Deobfuscating the bundle

CN bundles hide strings behind a tiny XOR-of-base64 helper with a hardcoded key:

```js
const _$d = (s, k = "Bt3QhcBtOI8H") => {
  const b = Buffer.from(s, "base64");
  for (let i = 0; i < b.length; i++) b[i] ^= k.charCodeAt(i % k.length);
  return b.toString();
};
```

`decode-xor.mjs` auto-detects the helper **by its body shape** (base64 → xor →
toString) rather than by name, learns the default key, and dumps every literal:

```bash
node decode-xor.mjs bundle.js > strings.txt
node decode-xor.mjs bundle.js --key Tyi1XHqJomzz --json | jq .strings[]
```

This is how the Qoder **OAuth client IDs** and **PKCE alphabet** were recovered.
Note the same vendor may ship **several keys** across bundles — run it on every
`*.js`/`*.mjs` you extract.

### Embedded native binaries

Large base64 literals frequently decode to WASM or prebuilt executables:

```bash
node extract-embedded.mjs bundle.js out/wasm 2000
file out/wasm/*
```

Qoder CN yields the Rust **auth WASM** (`qoder_auth_wasm_bg.wasm`) plus ELF/PE/
Mach-O copies of a machine-identity helper.

---

## 4. Embedded WASM (signing / crypto)

When the bundle calls `initWasm()` and a class like `QoderContext`, the real
auth/signing logic is in WASM and reads cleanly with `strings`:

```bash
strings -n 4 auth.wasm | rg -i 'ja3|cipher|tls|x-gw|cosy|hmac|rsa|aes|/api/|Bearer'
```

Look for the exported API names (they survive into plaintext), the header names
the request signer adds, and any embedded PEM public key. This tells you exactly
which headers you must synthesize and whether you must reimplement a signature
(see the Qoder findings doc for a worked example).

---

## 5. Tracing the OAuth / login flow

1. Find the login URL builder: search `sign-in`, `authorize`, `oauth_callback`,
   `selectAccounts`, `device/code`.
2. Extract the **PKCE** generator and its challenge method — CN clients commonly
   send both `verifier` **and** `challenge_method=S256` on the poll request, and
   may use a **non-standard alphabet**. Qoder CN uses the RFC 7636 unreserved set
   but at **66** characters (`A-Za-z0-9-._~`, indexed `byte % 66`), not 64 — verify
   the alphabet *and* its length. Getting either wrong breaks the exchange.
3. Extract the **client IDs** (almost always XOR-obfuscated) and the **redirect
   URI**.
4. Note the **poll** endpoint and success condition (often
   `{ token, refresh_token }` with `404` = "keep waiting").
5. Check for a **machine identity** requirement (`machine_id`, a signed
   `machine_token`) — on Qoder this comes from a Rust helper, and a wrong/blank
   value makes the token exchange fail.

To watch it live, redirect the client at your own collector using the
`*_ENDPOINT` env overrides found in recon, plus `*_AUTH_DEBUG`-style flags.

---

## 6. Native analysis with idalib-mcp

```python
idb_open(input_path="/path/to/binary", mode="force_headless",
         preferred_session_id="target", run_auto_analysis=True)
survey_binary(database="target")                     # first call: layout, imports, top fns
find(database="target", type="string", targets=["machineToken", "repPc.json"])
analyze_function(database="target", addr="main")     # pseudocode + strings + callers
decompile(database="target", addr="sub_40B544")
xrefs_to(database="target", addrs=["0x47e1d5"])
```

Practical sequence for a stripped Rust binary:

1. `survey_binary` → confirm the toolchain (`/rustc/<hash>`, `rustc-demangle`)
   and list `interesting_strings`.
2. `find` the distinctive literals (paths, JSON keys, URLs).
3. `xrefs_to` each literal → the referencing function is your feature.
4. `decompile` it; use `get_string` at odd addresses to decode Rust's packed
   string tables (JSON keys often concatenate with no NUL separator).

Restrict to the specific function — decompiling a 5000-instruction `main`
produces thousands of lines. Prefer `analyze_function` (compact) over
`decompile` until you know the target.

---

## 7. Checklist for a new provider

- [ ] OAuth: auth URL, client ID(s), redirect URI, PKCE alphabet + method, poll
      endpoint, success JSON shape, refresh endpoint.
- [ ] Machine identity: is a signed `machine_id`/`machine_token` required?
- [ ] Upstream endpoints: inference base, OpenAPI base, model-list, plus the
      exact path (e.g. `/algo/api/v2/service/pro/sse/agent_chat_generation`).
- [ ] Headers: `Authorization`, all `Cosy-*`/`X-*` product headers, `User-Agent`
      template, `Accept`, `Content-Type`.
- [ ] Body signing/encryption: plaintext JSON? AES-GCM envelope? per-field MAC?
- [ ] TLS fingerprint: JA3 string + JA4; pick the matching uTLS preset or build
      a custom `ClientHelloSpec`.
- [ ] Refresh / rotation semantics and error codes (`401` vs `404` vs `403`).
- [ ] Rate-limit / WAF headers to avoid tripping.

---

## 8. Legal / ethical scope

Reverse engineering here is for **interoperability**: making your own client talk
to a service you are licensed to use, with **your own** credentials. Do not
redistribute bundled binaries, do not bypass entitlement/billing, and respect
each vendor's ToS. Prefer documenting the wire contract over copying code.
