# Qoder CN — Client Analysis (OAuth, Endpoints, TLS, UA)

Reverse-engineering notes for adding a **QoderCN** provider to CLIProxyAPI.

Artifacts analysed (see [`reverse-toolkit/README.md`](reverse-toolkit/README.md)
for the method):

| Artifact | Version | Notes |
|---|---|---|
| `qodercn-ai-qoderclicn-1.1.55.tgz` (npm) | CLI `1.1.55` | bundled JS, XOR-obfuscated |
| `Qoder-CN-linux-amd64.deb` (`qoder-cn`) | Desktop `0.2.5`, Electron/Chromium **150**, Node 24 | asar + bundled worker runtime `1.1.49` |

Qoder CN is a **two-surface** product (CLI + Electron IDE) that shares one agent
runtime and one set of upstream services. The CN edition is a *hard fork* of the
global `qoder.sh` edition: different hosts, different OAuth client IDs, different
config directory, different header values. Both are branched in code on a single
`BRAND_IS_CN` / `bs` flag, so every constant below has a `qoder.sh` sibling.

---

## 1. Product identity

From `resources/product.json` and the CLI metadata object (`E8`):

| Field | Value |
|---|---|
| `productId` | `qoder-cn` |
| `appId` | `com.qodercn.app` |
| data dir | `com.qodercn.app.stable` |
| protocol scheme | `qoder-cn` |
| CLI config dir | `.qoder-cn` |
| CLI env prefix | `QODERCN_` |
| CLI binary | `qoderclicn` |
| CLI display | `QoderCN` |
| auth biz variant | `qoder` |
| region | `cn` |

Config/home layout:

```
~/.qoder-cn/                       # CLI config root (QODERCN_* env overrides)
~/.config/com.qodercn.app.stable/  # Electron profile
~/.config/qoder-cn/                # machine identity (umid/runtime-info)
```

Keychain prefix: `qoder-cli-cn`. Browser OAuth service id: `qoder-cli-cn-oauth`.

---

## 2. Endpoint map (production / CN)

The CLI resolves endpoints through an `env → region → purpose` table, exactly
mirroring the desktop's `environments` object. Both agree:

| Purpose | CN host | Global (`qoder.sh`) sibling |
|---|---|---|
| Website / auth base | `https://qoder.cn` | `https://qoder.sh` |
| **Inference base** | `https://gateway.qoder.com.cn` | `https://api2.qoder.sh` |
| Security inference | `https://gateway.qoder.com.cn` | `https://api2.qoder.sh` |
| Center | `https://gateway.qoder.com.cn` | `https://center.qoder.sh` |
| Web search | `https://gateway.qoder.com.cn` | `https://center.qoder.sh` |
| **OpenAPI base** | `https://openapi.qoder.com.cn` | `https://openapi.qoder.sh` |
| Market | `https://openapi.qoder.com.cn/mind` | — |
| Model server | `api2-v2.qoder.sh:*` | (global model path) |
| Docs | `https://docs.qoder.cn` | `https://docs.qoder.com` |
| Download / update | `https://static.qoder.com.cn` | `https://download.qoder.com` |
| RUM | `proj-xtrace-…log.aliyuncs.com` | (same) |

Aliases that collapse onto `gateway.qoder.com.cn` in CN:
`api1/api2/api3.qoder.sh` all map to it.

Environment prefixes used by the code: `prod`, `daily`, `test`
(`daily-gateway.qoder.com.cn`, `test-gateway.qoder.com.cn`, same for openapi).

> `QODER_AUTH_*`/`QODERCN_*` overrides exist for base URLs, client ID, redirect
> URI, biz variant — these are what let you redirect the real client to a local
> collector during analysis.

### Paths

Auth (base = `authBaseUrl`, i.e. `https://qoder.cn` / `test.qoder.com.cn`):

| Path | Method | Purpose |
|---|---|---|
| `/users/sign-in?biz_variant=…&oauth_callback=…` | GET (browser) | login page |
| `/device/selectAccounts?challenge=&challenge_method=S256&nonce=&machine_id=&client_id=&redirect_uri=` | GET | device/account selection — **the login URL** |

OpenAPI (base = `openapi.qoder.com.cn`):

| Path | Method | Purpose |
|---|---|---|
| `/api/v1/deviceToken/poll?nonce=&verifier=&challenge_method=S256` | GET | **token acquisition** |
| `/api/v1/deviceToken/refresh` | POST | refresh; body `{refresh_token, …machine fields}` |
| `/api/v1/userinfo` | GET | user profile (`Authorization: Bearer …`) |
| `/api/v1/jobToken/exchange` | POST | PAT → job token |
| `/api/v1/jobToken/refresh` | POST | job token refresh |
| `/api/v2/user/plan`, `/api/v2/me/usage`, `/api/v2/quota/usage`, `/api/v3/user/status` | GET | plan/quota/status |

### Quota reads (verified live)

`/api/v2/quota/usage` and `/api/v3/user/status` are the two **quota** endpoints,
and — unlike the model catalog — they are **plain bearer-token GETs**:

```
GET https://openapi.qoder.com.cn/api/v2/quota/usage
Authorization: Bearer dt-…      # only this header is required
```

Verified reachability matrix (probe returned 200 for every combination, so the
machine identifier and client headers are *not* required here):

| Headers sent | Result |
|---|---|
| `Authorization` only | 200 |
| + `User-Agent: qoder/1.1.55` | 200 |
| + `Cosy-Version`, `Cosy-ClientType` | 200 |
| + `Cosy-MachineId` | 200 |

A rejected token answers **401** with a `{code,message}` envelope, not the
OpenAI `{"error":…}` shape used by the model server:

```json
{ "code": "TOKEN_EXPIRE", "message": "token is not active", "timestamp": "1789803528159" }
```

Observed `/api/v2/quota/usage` body (CN **Free** tier, exhausted):

```json
{
  "userId": "019f5c18-…", "userType": "personal_standard",
  "usageType": "credits", "totalUsagePercentage": 0.0,
  "isQuotaExceeded": true,
  "expiresAt": 253402214400000,
  "upgradeUrl": "https://qoder.com.cn/pricing?client=qoder",
  "outerProviders": [],
  "userQuota": { "total": 0.0, "used": 0.0, "remaining": 0.0, "percentage": 0.0, "unit": "credits" },
  "isPlanQuotaProrated": false
}
```

Observed `/api/v3/user/status` body (same account):

```json
{
  "id": "019f5c18-…", "name": "tyhk84359", "userType": "personal_standard",
  "quota": 0, "isQuotaExceeded": true,
  "plan": "PLAN_TIER_FREE", "userTag": "Free",
  "nextResetAt": 1785166151983, "email": "",
  "whitelistStatus": "PASS", "isSubAccount": false,
  "featureSwitches": { "allow_byok": 2 }
}
```

Two details that matter when rendering these:

* **`expiresAt` is a sentinel, not a deadline.** `253402214400000` is year 9999
  (`9999-12-31T00:00:00Z`) and means "never expires"; it must not be shown as a
  countdown. `nextResetAt` (1785166151983 → 2026-07-27) is the real instant.
* **`unit` is `credits`**, and a zeroed ledger (`total/used/remaining == 0`) on a
  Free account is a genuine observation, not missing data — the `isQuotaExceeded`
  flag is what distinguishes an exhausted account from a failed read.

Contrast with the catalog, which lives on a different surface entirely:

| Route | Result | Why |
|---|---|---|
| `openapi.qoder.com.cn/api/v2/model/list?Encode=1` | **503** | route not served on the OpenAPI origin (v2 is otherwise live: `quota/usage` and `user/plan` answer 200 there) |
| `gateway.qoder.com.cn/algo/api/v2/model/list?Encode=1` | **403** `{"code":"101","message":"Signature invalid"}` | gated by the WASM request signature |
| `api2-v2.qoder.sh/model/v1/chat/completions` | **401** `{"error":"unauthorized"}` | the stored bearer token is not the credential this host accepts |

So **quota is implementable with the plain token; the model catalog is not** —
which is why the provider ships a static catalog fallback (see §8) but a live
quota read.

---
| `/api/v2/model/list?Encode=1[&outerProviders=…]` | GET | **model catalog** |
| `/api/v1/webSearch/oneSearch`, `/api/v1/webSearch/unifiedSearch` | POST | web search |
| `/api/v1/ping`, `/api/v2/tracking`, `/api/v2/spans` | | health/telemetry |
| `/api/v5/service/region/endpoints` (desktop v3) | GET | **dynamic endpoint election** |

Inference (base = `gateway.qoder.com.cn`, `/algo` is appended if absent):

| Path | Method | Purpose |
|---|---|---|
| `/algo/api/v2/service/pro/sse/agent_chat_generation` | POST | **agentic chat, SSE** |
| `/algo/api/v2/service/pro/invoke/chat_like?Encode=1` | POST | non-SSE chat |
| `/model/v1/chat/completions` | POST | OpenAI-compatible model server |
| `/algo/api/v2/service/pro/generateImage`, `/imageSearch`, `/videos` | POST | media |
| `/algo/api/v1/ping`, `/algo/api/v1/version`, `/algo/api/v2/service/region/endpoints` | GET | probes/elector |
| `/algo/api/v2/byok/check`, `/algo/api/v2/byok/config` | POST/GET | BYOK models |
| `/api/v1/services/aigc/multimodal-generation/generation` | POST | DashScope-style multimodal |
| `/api/v2/service/voice/polish`, `/api/v2/service/ws/asr` | | voice |

**Desktop inference** does *not* call these directly: the Electron shell bundles
the **same worker runtime** (`@qoder-ai/qoder-cn-agent-sdk` →
`_worker/qoder-worker-runtime.obf.mjs`) and delegates chat to it. So the CLI is
the single implementation to emulate — a nice consistency check.

---

## 3. OAuth login flow (PKCE + device/account selection)

Qoder CN uses a **hybrid browser + PKCE** flow. It is *not* a bare RFC 8628
`device_code` flow — there is no `/device/code` endpoint. The browser performs
the human step at `/device/selectAccounts`; the client polls
`/api/v1/deviceToken/poll` with a PKCE verifier.

### 3.1 Start

```text
verifier  = 43..128 chars drawn from a NON-STANDARD alphabet (see below)
challenge = base64url( sha256(verifier) )        // "=" stripped, +/ -> -_
nonce     = uuid4()
machineId = OS machine fingerprint (see §5)

loginUrl = {authBaseUrl}/device/selectAccounts
             ?challenge=<challenge>
             &challenge_method=S256
             &nonce=<nonce>
             &machine_id=<machineId>
             &client_id=<clientId>
             [&machine_token=<signed machine token>]
             [&redirect_uri=<redirectUri>]           // stable/canary only
```

If `QODER_AUTH_DIRECT_DEVICE_FLOW=1` (or a custom access domain is configured),
the login URL is used as-is. Otherwise the client wraps it in the web login page:

```text
loginUrl = {origin of the selectAccounts URL}/users/sign-in
             ?biz_variant=<authBizVariant>     // "qoder"
             &oauth_callback=<url-encoded selectAccounts URL>
```

The user authenticates in the browser; the browser then hits the
`selectAccounts` URL, which binds the account to the `nonce`+`challenge`.

### 3.2 PKCE detail (important)

```text
verifier alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"   // 66 chars

CLI      : len = 43 + floor(86 * random())          // uniform 43..128
           verifier[i] = alphabet[ randomByte_i % 66 ]
desktop  : len = 64                                  // fixed
           verifier[i] = alphabet[ randomByte_i % 66 ]

challenge = base64url( SHA-256(verifier) )           // '+/' -> '-_', strip '='
```

The alphabet is the RFC 7636 unreserved set, but it is **66 characters**
(`A-Za-z0-9-._~`), not the 64 one might assume, and it is indexed by
`byte % 66` (never `% 64`). A naive `% 64` reimplementation produces a different
character distribution. The CLI emits a uniformly random 43..128-char verifier;
the desktop always uses exactly 64 chars. Emit the verifier **verbatim** on the
poll request — the server does not re-derive it.

### 3.3 Poll

```http
GET {openApiBaseUrl}/api/v1/deviceToken/poll?nonce=<nonce>&verifier=<verifier>&challenge_method=S256
Accept: application/json
```

Client semantics:

| Response | Meaning | Action |
|---|---|---|
| `404` | not yet approved | sleep (backoff) and retry |
| `200` + `{token, refresh_token}` | **success** | persist, done |
| other non-2xx | hard error | abort |
| 5 consecutive network failures | give up | `NETWORK` error |

Overall wait window defaults to `ave` (~5 min, `LOGIN_TIMEOUT` on expiry).

Success payload shape:

```json
{ "token": "<access_token>", "refresh_token": "<refresh_token>",
  "expires_at": "…", "expire_time": "…", "refresh_token_expire_time": "…" }
```

### 3.4 Client IDs

Decoded from the XOR-obfuscated literals in the CLI bundle:

| Source | client ID |
|---|---|
| Desktop (`E8.authClientIds.prod` / `.test`) | `732aef47-9cf2-46a2-95fe-4cebb5d0d1fa` |
| CLI device flow, **prod/inner** (`ktc`) | `e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb` |
| CLI device flow, **test** (`Rtc`) | `e93fe488-5778-4c35-a6fc-0f54ed7b3139` |

The CLI picks the build-time variant; the desktop uses the single product ID for
both environments. Overridable via `QODER_AUTH_CLIENT_ID` /
`QODERCN_AUTH_CLIENT_ID`.

### 3.5 Refresh

```http
POST {openApiBaseUrl}/api/v1/deviceToken/refresh
Content-Type: application/json
Accept: application/json
User-Agent: qoder/<cliVersion>
{ "refresh_token": "...", <machine identity fields: machine_id, machine_token, …> }
```

`401`/`403` → invalidate stored credentials and force re-login. There is a
parallel `/api/v1/jobToken/{exchange,refresh}` pair for scoped "job" tokens
(`POST /api/v1/me/jobToken {clientId}`), used per-session.

### 3.6 Browser/desktop callback

The Electron app also supports a **redirect-URI** variant. Its packaged
executable/redirect contract looks for a loopback callback at
`…/oauth/callback`; the in-app MCP OAuth client is registered as
`qoder-desktop-mcp-oauth` v1.0.0. For the account login, the desktop uses the
same `device/selectAccounts` + `deviceToken/poll` pair as the CLI.

---

## 4. HTTP headers & User-Agent

### User-Agent

| Surface | Value |
|---|---|
| CLI API calls | `qoder/{cliVersion}` → `qoder/1.1.55` |
| CLI updater / security / external commands | `qodercli-updater`, `qodercli-security`, `qodercli-external-commands` |
| CLI installer script | `qodercli-installer/curl-bash (https://qoder.com)` |
| Desktop API calls (`Bx()`) | `Qoder` (literally, no version) |
| Desktop link preview | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36` |
| Desktop local server monitor | `QoderLocalServerMonitor/1.0` |
| HTTPDNS client | `httpdns-nodejs-sdk/1.0.0` |

The CLI's generic npm-style UA template `npm/{v} node/{v} {platform} {arch}` exists
only inside its `npm-registry-fetch` dependency, not for API calls.

### Request headers

Auth/OpenAPI calls:

```http
Accept: application/json
Authorization: Bearer <access_token>
User-Agent: qoder/1.1.55
Content-Type: application/json            # on writes
Cosy-MachineId: <machineId>               # from WASM signer
Cosy-MachineToken: <machineToken>
Cosy-MachineType: <machineType>           # when known
```

Desktop (`Bx()`):

```http
Accept: application/json
Authorization: Bearer <access_token>
Cosy-ClientType: 10
User-Agent: Qoder
```

Inference/agent stream (`agent_chat_generation`, decoded from the WASM string
table — the signer injects these):

```http
Content-Type: application/json
Cosy-Version: 1.1.55          # = CLI version / COSY_VERSION
Cosy-MachineId: <machineId>
Cosy-MachineToken: <machineToken>
Cosy-MachineType: <machineType>
Cosy-ClientType: 5            # CLI=5, desktop=10
Cosy-Business-Product: cli    # desktop: app
Cosy-Business-Type: agent
Cosy-Scene: assistant
Login-Version: v2
X-Model-Key: <model>
X-Model-Source: <source>
Accept: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
Accept-Encoding: identity
```

Root/tenant guards seen elsewhere: `Cosy-User`, `Cosy-Date`,
`Cosy-Organization-Id`, `Cosy-Organization-Tags`, `Cosy-Data-Policy: agree`.
Telemetry/remote: `x-gw-user-id`, `X-Qoder-Remote-Api-Version`,
`X-Qoder-Session-Id`, `X-Qoder-Model`, `X-Qoder-HTTPDNS-IP`.

Request/session ids: `x-request-id`, `x-qoder-request-id`, `x-qcs-request-id`,
`X-Session-ID`.

### Client metadata tuple

```jsonc
{ "client_type": "5",             // CLI; desktop "10"
  "business_product": "cli",      // desktop "app"
  "business_type": "agent",
  "scene": "assistant" }
```

`Cosy-Version` = `COSY_VERSION` = CLI version (`1.1.55`); desktop falls back to
`"1.0.0"` when unset.

---

## 5. Machine identity (`umid`) — a signing requirement

Token exchange/refresh and inference require a **machine identity**. It is not
derived in JS; the Electron app bundles a Rust helper at
`resources/umid/runtime-info` (schema `resources/umid/manifest.json`,
sha256 `e30b307e…`, 652488 bytes, linux-x64).

Observed output (this host — a **KVM guest**):

```json
{"machineToken":"P1gAWpgxyRU6KC79W_CUtEHR3NMiLWK2vJH14KOKvYozkZlZWLuW-ZwubagoPxn977fx8-qMu9GCj7-mJC8Rfbah",
 "machineType":"24e03dfa134c5e4fad",
 "machineCode":"ff9e2d228494e28a8e",
 "vmInfo":{"isVm":true,"brand":"KVM","percentage":85,"vmTypeCode":13}}
```

Deterministic: two runs returned byte-identical values (so it is keyed off
stable host attributes, not a random seed). The binary also embeds the
authenticity/telemetry endpoints `https://umid.daily.alibaba.net/repPc.json` and
`https://pre-umid.alibaba-inc.com/repPc.json`.

### What it reads (from `strings` / idalib)

- `/proc/sys/kernel/random/uuid` (fallback seed), `~/.config/.randomuuid[_Lock]`
- `/sys/class/dmi/id/{sys_vendor,product_name,product_version,board_vendor,
  manufacturer,bios_vendor}`, `/sys/hypervisor/{type,uuid}`
- `/proc/cpuinfo`, `/proc/1/cgroup`, `/proc/mounts`
- VM/hypervisor detection table: `vmware, virtualbox, kvm, xen, microsoft
  corporation, Hyper-V, Parallels, AWS EC2, Alibaba ECS, Tencent CVM, Google
  Cloud, Docker, LXC, Kubernetes, containerd` → `vmTypeCode`
- container detection via cgroup/mount/`pgrep`
- imports `gethostname`, `gethostid`, `getuid`, `uname`-ish syscalls

Binary layout (idalib): 1333 functions, base `0x400000`, Rust (paths under
`/rustc/e408947b…`), stripped but with readable panic/import strings. The JSON
writer packs keys as `fullmainbrandpercentagevmTypeCodemachineTokenmachineTypemachineCodemachineInfo`
— i.e. `machineToken`, `machineType`, `machineCode`, `vmInfo` — at
`unk_47E1D5` (12-byte key `machineToken`), referenced from `sub_40B544`
via `sub_413688` (string append) around `0x40D502`.

**Implication for CLIProxyAPI:** `Cosy-MachineToken` is a real signed fingerprint,
not a UUID. Either (a) capture and reuse a real `runtime-info` output, (b) invoke
the bundled helper when present, or (c) determine the server's tolerance for a
blank/placeholder token. A wrong value is a likely cause of otherwise
inexplicable token-exchange failures.

---

## 6. Request signing / encryption (WASM)

The CLI embeds a Rust **`qoder_auth_wasm`** module
(`qoder_auth_wasm_bg.wasm`, ~298 KB). JS never builds auth headers directly for
protected endpoints; it calls the WASM `QoderContext`:

```text
qodercontext_new(machineId, cosyVersion, userInfoJson, clientMetadataJson)
qodercontext_prepareRequest(endpoint, path, method, authMode, body?, headersJson?)
        -> { url, headers, body? }
qodercontext_prepareInferRequest(...)
qodercontext_refreshAuthFields(...)
decrypt_server_response(...)     // allows encrypted server payloads
```

Consequences:

- `prepareRequest` **can rewrite the URL** and **can replace the body** — do not
  assume the literal path/body you see in JS is what goes on the wire.
- Header names from the WASM string table: `Authorization`, `Cosy-Date`,
  `Cosy-User`, `Cosy-Key`, `appcode`, `sign`, `Date`, `Signature`, and the
  `Cosy-*` set above.
- Crypto primitives found in the module: **AES-256-GCM chunked encryption**,
  **AES-GCM**, **RSA-OAEP** (with an embedded PEM **public key** used as the
  fallback "profile" key), SHA-256/HMAC, base64url. `encrypt_user_info` +
  `key` imply a per-request envelope for some payloads.
- There is a signature/`authMode` switch (`"auth"` vs `"sign"`). The `"sign"`
  mode prepends a `Bearer COSY.…`-style token (string `Bearer COSY.` present).
- WASM also exposed: `get_httpdns_account_id/secret_key` (Aliyun HTTPDNS), and
  profile/model-cache encrypt/decrypt.

**Implication:** for a faithful provider you must reproduce the header/signature
scheme. Practical approach: for a first cut, replay the *observable* headers
captured from a real client session; treat body signing as a follow-up. If the
server accepts the plain `Authorization: Bearer <access_token>` +
`Cosy-Machine*` set on the `agent_chat_generation` path, a Go implementation can
skip the WASM entirely — verify empirically.

---

## 7. TLS fingerprint

### Desktop (Electron/Chromium 150, BoringSSL)

Captured with `strace` (the Electron app ignored `--proxy-server` on Linux):

```text
JA3 (with ALPN http/1.1)  1a3153f314dc13e133dc71d113a81b16
ja3str  771,4865-4866-4867-49199-49195-49200-49196-49191-52393-52392-49161-49171-49162-49172-156-157-47-53,0-23-65281-10-11-35-16-13-51-45-43-21,29-23-24,0
SNI     gateway.qoder.com.cn   ALPN  http/1.1   versions [772,771]

JA3 (no ALPN)             71dc8c533dd919ae9f4963224a4ba8fd
ja3str  771,4865-…-53,0-23-65281-10-11-35-13-51-45-43,29-23-24,0
```

Characteristics:

- **No GREASE** (no `0x?a?a` values) — a distinctive, stable signature.
- Cipher order: TLS 1.3 first (`0x1301,0x1302,0x1303` = AES-128-GCM,
  AES-256-GCM, ChaCha20-Poly1305), then ECDHE-ECDSA/RSA AES-GCM, then CBC.
- Extension order (`0-23-65281-10-11-35-16-13-51-45-43-21`):
  `server_name, extended_master_secret, renegotiation_info, supported_groups,
  ec_point_formats, session_ticket, alpn, signature_algorithms, key_share,
  psk_key_exchange_modes, supported_versions, padding`.
  Note `server_name` **first** and `padding` (21) **last**.
- Groups: `29, 23, 24` = X25519, P-256, P-384. **No X25519MLKEM768.**
- Point formats `0` (uncompressed only).
- Sig algs: `1027,2052,1025,1283,2053,1281,2054,1537,513`
  (ECDSA-SHA256, RSA-PSS-SHA256, RSA-PKCS1-SHA256, RSA-PSS-SHA384, ECDSA-SHA384,
  RSA-PKCS1-SHA384, RSA-PSS-SHA512, RSA-PKCS1-SHA512, ECDSA-SHA512).

### CLI on Node.js (`v24`, OpenSSL 3.x)

Captured via the CONNECT proxy:

```text
JA3  d67b094811e5145139d7cea5f014309f        # node undici, ALPN http/1.1
ja3str 771,4866-4867-4865-49199-49195-49200-49196-158-49191-103-49192-107-163-159-52393-52392-52394-49325-49311-49245-49249-49239-49235-162-49324-49310-49244-49248-49238-49234-49188-106-49187-64-49162-49172-57-56-49161-49171-51-50-157-49309-49233-156-49308-49232-61-60-53-47,65281-0-11-10-35-16-22-23-13-43-45-51,4588-29-23-30-24-25-256-257,0-1-2
```

Note the **`X25519MLKEM768` (4588)** group and the large (52-entry) cipher list —
this is the stock Node 24 / OpenSSL 3.5 profile (identical to the CodeBuddy Code
CLI already documented in `codebuddy-cn-tls-fingerprint.md`).

### CLI as a native Bun binary (BoringSSL)

The published CLI also ships a **Bun-compiled native binary** (the install script
downloads a `qoderclicn` artifact; `bunVersion` is probed at runtime). Bun uses
**BoringSSL** and produces a third, distinct profile:

```text
JA3  (Bun, ALPN http/1.1)  ≈ a44663b9db6ccaa680f6174478197a2f
extensions  65281-11-10-35-16-22-23-13-43-45-51        (renegotiation first, no SNI order quirk)
ciphers     4866-4867-4865-49199-49195-...             (TLS1.3 first)
```

So the *same product* yields **three** fingerprints depending on runtime
(Chromium/BoringSSL, Node/OpenSSL, Bun/BoringSSL). A provider should pick the one
matching the surface it emulates; the CLI-on-Node profile (`d67b0948…`) is the
easiest to reproduce from Go with uTLS, since Go's `crypto/tls` now shares the
`X25519MLKEM768` group.

### Recommended uTLS target

For a Go provider emulating the **CLI** (the surface that actually calls
`agent_chat_generation`):

- `TLSVersions`: 1.3 + 1.2, advertised `772,771`.
- Ciphers: TLS 1.3 `4866,4867,4865` first, then the OpenSSL order above.
- Extensions in **exactly** the captured order, `renegotiation_info(65281)`
  first, and `server_name` at position 2.
- Groups `4588,29,23,30,24,25,256,257`; sig-algs as captured.
- ALPN `http/1.1` (the CLI does **not** negotiate h2; the desktop omits ALPN
  unless it needs h2).
- **Never send GREASE.**

For the **desktop**, target JA3 `1a3153f3…` (Chromium-with-ALPN, no GREASE,
no MLKEM), which is close to a stock `HelloChrome_*` spec with GREASE removed and
`X25519MLKEM768` dropped.

---

## 8. Models

> ⚠️ 旧版“静态推断”模型 ID（`claude-opus-4-6` / `claude-sonnet-4-5` …）是**错的**。
> 真实目录见 **[qoder-cn-model-list-analysis.md](./qoder-cn-model-list-analysis.md)**（已用官方 CLI 的 WASM 解密 `catalog-v6`，实战可复现）。

The CN model catalog is **server-driven and WASM-encrypted** — it is NOT fetched via
`GET /api/v2/model/list` (that prefix is unrouted 503 in the observable network, and
`/algo/*` requires the WASM request signature). The real catalog lives at
`~/.qoder/.models/<uid>/catalog-v{5,6}`, decrypted with `model_cache_decrypt(fileText, uid)`.

For the **logged-in free account** (UID `019cbe3d-…`), `--list-models` shows only the
two enabled+free models:

```text
Qwen3.8-Max    (key: qmodel_38max,  format: openai, is_default: true, price_factor: 0.5, max_input: 180K, context: 200K/400K/1M, thinking: low/medium/xhigh)
Qwen3.8-Flash  (key: qfmodel,       format: openai, is_default: false, price_factor: 0.0, max_input: 180K, context: 200K/400K/1M, thinking: low/medium/xhigh)
```

Paid / not-enabled tiers present in the same catalog (per-scene): `Sonus` (`smodel`),
`Cantus` (`cmodel`), `Qwen3.7-Max` (`qmodel_latest`), `Qwen3.7-Plus` (`qmodel`),
`Kimi-K3` (`kmodel_latest`), `Kimi-K2.8-Preview` (`kmodel`), `GLM-5.3` (`gmodel`),
`GLM-5.3-Flash`, `DeepSeek-V4-Pro` (`dmodel`), `DeepSeek-Flash`, `MiniMax-M3` (`mmodel`),
plus aggregate tiers `Auto/Ultimate/Performance/Efficient`. `byok_teams` and
`byok_enterprise` buckets are empty for this account.

`-m` accepts either a catalog key or a BYOK `key`. `--reasoning-effort` accepts
`disabled|off|none|low|medium|high|xhigh|max`; `--thinking` accepts
`auto|adaptive|enabled|disabled`.

---

## 9. Provider implementation notes

1. **Auth**: implement the PKCE + `device/selectAccounts` + `deviceToken/poll`
   flow. Do **not** use the RFC 8628 shape (there is no `device_code`).
2. **Client ID**: default `e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb` (prod); make it
   configurable.
3. **Base URLs**: `gateway.qoder.com.cn` (inference, `/algo` prefix),
   `openapi.qoder.com.cn` (auth/API). Configurable for test/VPC.
4. **Headers**: mirror `Cosy-*` (version, machine id/token/type, client type,
   business product/type, scene, `Login-Version: v2`) and the `X-Model-*` pair
   for inference. UA `qoder/<version>`.
5. **Machine identity**: source `machineId`/`machineToken`/`machineType` from the
   bundled `runtime-info` helper (or accept them as provider config). Reuse, do
   not regenerate per request.
6. **Signing**: attempt plain Bearer + Cosy headers first; fall back to
   reproducing the WASM signer if the server rejects. Watch for encrypted
   bodies (`decrypt_server_response`).
7. **Streaming**: SSE from `agent_chat_generation`; the endpoint name already
   contains `sse`. Translate to the provider's SSE.
8. **TLS**: install the CLI uTLS profile (see §7) on the transport used for
   upstream calls, or a fingerprint-based WAF may block you.

---

## 10. Appendix — how the findings were obtained

```bash
# unpack
dpkg-deb -R Qoder-CN-linux-amd64.deb out/
node docs/reverse-toolkit/extract-asar.mjs "out/opt/Qoder CN/resources/app.asar" app/
tar -xzf qodercn-ai-qoderclicn-1.1.55.tgz -C npm/

# deobfuscate (recovered the OAuth client IDs + PKCE alphabet)
node docs/reverse-toolkit/decode-xor.mjs npm/package/bundle/qoderclicn.js > cli-strings.txt
node docs/reverse-toolkit/decode-xor.mjs npm/package/bundle/qoder-worker-runtime.mjs > worker-strings.txt

# embedded native/wasm blobs
node docs/reverse-toolkit/extract-embedded.mjs npm/package/bundle/qoderclicn.js extracted/
strings -n 5 extracted/*-wasm-*.bin | rg -i 'cosy|/api/|bearer|aes|rsa'

# TLS fingerprints
FP_OUT=/tmp/fp-cli docs/reverse-toolkit/fingerprint-client.sh -- \
    env HTTPS_PROXY=http://127.0.0.1:8899 node npm/package/bundle/qoderclicn.js --list-models
strace -f -e trace=write,writev,sendto,sendmsg -s 8192 -xx -o t.txt "out/opt/Qoder CN/qoder-cn" --no-sandbox …
python3 docs/reverse-toolkit/extract-hello.py t.txt

# machine identity binary
./out/opt/Qoder\ CN/resources/umid/runtime-info
# idalib: idb_open(mode="force_headless") -> survey_binary -> find(string) -> analyze_function
```

### Confidence

| Finding | Confidence | Basis |
|---|---|---|
| Endpoint host/path map | **High** | literal strings in both bundles |
| OAuth flow + PKCE alphabet | **High** | decoded source, two independent copies |
| Client IDs | **High** | decoded literals (CLI) + literal (desktop) |
| Request headers | **High** | both literals and WASM string table |
| TLS JA3 values | **High** | measured on the real binaries |
| Machine-identity algorithm | **Medium** | behavior + disassembly; exact hash not fully reversed |
| Body signing/AES envelope scope | **Medium** | WASM exports; server acceptance untested |

Items marked Medium should be validated against the live service with a real
account before relying on them.
