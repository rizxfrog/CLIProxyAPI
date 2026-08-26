# DeepSeek Web Provider

This document records how the `deepseek-web` provider works in CLIProxyAPI, the
protocol it implements, and how the implementation was verified against the live
`chat.deepseek.com` web client.

## What it is

`deepseek-web` is a "browser session" provider. It forwards OpenAI-format chat
requests through the **private** `chat.deepseek.com` web API by replaying the same
request sequence the DeepSeek web client performs. It does **not** use the DeepSeek
Open Platform API key.

## Credential

The provider needs the browser **`userToken`**, obtained from the DeepSeek web
page's Local Storage after logging in:

```
DevTools → Application → Local Storage → https://chat.deepseek.com → userToken
```

The value is stored as a JSON object. Both forms are accepted:

```json
{"value":"6Ztcgru9Aac0PwWo5NqVRiRtQTeZ6pbJcY6qXkf2VsqIRvwbxtw9OXaigz3xN3qI","__version":"0"}
```

or the raw token string. The executor unwraps the JSON `value` automatically.

> **Important:** the Local Storage `userToken.value` is itself the **short-lived
> access token**. On login DeepSeek calls `POST /api/v0/users/oauth/get_token` and
> the returned `data.biz_data.token` is byte-for-byte identical to `userToken.value`.
> There is no separate long-lived refresh token in the browser — when the token
> expires the user must re-copy a fresh one. `Refresh` re-validates the token but
> cannot recover an expired `userToken`.

## Configuration

```yaml
deepseek-web-api-key:
  - api-key: '{"value":"YOUR_USER_TOKEN","__version":"0"}'
    weight: 1
    prefix: "ds-web"                       # optional: require ds-web/<model>
    base-url: "https://chat.deepseek.com"  # optional override, mainly for testing
    proxy-url: "socks5://proxy.example.com:1080"  # optional per-token proxy
    excluded-models:
      - "deepseek-v4-pro-search"
```

The key entry reuses the CodeBuddy CN API-key shape (`api-key` / `base-url` /
`proxy-url` / `prefix` / `weight` / `models` / `excluded-models`), so the existing
key management and credential-weight machinery applies unchanged.

## Request flow

The executor performs the same sequence as the web client (verified 2026-08-26):

| Step | Endpoint | Notes |
| ---- | -------- | ----- |
| 1 | `GET  /api/v0/users/current` | `Authorization: Bearer <userToken>` → returns `data.biz_data.token` (short access token) |
| 2 | `POST /api/v0/chat_session/create` | body `{}` → returns `data.biz_data.chat_session.id` |
| 3 | `POST /api/v0/chat/create_pow_challenge` | body `{"target_path":"/api/v0/chat/completion"}` → returns `DeepSeekHashV1` challenge |
| 4 | (local) solve PoW | pure-Go Keccak-f[1600] solver |
| 5 | `POST /api/v0/chat/completion` | body below, `X-Ds-Pow-Response` header |
| 6 | `POST /api/v0/chat_session/delete` | best-effort cleanup |

### `chat/completion` request body

```json
{
  "chat_session_id": "a084217f-7aea-4c2a-a8a3-117946c83329",
  "parent_message_id": null,
  "model_type": "default",
  "prompt": "…",
  "ref_file_ids": [],
  "thinking_enabled": false,
  "search_enabled": true,
  "action": null,
  "preempt": false
}
```

### Client fingerprint headers

```http
x-client-bundle-id: com.deepseek.chat
x-client-platform: web
x-client-version: 2.4.0
x-client-locale: en_US
x-client-timezone-offset: <local offset in seconds>
```

## PoW (DeepSeekHashV1)

The challenge is solved client-side. The algorithm:

- `prefix = salt + "_" + expire_at + "_"`
- For `nonce` in `[0, difficulty)`, hash `prefix + nonce` and compare the digest
  against `challenge`.
- The hash is Keccak-f[1600] with **rounds 1..23 only** (round zero is skipped),
  `rate = 136` bytes, and SHA-3 domain separator `0x06`.

The pure-Go implementation is in
`internal/runtime/executor/helps/deepseek_web_pow.go`
(`SolveDeepSeekWebPoW`). It was cross-verified against a live captured challenge
(`difficulty=144000`) and produces the same `nonce` as the browser solver.

## SSE → OpenAI translation

DeepSeek returns a custom `text/event-stream`:

- `event: ready` / `event: update_session` control frames
- initial `data: {"v":{"response":{…,"fragments":[…]}}}` envelope
- patch frames `data: {"p":"response/fragments/-1/content","o":"APPEND","v":"…"}`
- short increment frames `data: {"v":"…"}`
- `FINISHED` status via `{"p":"response/status","v":"FINISHED"}`

The executor (`internal/runtime/executor/deepseek_web_executor.go`) parses these
frames and re-emits OpenAI `chat.completion.chunk` for streaming clients, or a
single `chat.completion` JSON for non-streaming clients, with reasoning surfaced as
`reasoning_content`.

## Model mapping

The OpenAI `model` string is not passed through verbatim. It derives three web
options (mirroring the upstream OmniRoute executor):

| Web option | Triggered by model id substring / body field |
| ---------- | -------------------------------------------- |
| `model_type: "expert"` | `pro`, `expert` (else `default`) |
| `thinking_enabled: true` | `r1`, `think`, `reason`, or `thinking_enabled` / `thinking` / `reasoning_effort` |
| `search_enabled: true`  | `search`, or `search_enabled` / `search` / `web_search` |

Registered models (`internal/registry/models/models.json`):

```text
deepseek-v4-pro
deepseek-v4-pro-think
deepseek-v4-pro-search
deepseek-v4-pro-think-search
deepseek-v4-flash
deepseek-v4-flash-think
deepseek-chat
deepseek-reasoner
```

## Multi-turn history

OpenAI `messages[]` are flattened into a single `prompt` string, because the web
endpoint has no native `messages` array:

```text
<system prompt>

User: <latest user message>

Assistant: <assistant reply>

Tool result (<name>): <tool output>
```

## Limitations

- **Tools are not supported.** DeepSeek web `completion` has no `tools[]` field. A
  request carrying `tools` returns HTTP 400 rather than silently dropping them.
- **No long-lived credential.** `userToken` is a short-lived access token.
- **Private, undocumented endpoints.** Any upstream change to fields, PoW, or
  client attestation can break the executor.
- **`x-hif-leim` is implemented.** The web client does not compute this locally;
  it polls DeepSeek's own `hif-leim` / `hif-dliq` endpoints and forwards the
  returned value verbatim. CLIProxyAPI does the same via
  `internal/runtime/executor/helps/deepseek_web_hif.go` (lazy fetch, 600s TTL
  cache, degrade-on-miss). It is not currently enforced by the completion
  endpoint, so omitting it still works — but sending it keeps the request closer
  to the real client fingerprint.
- **Terms of service / account risk.** Using a browser session token and the
  private web API may violate DeepSeek ToS and can trigger account flags. Use your
  own account and do not log the full token.

## Verification

- PoW cross-checked against a live captured `DeepSeekHashV1` challenge
  (`TestSolveDeepSeekWebPoWCapturedChallenge`).
- `userToken` parsing, prompt building, model-option mapping, SSE state machine,
  and executor execution covered by unit tests in
  `internal/runtime/executor/` and `internal/runtime/executor/helps/`.
- Build / vet / test all pass (`go build ./cmd/server`, `go vet`, `go test`).
