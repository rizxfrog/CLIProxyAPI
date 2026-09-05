# Chat Completions Protocol Smoke Tests

This document provides copy-paste `curl` commands plus an equivalent Go test
that verifies the OpenAI-compatible `/v1/chat/completions` endpoint against a
running CLIProxyAPI server.

Both non-streaming and streaming requests are covered.

## Prerequisites

- A running CLIProxyAPI instance (default: `http://127.0.0.1:8080`).
- A valid API key configured in `config.yaml` (the examples use `sk-test`).
- Replace `gpt-4o-mini` with any model exposed by your credentials
  (for example `glm-5.2` when a TRAE SOLO CN credential is configured).

```bash
# Environment used by the curl examples and the Go test
export CLIPROXY_BASE_URL="http://127.0.0.1:8317"
export CLIPROXY_API_KEY="sk-test"
export CLIPROXY_MODEL="deepseek-v4-flash"
```

## 1. Non-streaming completion

```bash
curl -sS "${CLIPROXY_BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${CLIPROXY_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"model\": \"${CLIPROXY_MODEL}\",
    \"messages\": [{\"role\": \"user\", \"content\": \"Say hello in one sentence.\"}],
    \"stream\": false
  }"
```

Expected shape:

```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello!"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0
  }
}
```

## 2. Streaming completion (SSE)

```bash
curl -sS -N "${CLIPROXY_BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${CLIPROXY_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"model\": \"${CLIPROXY_MODEL}\",
    \"messages\": [{\"role\": \"user\", \"content\": \"Hi, who are you?\"}],
    \"stream\": true
  }"
```

Expected stream:

```text
data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"1"},"finish_reason":null}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

## 3. TRAE SOLO CN model example

When a TRAE credential (`trae-api-key`) is configured, the same endpoint routes
`glm-5.2` to the TRAE `solo_work_lite` upstream channel.

```bash
curl -sS "${CLIPROXY_BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${CLIPROXY_API_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "glm-5.2",
    "messages": [{"role": "user", "content": "用一句话介绍你自己"}],
    "stream": false
  }'
```
