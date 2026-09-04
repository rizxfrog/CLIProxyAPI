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

## 4. Go test

The code below is a standalone `package test` test. Copy it to
`test/chat_completions_curl_test.go` and run:

```bash
CLIPROXY_BASE_URL="http://127.0.0.1:8080" \
CLIPROXY_API_KEY="sk-test" \
CLIPROXY_MODEL="gpt-4o-mini" \
go test -v -run TestChatCompletionsCurl ./test/
```

```go
package test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func chatCompletionsEnv(t *testing.T) (baseURL, apiKey, model string) {
	t.Helper()
	baseURL = strings.TrimRight(os.Getenv("CLIPROXY_BASE_URL"), "/")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8080"
	}
	apiKey = os.Getenv("CLIPROXY_API_KEY")
	if apiKey == "" {
		apiKey = "sk-test"
	}
	model = os.Getenv("CLIPROXY_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	return baseURL, apiKey, model
}

func postChatCompletion(t *testing.T, baseURL, apiKey string, body map[string]any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post chat completions: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := json.MarshalIndent(body, "", "  ")
		t.Fatalf("status = %d, want 200\nrequest:\n%s", resp.StatusCode, bodyBytes)
	}
	return resp
}

func TestChatCompletionsNonStreamingCurl(t *testing.T) {
	baseURL, apiKey, model := chatCompletionsEnv(t)
	resp := postChatCompletion(t, baseURL, apiKey, map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Say hello in one sentence."}},
		"stream":   false,
	})
	defer resp.Body.Close()

	var parsed struct {
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode non-streaming response: %v", err)
	}
	if parsed.Object != "chat.completion" {
		t.Fatalf("object = %q, want chat.completion", parsed.Object)
	}
	if len(parsed.Choices) == 0 {
		t.Fatal("no choices returned")
	}
	choice := parsed.Choices[0]
	if strings.TrimSpace(choice.Message.Content) == "" {
		t.Fatalf("message content is empty: %+v", parsed)
	}
	if choice.FinishReason != "stop" {
		t.Fatalf("finish_reason = %q, want stop", choice.FinishReason)
	}
	t.Logf("model=%q content=%q", parsed.Model, choice.Message.Content)
}

func TestChatCompletionsStreamingCurl(t *testing.T) {
	baseURL, apiKey, model := chatCompletionsEnv(t)
	resp := postChatCompletion(t, baseURL, apiKey, map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Count from 1 to 5."}},
		"stream":   true,
	})
	defer resp.Body.Close()

	type chunkPayload struct {
		Object  string `json:"object"`
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}

	sawChunk := false
	sawDone := false
	contentParts := make([]string, 0, 8)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "data: [DONE]" {
			sawDone = true
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var chunk chunkPayload
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil {
			t.Fatalf("decode streaming chunk: %v\nline: %s", err, line)
		}
		if chunk.Object != "chat.completion.chunk" {
			t.Fatalf("object = %q, want chat.completion.chunk", chunk.Object)
		}
		sawChunk = true
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			contentParts = append(contentParts, chunk.Choices[0].Delta.Content)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read streaming response: %v", err)
	}
	if !sawChunk {
		t.Fatal("no SSE chunk received")
	}
	if !sawDone {
		t.Fatal("stream did not end with data: [DONE]")
	}
	t.Logf("streamed content: %q", strings.Join(contentParts, ""))
}

func TestChatCompletionsTraeModelCurl(t *testing.T) {
	baseURL, apiKey, _ := chatCompletionsEnv(t)
	model := os.Getenv("CLIPROXY_TRAE_MODEL")
	if model == "" {
		model = "glm-5.2"
	}
	resp := postChatCompletion(t, baseURL, apiKey, map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "用一句话介绍你自己"}},
		"stream":   false,
	})
	defer resp.Body.Close()

	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode TRAE response: %v", err)
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		t.Fatalf("TRAE model %q returned empty content: %+v", model, parsed)
	}
	t.Logf("trae model=%q content=%q", parsed.Model, parsed.Choices[0].Message.Content)
}
```
