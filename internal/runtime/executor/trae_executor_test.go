package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTraeSSEDoneEmitsRawJSONOnly(t *testing.T) {
	state := newTraeSSEState("glm-5.2")
	frames := state.dispatchEvent("done", `{"finish_reason":"tool_calls"}`)
	if len(frames) != 1 {
		t.Fatalf("done frames = %d, want 1", len(frames))
	}
	if strings.HasPrefix(string(frames[0]), "data:") {
		t.Fatalf("executor must not emit SSE data prefix: %q", frames[0])
	}
	var payload map[string]any
	if err := json.Unmarshal(frames[0], &payload); err != nil {
		t.Fatalf("done frame is not JSON: %v", err)
	}
	if got := payload["object"]; got != "chat.completion.chunk" {
		t.Fatalf("object = %v, want chat.completion.chunk", got)
	}
}

func TestTraeNormalizeMessagesMapsDeveloperToSystem(t *testing.T) {
	body := []byte(`{"model":"glm-5.2","messages":[{"role":"developer","content":"Use the tool."}]}`)
	out := traeNormalizeMessages(body)
	var payload struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("decode normalized body: %v", err)
	}
	if len(payload.Messages) != 1 || payload.Messages[0].Role != "system" {
		t.Fatalf("messages = %+v, want developer mapped to system", payload.Messages)
	}
}

func TestTraeToolCallFunctionCallMapsToOpenAIFunction(t *testing.T) {
	state := newTraeSSEState("glm-5.2")
	frames := state.dispatchEvent("output", `{"response":"","tool_calls":[{"index":0,"id":"call_1","type":"function","function_call":{"name":"bash","arguments":"{\"command\":\"printf hi\"}"}}]}`)
	if len(frames) != 2 {
		t.Fatalf("tool output frames = %d, want role + tool call", len(frames))
	}
	var chunk struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(frames[1], &chunk); err != nil {
		t.Fatalf("decode tool chunk: %v", err)
	}
	if len(chunk.Choices) != 1 || len(chunk.Choices[0].Delta.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v", chunk.Choices)
	}
	call := chunk.Choices[0].Delta.ToolCalls[0]
	if call.Function.Name != "bash" || call.Function.Arguments != `{"command":"printf hi"}` {
		t.Fatalf("tool function = %+v", call.Function)
	}
}
