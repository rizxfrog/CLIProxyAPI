package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestDeepSeekWebUserToken(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "raw", raw: " raw-token ", want: "raw-token"},
		{name: "wrapped", raw: `{"value":"wrapped-token","__version":"0"}`, want: "wrapped-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deepSeekWebUserToken(&cliproxyauth.Auth{Attributes: map[string]string{"api_key": tt.raw}})
			if err != nil {
				t.Fatalf("deepSeekWebUserToken() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("deepSeekWebUserToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeepSeekWebMessagesToPrompt(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Hello"},{"role":"assistant","content":"Hi"},{"role":"user","content":[{"type":"text","text":"Again"}]}]}`)
	got, err := deepSeekWebMessagesToPrompt(body)
	if err != nil {
		t.Fatalf("deepSeekWebMessagesToPrompt() error = %v", err)
	}
	want := "Be concise\n\nUser: Hello\n\nAssistant: Hi\n\nUser: Again"
	if got != want {
		t.Fatalf("prompt = %q, want %q", got, want)
	}
}

func TestDeepSeekWebModelOptions(t *testing.T) {
	modelType, thinking, search := deepSeekWebModelOptions("deepseek-v4-pro-think-search", []byte(`{"messages":[]}`))
	if modelType != "expert" || !thinking || !search {
		t.Fatalf("options = %q, %v, %v", modelType, thinking, search)
	}
}

func TestDeepSeekWebSSEState(t *testing.T) {
	state := newDeepSeekWebSSEState("deepseek-reasoner")
	frames := state.consume([]byte(`{"v":{"response":{"thinking_enabled":true,"fragments":[{"type":"THINK","content":"plan"}]}}}`))
	if len(frames) != 2 || gjson.GetBytes(bytes.TrimPrefix(frames[1], []byte("data: ")), "choices.0.delta.reasoning_content").String() != "plan" {
		t.Fatalf("reasoning frames = %q", frames)
	}
	frames = state.consume([]byte(`{"p":"response/fragments","o":"APPEND","v":{"type":"RESPONSE","content":"answer"}}`))
	if len(frames) != 1 || gjson.GetBytes(bytes.TrimPrefix(frames[0], []byte("data: ")), "choices.0.delta.content").String() != "answer" {
		t.Fatalf("content frames = %q", frames)
	}
	state.consume([]byte(`{"v":"!"}`))
	finished := state.finishFrames()
	if len(finished) != 2 || string(finished[1]) != "[DONE]" {
		t.Fatalf("finish frames = %q", finished)
	}
	response := state.nonStreamResponse()
	if got := gjson.GetBytes(response, "choices.0.message.reasoning_content").String(); got != "plan" {
		t.Fatalf("reasoning_content = %q", got)
	}
	if got := gjson.GetBytes(response, "choices.0.message.content").String(); got != "answer!" {
		t.Fatalf("content = %q", got)
	}
}

func TestDeepSeekWebExecutorExecute(t *testing.T) {
	const capturedChallenge = "ea74b2a42974e90c46295a2fbd0b6942bb686efc1b71e5aa70abeda64869ade4"
	var mu sync.Mutex
	paths := make([]string, 0, 5)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.Header.Get("X-Client-Version") != "2.4.0" {
			t.Errorf("X-Client-Version = %q", r.Header.Get("X-Client-Version"))
		}
		switch r.URL.Path {
		case "/api/v0/users/current":
			if r.Header.Get("Authorization") != "Bearer user-token" {
				t.Errorf("users/current authorization = %q", r.Header.Get("Authorization"))
			}
			fmt.Fprint(w, `{"code":0,"data":{"biz_data":{"token":"access-token"}}}`)
		case "/api/v0/chat_session/create":
			fmt.Fprint(w, `{"code":0,"data":{"biz_data":{"chat_session":{"id":"session-1"}}}}`)
		case "/api/v0/chat/create_pow_challenge":
			fmt.Fprintf(w, `{"code":0,"data":{"biz_data":{"challenge":{"algorithm":"DeepSeekHashV1","challenge":%q,"salt":"09fd35c1f240633d7545","signature":"sig","difficulty":144000,"expire_at":1787756464033,"target_path":"/api/v0/chat/completion"}}}}`, capturedChallenge)
		case "/api/v0/chat/completion":
			powJSON, errDecode := base64.StdEncoding.DecodeString(r.Header.Get("X-Ds-Pow-Response"))
			if errDecode != nil || gjson.GetBytes(powJSON, "answer").Int() != 75656 {
				t.Errorf("invalid PoW response: %s (%v)", powJSON, errDecode)
			}
			var payload map[string]any
			if errDecodeBody := json.NewDecoder(r.Body).Decode(&payload); errDecodeBody != nil {
				t.Errorf("decode completion body: %v", errDecodeBody)
			}
			if payload["chat_session_id"] != "session-1" || payload["prompt"] != "User: hello" {
				t.Errorf("completion payload = %#v", payload)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintln(w, `event: ready`)
			fmt.Fprintln(w, `data: {"v":{"response":{"thinking_enabled":false,"fragments":[{"type":"RESPONSE","content":"hello"}]}}}`)
			fmt.Fprintln(w, `data: {"v":" world"}`)
			fmt.Fprintln(w, `data: {"p":"response/status","v":"FINISHED"}`)
		case "/api/v0/chat_session/delete":
			fmt.Fprint(w, `{"code":0,"data":{"biz_data":{}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewDeepSeekWebExecutor(nil)
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": `{"value":"user-token"}`, "base_url": server.URL}}
	requestBody := []byte(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	response, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "deepseek-chat", Payload: requestBody}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI,
		OriginalRequest: requestBody,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := gjson.GetBytes(response.Payload, "choices.0.message.content").String(); got != "hello world" {
		t.Fatalf("content = %q, payload=%s", got, response.Payload)
	}
	mu.Lock()
	joined := strings.Join(paths, ",")
	mu.Unlock()
	for _, required := range []string{"/api/v0/users/current", "/api/v0/chat_session/create", "/api/v0/chat/create_pow_challenge", "/api/v0/chat/completion", "/api/v0/chat_session/delete"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("request paths %q missing %q", joined, required)
		}
	}
}
