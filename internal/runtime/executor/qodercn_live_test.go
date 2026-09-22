package executor

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// TestLiveQoderCNEndToEnd exercises the full signed transport against the real
// Qoder CN gateway. It is skipped unless QODERCN_LIVE_AUTH_FILE points at a live
// auth JSON (a data/auth_files/qoder-cn-*.json path):
//
//	QODERCN_LIVE_AUTH_FILE=data/auth_files/qoder-cn-*.json \
//	  go test ./internal/runtime/executor/ -run TestLiveQoderCNEndToEnd -v
func TestLiveQoderCNEndToEnd(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("QODERCN_LIVE_AUTH_FILE"))
	if path == "" {
		t.Skip("set QODERCN_LIVE_AUTH_FILE to a qoder-cn auth JSON to run the live test")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var authFile map[string]any
	if err := json.Unmarshal(raw, &authFile); err != nil {
		t.Fatalf("parse auth file: %v", err)
	}
	accessToken, _ := authFile["access_token"].(string)
	if strings.TrimSpace(accessToken) == "" {
		t.Fatal("auth file has no access_token")
	}

	executor := NewQoderCNExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID:       "live-qoder-cn.json",
		Provider: "qoder-cn",
		Metadata: map[string]any{"access_token": accessToken},
	}
	if refresh, _ := authFile["refresh_token"].(string); refresh != "" {
		auth.Metadata["refresh_token"] = refresh
	}

	// Identity resolution (this is what PrepareRequestAuth does in production).
	prepared, err := executor.PrepareRequestAuth(context.Background(), auth)
	if err != nil {
		t.Fatalf("PrepareRequestAuth: %v", err)
	}
	t.Logf("resolved identity: uid=%v name=%v user_type=%v",
		prepared.Metadata["uid"], prepared.Metadata["name"], prepared.Metadata["user_type"])

	body := []byte(`{"model":"qmodel_38max","stream":true,"messages":[{"role":"user","content":"Reply with exactly the word PONG and nothing else."}]}`)
	opts := cliproxyexecutor.Options{
		Stream:          true,
		OriginalRequest: body,
		SourceFormat:    "openai",
	}

	result, err := executor.ExecuteStream(context.Background(), prepared, cliproxyexecutor.Request{
		Model:   "qoder/qmodel_38max",
		Payload: body,
	}, opts)
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}

	var content, reasoning strings.Builder
	chunks := 0
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error: %v", chunk.Err)
		}
		chunks++
		payload := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(chunk.Payload)), "data:"))
		if payload == "" || payload == "[DONE]" || !json.Valid([]byte(payload)) {
			continue
		}
		content.WriteString(gjson.Get(payload, "choices.0.delta.content").String())
		reasoning.WriteString(gjson.Get(payload, "choices.0.delta.reasoning_content").String())
	}
	t.Logf("chunks=%d content=%q reasoning=%q", chunks, content.String(), reasoning.String())
	if chunks == 0 {
		t.Fatal("no stream chunks received")
	}
	if strings.TrimSpace(content.String()) == "" && strings.TrimSpace(reasoning.String()) == "" {
		t.Fatal("stream produced neither content nor reasoning")
	}
}
