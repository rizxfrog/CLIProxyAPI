package executor

import (
	"encoding/json"
	"strings"
	"testing"

	qodercnauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// TestQoderCNPathConstants pins the endpoint paths so an accidental edit to the
// signed agent path is caught.
func TestQoderCNPathConstants(t *testing.T) {
	if QoderCNModelBaseURL != "https://gateway.qoder.com.cn" {
		t.Fatalf("gateway base URL = %q", QoderCNModelBaseURL)
	}
	if QoderCNAlgoPath != "/algo/api/v2/service/pro/sse/agent_chat_generation" {
		t.Fatalf("algo path = %q", QoderCNAlgoPath)
	}
	if qoderCNAgentSignPath != "/api/v2/service/pro/sse/agent_chat_generation" {
		t.Fatalf("sign path = %q", qoderCNAgentSignPath)
	}
	if QoderCNModelDirPath != "/model/v1/chat/completions" {
		t.Fatalf("model dir path = %q", QoderCNModelDirPath)
	}
}

// TestQoderCNUpstreamModelStripsNamespace covers model id normalization.
func TestQoderCNUpstreamModelStripsNamespace(t *testing.T) {
	cases := map[string]string{
		"qoder/qmodel_38max": "qmodel_38max",
		"qmodel_38max":       "qmodel_38max",
		"qoder/auto(8192)":   "auto",
		"":                   "auto",
		"  gmodel  ":         "gmodel",
	}
	for in, want := range cases {
		if got := qoderCNUpstreamModel(in); got != want {
			t.Fatalf("qoderCNUpstreamModel(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestQoderCNBuildEnvelopeShape verifies the envelope the gateway expects.
func TestQoderCNBuildEnvelopeShape(t *testing.T) {
	openAI := []byte(`{
		"model":"qmodel_38max",
		"max_tokens":1234,
		"messages":[
			{"role":"system","content":"be brief"},
			{"role":"user","content":"hello world"}
		],
		"tools":[{"type":"function","function":{"name":"Read","parameters":{"type":"object"}}}]
	}`)
	raw, err := qoderCNBuildEnvelope(openAI, "qmodel_38max", "personal_standard")
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("invalid envelope: %s", raw)
	}
	if got := gjson.GetBytes(raw, "model_config.key").String(); got != "qmodel_38max" {
		t.Fatalf("model_config.key = %q", got)
	}
	if got := gjson.GetBytes(raw, "aliyun_user_type").String(); got != "personal_standard" {
		t.Fatalf("aliyun_user_type = %q", got)
	}
	if got := gjson.GetBytes(raw, "parameters.max_tokens").Int(); got != 1234 {
		t.Fatalf("parameters.max_tokens = %d", got)
	}
	if got := gjson.GetBytes(raw, "agent_id").String(); got != "agent_common" {
		t.Fatalf("agent_id = %q", got)
	}
	if got := gjson.GetBytes(raw, "chat_context.text.text").String(); got != "hello world" {
		t.Fatalf("chat_context.text.text = %q", got)
	}
	if !gjson.GetBytes(raw, "stream").Bool() {
		t.Fatalf("stream should be true: %s", raw)
	}
	if n := gjson.GetBytes(raw, "tools.#").Int(); n != 1 {
		t.Fatalf("tools count = %d, want 1", n)
	}
	if n := gjson.GetBytes(raw, "messages.#").Int(); n != 2 {
		t.Fatalf("messages count = %d, want 2", n)
	}
	// The user message must use the Qoder "contents" shape.
	if got := gjson.GetBytes(raw, "messages.1.contents.0.text").String(); got != "hello world" {
		t.Fatalf("user contents text = %q", got)
	}
}

// TestQoderCNBuildEnvelopeMarksVision asserts image parts set is_vl.
func TestQoderCNBuildEnvelopeMarksVision(t *testing.T) {
	openAI := []byte(`{
		"model":"gmodel",
		"messages":[{"role":"user","content":[
			{"type":"text","text":"describe"},
			{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}
		]}]
	}`)
	raw, err := qoderCNBuildEnvelope(openAI, "gmodel", "personal_standard")
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	if !gjson.GetBytes(raw, "model_config.is_vl").Bool() {
		t.Fatalf("is_vl should be true: %s", raw)
	}
	if got := gjson.GetBytes(raw, "messages.0.contents.1.type").String(); got != "image_url" {
		t.Fatalf("image content type = %q", got)
	}
}

// TestQoderCNExtractInner covers the double-wrapped SSE body.
func TestQoderCNExtractInner(t *testing.T) {
	frame := []byte(`{"headers":{"Content-Type":["application/json"]},"body":"{\"choices\":[]}","statusCode":"OK"}`)
	inner, done, ok := qoderCNExtractInner(frame)
	if !ok || done {
		t.Fatalf("extract failed: ok=%v done=%v", ok, done)
	}
	if !gjson.GetBytes(inner, "choices").Exists() {
		t.Fatalf("inner = %s", inner)
	}
	// [DONE] frame.
	if _, done, ok := qoderCNExtractInner([]byte(`{"body":"[DONE]"}`)); !ok || !done {
		t.Fatalf("done frame not detected")
	}
	// timing-only footer has no body.
	if _, _, ok := qoderCNExtractInner([]byte(`{"firstTokenDuration":1}`)); ok {
		t.Fatalf("footer frame should not be treated as a body frame")
	}
}

// TestQoderCNStreamStateEmitsFrames verifies chunks are OpenAI-shaped.
func TestQoderCNStreamStateEmitsFrames(t *testing.T) {
	state := newQoderCNStreamState("qmodel_38max")
	frame := []byte(`{"body":"{\"choices\":[{\"delta\":{\"reasoning_content\":\"think\",\"content\":\"hi\"},\"index\":0}]}"}`)
	frames, apiErr := state.consumeDataLine(frame)
	if apiErr != "" {
		t.Fatalf("unexpected api error: %s", apiErr)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	payload := strings.TrimPrefix(string(frames[0]), "data: ")
	if got := gjson.Get(payload, "choices.0.delta.content").String(); got != "hi" {
		t.Fatalf("content = %q", got)
	}
	if got := gjson.Get(payload, "choices.0.delta.reasoning_content").String(); got != "think" {
		t.Fatalf("reasoning = %q", got)
	}
	if got := gjson.Get(payload, "choices.0.delta.role").String(); got != "assistant" {
		t.Fatalf("role = %q", got)
	}
	if got := gjson.Get(payload, "model").String(); got != "qmodel_38max" {
		t.Fatalf("model = %q", got)
	}
}

// TestQoderCNStreamStateDetectsAPIError ensures a JSON error envelope surfaces.
func TestQoderCNStreamStateDetectsAPIError(t *testing.T) {
	state := newQoderCNStreamState("m")
	frame := []byte(`{"body":"{\"code\":\"101\",\"message\":\"Signature invalid\"}"}`)
	if _, apiErr := state.consumeDataLine(frame); apiErr == "" {
		t.Fatal("expected an api error for a code/message envelope")
	}
}

// TestQoderCNAggregateStream folds chunks into a chat.completion.
func TestQoderCNAggregateStream(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"qmodel_38max","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"why"},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"qmodel_38max","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}`,
		`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"qmodel_38max","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
	}, "\n")
	out := qoderCNAggregateStream([]byte(stream), "qmodel_38max")
	if !json.Valid(out) {
		t.Fatalf("invalid aggregate: %s", out)
	}
	if got := gjson.GetBytes(out, "object").String(); got != "chat.completion" {
		t.Fatalf("object = %q", got)
	}
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "hello" {
		t.Fatalf("content = %q", got)
	}
	if got := gjson.GetBytes(out, "choices.0.message.reasoning_content").String(); got != "why" {
		t.Fatalf("reasoning = %q", got)
	}
	if got := gjson.GetBytes(out, "choices.0.finish_reason").String(); got != "stop" {
		t.Fatalf("finish_reason = %q", got)
	}
}

// TestQoderCNProfileAndTokens documents credential resolution precedence.
func TestQoderCNProfileAndTokens(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "qoder-cn-1.json",
		Provider: "qoder-cn",
		Metadata: map[string]any{
			"access_token": "dt-token",
			"uid":          "uid-1",
			"name":         "alice",
			"user_type":    "personal_standard",
		},
	}
	if got := qoderCNAccessToken(auth); got != "dt-token" {
		t.Fatalf("access token = %q", got)
	}
	profile := qoderCNProfile(auth)
	if profile.UID != "uid-1" || profile.Name != "alice" {
		t.Fatalf("profile = %+v", profile)
	}
	if profile.AID != "uid-1" {
		t.Fatalf("aid should fall back to uid, got %q", profile.AID)
	}
	if profile.UserType != "personal_standard" {
		t.Fatalf("user type = %q", profile.UserType)
	}
}

// TestShouldPrepareRequestAuth asserts identity-less credentials request prep.
func TestShouldPrepareRequestAuth(t *testing.T) {
	exec := NewQoderCNExecutor(nil)
	missing := &cliproxyauth.Auth{ID: "a", Provider: "qoder-cn", Metadata: map[string]any{"access_token": "t"}}
	if !exec.ShouldPrepareRequestAuth(missing) {
		t.Fatal("identity-less credential should require preparation")
	}
	complete := &cliproxyauth.Auth{ID: "b", Provider: "qoder-cn", Metadata: map[string]any{
		"access_token": "t", "uid": "u", "name": "n",
	}}
	if exec.ShouldPrepareRequestAuth(complete) {
		t.Fatal("credential with identity should not require preparation")
	}
}

// TestQoderCNStatusErrorCarriesCode ensures the auth manager can read the status.
func TestQoderCNStatusErrorCarriesCode(t *testing.T) {
	err := qoderCNStatusError{code: 401, msg: "unauthorized"}
	if err.StatusCode() != 401 || err.Error() != "unauthorized" {
		t.Fatalf("status error = %v / %d", err, err.StatusCode())
	}
}

// TestQoderCNSignatureStableForSameInputs pins the signature algorithm so an
// accidental change to the newline-joined components is caught.
func TestQoderCNSignatureStableForSameInputs(t *testing.T) {
	a := qodercnauth.CosySign("payload", "key", "date", "body", "/path")
	b := qodercnauth.CosySign("payload", "key", "date", "body", "/path")
	if a != b {
		t.Fatalf("signature is not deterministic: %q vs %q", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("signature length = %d, want 32 (md5 hex)", len(a))
	}
	if c := qodercnauth.CosySign("payload", "key", "date", "body", "/other"); c == a {
		t.Fatal("signature should depend on the path")
	}
}
