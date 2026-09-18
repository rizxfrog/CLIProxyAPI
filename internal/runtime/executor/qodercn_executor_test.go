package executor

import (
	"context"
	"encoding/json"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// TestPrepareQoderCNAuthSeedsModelBaseURL checks the base_url that the
// OpenAI-compatible executor turns into {base}/chat/completions.
func TestPrepareQoderCNAuthSeedsModelBaseURL(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "qoder-cn-1.json",
		Provider: "qoder-cn",
		Metadata: map[string]any{"access_token": "tok"},
	}
	prepared := prepareQoderCNAuth(auth)
	if prepared == nil {
		t.Fatal("prepareQoderCNAuth returned nil")
	}
	if got := prepared.Attributes["base_url"]; got != QoderCNModelBaseURL {
		t.Fatalf("base_url = %q, want %q", got, QoderCNModelBaseURL)
	}
	// The compat executor appends "/chat/completions".
	if got := prepared.Attributes["base_url"] + "/chat/completions"; got != QoderCNModelBaseURL+"/chat/completions" {
		t.Fatalf("resolved endpoint = %q", got)
	}
	if got := prepared.Attributes["api_key"]; got != "tok" {
		t.Fatalf("api_key = %q, want the access token", got)
	}
	for _, header := range []string{"User-Agent", "Cosy-Version", "Cosy-ClientType", "Cosy-Business-Product"} {
		if prepared.Attributes["header:"+header] == "" {
			t.Fatalf("missing default header %q", header)
		}
	}
}

// TestPrepareQoderCNTrimsFullEndpoint ensures a caller that stored the complete
// endpoint path does not end up with a doubled "/chat/completions".
func TestPrepareQoderCNTrimsFullEndpoint(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "qoder-cn-2.json",
		Provider: "qoder-cn",
		Metadata: map[string]any{"access_token": "tok"},
		Attributes: map[string]string{
			"base_url": "https://api2-v2.qoder.sh/model/v1/chat/completions",
		},
	}
	prepared := prepareQoderCNAuth(auth)
	want := "https://api2-v2.qoder.sh/model/v1"
	if got := prepared.Attributes["base_url"]; got != want {
		t.Fatalf("base_url = %q, want %q", got, want)
	}
}

// TestPrepareQoderCNHonoursCustomHeaders ensures operator-supplied header
// overrides win over the built-in defaults.
func TestPrepareQoderCNHonoursCustomHeaders(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "qoder-cn-3.json",
		Provider: "qoder-cn",
		Metadata: map[string]any{"access_token": "tok"},
		Attributes: map[string]string{
			"header:User-Agent": "custom-agent/1.0",
		},
	}
	prepared := prepareQoderCNAuth(auth)
	if got := prepared.Attributes["header:User-Agent"]; got != "custom-agent/1.0" {
		t.Fatalf("User-Agent = %q, want the custom value", got)
	}
}

// TestApplyQoderCNOutgoingTransformsInjectsEnvelope verifies that the required
// metadata.context envelope is added to a bare OpenAI body.
func TestApplyQoderCNOutgoingTransformsInjectsEnvelope(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`)
	auth := &cliproxyauth.Auth{ID: "qoder-cn-x.json", Provider: "qoder-cn"}

	got := applyQoderCNOutgoingTransforms(context.Background(), auth, "claude-sonnet-4-5", cliproxyexecutor.Options{Stream: true}, body)
	if !json.Valid(got) {
		t.Fatalf("transform produced invalid JSON: %s", got)
	}
	if !gjson.GetBytes(got, "metadata.context").Exists() {
		t.Fatalf("metadata.context was not injected: %s", got)
	}
	if ct := gjson.GetBytes(got, "metadata.context.client_type").String(); ct != "5" {
		t.Fatalf("client_type = %q, want \"5\" (CLI)", ct)
	}
	if sid := gjson.GetBytes(got, "metadata.context.session_id").String(); sid == "" {
		t.Fatalf("session_id missing: %s", got)
	}
	// The OpenAI fields must survive untouched.
	if m := gjson.GetBytes(got, "model").String(); m != "claude-sonnet-4-5" {
		t.Fatalf("model = %q", m)
	}
	if n := gjson.GetBytes(got, "messages.#").Int(); n != 1 {
		t.Fatalf("messages count = %d, want 1", n)
	}
}

// TestApplyQoderCNOutgoingTransformsStreamFlag asserts the stream flag mirrors
// the caller's intent. Setting stream:true for a non-streaming client would make
// the upstream return an SSE body the caller cannot parse.
func TestApplyQoderCNOutgoingTransformsStreamFlag(t *testing.T) {
	body := []byte(`{"model":"m","messages":[]}`)
	auth := &cliproxyauth.Auth{ID: "s.json", Provider: "qoder-cn"}

	streamed := applyQoderCNOutgoingTransforms(context.Background(), auth, "m", cliproxyexecutor.Options{Stream: true}, body)
	if !gjson.GetBytes(streamed, "stream").Bool() {
		t.Fatalf("stream = false, want true for a streaming request: %s", streamed)
	}
	if !gjson.GetBytes(streamed, "stream_options.include_usage").Bool() {
		t.Fatalf("stream_options.include_usage missing: %s", streamed)
	}

	plain := applyQoderCNOutgoingTransforms(context.Background(), auth, "m", cliproxyexecutor.Options{}, body)
	if gjson.GetBytes(plain, "stream").Bool() {
		t.Fatalf("stream = true, want false for a non-streaming request: %s", plain)
	}
}

// TestApplyQoderCNOutgoingTransformsPreservesExistingEnvelope ensures an
// operator-supplied business block is not clobbered by the injected envelope.
func TestApplyQoderCNOutgoingTransformsPreservesExistingEnvelope(t *testing.T) {
	body := []byte(`{"model":"m","messages":[],"metadata":{"context":{"request_id":"r1"}}}`)
	auth := &cliproxyauth.Auth{ID: "e.json", Provider: "qoder-cn"}
	got := applyQoderCNOutgoingTransforms(context.Background(), auth, "m", cliproxyexecutor.Options{}, body)
	if rid := gjson.GetBytes(got, "metadata.context.request_id").String(); rid != "r1" {
		t.Fatalf("existing envelope was overwritten: %s", got)
	}
}

// TestQoderCNStripMetadataEnvelope covers the response-side cleanup helper.
func TestQoderCNStripMetadataEnvelope(t *testing.T) {
	in := []byte(`{"id":"1","metadata":{"context":{"a":1}},"choices":[]}`)
	out := qoderCNStripMetadataEnvelope(in)
	if gjson.GetBytes(out, "metadata").Exists() {
		t.Fatalf("metadata not stripped: %s", out)
	}
	if !gjson.GetBytes(out, "choices").Exists() {
		t.Fatalf("unrelated fields were dropped: %s", out)
	}
	if got := qoderCNStripMetadataEnvelope(nil); got != nil {
		t.Fatalf("nil input should return nil, got %v", got)
	}
}

// TestQoderCNMachineIDPrecedence documents how Cosy-MachineId is resolved.
func TestQoderCNMachineIDPrecedence(t *testing.T) {
	if got := qoderCNMachineID(nil); got != "" {
		t.Fatalf("nil auth machine id = %q, want empty", got)
	}
	fromMetadata := &cliproxyauth.Auth{ID: "a", Metadata: map[string]any{"machine_id": "from-meta"}}
	if got := qoderCNMachineID(fromMetadata); got != "from-meta" {
		t.Fatalf("machine id = %q, want from-meta", got)
	}
	fromAttributes := &cliproxyauth.Auth{ID: "b", Attributes: map[string]string{"machine_id": "from-attr"}}
	if got := qoderCNMachineID(fromAttributes); got != "from-attr" {
		t.Fatalf("machine id = %q, want from-attr", got)
	}
	// The metadata value wins when both are present.
	both := &cliproxyauth.Auth{ID: "c", Metadata: map[string]any{"machine_id": "meta"}, Attributes: map[string]string{"machine_id": "attr"}}
	if got := qoderCNMachineID(both); got != "meta" {
		t.Fatalf("machine id = %q, want meta", got)
	}
}

// TestQoderCNPathConstants pins the endpoint paths so an accidental edit to the
// signature-gated path is caught.
func TestQoderCNPathConstants(t *testing.T) {
	if QoderCNModelBaseURL != "https://api2-v2.qoder.sh" {
		t.Fatalf("model base URL = %q", QoderCNModelBaseURL)
	}
	// The compat executor appends "/chat/completions", so the base must be the
	// "/model/v1" prefix and the full path must not be doubled.
	if QoderCNChatCompletionsPath != "/model/v1/chat/completions" {
		t.Fatalf("chat completions path = %q", QoderCNChatCompletionsPath)
	}
	if QoderCNAgentChatGenerationPath != "/algo/api/v2/service/pro/sse/agent_chat_generation" {
		t.Fatalf("agent chat generation path = %q", QoderCNAgentChatGenerationPath)
	}
}
