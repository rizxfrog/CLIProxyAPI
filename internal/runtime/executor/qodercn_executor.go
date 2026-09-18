// Package executor provides per-provider runtime executors.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	qodercnauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// QoderCNModelBaseURL is the Qoder model-server origin. The OpenAI-compatible
// executor appends "/chat/completions", so the stored base_url is the
// ".../model/v1" prefix.
const QoderCNModelBaseURL = qodercnauth.ModelBaseURL

// QoderCNChatCompletionsPath is the upstream path relative to the model-server
// origin. The OpenAI-compatible executor appends "/chat/completions", and the
// base_url therefore carries the "/model/v1" prefix.
const QoderCNChatCompletionsPath = "/model/v1/chat/completions"

// QoderCNAgentChatGenerationPath is the signature-gated agentic SSE endpoint
// used by the official client's default ("legacy") transport. CLIProxyAPI does
// not reproduce the WASM request signature, so this path is documented for
// reference only and is not used by the executor.
const QoderCNAgentChatGenerationPath = "/algo/api/v2/service/pro/sse/agent_chat_generation"

// qoderCNMetadataContextKey is the envelope Qoder expects alongside the standard
// OpenAI fields. The official client always sends it; the gateway rejects a bare
// OpenAI body with a routing error.
const qoderCNMetadataContextKey = "metadata.context"

// QoderCNExecutor talks to the Qoder CN model server's OpenAI-compatible
// /model/v1/chat/completions endpoint.
//
// Authentication is a plain OAuth bearer token (no request signing), which is
// why the official client's "http"/"sse" model transport can be reproduced
// without the bundled qoder_auth_wasm signer.
//
// Two provider quirks are handled here:
//
//  1. Every request must carry a `metadata.context` envelope describing the
//     session, request and client type. A bare OpenAI body is rejected.
//  2. Streaming must be requested explicitly; the executor's outgoing transform
//     sets stream=true and stream_options.include_usage=true.
type QoderCNExecutor struct {
	*OpenAICompatExecutor
}

// NewQoderCNExecutor constructs a Qoder CN executor.
func NewQoderCNExecutor(cfg *config.Config) *QoderCNExecutor {
	e := NewOpenAICompatExecutor(constant.QoderCN, cfg)
	e.httpClientFactory = helps.NewQoderCNHTTPClient
	e.outgoingTransforms = applyQoderCNOutgoingTransforms
	return &QoderCNExecutor{OpenAICompatExecutor: e}
}

// Identifier returns the executor identifier.
func (e *QoderCNExecutor) Identifier() string { return constant.QoderCN }

// Execute runs a non-streaming request.
//
// Unlike CodeBuddy CN, Qoder's model server accepts non-streaming requests, so
// this delegates directly instead of forcing and re-aggregating a stream.
func (e *QoderCNExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.OpenAICompatExecutor.Execute(ctx, prepareQoderCNAuth(auth), req, opts)
}

// ExecuteStream runs a streaming request.
func (e *QoderCNExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return e.OpenAICompatExecutor.ExecuteStream(ctx, prepareQoderCNAuth(auth), req, opts)
}

// PrepareRequest injects Qoder CN credentials into ad-hoc requests.
func (e *QoderCNExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	return e.OpenAICompatExecutor.PrepareRequest(req, prepareQoderCNAuth(auth))
}

// HttpRequest executes an ad-hoc Qoder CN request with normalized credentials.
func (e *QoderCNExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	return e.OpenAICompatExecutor.HttpRequest(ctx, prepareQoderCNAuth(auth), req)
}

// Refresh rotates Qoder CN OAuth credentials using the stored refresh token.
func (e *QoderCNExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("qoder-cn executor: auth is nil")
	}
	refreshToken := qoderCNMetadataString(auth, "refresh_token")
	if refreshToken == "" {
		return auth, nil
	}
	client := qodercnauth.NewClientWithProxyURL(e.cfg, auth.ProxyURL)
	token, err := client.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["type"] = constant.QoderCN
	auth.Metadata["auth_kind"] = cliproxyauth.AuthKindOAuth
	auth.Metadata["access_token"] = token.AccessToken
	if strings.TrimSpace(token.RefreshToken) != "" {
		auth.Metadata["refresh_token"] = token.RefreshToken
	}
	if strings.TrimSpace(token.TokenType) != "" {
		auth.Metadata["token_type"] = token.TokenType
	}
	if token.ExpiresIn > 0 {
		auth.Metadata["expires_in"] = token.ExpiresIn
	}
	if !token.ExpiresAt.IsZero() {
		auth.Metadata["expired"] = token.ExpiresAt.UTC().Format(time.RFC3339)
	}
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[cliproxyauth.AttributeAuthKind] = cliproxyauth.AuthKindOAuth
	if strings.TrimSpace(auth.Attributes["base_url"]) == "" {
		auth.Attributes["base_url"] = QoderCNModelBaseURL
	}
	return auth, nil
}

// prepareQoderCNAuth normalizes Qoder CN credentials, seeds the model-server base
// URL, and applies the client headers the official CLI sends.
func prepareQoderCNAuth(auth *cliproxyauth.Auth) *cliproxyauth.Auth {
	if auth == nil {
		return nil
	}
	prepared := auth.Clone()
	if prepared.Attributes == nil {
		prepared.Attributes = make(map[string]string)
	}
	// Normalize base_url unconditionally: the OpenAI-compatible executor appends
	// "/chat/completions", so a value that already carries the full endpoint path
	// (common when an operator pastes it from the official client config) must be
	// trimmed back to the "/model/v1" prefix or the path would be doubled.
	baseURL := strings.TrimSpace(prepared.Attributes["base_url"])
	if baseURL == "" {
		baseURL = qoderCNMetadataString(prepared, "base_url")
	}
	if baseURL == "" {
		baseURL = QoderCNModelBaseURL
	}
	prepared.Attributes["base_url"] = strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/chat/completions")

	if strings.TrimSpace(prepared.Attributes["api_key"]) == "" {
		prepared.Attributes["api_key"] = qoderCNMetadataString(prepared, "access_token")
	}

	defaultHeaders := map[string]string{
		"User-Agent":            qodercnauth.UserAgent,
		"Cosy-Version":          qodercnauth.ClientVersion,
		"Cosy-MachineId":        qoderCNMachineID(prepared),
		"Cosy-ClientType":       "5",
		"Cosy-Business-Product": "cli",
		"Cosy-Business-Type":    "agent",
		"Cosy-Scene":            "assistant",
		"Login-Version":         "v2",
	}
	for name, value := range defaultHeaders {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if !qoderCNHasCustomHeader(prepared.Attributes, name) {
			prepared.Attributes["header:"+name] = value
		}
	}
	return prepared
}

// qoderCNMachineID returns the machine identity used for Cosy-MachineId. The
// official client sends a plain UUID generated once per install; operators can
// pin one by setting machine_id in the auth file metadata.
func qoderCNMachineID(auth *cliproxyauth.Auth) string {
	if auth != nil {
		if value := qoderCNMetadataString(auth, "machine_id"); value != "" {
			return value
		}
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes["machine_id"]); value != "" {
				return value
			}
		}
	}
	return ""
}

func qoderCNMetadataString(auth *cliproxyauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func qoderCNHasCustomHeader(attrs map[string]string, name string) bool {
	for key := range attrs {
		if strings.HasPrefix(key, "header:") &&
			strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(key, "header:")), name) {
			return true
		}
	}
	return false
}

// applyQoderCNOutgoingTransforms prepares the final upstream body:
//   - inject the metadata.context envelope the gateway requires
//   - force streaming plus usage reporting when the caller asked for a stream
func applyQoderCNOutgoingTransforms(_ context.Context, auth *cliproxyauth.Auth, _ string, opts cliproxyexecutor.Options, translated []byte) []byte {
	if len(translated) == 0 {
		return translated
	}
	body := translated

	// Only advertise a stream when the client actually requested one. A
	// non-streaming request must not set stream:true, or the response becomes an
	// SSE body the caller cannot parse.
	if opts.Stream {
		body = helps.SetBoolIfDifferent(body, "stream", true)
		body = helps.SetBoolIfDifferent(body, "stream_options.include_usage", true)
	} else {
		body = helps.SetBoolIfDifferent(body, "stream", false)
	}

	if !gjson.GetBytes(body, qoderCNMetadataContextKey).Exists() {
		envelope, errMarshal := json.Marshal(qoderCNContextEnvelope(auth))
		if errMarshal == nil {
			if updated, errSet := sjson.SetRawBytes(body, qoderCNMetadataContextKey, envelope); errSet == nil {
				body = updated
			}
		}
	}
	return body
}

// qoderCNContextEnvelope builds the metadata.context object. The official client
// sends request/session identifiers plus the client type; the gateway tolerates
// absent optional members but not an absent envelope.
func qoderCNContextEnvelope(auth *cliproxyauth.Auth) map[string]any {
	envelope := map[string]any{
		"client_type": "5",
	}
	if auth == nil {
		return envelope
	}
	if sessionID := qoderCNSessionID(auth); sessionID != "" {
		envelope["session_id"] = sessionID
	}
	if requestID := qoderCNMetadataString(auth, "request_id"); requestID != "" {
		envelope["request_id"] = requestID
	}
	if business, ok := auth.Metadata["business"]; ok && business != nil {
		envelope["business"] = business
	}
	return envelope
}

// qoderCNSessionID returns a stable session identifier for the credential so
// consecutive requests share a logical session, mirroring the official client.
func qoderCNSessionID(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if value := qoderCNMetadataString(auth, "session_id"); value != "" {
		return value
	}
	if auth.ID != "" {
		return auth.ID
	}
	return auth.Provider
}

// qoderCNStripMetadataEnvelope removes the metadata.context member that Qoder
// requires on requests but does not include in responses, so upstream response
// bodies stay OpenAI-shaped for clients.
//
// It is exported for tests and kept small on purpose: the transform runs on the
// response path only when an upstream echoes the envelope back.
func qoderCNStripMetadataEnvelope(payload []byte) []byte {
	if len(payload) == 0 || !gjson.GetBytes(payload, "metadata").Exists() {
		return payload
	}
	updated, err := sjson.DeleteBytes(payload, "metadata")
	if err != nil {
		return payload
	}
	return updated
}
