// Package executor provides per-provider runtime executors.
package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// TraeWork 桌面客户端（TRAE SOLO CN）上游常量。
// 逆向自 https://github.com/router-for-me/traework2api，对应 SOLO 中国版
// solo_work_lite 免费对话通道。
const (
	// TraeAgentHost is the SOLO CN agent gateway used by the desktop IDE.
	TraeAgentHost = "https://trae-api-cn.mchost.guru"
	// TraeUgHost hosts the check-in / credits endpoints.
	TraeUgHost = "https://api.trae.cn"
	// TraeOAuthHost hosts ExchangeToken / GetUserInfo.
	TraeOAuthHost = "https://api.trae.com.cn"

	// TraeClientID is the public OAuth client id shipped with the SOLO desktop client.
	TraeClientID = "en1oxy7wnw8j9n"
	// TraeAppID is the desktop IDE application id.
	TraeAppID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
	// TraeFunction is the SOLO work-lite free chat function.
	TraeFunction = "solo_work_lite"

	// TraeIdeVersion is the desktop IDE version identifier sent in headers.
	TraeIdeVersion = "0.1.43"
	// TraeIdeVersionCode is the desktop IDE build code sent in headers.
	TraeIdeVersionCode = "20260716"

	// TraeChatPath is the llm_utils_chat endpoint path.
	TraeChatPath = "/api/agent/v3/llm_utils_chat"
	// TraeModelsPath is the get_detail_param endpoint path.
	TraeModelsPath = "/api/ide/v1/get_detail_param"
	// TraeExchangePath is the OAuth token exchange endpoint path.
	TraeExchangePath = "/cloudide/api/v3/trae/oauth/ExchangeToken"
	// TraeUserInfoPath is the OAuth GetUserInfo endpoint path.
	TraeUserInfoPath = "/cloudide/api/v3/trae/GetUserInfo"

	// TraeDefaultModel is used when the client does not supply a model.
	TraeDefaultModel = "glm-5.2"
)

// traeAuthCredentials carries the resolved Trae credential snapshot for one
// execution or refresh operation.
type traeAuthCredentials struct {
	accessToken  string
	refreshToken string
	apiHost      string
	uid          string
	machineID    string
	deviceID     string
}

// TraeExecutor translates OpenAI chat requests to the TRAE SOLO CN desktop
// channel (solo_work_lite / llm_utils_chat) and converts the upstream SSE
// event stream back into OpenAI-compatible responses.
//
// The upstream protocol is a single POST returning a text/event-stream with
// event types: metadata, timing_cost, output, extra_info, token_usage, done,
// and error. The output event carries content / reasoning_content / tool_calls
// deltas which are accumulated and emitted as OpenAI chat.completion chunks.
type TraeExecutor struct {
	cfg *config.Config
}

// NewTraeExecutor constructs a Trae SOLO CN executor.
func NewTraeExecutor(cfg *config.Config) *TraeExecutor {
	return &TraeExecutor{cfg: cfg}
}

// Identifier returns the executor identifier.
func (e *TraeExecutor) Identifier() string { return constant.Trae }

// RequestToFormat reports the upstream request format. Trae accepts an
// OpenAI-shaped body (the executor rewrites it before dispatch).
func (e *TraeExecutor) RequestToFormat(_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) sdktranslator.Format {
	return sdktranslator.FormatOpenAI
}

// PrepareRequest injects Trae SOLO desktop headers into an ad-hoc request.
// It is primarily useful for management-plane ad-hoc calls; normal chat
// execution builds headers inline via applyTraeHeaders.
func (e *TraeExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	creds := traeCredentialsFromAuth(auth)
	if creds.accessToken != "" {
		req.Header.Set("Authorization", "Cloud-IDE-JWT "+creds.accessToken)
		req.Header.Set("X-Cloudide-Token", creds.accessToken)
		req.Header.Set("X-Ide-Token", creds.accessToken)
	}
	applyTraeCommonHeaders(req, auth, creds, true)
	applyTraeDesktopHeaders(req, auth, creds)
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
	return nil
}

// HttpRequest injects Trae credentials and executes the request.
func (e *TraeExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("trae executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if errPrepare := e.PrepareRequest(httpReq, auth); errPrepare != nil {
		return nil, errPrepare
	}
	return helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
}

// Execute performs a non-streaming chat completion against Trae SOLO CN.
// The upstream only supports streaming, so the executor drives a streamed
// request and aggregates the SOLO SSE events into a chat.completion.
func (e *TraeExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	streamResult, errStream := e.ExecuteStream(ctx, auth, req, opts)
	if errStream != nil {
		return resp, errStream
	}
	if streamResult == nil {
		return resp, nil
	}

	agg := newTraeSSEState(req.Model)
	for chunk := range streamResult.Chunks {
		if chunk.Err != nil {
			return resp, chunk.Err
		}
		agg.consumePayload(chunk.Payload)
	}

	return cliproxyexecutor.Response{
		Payload: agg.nonStreamResponse(),
		Headers: streamResult.Headers,
	}, nil
}

// ExecuteStream performs the llm_utils_chat POST and translates the upstream
// SOLO SSE stream into OpenAI chat.completion.chunk frames.
func (e *TraeExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	creds := traeCredentialsFromAuth(auth)
	if strings.TrimSpace(creds.accessToken) == "" {
		return nil, traeStatusError{code: http.StatusUnauthorized, msg: "trae executor: missing access token"}
	}

	body, errBody := e.prepareTraeBody(req, opts)
	if errBody != nil {
		return nil, errBody
	}

	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, e.agentEndpoint(auth, TraeChatPath), bytes.NewReader(body))
	if errRequest != nil {
		return nil, errRequest
	}
	applyTraeChatHeaders(request, auth, creds, true)

	httpResp, errDo := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(request)
	if errDo != nil {
		return nil, errDo
	}
	if errStatus := traeResponseError(httpResp); errStatus != nil {
		_ = httpResp.Body.Close()
		return nil, errStatus
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("trae executor: close stream body error: %v", errClose)
			}
		}()

		state := newTraeSSEState(req.Model)
		emit := func(frame []byte) bool {
			select {
			case out <- cliproxyexecutor.StreamChunk{Payload: frame}:
				return true
			case <-ctx.Done():
				return false
			}
		}

		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1_048_576)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			frames := state.consumeSSELine(line)
			for _, frame := range frames {
				if !emit(frame) {
					return
				}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("trae executor: read stream: %w", errScan)}:
			case <-ctx.Done():
			}
			return
		}
		for _, frame := range state.finishFrames() {
			if !emit(frame) {
				return
			}
		}
	}()

	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

// Refresh rotates the Trae access token via ExchangeToken. The desktop client
// issues a long-lived refresh token during the /authorize flow; the executor
// mirrors that refresh path so tokens can be kept alive indefinitely.
func (e *TraeExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("trae executor: auth is nil")
	}
	creds := traeCredentialsFromAuth(auth)
	if strings.TrimSpace(creds.refreshToken) == "" {
		return auth, nil
	}

	host := creds.apiHost
	if strings.TrimSpace(host) == "" {
		host = TraeOAuthHost
	}
	payload, _ := json.Marshal(map[string]any{
		"ClientID":     TraeClientID,
		"RefreshToken": creds.refreshToken,
		"ClientSecret": "-",
		"UserID":       "",
	})
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(host, "/")+TraeExchangePath, bytes.NewReader(payload))
	if errRequest != nil {
		return nil, errRequest
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Trae/"+TraeIdeVersion)

	httpResp, errDo := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(request)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("trae executor: close exchange body error: %v", errClose)
		}
	}()
	respBody, errRead := io.ReadAll(httpResp.Body)
	if errRead != nil {
		return nil, errRead
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, traeStatusError{code: httpResp.StatusCode, msg: string(respBody)}
	}
	var envelope struct {
		Result struct {
			Token               string `json:"Token"`
			RefreshToken        string `json:"RefreshToken"`
			TokenExpireAt       int64  `json:"TokenExpireAt"`
			TokenExpireDuration int64  `json:"TokenExpireDuration"`
		} `json:"Result"`
	}
	if errUnmarshal := json.Unmarshal(respBody, &envelope); errUnmarshal != nil {
		return nil, fmt.Errorf("trae executor: exchange parse: %w", errUnmarshal)
	}
	if strings.TrimSpace(envelope.Result.Token) == "" {
		return nil, fmt.Errorf("trae executor: exchange returned no token — re-login required")
	}

	prepared := auth.Clone()
	if prepared.Metadata == nil {
		prepared.Metadata = make(map[string]any)
	}
	prepared.Metadata["access_token"] = envelope.Result.Token
	if strings.TrimSpace(envelope.Result.RefreshToken) != "" {
		prepared.Metadata["refresh_token"] = envelope.Result.RefreshToken
	}
	expiresAt := envelope.Result.TokenExpireAt
	if expiresAt > 1e12 {
		expiresAt /= 1000
	}
	if expiresAt <= 0 && envelope.Result.TokenExpireDuration > 0 {
		expiresAt = time.Now().Add(time.Duration(envelope.Result.TokenExpireDuration) * time.Second).Unix()
	}
	if expiresAt > 0 {
		prepared.Metadata["expires_at"] = expiresAt
	}
	if prepared.Attributes == nil {
		prepared.Attributes = make(map[string]string)
	}
	prepared.Attributes["api_key"] = envelope.Result.Token
	return prepared, nil
}

// CountTokens is not supported by the SOLO CN channel.
func (e *TraeExecutor) CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, errors.New("trae executor: count tokens is not supported")
}

// agentEndpoint resolves the agent gateway from auth attributes, falling back
// to the public TraeAgentHost.
func (e *TraeExecutor) agentEndpoint(auth *cliproxyauth.Auth, path string) string {
	base := TraeAgentHost
	if auth != nil && auth.Attributes != nil {
		if configured := strings.TrimSpace(auth.Attributes["base_url"]); configured != "" {
			base = configured
		}
	}
	return strings.TrimRight(base, "/") + path
}

// prepareTraeBody rewrites an OpenAI-shaped payload into the SOLO
// llm_utils_chat request format:
//
//	{function:"solo_work_lite", stream:true, config_name:<model>, model:<model>}
func (e *TraeExecutor) prepareTraeBody(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) ([]byte, error) {
	body := bytes.Clone(req.Payload)
	if len(body) == 0 {
		return nil, traeStatusError{code: http.StatusBadRequest, msg: "trae executor: empty request payload"}
	}

	body, _ = sjson.SetBytes(body, "stream", true)
	body, _ = sjson.SetBytes(body, "function", TraeFunction)

	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = TraeDefaultModel
	}
	body, _ = sjson.SetBytes(body, "config_name", model)
	body, _ = sjson.SetBytes(body, "model", model)

	body = traeNormalizeMessages(body)
	body = traeNormalizeToolChoice(body)
	body = traeNormalizeTools(body)
	return body, nil
}

// traeNormalizeMessages converts OpenAI message content to the SOLO shape:
// string content becomes [{type:"text",text:...}], and assistant tool_calls
// are rewritten from function to function_call.
func traeNormalizeMessages(body []byte) []byte {
	messages := gjson.GetBytes(body, "messages")
	if !messages.IsArray() {
		return body
	}
	changed := false
	var out []any
	messages.ForEach(func(_, mi gjson.Result) bool {
		msg := mi.Value()
		m, _ := msg.(map[string]any)
		if m == nil {
			out = append(out, msg)
			return true
		}

		role, _ := m["role"].(string)
		if role == "assistant" {
			if tcs, ok := m["tool_calls"].([]any); ok {
				kept := make([]any, 0, len(tcs))
				for _, tci := range tcs {
					tc, _ := tci.(map[string]any)
					if tc == nil {
						continue
					}
					if fn, ok := tc["function"].(map[string]any); ok {
						tc["function_call"] = fn
						delete(tc, "function")
						changed = true
					}
					if fc, ok := tc["function_call"].(map[string]any); ok {
						name, _ := fc["name"].(string)
						if strings.TrimSpace(name) == "" {
							continue
						}
					}
					kept = append(kept, tc)
				}
				if len(kept) == 0 {
					delete(m, "tool_calls")
					changed = true
				} else {
					m["tool_calls"] = kept
				}
			}
		}

		if content, present := m["content"]; present && content != nil {
			switch c := content.(type) {
			case string:
				m["content"] = []any{map[string]any{"type": "text", "text": c}}
				changed = true
			default:
				// Already an array: pass through (multimodal).
			}
		}
		out = append(out, m)
		return true
	})
	if !changed {
		return body
	}
	marshaled, errMarshal := json.Marshal(out)
	if errMarshal != nil {
		return body
	}
	body, _ = sjson.SetRawBytes(body, "messages", marshaled)
	return body
}

// traeNormalizeToolChoice rewrites OpenAI tool_choice into the upstream
// string form ("none" suppresses tools entirely).
func traeNormalizeToolChoice(body []byte) []byte {
	raw := gjson.GetBytes(body, "tool_choice")
	if !raw.Exists() {
		return body
	}
	switch v := raw.Value().(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(v), "none") {
			body, _ = sjson.DeleteBytes(body, "tool_choice")
			body, _ = sjson.DeleteBytes(body, "tools")
			body, _ = sjson.DeleteBytes(body, "functions")
		}
	case map[string]any:
		typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(v["type"])))
		switch typ {
		case "none":
			body, _ = sjson.DeleteBytes(body, "tool_choice")
			body, _ = sjson.DeleteBytes(body, "tools")
			body, _ = sjson.DeleteBytes(body, "functions")
		case "auto", "required":
			body, _ = sjson.SetBytes(body, "tool_choice", typ)
		case "function":
			name := ""
			if fn, ok := v["function"].(map[string]any); ok {
				name, _ = fn["name"].(string)
			}
			if name == "" {
				name, _ = v["name"].(string)
			}
			if name = strings.TrimSpace(name); name != "" {
				body, _ = sjson.SetBytes(body, "tool_choice", name)
			} else {
				body, _ = sjson.SetBytes(body, "tool_choice", "auto")
			}
		default:
			body, _ = sjson.DeleteBytes(body, "tool_choice")
		}
	default:
		body, _ = sjson.DeleteBytes(body, "tool_choice")
	}
	return body
}

// traeNormalizeTools serializes tools[].function.parameters from object to
// JSON string, as required by the upstream Go struct, and drops malformed
// tool entries.
func traeNormalizeTools(body []byte) []byte {
	raw := gjson.GetBytes(body, "tools")
	if !raw.IsArray() {
		return body
	}
	changed := false
	out := make([]any, 0, len(raw.Array()))
	raw.ForEach(func(_, t gjson.Result) bool {
		m, ok := t.Value().(map[string]any)
		if !ok {
			return true
		}
		fn, ok := m["function"].(map[string]any)
		if !ok {
			return true
		}
		if params, ok := fn["parameters"]; ok {
			if paramsMap, isMap := params.(map[string]any); isMap {
				if s, errMarshal := json.Marshal(paramsMap); errMarshal == nil {
					fn["parameters"] = string(s)
					changed = true
				}
			}
		}
		out = append(out, m)
		return true
	})
	if !changed {
		return body
	}
	if len(out) == 0 {
		body, _ = sjson.DeleteBytes(body, "tools")
		return body
	}
	marshaled, errMarshal := json.Marshal(out)
	if errMarshal != nil {
		return body
	}
	body, _ = sjson.SetRawBytes(body, "tools", marshaled)
	return body
}

// traeCredentialsFromAuth resolves Trae credential fields from auth attributes
// (immutable) and metadata (mutable runtime state).
func traeCredentialsFromAuth(auth *cliproxyauth.Auth) traeAuthCredentials {
	var creds traeAuthCredentials
	if auth == nil {
		return creds
	}
	if auth.Attributes != nil {
		creds.accessToken = strings.TrimSpace(auth.Attributes["api_key"])
		creds.apiHost = strings.TrimSpace(auth.Attributes["base_url"])
		creds.uid = strings.TrimSpace(auth.Attributes["uid"])
		creds.machineID = strings.TrimSpace(auth.Attributes["machine_id"])
		creds.deviceID = strings.TrimSpace(auth.Attributes["device_id"])
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
			creds.accessToken = strings.TrimSpace(v)
		}
		if v, ok := auth.Metadata["refresh_token"].(string); ok {
			creds.refreshToken = strings.TrimSpace(v)
		}
		if v, ok := auth.Metadata["api_host"].(string); ok && strings.TrimSpace(v) != "" {
			creds.apiHost = strings.TrimSpace(v)
		}
		if v, ok := auth.Metadata["uid"].(string); ok && strings.TrimSpace(v) != "" {
			creds.uid = strings.TrimSpace(v)
		}
		if v, ok := auth.Metadata["machine_id"].(string); ok && strings.TrimSpace(v) != "" {
			creds.machineID = strings.TrimSpace(v)
		}
		if v, ok := auth.Metadata["device_id"].(string); ok && strings.TrimSpace(v) != "" {
			creds.deviceID = strings.TrimSpace(v)
		}
	}
	if creds.apiHost == "" {
		creds.apiHost = TraeAgentHost
	}
	return creds
}

// applyTraeChatHeaders sets the llm_utils_chat request headers.
func applyTraeChatHeaders(req *http.Request, auth *cliproxyauth.Auth, creds traeAuthCredentials, stream bool) {
	applyTraeCommonHeaders(req, auth, creds, stream)
	applyTraeDesktopHeaders(req, auth, creds)
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
}

// applyTraeCommonHeaders sets the auth / content negotiation headers shared
// by the SOLO agent endpoints.
func applyTraeCommonHeaders(req *http.Request, auth *cliproxyauth.Auth, creds traeAuthCredentials, stream bool) {
	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", "Trae/"+TraeIdeVersion)
	if creds.accessToken != "" {
		req.Header.Set("Authorization", "Cloud-IDE-JWT "+creds.accessToken)
		req.Header.Set("X-Cloudide-Token", creds.accessToken)
		req.Header.Set("X-Ide-Token", creds.accessToken)
	}
	if creds.uid != "" {
		req.Header.Set("X-Uid", creds.uid)
	}
}

// applyTraeDesktopHeaders sets the desktop-IDE identification headers.
func applyTraeDesktopHeaders(req *http.Request, auth *cliproxyauth.Auth, creds traeAuthCredentials) {
	req.Header.Set("X-App-Id", TraeAppID)
	req.Header.Set("X-App-Version", "default")
	req.Header.Set("X-Ide-Version", TraeIdeVersion)
	req.Header.Set("X-Ide-Version-Code", TraeIdeVersionCode)
	req.Header.Set("X-App-Version-Code", TraeIdeVersionCode)
	req.Header.Set("X-Ide-Version-Type", "stable")
	req.Header.Set("X-Device-Type", "windows")
	req.Header.Set("X-OS-Version", "Windows 11 Pro")
	req.Header.Set("X-Device-Brand", "83DG")
	req.Header.Set("Request-Traffic-Type", "prod")
	if creds.machineID != "" {
		req.Header.Set("X-Machine-Id", creds.machineID)
	}
	if creds.deviceID != "" {
		req.Header.Set("X-Device-Id", creds.deviceID)
	}
}

// traeResponseError inspects an upstream HTTP response and converts non-2xx
// responses into a traeStatusError.
func traeResponseError(response *http.Response) error {
	if response == nil {
		return fmt.Errorf("trae executor: nil upstream response")
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return traeStatusError{code: response.StatusCode, msg: string(body)}
}

// traeStatusError carries an HTTP-like status code.
type traeStatusError struct {
	code int
	msg  string
}

func (e traeStatusError) Error() string   { return e.msg }
func (e traeStatusError) StatusCode() int { return e.code }

// traeSSEState parses SOLO SSE lines and emits OpenAI chat.completion chunks.
type traeSSEState struct {
	id       string
	model    string
	created  int64
	event    string
	data     strings.Builder
	content  strings.Builder
	reason   strings.Builder
	usageRaw string

	roleEmitted bool
	finished    bool
	toolCalls   map[int]map[string]any
	toolOrder   []int
}

func newTraeSSEState(model string) *traeSSEState {
	return &traeSSEState{
		id:        fmt.Sprintf("chatcmpl-trae-%d", time.Now().UnixNano()),
		model:     model,
		created:   time.Now().Unix(),
		toolCalls: map[int]map[string]any{},
	}
}

// consumeSSELine feeds one SSE text line into the parser and returns any
// completed OpenAI frames triggered by an event boundary.
func (s *traeSSEState) consumeSSELine(line string) [][]byte {
	switch {
	case line == "":
		if s.event == "" {
			return nil
		}
		frames := s.dispatchEvent(s.event, s.data.String())
		s.event = ""
		s.data.Reset()
		return frames
	case strings.HasPrefix(line, "event:"):
		s.event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
	case strings.HasPrefix(line, "data:"):
		s.data.WriteString(strings.TrimPrefix(line, "data:"))
	}
	return nil
}

// consumePayload feeds a raw payload (for aggregated non-streaming path).
func (s *traeSSEState) consumePayload(payload []byte) {
	if len(payload) == 0 {
		return
	}
	// Non-streaming path receives OpenAI chunks already emitted by the
	// streaming translator; parse and accumulate content / reasoning deltas.
	if !json.Valid(payload) {
		return
	}
	root := gjson.ParseBytes(payload)
	root.Get("choices").ForEach(func(_, choice gjson.Result) bool {
		delta := choice.Get("delta")
		if c := delta.Get("content").String(); c != "" {
			s.content.WriteString(c)
		}
		if r := delta.Get("reasoning_content").String(); r != "" {
			s.reason.WriteString(r)
		}
		if u := root.Get("usage"); u.Exists() && u.Raw != "null" {
			s.usageRaw = u.Raw
		}
		return true
	})
}

// dispatchEvent handles a complete SOLO SSE event and returns OpenAI frames.
func (s *traeSSEState) dispatchEvent(event, dataLine string) [][]byte {
	ev := strings.TrimSpace(event)
	if dataLine == "" {
		return nil
	}
	var raw map[string]any
	if errUnmarshal := json.Unmarshal([]byte(dataLine), &raw); errUnmarshal != nil {
		return nil
	}
	switch ev {
	case "output":
		return s.handleOutput(raw)
	case "token_usage":
		s.usageRaw = dataLine
	case "done":
		finish := "stop"
		if v, ok := raw["finish_reason"].(string); ok && strings.TrimSpace(v) != "" {
			finish = v
		}
		s.finished = true
		return [][]byte{s.streamFrame(map[string]any{}, finish), []byte("data: [DONE]\n\n")}
	case "error":
		code, _ := raw["code"].(float64)
		msg, _ := raw["message"].(string)
		return [][]byte{s.streamFrame(map[string]any{
			"content": fmt.Sprintf("trae error code=%d msg=%s", int64(code), msg),
		}, "stop"), []byte("data: [DONE]\n\n")}
	}
	return nil
}

// handleOutput converts an SOLO output event into an OpenAI chunk.
func (s *traeSSEState) handleOutput(raw map[string]any) [][]byte {
	delta := map[string]any{}
	if v, ok := raw["response"].(string); ok && v != "" {
		delta["content"] = v
	}
	if v, ok := raw["reasoning_content"].(string); ok && v != "" {
		delta["reasoning_content"] = v
	}
	if v, ok := raw["tool_calls"]; ok && v != nil {
		s.mergeToolCalls(v, delta)
	}
	if len(delta) == 0 {
		return nil
	}
	frames := make([][]byte, 0, 2)
	if !s.roleEmitted {
		s.roleEmitted = true
		frames = append(frames, s.streamFrame(map[string]any{"role": "assistant", "content": ""}, nil))
	}
	frames = append(frames, s.streamFrame(delta, nil))
	return frames
}

// mergeToolCalls merges SOLO tool_calls (which use function_call) into
// OpenAI tool_calls (which use function).
func (s *traeSSEState) mergeToolCalls(value any, delta map[string]any) {
	var arr []map[string]any
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				arr = append(arr, m)
			}
		}
	case map[string]any:
		arr = append(arr, v)
	default:
		return
	}
	if len(arr) == 0 {
		return
	}
	calls := make([]any, 0, len(arr))
	for _, call := range arr {
		if fc, ok := call["function_call"].(map[string]any); ok {
			call["function"] = fc
			delete(call, "function_call")
		}
		if fn, ok := call["function"].(map[string]any); ok {
			delete(fn, "namespace")
			delete(fn, "partial_arguments")
		}
		calls = append(calls, call)
	}
	delta["tool_calls"] = calls
}

// streamFrame builds one OpenAI chat.completion.chunk frame.
func (s *traeSSEState) streamFrame(delta map[string]any, finish any) []byte {
	choice := map[string]any{"index": 0, "delta": delta}
	if finish != nil {
		choice["finish_reason"] = finish
	}
	body, _ := json.Marshal(map[string]any{
		"id":      s.id,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{choice},
	})
	return body
}

// finishFrames emits terminal frames when the upstream stream ended without a
// done event.
func (s *traeSSEState) finishFrames() [][]byte {
	if s.finished {
		return nil
	}
	frames := make([][]byte, 0, 3)
	if !s.roleEmitted {
		s.roleEmitted = true
		frames = append(frames, s.streamFrame(map[string]any{"role": "assistant", "content": ""}, nil))
	}
	frames = append(frames, s.streamFrame(map[string]any{}, "stop"), []byte("data: [DONE]\n\n"))
	s.finished = true
	return frames
}

// nonStreamResponse aggregates the accumulated deltas into a chat.completion.
func (s *traeSSEState) nonStreamResponse() []byte {
	message := map[string]any{"role": "assistant", "content": s.content.String()}
	if s.reason.Len() > 0 {
		message["reasoning_content"] = s.reason.String()
	}
	if len(s.toolOrder) > 0 {
		// Not fully wired for aggregation; keep content-only for now.
	}
	resp := map[string]any{
		"id":      s.id,
		"object":  "chat.completion",
		"created": s.created,
		"model":   s.model,
		"choices": []any{
			map[string]any{"index": 0, "message": message, "finish_reason": "stop"},
		},
	}
	if s.usageRaw != "" && json.Valid([]byte(s.usageRaw)) {
		resp["usage"] = json.RawMessage(s.usageRaw)
	}
	body, _ := json.Marshal(resp)
	return body
}

// Ensure the unused import guard is satisfied for strconv (kept for future
// model parsing). It is referenced to avoid accidental removal.
var _ = strconv.Itoa
