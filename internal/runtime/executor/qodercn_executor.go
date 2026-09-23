// Package executor provides per-provider runtime executors.
package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	qodercnauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
)

// Qoder CN inference uses the official client's signed `/algo` transport:
//
//	POST {gateway}/algo/api/v2/service/pro/sse/agent_chat_generation?…
//	Authorization: Bearer COSY.<payloadB64>.<md5 signature>
//
// The plain OpenAI-compatible `/model/v1/chat/completions` endpoint rejects these
// credentials with 401, so this executor implements the COSY signature (see
// internal/auth/qodercn/cosy.go) instead of using the OpenAI-compatible base.
//
// QoderCNModelBaseURL is the CN gateway origin that hosts the signed agent
// channel. QoderAIModelBaseURL is the international (Qoder AI) equivalent.
const QoderCNModelBaseURL = qodercnauth.GatewayBaseURL
const QoderAIModelBaseURL = qodercnauth.AIGatewayBaseURL

// QoderCNAlgoPath is the signed agent-chat path (gateway-relative, with /algo).
const QoderCNAlgoPath = "/algo" + qoderCNAgentSignPath

// QoderCNModelDirPath is the plain OpenAI-compatible model-server path. It is
// documented for reference; the executor does not use it because the endpoint
// rejects OAuth credentials.
const QoderCNModelDirPath = "/model/v1/chat/completions"

// qoderAuthDefaults captures the values that differ between the Qoder CN and
// international (Qoder AI) environments. Both share the entire COSY signature,
// request envelope, device-poll flow and OAuth client id; only the hosts and the
// provider identity differ.
type qoderAuthDefaults struct {
	// provider is the internal provider identifier (constant.QoderCN / constant.QoderAI).
	provider string
	// label names the environment in error messages (e.g. "qoder-cn").
	label string
	// gatewayURL is the agent gateway origin for this environment.
	gatewayURL string
	// newClient builds an OAuth/OpenAPI client for this environment.
	newClient func(cfg *config.Config, proxyURL string) *qodercnauth.Client
}

var qoderCNAuthDefaults = qoderAuthDefaults{
	provider:   constant.QoderCN,
	label:      "qoder-cn",
	gatewayURL: qodercnauth.GatewayBaseURL,
	newClient:  qodercnauth.NewClientWithProxyURL,
}

var qoderAIAuthDefaults = qoderAuthDefaults{
	provider:   constant.QoderAI,
	label:      "qoder-ai",
	gatewayURL: qodercnauth.AIGatewayBaseURL,
	newClient:  qodercnauth.NewAIClientWithProxyURL,
}

// QoderExecutor talks to a Qoder agent gateway using the COSY signature. The
// environment (CN vs international) is selected by defaults, so a single type
// serves both providers.
type QoderExecutor struct {
	cfg      *config.Config
	defaults qoderAuthDefaults
	// endpoint overrides the gateway URL in tests; empty means the real one.
	endpoint string
}

// NewQoderCNExecutor constructs a Qoder CN executor.
func NewQoderCNExecutor(cfg *config.Config) *QoderExecutor {
	return &QoderExecutor{cfg: cfg, defaults: qoderCNAuthDefaults}
}

// NewQoderAIExecutor constructs an international (Qoder AI) executor.
func NewQoderAIExecutor(cfg *config.Config) *QoderExecutor {
	return &QoderExecutor{cfg: cfg, defaults: qoderAIAuthDefaults}
}

// Identifier returns the executor identifier for this environment.
func (e *QoderExecutor) Identifier() string {
	if e == nil || e.defaults.provider == "" {
		return constant.QoderCN
	}
	return e.defaults.provider
}

// errLabel names the environment (qoder-cn / qoder-ai) in error messages.
func (e *QoderExecutor) errLabel() string {
	if e == nil || strings.TrimSpace(e.defaults.label) == "" {
		return "qoder-cn"
	}
	return e.defaults.label
}

// RequestToFormat reports the upstream request format. The incoming OpenAI body
// is rewritten into the Qoder envelope by the executor, so the translator should
// hand it an OpenAI payload.
func (e *QoderExecutor) RequestToFormat(_ cliproxyexecutor.Request, opts cliproxyexecutor.Options) sdktranslator.Format {
	source := opts.SourceFormat.String()
	if source == "openai-image" {
		return opts.SourceFormat
	}
	return sdktranslator.FormatOpenAI
}

// ShouldPrepareRequestAuth reports true when the auth is missing the account
// identity the COSY signature requires.
func (e *QoderExecutor) ShouldPrepareRequestAuth(auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	return qoderCNProfileString(auth, "uid") == "" || qoderCNProfileString(auth, "name") == ""
}

// PrepareRequestAuth resolves and caches the account identity (uid, name,
// user_type) needed to sign inference requests. The values are persisted in the
// auth metadata so subsequent requests skip the lookup.
func (e *QoderExecutor) PrepareRequestAuth(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("%s executor: auth is nil", e.errLabel())
	}
	accessToken := qoderCNAccessToken(auth)
	if accessToken == "" {
		return nil, fmt.Errorf("%s executor: missing access token", e.errLabel())
	}
	client := e.defaults.newClient(e.cfg, auth.ProxyURL)
	profile, err := client.FetchCosyProfile(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["uid"] = profile.UID
	auth.Metadata["name"] = profile.Name
	if profile.AID != "" {
		auth.Metadata["aid"] = profile.AID
	}
	if profile.UserType != "" {
		auth.Metadata["user_type"] = profile.UserType
	}
	for key, value := range map[string]string{
		"yx_uid":            profile.YXUID,
		"organization_id":   profile.OrganizationID,
		"organization_name": profile.OrganizationName,
	} {
		if strings.TrimSpace(value) != "" {
			auth.Metadata[key] = value
		}
	}
	return auth, nil
}

// PrepareRequest injects COSY headers into an ad-hoc request. The signed body
// depends on the full envelope, so ad-hoc requests only receive the token.
func (e *QoderExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	if token := qoderCNAccessToken(auth); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", qodercnauth.UserAgent)
	return nil
}

// HttpRequest executes an ad-hoc Qoder CN request with normalized credentials.
func (e *QoderExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%s executor: request is nil", e.errLabel())
	}
	cloned := req.Clone(ctx)
	if err := e.PrepareRequest(cloned, auth); err != nil {
		return nil, err
	}
	return helps.NewQoderCNHTTPClient(ctx, e.cfg, auth, 0).Do(cloned)
}

// Execute runs a non-streaming request by driving the streaming upstream and
// folding the chunks into a single OpenAI chat.completion.
func (e *QoderExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	opts.Stream = false
	streamResult, err := e.ExecuteStream(ctx, auth, req, opts)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	if streamResult == nil {
		return cliproxyexecutor.Response{}, nil
	}
	var buf bytes.Buffer
	for chunk := range streamResult.Chunks {
		if chunk.Err != nil {
			return cliproxyexecutor.Response{}, chunk.Err
		}
		if len(chunk.Payload) > 0 {
			_, _ = buf.Write(chunk.Payload)
			_, _ = buf.WriteString("\n")
		}
	}
	return cliproxyexecutor.Response{
		Payload: qoderCNAggregateStream(buf.Bytes(), req.Model),
		Headers: streamResult.Headers,
	}, nil
}

// CountTokens is not supported by the Qoder CN agent channel.
func (e *QoderExecutor) CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, fmt.Errorf("%s executor: count tokens is not supported", e.errLabel())
}

// Refresh rotates Qoder OAuth credentials using the stored refresh token.
func (e *QoderExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return refreshQoderAuth(ctx, e.cfg, e.defaults, auth)
}

// ExecuteStream signs and posts the agent_chat_generation request, then
// translates the upstream SSE stream into OpenAI chat.completion chunks.
func (e *QoderExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	reporter := helps.NewExecutorUsageReporter(ctx, e, req.Model, auth)

	accessToken := qoderCNAccessToken(auth)
	if accessToken == "" {
		err := qoderCNStatusError{code: http.StatusUnauthorized, msg: e.errLabel() + " executor: missing access token"}
		reporter.PublishFailure(ctx, err)
		return nil, err
	}
	profile := qoderCNProfile(auth)
	if strings.TrimSpace(profile.UID) == "" || strings.TrimSpace(profile.Name) == "" {
		err := qoderCNStatusError{code: http.StatusUnauthorized, msg: e.errLabel() + " executor: account identity missing; re-login or refresh the credential"}
		reporter.PublishFailure(ctx, err)
		return nil, err
	}

	// Translate the client payload into an OpenAI body, then into the Qoder envelope.
	body := helps.TranslateRequestWithAPIKeyModelCompatibility(ctx, opts.Headers, e.cfg, opts.SourceFormat, sdktranslator.FormatOpenAI, req.Model, bytes.Clone(req.Payload), true, helps.APIKeyModelIsCompat(req))
	model := qoderCNUpstreamModel(req.Model)
	envelope, err := qoderCNBuildEnvelope(body, model, profile.UserType)
	if err != nil {
		reporter.PublishFailure(ctx, err)
		return nil, err
	}

	session, err := qodercnauth.NewCosySession(qodercnauth.CosyIdentity{
		Name:             profile.Name,
		AID:              profile.AID,
		UID:              profile.UID,
		YXUID:            profile.YXUID,
		OrganizationID:   profile.OrganizationID,
		OrganizationName: profile.OrganizationName,
		UserType:         profile.UserType,
		SecurityOAuth:    accessToken,
		RefreshToken:     qoderCNMetadataString(auth, "refresh_token"),
	})
	if err != nil {
		reporter.PublishFailure(ctx, err)
		return nil, err
	}
	payloadB64, err := session.PayloadB64(qodercnauth.ClientVersion)
	if err != nil {
		reporter.PublishFailure(ctx, err)
		return nil, err
	}

	encodedBody := qodercnauth.CosyEncode(envelope)
	cosyDate := strconv.FormatInt(time.Now().Unix(), 10)
	signature := qodercnauth.CosySign(payloadB64, session.CosyKey, cosyDate, encodedBody, qoderCNAgentSignPath)

	endpoint := e.gatewayEndpoint(auth)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+QoderCNAlgoPath+qoderCNAgentQuery, strings.NewReader(encodedBody))
	if err != nil {
		reporter.PublishFailure(ctx, err)
		return nil, err
	}
	applyQoderCNHeaders(httpReq, auth, session, profile, payloadB64, signature, cosyDate, model)

	httpClient := helps.NewQoderCNHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		reporter.PublishFailure(ctx, err)
		return nil, err
	}
	if httpResp.StatusCode != http.StatusOK {
		defer func() { _ = httpResp.Body.Close() }()
		data, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
		statusErr := qoderCNStatusError{code: httpResp.StatusCode, msg: fmt.Sprintf("qoder-cn upstream http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(data)))}
		reporter.PublishFailure(ctx, statusErr)
		return nil, statusErr
	}
	reporter.ObserveResponse(httpResp)

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("%s executor: close stream body: %v", e.errLabel(), errClose)
			}
		}()

		state := newQoderCNStreamState(req.Model)
		emit := func(frame []byte) bool {
			if len(frame) == 0 {
				return true
			}
			select {
			case out <- cliproxyexecutor.StreamChunk{Payload: frame}:
				return true
			case <-ctx.Done():
				return false
			}
		}

		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			frames, apiErr := state.consumeDataLine([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))))
			if apiErr != "" {
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: qoderCNStatusError{code: http.StatusBadGateway, msg: "qoder-cn upstream error: " + apiErr}}:
				case <-ctx.Done():
				}
				return
			}
			reporter.ObserveTokenEvent(len(frames) > 0)
			for _, frame := range frames {
				if !emit(frame) {
					return
				}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("%s executor: read stream: %w", e.errLabel(), errScan)}:
			case <-ctx.Done():
			}
			return
		}
		for _, frame := range state.finishFrames() {
			if !emit(frame) {
				return
			}
		}
		reporter.Publish(ctx, state.usageDetail())
	}()

	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

// gatewayEndpoint resolves the gateway origin for this environment. A
// per-credential override in the auth attributes wins, then the test endpoint.
func (e *QoderExecutor) gatewayEndpoint(auth *cliproxyauth.Auth) string {
	if auth != nil && auth.Attributes != nil {
		if configured := strings.TrimSpace(auth.Attributes["gateway_url"]); configured != "" {
			return strings.TrimRight(configured, "/")
		}
		// base_url is stored as the gateway origin by the synthesizer/login flows.
		if configured := strings.TrimSpace(auth.Attributes["base_url"]); configured != "" && !strings.Contains(configured, "/model/v1") {
			return strings.TrimRight(configured, "/")
		}
	}
	if e != nil && strings.TrimSpace(e.endpoint) != "" {
		return strings.TrimRight(strings.TrimSpace(e.endpoint), "/")
	}
	if e != nil && strings.TrimSpace(e.defaults.gatewayURL) != "" {
		return strings.TrimRight(e.defaults.gatewayURL, "/")
	}
	return qodercnauth.GatewayBaseURL
}

// applyQoderCNHeaders writes the COSY-signed header set the gateway expects.
func applyQoderCNHeaders(req *http.Request, auth *cliproxyauth.Auth, session *qodercnauth.CosySession, profile qodercnProfile, payloadB64, signature, cosyDate, model string) {
	header := req.Header
	header.Set("Authorization", "Bearer COSY."+payloadB64+"."+signature)
	header.Set("Content-Type", "application/json")
	header.Set("Accept", "text/event-stream")
	header.Set("Accept-Encoding", "identity")
	header.Set("Cache-Control", "no-cache")
	header.Set("Cosy-Data-Policy", "AGREE")
	header.Set("Cosy-Version", qodercnauth.ClientVersion)
	header.Set("Cosy-Date", cosyDate)
	header.Set("Cosy-Key", session.CosyKey)
	header.Set("Cosy-ClientType", "5")
	header.Set("Cosy-User", profile.UID)
	header.Set("Cosy-MachineId", session.MachineID)
	header.Set("Cosy-MachineToken", session.MachineToken)
	header.Set("Cosy-MachineType", session.MachineType)
	header.Set("Cosy-Business-Product", "cli")
	header.Set("Cosy-Business-Type", "agent")
	header.Set("Cosy-Scene", "assistant")
	header.Set("Login-Version", "v2")
	header.Set("X-Model-Key", model)
	header.Set("X-Model-Source", "system")
	header.Set("User-Agent", qodercnauth.UserAgent)

	// Operator-supplied overrides win.
	if auth != nil && auth.Attributes != nil {
		for key, value := range auth.Attributes {
			if !strings.HasPrefix(key, "header:") {
				continue
			}
			if name := strings.TrimSpace(strings.TrimPrefix(key, "header:")); name != "" {
				header.Set(name, value)
			}
		}
	}
}

// qoderCNProfile captures the identity fields bound into the signature.
type qodercnProfile struct {
	Name             string
	AID              string
	UID              string
	YXUID            string
	OrganizationID   string
	OrganizationName string
	UserType         string
}

func qoderCNProfile(auth *cliproxyauth.Auth) qodercnProfile {
	profile := qodercnProfile{
		Name:             qoderCNProfileString(auth, "name"),
		AID:              qoderCNProfileString(auth, "aid"),
		UID:              qoderCNProfileString(auth, "uid"),
		YXUID:            qoderCNProfileString(auth, "yx_uid"),
		OrganizationID:   qoderCNProfileString(auth, "organization_id"),
		OrganizationName: qoderCNProfileString(auth, "organization_name"),
		UserType:         qoderCNProfileString(auth, "user_type"),
	}
	if profile.AID == "" {
		profile.AID = profile.UID
	}
	if profile.UserType == "" {
		profile.UserType = "personal_standard"
	}
	return profile
}

func qoderCNProfileString(auth *cliproxyauth.Auth, key string) string {
	if value := qoderCNMetadataString(auth, key); value != "" {
		return value
	}
	if auth != nil && auth.Attributes != nil {
		return strings.TrimSpace(auth.Attributes[key])
	}
	return ""
}

// qoderCNAccessToken resolves the device/OAuth token the signature binds.
func qoderCNAccessToken(auth *cliproxyauth.Auth) string {
	if token := qoderCNMetadataString(auth, "access_token"); token != "" {
		return token
	}
	if auth != nil && auth.Attributes != nil {
		return strings.TrimSpace(auth.Attributes["api_key"])
	}
	return ""
}

// qoderCNUpstreamModel strips a namespace prefix ("qoder/…") and any thinking
// suffix, leaving the bare gateway model key.
func qoderCNUpstreamModel(model string) string {
	model = strings.TrimSpace(model)
	if idx := strings.LastIndex(model, "/"); idx >= 0 && idx+1 < len(model) {
		model = model[idx+1:]
	}
	model = strings.TrimSpace(model)
	// Drop a trailing "(…)" thinking suffix if present.
	if open := strings.IndexByte(model, '('); open > 0 && strings.HasSuffix(model, ")") {
		model = strings.TrimSpace(model[:open])
	}
	if model == "" {
		return "auto"
	}
	return model
}

// qoderCNMetadataString reads a string value from the auth metadata.
func qoderCNMetadataString(auth *cliproxyauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

// qoderCNStatusError carries an HTTP status so the auth manager can update state.
type qoderCNStatusError struct {
	code int
	msg  string
}

func (e qoderCNStatusError) Error() string   { return e.msg }
func (e qoderCNStatusError) StatusCode() int { return e.code }

// refreshQoderAuth rotates Qoder OAuth credentials via the refresh token.
func refreshQoderAuth(ctx context.Context, cfg *config.Config, defaults qoderAuthDefaults, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("%s executor: auth is nil", defaults.label)
	}
	refreshToken := qoderCNMetadataString(auth, "refresh_token")
	if refreshToken == "" {
		return auth, nil
	}
	client := defaults.newClient(cfg, auth.ProxyURL)
	token, err := client.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["type"] = defaults.provider
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
	return auth, nil
}

// qoderCNStreamState folds upstream SSE frames into OpenAI chat.completion.chunk
// frames and accumulates usage.
type qoderCNStreamState struct {
	model        string
	completionID string
	created      int64
	sentRole     bool
	toolIndexes  map[string]int
	nextTool     int
	finishReason string
	usage        *qoderCNUsage
}

type qoderCNUsage struct {
	prompt     int64
	completion int64
	reasoning  int64
	cached     int64
	total      int64
}

func newQoderCNStreamState(model string) *qoderCNStreamState {
	return &qoderCNStreamState{
		model:        model,
		completionID: "chatcmpl-" + randomHexString(24),
		created:      time.Now().Unix(),
		toolIndexes:  map[string]int{},
	}
}

// consumeDataLine handles one upstream `data:` payload and returns the OpenAI
// chunk frames it produced. apiErr is non-empty for an upstream error envelope.
func (s *qoderCNStreamState) consumeDataLine(dataLine []byte) ([][]byte, string) {
	inner, done, ok := qoderCNExtractInner(dataLine)
	if !ok {
		return nil, ""
	}
	if done {
		return s.finishFrames(), ""
	}
	if apiErr := qoderCNAPIError(inner); apiErr != "" {
		return nil, apiErr
	}
	if usageNode := gjson.GetBytes(inner, "usage"); usageNode.Exists() {
		s.usage = &qoderCNUsage{
			prompt:     usageNode.Get("prompt_tokens").Int(),
			completion: usageNode.Get("completion_tokens").Int(),
			reasoning:  usageNode.Get("completion_tokens_details.reasoning_tokens").Int(),
			cached:     usageNode.Get("prompt_tokens_details.cached_tokens").Int(),
			total:      usageNode.Get("total_tokens").Int(),
		}
	}
	choice := gjson.GetBytes(inner, "choices.0")
	if !choice.Exists() {
		return nil, ""
	}
	if finish := strings.TrimSpace(choice.Get("finish_reason").String()); finish != "" {
		s.finishReason = qoderCNMapFinishReason(finish)
	}
	delta := choice.Get("delta")
	if !delta.Exists() {
		return nil, ""
	}
	out := make([][]byte, 0, 2)
	payload := map[string]any{}
	if !s.sentRole {
		s.sentRole = true
		payload["role"] = "assistant"
	}
	if content := delta.Get("content").String(); content != "" {
		payload["content"] = content
	}
	if reasoning := delta.Get("reasoning_content").String(); reasoning != "" {
		payload["reasoning_content"] = reasoning
	}
	if toolCalls := delta.Get("tool_calls"); toolCalls.Exists() && toolCalls.IsArray() {
		normalized := make([]any, 0, len(toolCalls.Array()))
		for _, call := range toolCalls.Array() {
			id := strings.TrimSpace(call.Get("id").String())
			index := int(call.Get("index").Int())
			if id != "" {
				if _, seen := s.toolIndexes[id]; !seen {
					s.toolIndexes[id] = index
				} else {
					index = s.toolIndexes[id]
				}
			} else if len(s.toolIndexes) == 0 {
				index = s.nextTool
				s.nextTool++
			}
			entry := map[string]any{
				"index": index,
				"type":  "function",
				"function": map[string]any{
					"name":      call.Get("function.name").String(),
					"arguments": call.Get("function.arguments").String(),
				},
			}
			if id != "" {
				entry["id"] = id
			}
			normalized = append(normalized, entry)
		}
		if len(normalized) > 0 {
			payload["tool_calls"] = normalized
		}
	}
	if len(payload) > 0 {
		out = append(out, s.frame(payload, nil))
	}
	return out, ""
}

// finishFrames emits the terminal chunk plus the usage-only chunk [DONE].
func (s *qoderCNStreamState) finishFrames() [][]byte {
	reason := s.finishReason
	if reason == "" {
		reason = "stop"
	}
	frames := [][]byte{s.frame(map[string]any{}, reason)}
	if s.usage != nil {
		frames = append(frames, s.usageFrame())
	}
	frames = append(frames, []byte("data: [DONE]\n\n"))
	return frames
}

func (s *qoderCNStreamState) frame(delta map[string]any, finish any) []byte {
	choice := map[string]any{"index": 0, "delta": delta, "finish_reason": finish}
	chunk := map[string]any{
		"id":      s.completionID,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{choice},
	}
	raw, _ := json.Marshal(chunk)
	return append([]byte("data: "), append(raw, '\n', '\n')...)
}

func (s *qoderCNStreamState) usageFrame() []byte {
	chunk := map[string]any{
		"id":      s.completionID,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{},
		"usage": map[string]any{
			"prompt_tokens":     s.usage.prompt,
			"completion_tokens": s.usage.completion,
			"total_tokens":      s.usage.total,
			"completion_tokens_details": map[string]any{
				"reasoning_tokens": s.usage.reasoning,
			},
			"prompt_tokens_details": map[string]any{
				"cached_tokens": s.usage.cached,
			},
		},
	}
	raw, _ := json.Marshal(chunk)
	return append([]byte("data: "), append(raw, '\n', '\n')...)
}

func (s *qoderCNStreamState) usageDetail() usage.Detail {
	if s.usage == nil {
		return usage.Detail{}
	}
	return usage.Detail{
		InputTokens:     s.usage.prompt,
		OutputTokens:    s.usage.completion,
		ReasoningTokens: s.usage.reasoning,
		CachedTokens:    s.usage.cached,
		TotalTokens:     s.usage.total,
	}
}

// qoderCNAggregateStream folds OpenAI SSE chunks into a single non-streaming
// chat.completion response.
func qoderCNAggregateStream(raw []byte, model string) []byte {
	var (
		content   strings.Builder
		reasoning strings.Builder
		toolCalls []any
		finish    = "stop"
		id        string
		created   int64
		usageNode map[string]any
	)
	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		if !json.Valid(payload) {
			continue
		}
		if id == "" {
			if v := gjson.GetBytes(payload, "id").String(); v != "" {
				id = v
			}
		}
		if created == 0 {
			if v := gjson.GetBytes(payload, "created").Int(); v != 0 {
				created = v
			}
		}
		if v := gjson.GetBytes(payload, "choices.0.finish_reason").String(); v != "" {
			finish = v
		}
		if v := gjson.GetBytes(payload, "choices.0.delta.content").String(); v != "" {
			content.WriteString(v)
		}
		if v := gjson.GetBytes(payload, "choices.0.delta.reasoning_content").String(); v != "" {
			reasoning.WriteString(v)
		}
		if tc := gjson.GetBytes(payload, "choices.0.delta.tool_calls"); tc.IsArray() {
			toolCalls = qoderCNMergeToolCalls(toolCalls, tc.Array())
		}
		if u := gjson.GetBytes(payload, "usage"); u.Exists() && u.Get("total_tokens").Exists() {
			usageNode = u.Value().(map[string]any)
		}
	}
	if id == "" {
		id = "chatcmpl-" + randomHexString(24)
	}
	if created == 0 {
		created = time.Now().Unix()
	}
	message := map[string]any{"role": "assistant", "content": content.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	response := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}},
	}
	if usageNode != nil {
		response["usage"] = usageNode
	}
	out, _ := json.Marshal(response)
	return out
}

// qoderCNMergeToolCalls accumulates streamed tool_call deltas by index.
func qoderCNMergeToolCalls(acc []any, deltas []gjson.Result) []any {
	for _, delta := range deltas {
		index := int(delta.Get("index").Int())
		for len(acc) <= index {
			acc = append(acc, map[string]any{
				"id":       "",
				"type":     "function",
				"function": map[string]any{"name": "", "arguments": ""},
			})
		}
		entry, _ := acc[index].(map[string]any)
		if entry == nil {
			entry = map[string]any{"type": "function", "function": map[string]any{"name": "", "arguments": ""}}
			acc[index] = entry
		}
		if id := delta.Get("id").String(); id != "" {
			entry["id"] = id
		}
		if name := delta.Get("function.name").String(); name != "" {
			if fn, ok := entry["function"].(map[string]any); ok {
				fn["name"] = name
			}
		}
		if args := delta.Get("function.arguments").String(); args != "" {
			if fn, ok := entry["function"].(map[string]any); ok {
				existing, _ := fn["arguments"].(string)
				fn["arguments"] = existing + args
			}
		}
	}
	return acc
}

func qoderCNMapFinishReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case "tool_calls", "function_call":
		return "tool_calls"
	case "length", "max_tokens":
		return "length"
	case "content_filter":
		return "content_filter"
	default:
		return "stop"
	}
}

// randomHexString returns n random lowercase hex characters.
func randomHexString(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(buf)[:n]
}
