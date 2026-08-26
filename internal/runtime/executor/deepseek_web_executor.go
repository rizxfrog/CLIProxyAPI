package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
)

const DeepSeekWebBaseURL = "https://chat.deepseek.com"

// DeepSeekWebExecutor translates OpenAI chat requests to DeepSeek's private web API.
type DeepSeekWebExecutor struct {
	cfg *config.Config
	hif *helps.DeepSeekWebHifClient
}

func NewDeepSeekWebExecutor(cfg *config.Config) *DeepSeekWebExecutor {
	return &DeepSeekWebExecutor{cfg: cfg, hif: helps.NewDeepSeekWebHifClient(cfg)}
}

func (e *DeepSeekWebExecutor) Identifier() string { return constant.DeepSeekWeb }

func (e *DeepSeekWebExecutor) RequestToFormat(_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) sdktranslator.Format {
	return sdktranslator.FormatOpenAI
}

func (e *DeepSeekWebExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	token, errToken := deepSeekWebUserToken(auth)
	if errToken != nil {
		return errToken
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
	return nil
}

func (e *DeepSeekWebExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("deepseek-web executor: request is nil")
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

func (e *DeepSeekWebExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	prepared, errPrepare := e.prepareCompletion(ctx, auth, req, opts)
	if errPrepare != nil {
		return resp, errPrepare
	}
	defer e.deleteSession(ctx, auth, prepared.accessToken, prepared.sessionID)

	httpResp, errDo := e.sendCompletion(ctx, auth, prepared)
	if errDo != nil {
		return resp, errDo
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("deepseek-web executor: close response body error: %v", errClose)
		}
	}()
	if errStatus := deepSeekWebResponseError(httpResp); errStatus != nil {
		return resp, errStatus
	}

	state := newDeepSeekWebSSEState(req.Model)
	scanner := bufio.NewScanner(httpResp.Body)
	scanner.Buffer(nil, 1_048_576)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		state.consume(bytes.TrimSpace(line[len("data:"):]))
	}
	if errScan := scanner.Err(); errScan != nil {
		return resp, fmt.Errorf("deepseek-web executor: read stream: %w", errScan)
	}
	openAIResponse := state.nonStreamResponse()
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	var param any
	translated := sdktranslator.TranslateNonStream(ctx, sdktranslator.FormatOpenAI, responseFormat, req.Model, opts.OriginalRequest, prepared.openAIBody, openAIResponse, &param)
	return cliproxyexecutor.Response{Payload: translated, Headers: httpResp.Header.Clone()}, nil
}

func (e *DeepSeekWebExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	prepared, errPrepare := e.prepareCompletion(ctx, auth, req, opts)
	if errPrepare != nil {
		return nil, errPrepare
	}
	httpResp, errDo := e.sendCompletion(ctx, auth, prepared)
	if errDo != nil {
		e.deleteSession(ctx, auth, prepared.accessToken, prepared.sessionID)
		return nil, errDo
	}
	if errStatus := deepSeekWebResponseError(httpResp); errStatus != nil {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("deepseek-web executor: close error response body: %v", errClose)
		}
		e.deleteSession(ctx, auth, prepared.accessToken, prepared.sessionID)
		return nil, errStatus
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("deepseek-web executor: close stream body error: %v", errClose)
			}
		}()
		defer e.deleteSession(ctx, auth, prepared.accessToken, prepared.sessionID)

		state := newDeepSeekWebSSEState(req.Model)
		responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
		var param any
		emit := func(openAIFrame []byte) bool {
			chunks := sdktranslator.TranslateStream(ctx, sdktranslator.FormatOpenAI, responseFormat, req.Model, opts.OriginalRequest, prepared.openAIBody, openAIFrame, &param)
			for _, chunk := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunk}:
				case <-ctx.Done():
					return false
				}
			}
			return true
		}

		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1_048_576)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			frames := state.consume(bytes.TrimSpace(line[len("data:"):]))
			for _, frame := range frames {
				if !emit(frame) {
					return
				}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("deepseek-web executor: read stream: %w", errScan)}:
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

func (e *DeepSeekWebExecutor) CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, errors.New("deepseek-web executor: count tokens is not supported")
}

func (e *DeepSeekWebExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("deepseek-web executor: auth is nil")
	}
	userToken, errToken := deepSeekWebUserToken(auth)
	if errToken != nil {
		return nil, errToken
	}
	if _, errAcquire := e.acquireAccessToken(ctx, auth, userToken); errAcquire != nil {
		return nil, errAcquire
	}
	return auth, nil
}

type deepSeekWebPreparedRequest struct {
	accessToken string
	sessionID   string
	powResponse string
	payload     []byte
	openAIBody  []byte
}

type deepSeekWebChallenge struct {
	Algorithm  string `json:"algorithm"`
	Challenge  string `json:"challenge"`
	Salt       string `json:"salt"`
	Signature  string `json:"signature"`
	Difficulty int    `json:"difficulty"`
	ExpireAt   int64  `json:"expire_at"`
	TargetPath string `json:"target_path"`
}

func (e *DeepSeekWebExecutor) prepareCompletion(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*deepSeekWebPreparedRequest, error) {
	userToken, errToken := deepSeekWebUserToken(auth)
	if errToken != nil {
		return nil, errToken
	}
	if userToken == "" {
		return nil, statusErr{code: http.StatusUnauthorized, msg: "deepseek-web executor: missing userToken"}
	}
	openAIBody := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, opts.SourceFormat, sdktranslator.FormatOpenAI, req.Model, bytes.Clone(req.Payload), opts.Stream)
	if gjson.GetBytes(openAIBody, "tools.#").Int() > 0 {
		return nil, deepSeekWebRequestError{message: "deepseek-web does not support tools yet"}
	}
	prompt, errPrompt := deepSeekWebMessagesToPrompt(openAIBody)
	if errPrompt != nil {
		return nil, errPrompt
	}
	accessToken, errAccess := e.acquireAccessToken(ctx, auth, userToken)
	if errAccess != nil {
		return nil, errAccess
	}
	sessionID, errSession := e.createSession(ctx, auth, accessToken)
	if errSession != nil {
		return nil, errSession
	}
	challenge, errChallenge := e.getChallenge(ctx, auth, accessToken)
	if errChallenge != nil {
		e.deleteSession(ctx, auth, accessToken, sessionID)
		return nil, errChallenge
	}
	answer, errSolve := helps.SolveDeepSeekWebPoW(challenge.Algorithm, challenge.Challenge, challenge.Salt, challenge.Difficulty, challenge.ExpireAt)
	if errSolve != nil {
		e.deleteSession(ctx, auth, accessToken, sessionID)
		return nil, errSolve
	}
	answerPayload, errMarshal := json.Marshal(map[string]any{
		"algorithm": challenge.Algorithm, "challenge": challenge.Challenge,
		"salt": challenge.Salt, "answer": answer, "signature": challenge.Signature,
		"target_path": challenge.TargetPath,
	})
	if errMarshal != nil {
		return nil, errMarshal
	}
	modelType, thinkingEnabled, searchEnabled := deepSeekWebModelOptions(req.Model, openAIBody)
	var refFileIDs []any
	if raw := gjson.GetBytes(openAIBody, "ref_file_ids"); raw.IsArray() {
		_ = json.Unmarshal([]byte(raw.Raw), &refFileIDs)
	}
	payload, errPayload := json.Marshal(map[string]any{
		"chat_session_id": sessionID, "parent_message_id": nil, "model_type": modelType,
		"prompt": prompt, "ref_file_ids": refFileIDs, "thinking_enabled": thinkingEnabled,
		"search_enabled": searchEnabled, "action": nil, "preempt": false,
	})
	if errPayload != nil {
		return nil, errPayload
	}
	return &deepSeekWebPreparedRequest{
		accessToken: accessToken, sessionID: sessionID,
		powResponse: base64.StdEncoding.EncodeToString(answerPayload), payload: payload,
		openAIBody: openAIBody,
	}, nil
}

func (e *DeepSeekWebExecutor) acquireAccessToken(ctx context.Context, auth *cliproxyauth.Auth, userToken string) (string, error) {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, e.endpoint(auth, "/api/v0/users/current"), nil)
	if errRequest != nil {
		return "", errRequest
	}
	e.applyHeaders(request, userToken, auth)
	response, errDo := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(request)
	if errDo != nil {
		return "", fmt.Errorf("deepseek-web executor: acquire access token: %w", errDo)
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Errorf("deepseek-web executor: close users/current body error: %v", errClose)
		}
	}()
	body, errRead := io.ReadAll(response.Body)
	if errRead != nil {
		return "", errRead
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", statusErr{code: response.StatusCode, msg: string(body)}
	}
	if code := gjson.GetBytes(body, "code").Int(); code != 0 {
		return "", statusErr{code: http.StatusUnauthorized, msg: string(body)}
	}
	token := strings.TrimSpace(gjson.GetBytes(body, "data.biz_data.token").String())
	if token == "" {
		token = strings.TrimSpace(gjson.GetBytes(body, "biz_data.token").String())
	}
	if token == "" {
		return "", statusErr{code: http.StatusUnauthorized, msg: "deepseek-web executor: users/current returned no token"}
	}
	return token, nil
}

func (e *DeepSeekWebExecutor) createSession(ctx context.Context, auth *cliproxyauth.Auth, token string) (string, error) {
	body, errCall := e.callJSON(ctx, auth, http.MethodPost, "/api/v0/chat_session/create", token, []byte("{}"))
	if errCall != nil {
		return "", errCall
	}
	sessionID := strings.TrimSpace(gjson.GetBytes(body, "data.biz_data.chat_session.id").String())
	if sessionID == "" {
		sessionID = strings.TrimSpace(gjson.GetBytes(body, "biz_data.chat_session.id").String())
	}
	if sessionID == "" {
		return "", fmt.Errorf("deepseek-web executor: chat_session/create returned no session id")
	}
	return sessionID, nil
}

func (e *DeepSeekWebExecutor) getChallenge(ctx context.Context, auth *cliproxyauth.Auth, token string) (deepSeekWebChallenge, error) {
	body, errCall := e.callJSON(ctx, auth, http.MethodPost, "/api/v0/chat/create_pow_challenge", token, []byte(`{"target_path":"/api/v0/chat/completion"}`))
	if errCall != nil {
		return deepSeekWebChallenge{}, errCall
	}
	var envelope struct {
		Data struct {
			BizData struct {
				Challenge deepSeekWebChallenge `json:"challenge"`
			} `json:"biz_data"`
		} `json:"data"`
	}
	if errUnmarshal := json.Unmarshal(body, &envelope); errUnmarshal != nil {
		return deepSeekWebChallenge{}, errUnmarshal
	}
	if envelope.Data.BizData.Challenge.Challenge == "" {
		return deepSeekWebChallenge{}, fmt.Errorf("deepseek-web executor: create_pow_challenge returned no challenge")
	}
	return envelope.Data.BizData.Challenge, nil
}

func (e *DeepSeekWebExecutor) callJSON(ctx context.Context, auth *cliproxyauth.Auth, method, path, token string, body []byte) ([]byte, error) {
	request, errRequest := http.NewRequestWithContext(ctx, method, e.endpoint(auth, path), bytes.NewReader(body))
	if errRequest != nil {
		return nil, errRequest
	}
	e.applyHeaders(request, token, auth)
	request.Header.Set("Content-Type", "application/json")
	response, errDo := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(request)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Errorf("deepseek-web executor: close %s body error: %v", path, errClose)
		}
	}()
	responseBody, errRead := io.ReadAll(response.Body)
	if errRead != nil {
		return nil, errRead
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, statusErr{code: response.StatusCode, msg: string(responseBody)}
	}
	if code := gjson.GetBytes(responseBody, "code").Int(); code != 0 {
		status := http.StatusBadGateway
		if code == 40003 {
			status = http.StatusUnauthorized
		} else if code == 40002 {
			status = http.StatusTooManyRequests
		}
		return nil, statusErr{code: status, msg: string(responseBody)}
	}
	return responseBody, nil
}

func (e *DeepSeekWebExecutor) sendCompletion(ctx context.Context, auth *cliproxyauth.Auth, prepared *deepSeekWebPreparedRequest) (*http.Response, error) {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint(auth, "/api/v0/chat/completion"), bytes.NewReader(prepared.payload))
	if errRequest != nil {
		return nil, errRequest
	}
	e.applyHeaders(request, prepared.accessToken, auth)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Ds-Pow-Response", prepared.powResponse)
	_, offset := time.Now().Zone()
	request.Header.Set("X-Client-Timezone-Offset", fmt.Sprintf("%d", offset))
	return helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(request)
}

func (e *DeepSeekWebExecutor) deleteSession(ctx context.Context, auth *cliproxyauth.Auth, token, sessionID string) {
	if token == "" || sessionID == "" {
		return
	}
	payload, _ := json.Marshal(map[string]string{"chat_session_id": sessionID})
	_, _ = e.callJSON(ctx, auth, http.MethodPost, "/api/v0/chat_session/delete", token, payload)
}

func (e *DeepSeekWebExecutor) endpoint(auth *cliproxyauth.Auth, path string) string {
	baseURL := DeepSeekWebBaseURL
	if auth != nil && auth.Attributes != nil {
		if configured := strings.TrimSpace(auth.Attributes["base_url"]); configured != "" {
			baseURL = configured
		}
	}
	return strings.TrimRight(baseURL, "/") + path
}

func (e *DeepSeekWebExecutor) applyHeaders(request *http.Request, token string, auth *cliproxyauth.Auth) {
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Origin", strings.TrimSuffix(e.endpoint(auth, ""), "/"))
	request.Header.Set("Referer", strings.TrimSuffix(e.endpoint(auth, ""), "/")+"/")
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	request.Header.Set("X-Client-Bundle-Id", "com.deepseek.chat")
	request.Header.Set("X-Client-Locale", "en_US")
	request.Header.Set("X-Client-Platform", "web")
	request.Header.Set("X-Client-Version", "2.4.0")
	if e.hif != nil {
		ctx := request.Context()
		if leim := e.hif.LeimHeader(ctx, auth); leim != "" {
			request.Header.Set("X-Hif-Leim", leim)
		}
		if dliq := e.hif.DliqHeader(ctx, auth); dliq != "" {
			request.Header.Set("X-Hif-Dliq", dliq)
		}
	}
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(request, auth.Attributes)
	}
}

func deepSeekWebUserToken(auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	raw := ""
	if auth.Attributes != nil {
		raw = strings.TrimSpace(auth.Attributes["api_key"])
	}
	if raw == "" && auth.Metadata != nil {
		if token, ok := auth.Metadata["user_token"].(string); ok {
			raw = strings.TrimSpace(token)
		}
	}
	if raw == "" {
		return "", nil
	}
	var wrapped struct {
		Value string `json:"value"`
	}
	if strings.HasPrefix(raw, "{") {
		if errUnmarshal := json.Unmarshal([]byte(raw), &wrapped); errUnmarshal != nil {
			return "", fmt.Errorf("deepseek-web executor: invalid userToken JSON: %w", errUnmarshal)
		}
		if strings.TrimSpace(wrapped.Value) == "" {
			return "", fmt.Errorf("deepseek-web executor: userToken JSON has no value")
		}
		return strings.TrimSpace(wrapped.Value), nil
	}
	return raw, nil
}

func deepSeekWebMessagesToPrompt(body []byte) (string, error) {
	var request struct {
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
			Name    string `json:"name"`
		} `json:"messages"`
	}
	if errUnmarshal := json.Unmarshal(body, &request); errUnmarshal != nil {
		return "", fmt.Errorf("deepseek-web executor: invalid OpenAI request: %w", errUnmarshal)
	}
	if len(request.Messages) == 0 {
		return "", deepSeekWebRequestError{message: "deepseek-web requires at least one message"}
	}
	parts := make([]string, 0, len(request.Messages))
	for _, message := range request.Messages {
		text := deepSeekWebContentText(message.Content)
		if strings.TrimSpace(text) == "" {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(message.Role))
		switch role {
		case "system":
			parts = append(parts, text)
		case "assistant":
			parts = append(parts, "Assistant: "+text)
		case "tool":
			name := strings.TrimSpace(message.Name)
			if name == "" {
				name = "tool"
			}
			parts = append(parts, "Tool result ("+name+"): "+text)
		default:
			parts = append(parts, "User: "+text)
		}
	}
	return strings.Join(parts, "\n\n"), nil
}

func deepSeekWebContentText(content any) string {
	switch value := content.(type) {
	case string:
		return value
	case []any:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			if block, ok := item.(map[string]any); ok {
				if text, okText := block["text"].(string); okText {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func deepSeekWebModelOptions(model string, body []byte) (modelType string, thinking, search bool) {
	lowerModel := strings.ToLower(model)
	modelType = "default"
	if strings.Contains(lowerModel, "pro") || strings.Contains(lowerModel, "expert") {
		modelType = "expert"
	}
	thinking = strings.Contains(lowerModel, "r1") || strings.Contains(lowerModel, "think") || strings.Contains(lowerModel, "reason") ||
		gjson.GetBytes(body, "thinking_enabled").Bool() || gjson.GetBytes(body, "thinking").Bool() || gjson.GetBytes(body, "reasoning_effort").Exists()
	search = strings.Contains(lowerModel, "search") || gjson.GetBytes(body, "search_enabled").Bool() || gjson.GetBytes(body, "search").Bool() || gjson.GetBytes(body, "web_search").Bool()
	return modelType, thinking, search
}

type deepSeekWebRequestError struct{ message string }

func (e deepSeekWebRequestError) Error() string         { return e.message }
func (e deepSeekWebRequestError) StatusCode() int       { return http.StatusBadRequest }
func (e deepSeekWebRequestError) IsRequestScoped() bool { return true }

func deepSeekWebResponseError(response *http.Response) error {
	if response == nil {
		return fmt.Errorf("deepseek-web executor: nil upstream response")
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 && !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return nil
	}
	body, _ := io.ReadAll(response.Body)
	status := response.StatusCode
	if status >= 200 && status < 300 {
		status = http.StatusBadGateway
		code := gjson.GetBytes(body, "code").Int()
		if code == 40003 {
			status = http.StatusUnauthorized
		} else if code == 40002 {
			status = http.StatusTooManyRequests
		}
	}
	return statusErr{code: status, msg: string(body)}
}

type deepSeekWebDelta struct {
	text      string
	reasoning bool
}

type deepSeekWebSSEState struct {
	id          string
	model       string
	created     int64
	currentPath string
	content     strings.Builder
	reasoning   strings.Builder
	roleEmitted bool
	finished    bool
}

func newDeepSeekWebSSEState(model string) *deepSeekWebSSEState {
	return &deepSeekWebSSEState{
		id: fmt.Sprintf("chatcmpl-dsweb-%d", time.Now().UnixNano()), model: model,
		created: time.Now().Unix(),
	}
}

func (s *deepSeekWebSSEState) consume(payload []byte) [][]byte {
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return nil
	}
	var data map[string]any
	if errUnmarshal := json.Unmarshal(payload, &data); errUnmarshal != nil {
		return nil
	}
	deltas := s.extractDeltas(data)
	frames := make([][]byte, 0, len(deltas)+1)
	for _, delta := range deltas {
		if delta.text == "" {
			continue
		}
		if !s.roleEmitted {
			s.roleEmitted = true
			frames = append(frames, s.streamFrame(map[string]any{"role": "assistant", "content": ""}, nil))
		}
		if delta.reasoning {
			s.reasoning.WriteString(delta.text)
			frames = append(frames, s.streamFrame(map[string]any{"reasoning_content": delta.text}, nil))
		} else {
			s.content.WriteString(delta.text)
			frames = append(frames, s.streamFrame(map[string]any{"content": delta.text}, nil))
		}
	}
	if path, _ := data["p"].(string); path == "response/status" && data["v"] == "FINISHED" {
		s.finished = true
	}
	return frames
}

func (s *deepSeekWebSSEState) extractDeltas(data map[string]any) []deepSeekWebDelta {
	var deltas []deepSeekWebDelta
	if responseWrapper, ok := data["v"].(map[string]any); ok {
		if response, okResponse := responseWrapper["response"].(map[string]any); okResponse {
			if enabled, okEnabled := response["thinking_enabled"].(bool); okEnabled {
				if enabled {
					s.currentPath = "thinking"
				} else {
					s.currentPath = "content"
				}
			}
			deltas = append(deltas, s.fragmentDeltas(response["fragments"])...)
		}
	}
	path, _ := data["p"].(string)
	if path == "response/fragments" {
		deltas = append(deltas, s.fragmentDeltas(data["v"])...)
		return deltas
	}
	if value, ok := data["v"].(string); ok && path != "response/status" && path != "response/search_status" {
		deltas = append(deltas, deepSeekWebDelta{text: value, reasoning: s.currentPath == "thinking"})
	}
	return deltas
}

func (s *deepSeekWebSSEState) fragmentDeltas(value any) []deepSeekWebDelta {
	items, ok := value.([]any)
	if !ok {
		if item, okItem := value.(map[string]any); okItem {
			items = []any{item}
		} else {
			return nil
		}
	}
	out := make([]deepSeekWebDelta, 0, len(items))
	for _, raw := range items {
		fragment, okFragment := raw.(map[string]any)
		if !okFragment {
			continue
		}
		typeName := strings.ToUpper(fmt.Sprint(fragment["type"]))
		if typeName == "THINK" {
			s.currentPath = "thinking"
		}
		if typeName == "ANSWER" || typeName == "RESPONSE" {
			s.currentPath = "content"
		}
		text, _ := fragment["content"].(string)
		if text != "" {
			out = append(out, deepSeekWebDelta{text: text, reasoning: s.currentPath == "thinking"})
		}
	}
	return out
}

func (s *deepSeekWebSSEState) streamFrame(delta map[string]any, finishReason any) []byte {
	body, _ := json.Marshal(map[string]any{
		"id": s.id, "object": "chat.completion.chunk", "created": s.created, "model": s.model,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finishReason}},
	})
	return append([]byte("data: "), body...)
}

func (s *deepSeekWebSSEState) finishFrames() [][]byte {
	frames := make([][]byte, 0, 3)
	if !s.roleEmitted {
		s.roleEmitted = true
		frames = append(frames, s.streamFrame(map[string]any{"role": "assistant", "content": ""}, nil))
	}
	frames = append(frames, s.streamFrame(map[string]any{}, "stop"), []byte("[DONE]"))
	return frames
}

func (s *deepSeekWebSSEState) nonStreamResponse() []byte {
	message := map[string]any{"role": "assistant", "content": s.content.String()}
	if s.reasoning.Len() > 0 {
		message["reasoning_content"] = s.reasoning.String()
	}
	body, _ := json.Marshal(map[string]any{
		"id": s.id, "object": "chat.completion", "created": s.created, "model": s.model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
	})
	return body
}
