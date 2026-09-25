// Package xiaohuanxiong implements credential acquisition for SenseTime's
// Xiaohuanxiong (商汤小浣熊 / Raccoon) office assistant.
//
// Xiaohuanxiong does not expose a standard OAuth2 authorization server. The
// desktop client performs a browser-based authorization-code exchange against
// the web site: it opens
//
//	https://xiaohuanxiong.com/code/authorize?login_source=desktop&appname=...
//
// in the system browser, which redirects to the desktop deep link
//
//	office-raccoon://auth/callback?code=<authorization_code>
//
// and the client then exchanges that one-time code for an access/refresh token
// pair at POST /api/web/auth/v1/login_with_authorization_code.
//
// This package mirrors that flow. The client only ever talks to its fixed
// upstream; BaseURL is injectable for tests.
package xiaohuanxiong

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

const (
	// Provider is the CLIProxyAPI provider identifier.
	Provider = "xiaohuanxiong"
	// BaseURL is the Xiaohuanxiong web origin.
	BaseURL = "https://xiaohuanxiong.com"
	// LoginPath is the web login page used to start browser authorization.
	LoginPath = "/login"
	// AuthorizePath is the desktop authorization-code endpoint.
	AuthorizePath = "/code/authorize"
	// AuthAPIPrefix is the web authentication API prefix.
	AuthAPIPrefix = "/api/web/auth/v1"
	// LLMPath is the OpenAI-compatible LLM gateway base path.
	LLMPath = "/api/web/llm/v2"
	// LLMBaseURL is the OpenAI-compatible gateway used for inference.
	LLMBaseURL = BaseURL + LLMPath
	// CallbackScheme is the desktop deep-link scheme used for the OAuth callback.
	CallbackScheme = "office-raccoon"
	// CallbackHost is the deep-link host for the authorization callback.
	CallbackHost = "auth"
	// CallbackPath is the deep-link path for the authorization callback.
	CallbackPath = "/callback"
	// AppName is the login_source=desktop appname query value.
	AppName = "办公小浣熊客户端"

	// RefreshWindowSeconds is how long before expiry a token is considered stale.
	// The desktop client refreshes when exp - now < 300s.
	RefreshWindowSeconds = 300
	// AuthCodeNotFound is the upstream error code for a missing/expired/consumed
	// authorization code.
	AuthCodeNotFound = 200035

	defaultHTTPTimeout = 30 * time.Second
)

// Error is a structured upstream API error.
type Error struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Code is the upstream business error code (payload "code").
	Code int
	// Message is the upstream error message.
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return "xiaohuanxiong: unknown error"
	}
	if e.Code != 0 {
		return fmt.Sprintf("xiaohuanxiong: HTTP %d code %d: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("xiaohuanxiong: HTTP %d: %s", e.StatusCode, e.Message)
}

// StatusCodeValue lets callers inspect the HTTP status without importing net/http.
func (e *Error) StatusCodeValue() int {
	if e == nil {
		return 0
	}
	return e.StatusCode
}

// TokenData holds the credential payload returned by the token endpoints.
type TokenData struct {
	// AccessToken is the bearer token used for LLM and catalog requests.
	AccessToken string
	// RefreshToken rotates the access token.
	RefreshToken string
	// OfficeIdentity is the optional office account identity.
	OfficeIdentity string
	// OfficeOrgName is the optional organization display name.
	OfficeOrgName string
	// OfficeOrgRole is the optional organization role.
	OfficeOrgRole string
}

// Client performs Xiaohuanxiong credential requests.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a proxy-aware Xiaohuanxiong client.
func NewClient(cfg *config.Config) *Client {
	return NewClientWithProxyURL(cfg, "")
}

// NewClientWithProxyURL creates a client with an optional per-auth proxy override.
func NewClientWithProxyURL(cfg *config.Config, proxyURL string) *Client {
	return NewClientWithBaseURL(cfg, proxyURL, BaseURL)
}

// NewClientWithBaseURL creates a client against an explicit origin. It exists so
// tests and self-hosted deployments can point at another xiaohuanxiong host.
func NewClientWithBaseURL(cfg *config.Config, proxyURL, baseURL string) *Client {
	httpClient := &http.Client{Timeout: defaultHTTPTimeout}
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
	}
	if strings.TrimSpace(proxyURL) != "" {
		sdkCfg.ProxyURL = strings.TrimSpace(proxyURL)
	}
	httpClient = util.SetProxy(&sdkCfg, httpClient)

	normalizedBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if normalizedBase == "" {
		normalizedBase = BaseURL
	}
	return &Client{httpClient: httpClient, baseURL: normalizedBase}
}

// BaseURL returns the origin this client talks to.
func (c *Client) BaseURL() string {
	if c == nil || c.baseURL == "" {
		return BaseURL
	}
	return c.baseURL
}

// AuthAPIURL returns the web authentication API base URL.
func (c *Client) AuthAPIURL() string {
	return c.BaseURL() + AuthAPIPrefix
}

// LLMBaseURL returns the OpenAI-compatible gateway base URL.
func (c *Client) LLMBaseURL() string {
	return c.BaseURL() + LLMPath
}

// AuthorizationURL builds the browser URL that starts the desktop login flow.
//
// The parameters match the desktop client exactly: login_source=desktop and
// appname=办公小浣熊客户端. The web site prompts for login and then redirects to
// the office-raccoon deep link carrying a one-time authorization code.
func AuthorizationURL(loginURL string) string {
	base := strings.TrimSpace(loginURL)
	if base == "" {
		base = BaseURL + LoginPath
	}
	u, err := url.Parse(base)
	if err != nil {
		fallback := fmt.Sprintf("%s%s", BaseURL, AuthorizePath)
		u, err = url.Parse(fallback)
		if err != nil {
			return fallback
		}
	}
	// /login is a page; the authorization endpoint is a sibling under /code.
	if strings.HasSuffix(u.Path, "/login") || u.Path == "" {
		u.Path = AuthorizePath
	}
	q := u.Query()
	q.Set("login_source", "desktop")
	q.Set("appname", AppName)
	u.RawQuery = q.Encode()
	return u.String()
}

// CallbackURL returns the deep link the browser is expected to redirect to. It is
// informational only: the upstream redirect target is fixed.
func CallbackURL() string {
	return fmt.Sprintf("%s://%s%s", CallbackScheme, CallbackHost, CallbackPath)
}

// callbackCodeQueryKeys are the query/fragment keys that carry the one-time
// authorization code. The desktop deep link uses "code"; the IDE redirect
// branch of the web authorize page appends "authorization_code".
var callbackCodeQueryKeys = []string{"code", "authorization_code"}

// ParseCallbackCode extracts the one-time authorization code from what the user
// pasted. Both formats are supported:
//
//	office-raccoon://auth/callback?code=<code>   (desktop deep link)
//	<code>                                       (bare authorization code)
//
// The delivery mechanism is a client-side deep link that never reaches a server
// (see CallbackURL), so the proxy cannot observe the redirect; the operator
// pastes whatever the browser or DevTools shows. An https callback, a query
// pair pasted without its leading "?" or with its key ("code=<code>",
// "authorization_code=<code>"), and a fragment form are all accepted, because
// those are the other places the code surfaces. An authorization code is opaque
// and may itself contain "=" or post-URL characters (base64 padding), so input
// without a recognizable code parameter is returned verbatim as the code.
func ParseCallbackCode(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("xiaohuanxiong: empty callback URL")
	}

	if hasCallbackCodeParam(raw) {
		// A query string or fragment pasted on its own ("code=<code>",
		// "?code=<code>", "#code=<code>").
		if code := codeFromQuery(raw); code != "" {
			return code, nil
		}
		u, errParse := url.Parse(raw)
		if errParse != nil {
			return "", fmt.Errorf("xiaohuanxiong: invalid callback URL")
		}
		if code := codeFromQuery(u.RawQuery); code != "" {
			return code, nil
		}
		// Some redirect forms carry the code in the fragment.
		if code := codeFromQuery(u.Fragment); code != "" {
			return code, nil
		}
		// url.Parse keeps the query of a non-hierarchical URL (for example
		// office-raccoon:auth/callback?code=...) in Opaque instead of RawQuery.
		if idxOpaque := strings.Index(u.Opaque, "?"); idxOpaque >= 0 {
			if code := codeFromQuery(u.Opaque[idxOpaque+1:]); code != "" {
				return code, nil
			}
		}
		// A deep link or https callback with no usable code is a genuine user
		// error; report it instead of returning the URL as the code.
		if strings.Contains(raw, "://") || strings.HasPrefix(raw, "?") || strings.HasPrefix(raw, "#") {
			return "", fmt.Errorf("xiaohuanxiong: callback URL has no code parameter")
		}
	}

	// Not URL- or query-shaped: treat it as the opaque one-time code itself.
	return raw, nil
}

// hasCallbackCodeParam reports whether the input carries URL/query syntax that
// should be parsed rather than treated as a bare code.
func hasCallbackCodeParam(raw string) bool {
	if strings.Contains(raw, "://") {
		return true
	}
	// A leading delimiter is query/fragment syntax; an opaque one-time code never
	// starts with it.
	if strings.HasPrefix(raw, "?") || strings.HasPrefix(raw, "#") {
		return true
	}
	for _, key := range callbackCodeQueryKeys {
		if strings.Contains(raw, key+"=") {
			return true
		}
	}
	return false
}

// codeFromQuery parses query-like text (with or without a leading "?/&#" and
// with or without a preceding URL path) and returns the authorization code.
func codeFromQuery(rawQuery string) string {
	rawQuery = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(rawQuery), "?#&"))
	if rawQuery == "" {
		return ""
	}
	values, errParse := url.ParseQuery(rawQuery)
	if errParse != nil {
		return ""
	}
	for _, key := range callbackCodeQueryKeys {
		if code := strings.TrimSpace(values.Get(key)); code != "" {
			return code
		}
	}
	// Fall back to a case-insensitive scan: a hand-typed key may not preserve
	// the upstream's lowercase spelling.
	for name, entries := range values {
		if !isCallbackCodeKey(name) {
			continue
		}
		for _, entry := range entries {
			if code := strings.TrimSpace(entry); code != "" {
				return code
			}
		}
	}
	return ""
}

// isCallbackCodeKey reports whether a query key spells a code parameter,
// ignoring case and hyphen/underscore spelling.
func isCallbackCodeKey(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
	for _, key := range callbackCodeQueryKeys {
		if normalized == key {
			return true
		}
	}
	return false
}

// apiEnvelope is the shared response envelope for the web API.
type apiEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// tokenPayload mirrors the data object of the token endpoints.
type tokenPayload struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	OfficeIdentity string `json:"office_identity"`
	OfficeOrgName  string `json:"office_org_name"`
	OfficeOrgRole  string `json:"office_org_role"`
}

// ExchangeAuthorizationCode trades a one-time authorization code for tokens.
func (c *Client) ExchangeAuthorizationCode(ctx context.Context, code string) (*TokenData, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("xiaohuanxiong: authorization code is empty")
	}
	body, errMarshal := json.Marshal(map[string]string{"authorization_code": code})
	if errMarshal != nil {
		return nil, fmt.Errorf("xiaohuanxiong: encode exchange request: %w", errMarshal)
	}
	envelope, errDo := c.postJSON(ctx, c.AuthAPIURL()+"/login_with_authorization_code", body)
	if errDo != nil {
		return nil, errDo
	}
	if envelope.Code == AuthCodeNotFound {
		return nil, fmt.Errorf("xiaohuanxiong: authorization code is invalid, expired, or already used")
	}
	return decodeTokenPayload(envelope)
}

// Refresh rotates access/refresh tokens.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenData, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("xiaohuanxiong: refresh token is empty")
	}
	body, errMarshal := json.Marshal(map[string]string{"refresh_token": refreshToken})
	if errMarshal != nil {
		return nil, fmt.Errorf("xiaohuanxiong: encode refresh request: %w", errMarshal)
	}
	envelope, errDo := c.postJSON(ctx, c.AuthAPIURL()+"/refresh", body)
	if errDo != nil {
		return nil, errDo
	}
	return decodeTokenPayload(envelope)
}

// FetchModelCatalog retrieves the chat model catalog with the given bearer token.
//
// The response is returned verbatim so callers can decide how much of the
// upstream shape (ability level, tags, billing) they want to surface.
func (c *Client) FetchModelCatalog(ctx context.Context, accessToken string) ([]byte, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("xiaohuanxiong: access token is empty")
	}
	endpoint := c.LLMBaseURL() + "/model_catalog"
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if errReq != nil {
		return nil, fmt.Errorf("xiaohuanxiong: create catalog request: %w", errReq)
	}
	applyHeaders(req, accessToken)
	resp, errDo := c.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("xiaohuanxiong: catalog request failed: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			return
		}
	}()
	data, errRead := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if errRead != nil {
		return nil, fmt.Errorf("xiaohuanxiong: read catalog response: %w", errRead)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(data))}
	}
	return data, nil
}

// postJSON performs a JSON POST and unwraps the shared response envelope.
func (c *Client) postJSON(ctx context.Context, endpoint string, body []byte) (*apiEnvelope, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if errReq != nil {
		return nil, fmt.Errorf("xiaohuanxiong: create request: %w", errReq)
	}
	applyHeaders(req, "")
	resp, errDo := c.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("xiaohuanxiong: request failed: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			return
		}
	}()

	data, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return nil, fmt.Errorf("xiaohuanxiong: read response: %w", errRead)
	}

	var envelope apiEnvelope
	if errUnmarshal := json.Unmarshal(data, &envelope); errUnmarshal != nil {
		if resp.StatusCode >= 400 {
			return nil, &Error{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(data))}
		}
		return nil, fmt.Errorf("xiaohuanxiong: invalid JSON response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 || (envelope.Code != 0 && envelope.Code != AuthCodeNotFound) {
		return nil, &Error{StatusCode: resp.StatusCode, Code: envelope.Code, Message: envelope.Message}
	}
	return &envelope, nil
}

// decodeTokenPayload validates the data object of a token response.
func decodeTokenPayload(envelope *apiEnvelope) (*TokenData, error) {
	if envelope == nil {
		return nil, fmt.Errorf("xiaohuanxiong: empty token response")
	}
	var payload tokenPayload
	if errUnmarshal := json.Unmarshal(envelope.Data, &payload); errUnmarshal != nil {
		return nil, fmt.Errorf("xiaohuanxiong: invalid token payload: %w", errUnmarshal)
	}
	accessToken := strings.TrimSpace(payload.AccessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("xiaohuanxiong: token response has no access_token")
	}
	return &TokenData{
		AccessToken:    accessToken,
		RefreshToken:   strings.TrimSpace(payload.RefreshToken),
		OfficeIdentity: strings.TrimSpace(payload.OfficeIdentity),
		OfficeOrgName:  strings.TrimSpace(payload.OfficeOrgName),
		OfficeOrgRole:  strings.TrimSpace(payload.OfficeOrgRole),
	}, nil
}

// applyHeaders sets the headers shared by every Xiaohuanxiong API request.
func applyHeaders(req *http.Request, accessToken string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(accessToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	}
}
