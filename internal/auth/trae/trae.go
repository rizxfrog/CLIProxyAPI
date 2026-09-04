// Package trae implements the TRAE SOLO CN desktop OAuth login flow.
//
// Unlike CodeBuddy's device flow or Codex's authorization-code + PKCE flow,
// TRAE has no public device-code endpoint. The desktop client opens
// https://www.trae.cn/authorization with auth_from=solo and an
// auth_callback_url that must be a 127.0.0.1 loopback address. After the user
// signs in, TRAE packs the credential bundle into the callback URL query
// string. The desktop client parses that URL; for CLIProxyAPI deployments
// (often remote) the user copies the full callback URL from the browser
// address bar and pastes it back so the server can exchange it for tokens.
package trae

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	// AuthorizationHost is the TRAE CN authorization page.
	AuthorizationHost = "https://www.trae.cn"
	// OAuthHost is the ExchangeToken / GetUserInfo host for TRAE SOLO CN.
	OAuthHost = "https://api.trae.com.cn"
	// AgentHost is the SOLO CN desktop agent gateway.
	AgentHost = "https://trae-api-cn.mchost.guru"

	// ClientID is the public OAuth client id shipped with the SOLO desktop client.
	ClientID = "en1oxy7wnw8j9n"
	// IdeVersion is the desktop IDE version sent in OAuth headers.
	IdeVersion = "0.1.43"

	// CallbackPath is the loopback path TRAE redirects to after login.
	CallbackPath = "/authorize"
	// CallbackPort is the loopback port embedded in auth_callback_url. The
	// callback itself is never served; users paste the URL back manually.
	CallbackPort = "18080"
)

// TokenData is the normalized TRAE credential bundle produced by a successful
// login. The fields mirror the auth file shape used by traework2api so tokens
// can be imported into the runtime executor unchanged.
type TokenData struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // Unix seconds; 0 when unknown.
	UID          string
	Nickname     string
	EnterpriseID string
	MachineID    string
	DeviceID     string
	APIHost      string
}

// Client performs TRAE credential-acquisition requests.
type Client struct {
	httpClient *http.Client
	apiHost    string
	clientID   string
}

// NewClient creates a proxy-aware TRAE OAuth client.
func NewClient(cfg *config.Config) *Client {
	return NewClientWithProxyURL(cfg, "")
}

// NewClientWithProxyURL creates a client with an optional per-auth proxy override.
func NewClientWithProxyURL(cfg *config.Config, proxyURL string) *Client {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
	}
	if strings.TrimSpace(proxyURL) != "" {
		sdkCfg.ProxyURL = strings.TrimSpace(proxyURL)
	}
	httpClient = util.SetProxy(&sdkCfg, httpClient)
	return &Client{httpClient: httpClient, apiHost: OAuthHost, clientID: ClientID}
}

// LoginURL carries the generated login page URL and the identity pair that must
// accompany the final token record.
type LoginURL struct {
	URL       string
	State     string
	MachineID string
	DeviceID  string
}

// BuildLoginURL generates the TRAE desktop authorization URL. The callback URL
// deliberately uses a 127.0.0.1 loopback host because TRAE rejects non-loopback
// auth_callback_url values with "Login Failed".
func (c *Client) BuildLoginURL() (*LoginURL, error) {
	machineID, errMachine := randomHex(16)
	if errMachine != nil {
		return nil, fmt.Errorf("trae: generate machine id: %w", errMachine)
	}
	deviceID, errDevice := randomHex(16)
	if errDevice != nil {
		return nil, fmt.Errorf("trae: generate device id: %w", errDevice)
	}
	traceID := mustRandomHex(8)

	params := url.Values{}
	params.Set("login_version", "1")
	params.Set("auth_from", "solo")
	params.Set("login_channel", "native_ide")
	params.Set("plugin_version", "2.3.62834")
	params.Set("auth_type", "local")
	params.Set("client_id", c.clientID)
	params.Set("redirect", "0")
	params.Set("login_trace_id", traceID)
	params.Set("auth_callback_url", "http://127.0.0.1:"+CallbackPort+CallbackPath)
	params.Set("machine_id", machineID)
	params.Set("device_id", deviceID)
	params.Set("x_device_id", deviceID)
	params.Set("x_machine_id", machineID)
	params.Set("x_device_brand", "PC")
	params.Set("x_device_type", "PC")
	params.Set("x_os_version", "1.0")
	params.Set("x_app_version", IdeVersion)
	params.Set("x_app_type", "stable")

	return &LoginURL{
		URL:       AuthorizationHost + "/authorization?" + params.Encode(),
		State:     traceID,
		MachineID: machineID,
		DeviceID:  deviceID,
	}, nil
}

// ParseCallback parses a TRAE callback URL pasted by the user. It accepts the
// full URL (https://...), a bare query string, or the legacy userJwt-only shape.
func (c *Client) ParseCallback(callbackURL string) (*TokenData, error) {
	trimmed := strings.TrimSpace(callbackURL)
	if trimmed == "" {
		return nil, fmt.Errorf("trae: callback URL is required")
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse != nil {
		return nil, fmt.Errorf("trae: parse callback URL: %w", errParse)
	}
	q := parsed.Query()

	refreshToken := strings.TrimSpace(q.Get("refreshToken"))
	userInfoRaw := strings.TrimSpace(q.Get("userInfo"))
	userJwtRaw := strings.TrimSpace(q.Get("userJwt"))

	userInfo, _ := parseJSONObject(userInfoRaw)
	userJwt, _ := parseJSONObject(userJwtRaw)

	uid := strings.TrimSpace(jsonString(userInfo["UserID"]))
	nickname := strings.TrimSpace(jsonString(userInfo["ScreenName"]))
	enterpriseID := strings.TrimSpace(jsonString(userInfo["TenantID"]))

	// Fallback to the legacy userJwt shape when the new callback query fields
	// are missing (older SOLO builds return only userJwt).
	jwtToken := strings.TrimSpace(jsonString(userJwt["Token"]))
	jwtRefresh := strings.TrimSpace(jsonString(userJwt["RefreshToken"]))
	if refreshToken == "" {
		refreshToken = jwtRefresh
	}

	token := jwtToken
	expiresAt := int64(0)
	if refreshToken != "" {
		exchanged, errExchange := c.ExchangeToken(context.Background(), refreshToken)
		if errExchange != nil {
			return nil, errExchange
		}
		token = exchanged.AccessToken
		if exchanged.RefreshToken != "" {
			refreshToken = exchanged.RefreshToken
		}
		expiresAt = exchanged.ExpiresAt
	} else if token == "" {
		return nil, fmt.Errorf("trae: callback URL missing refreshToken and userJwt token")
	}

	if token == "" {
		return nil, fmt.Errorf("trae: callback URL yielded no access token")
	}

	// Best-effort user info lookup; fall back to callback userInfo when the
	// GetUserInfo endpoint is unreachable (the token may already be valid).
	if uid == "" || nickname == "" {
		if infoUID, infoNickname, infoEnterprise, errUser := c.GetUserInfo(context.Background(), token); errUser == nil {
			if uid == "" {
				uid = infoUID
			}
			if nickname == "" {
				nickname = infoNickname
			}
			if enterpriseID == "" {
				enterpriseID = infoEnterprise
			}
		} else {
			log.Warnf("trae: GetUserInfo failed (using callback userInfo): %v", errUser)
		}
	}
	if uid == "" {
		return nil, fmt.Errorf("trae: could not determine account uid")
	}

	return &TokenData{
		AccessToken:  token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		UID:          uid,
		Nickname:     nickname,
		EnterpriseID: enterpriseID,
		APIHost:      c.apiHost,
	}, nil
}

// ExchangeToken swaps a refresh token for a fresh access token. The upstream
// rotates the refresh token on success.
func (c *Client) ExchangeToken(ctx context.Context, refreshToken string) (*TokenData, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("trae: refresh token is required")
	}
	body, _ := json.Marshal(map[string]any{
		"ClientID":     c.clientID,
		"RefreshToken": refreshToken,
		"ClientSecret": "-",
		"UserID":       "",
	})
	raw, errDo := c.postJSON(ctx, c.apiHost+"/cloudide/api/v3/trae/oauth/ExchangeToken", body)
	if errDo != nil {
		return nil, errDo
	}
	var envelope struct {
		Result struct {
			Token               string `json:"Token"`
			RefreshToken        string `json:"RefreshToken"`
			TokenExpireAt       int64  `json:"TokenExpireAt"`
			TokenExpireDuration int64  `json:"TokenExpireDuration"`
		} `json:"Result"`
	}
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		return nil, fmt.Errorf("trae: parse exchange response: %w", errUnmarshal)
	}
	if strings.TrimSpace(envelope.Result.Token) == "" {
		return nil, fmt.Errorf("trae: exchange returned no token")
	}
	expiresAt := envelope.Result.TokenExpireAt
	if expiresAt > 1e12 {
		expiresAt /= 1000
	}
	if expiresAt <= 0 && envelope.Result.TokenExpireDuration > 0 {
		expiresAt = time.Now().Add(time.Duration(envelope.Result.TokenExpireDuration) * time.Second).Unix()
	}
	out := &TokenData{
		AccessToken:  envelope.Result.Token,
		RefreshToken: envelope.Result.RefreshToken,
		ExpiresAt:    expiresAt,
	}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	return out, nil
}

// GetUserInfo resolves account identity for a token.
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (uid, nickname, enterpriseID string, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	body, _ := json.Marshal(map[string]any{"ReqSource": "IDE", "IDEVersion": IdeVersion})
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.apiHost+"/cloudide/api/v3/trae/GetUserInfo", bytes.NewReader(body))
	if errRequest != nil {
		return "", "", "", errRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Trae/"+IdeVersion)
	req.Header.Set("X-Cloudide-Token", accessToken)
	resp, errDo := c.httpClient.Do(req)
	if errDo != nil {
		return "", "", "", fmt.Errorf("trae: get user info: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("trae: close userinfo body: %v", errClose)
		}
	}()
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return "", "", "", errRead
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("trae: get user info HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var envelope struct {
		Result struct {
			UserID       string `json:"UserID"`
			ScreenName   string `json:"ScreenName"`
			EnterpriseID string `json:"EnterpriseID"`
		} `json:"Result"`
	}
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		return "", "", "", fmt.Errorf("trae: parse userinfo response: %w", errUnmarshal)
	}
	return strings.TrimSpace(envelope.Result.UserID), strings.TrimSpace(envelope.Result.ScreenName), strings.TrimSpace(envelope.Result.EnterpriseID), nil
}

// postJSON sends a JSON POST and returns the response body for 2xx responses.
func (c *Client) postJSON(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if errRequest != nil {
		return nil, errRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Trae/"+IdeVersion)
	resp, errDo := c.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("trae: post %s: %w", endpoint, errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("trae: close exchange body: %v", errClose)
		}
	}()
	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return nil, errRead
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trae: post %s HTTP %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func randomHex(bytesCount int) (string, error) {
	buf := make([]byte, bytesCount)
	if _, errRead := rand.Read(buf); errRead != nil {
		return "", errRead
	}
	return hex.EncodeToString(buf), nil
}

func mustRandomHex(bytesCount int) string {
	value, err := randomHex(bytesCount)
	if err != nil {
		// crypto/rand failure is unrecoverable for login URL generation.
		panic(err)
	}
	return value
}

func parseJSONObject(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func jsonString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}
