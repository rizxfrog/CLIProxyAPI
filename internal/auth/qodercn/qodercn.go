// Package qodercn implements the Qoder CN (qoder.cn / qoder.com.cn) browser +
// PKCE device polling authorization flow.
//
// The flow is not RFC 8628 despite using the word "device". There is no
// /device/code endpoint. Instead:
//
//  1. The client generates a PKCE verifier/challenge and a nonce, then opens
//     {authBaseUrl}/device/selectAccounts?challenge=…&challenge_method=S256
//     &nonce=…&machine_id=…&client_id=… in a browser, wrapped in the web login
//     page /users/sign-in?biz_variant=qoder&oauth_callback=… .
//  2. The client polls {openApiBaseUrl}/api/v1/deviceToken/poll?nonce=…&verifier=…
//     &challenge_method=S256 once per second. A 404 means "still pending".
//  3. On success the poll returns {token, refresh_token, …}.
//
// Verified against the Qoder CN desktop client 0.2.5 (Electron 150) and the CLI
// 1.1.55. See docs/qoder-cn-client-analysis.md.
package qodercn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

const (
	// AuthBaseURL is the Qoder CN authentication origin that serves the browser
	// account-selection page.
	AuthBaseURL = "https://qoder.cn"

	// OpenAPIBaseURL is the Qoder CN OpenAPI origin that serves the device token
	// poll, refresh, and account endpoints.
	OpenAPIBaseURL = "https://openapi.qoder.com.cn"

	// TestOpenAPIBaseURL is the test-environment OpenAPI origin.
	TestOpenAPIBaseURL = "https://test-openapi.qoder.com.cn"

	// ModelBaseURL is the Qoder model server origin hosting the OpenAI-compatible
	// /model/v1/chat/completions endpoint. This is the same host the official CN
	// CLI uses for its "http" model transport (foc[hP()]).
	ModelBaseURL = "https://api2-v2.qoder.sh"

	// ClientID is the public OAuth client identifier used by the Qoder CN CLI
	// device flow (decoded from the XOR-obfuscated bundle literal).
	ClientID = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"

	// DesktopClientID is the public client identifier used by the Qoder CN
	// desktop application (as declared in the packaged product metadata).
	DesktopClientID = "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa"

	// BizVariant is the auth business variant sent to the web login page.
	BizVariant = "qoder"

	// ClientVersion is the Qoder CN CLI version emulated for Cosy-Version and UA.
	ClientVersion = "1.1.55"

	// UserAgent is the API user agent used by the Qoder CN CLI.
	UserAgent = "qoder/" + ClientVersion

	// BrowserUserAgent is the user agent the desktop client uses for the
	// /device/selectAccounts navigation.
	BrowserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) " +
		"QoderCNApp/0.2.5 Chrome/150.0.7871.114 Electron/43.1.1 Safari/537.36"

	// pkceAlphabet is the exact verifier alphabet used by the official clients.
	// Note this is the RFC 7636 unreserved set, but at 66 characters, and the
	// bytes are reduced modulo 66 (not 64).
	pkceAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

	// pollInterval is the observed poll cadence of the official desktop client.
	pollInterval = time.Second

	// pollTimeout bounds a single device-flow authorization window.
	pollTimeout = 5 * time.Minute

	// desktopVerifierLength is the fixed verifier length of the desktop client.
	desktopVerifierLength = 64
)

var refreshGroup singleflight.Group

// DeviceCode carries the authorization URL and the PKCE material that must be
// replayed on the poll request.
type DeviceCode struct {
	// Nonce binds the browser approval to this client instance.
	Nonce string
	// Verifier is the raw PKCE verifier; it is replayed verbatim when polling.
	Verifier string
	// Challenge is base64url(sha256(Verifier)), sent to the authorize URL.
	Challenge string
	// MachineID is the caller-supplied device identifier (a plain UUID).
	MachineID string
	// AuthURL is the URL the user must open in a browser.
	AuthURL string
	// ExpiresIn is the number of seconds the authorization stays valid.
	ExpiresIn int
}

// TokenData contains the Qoder CN access and refresh tokens.
type TokenData struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	ExpiresAt    time.Time
}

// Client performs Qoder CN credential-acquisition requests.
type Client struct {
	httpClient  *http.Client
	authBase    string
	openAPIBase string
	clientID    string
	redirectURI string
}

// Options customizes the Qoder CN OAuth client endpoints.
type Options struct {
	// ProxyURL overrides the configured proxy for these requests.
	ProxyURL string
	// AuthBaseURL overrides the browser authorization origin.
	AuthBaseURL string
	// OpenAPIBaseURL overrides the OpenAPI origin used for polling.
	OpenAPIBaseURL string
	// ClientID overrides the OAuth client identifier.
	ClientID string
	// RedirectURI optionally adds a redirect_uri to the authorize request.
	RedirectURI string
}

// NewClient creates a Qoder CN OAuth client using defaults from cfg.
func NewClient(cfg *config.Config) *Client {
	return NewClientWithOptions(cfg, Options{})
}

// NewClientWithProxyURL creates a client with a per-auth proxy override.
func NewClientWithProxyURL(cfg *config.Config, proxyURL string) *Client {
	return NewClientWithOptions(cfg, Options{ProxyURL: proxyURL})
}

// NewClientWithOptions creates a Qoder CN OAuth client.
func NewClientWithOptions(cfg *config.Config, opts Options) *Client {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
	}
	if proxyURL := strings.TrimSpace(opts.ProxyURL); proxyURL != "" {
		sdkCfg.ProxyURL = proxyURL
	}
	httpClient = util.SetProxy(&sdkCfg, httpClient)

	authBase := strings.TrimSpace(opts.AuthBaseURL)
	if authBase == "" {
		authBase = AuthBaseURL
	}
	openAPIBase := strings.TrimSpace(opts.OpenAPIBaseURL)
	if openAPIBase == "" {
		openAPIBase = OpenAPIBaseURL
	}
	clientID := strings.TrimSpace(opts.ClientID)
	if clientID == "" {
		clientID = ClientID
	}
	return &Client{
		httpClient:  httpClient,
		authBase:    strings.TrimRight(authBase, "/"),
		openAPIBase: strings.TrimRight(openAPIBase, "/"),
		clientID:    clientID,
		redirectURI: strings.TrimSpace(opts.RedirectURI),
	}
}

// StartDeviceFlow builds the browser authorization URL and its PKCE material.
//
// machineID may be empty, in which case a random UUID is generated. The official
// clients use a plain UUID here (not the signed umid machine token).
func (c *Client) StartDeviceFlow(ctx context.Context, machineID string) (*DeviceCode, error) {
	if c == nil {
		return nil, fmt.Errorf("qoder-cn: client is nil")
	}
	_ = ctx

	machineID = strings.TrimSpace(machineID)
	if machineID == "" {
		machineID = uuid.NewString()
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, err
	}
	nonce := uuid.NewString()

	authURL, err := c.buildAuthURL(challenge, nonce, machineID)
	if err != nil {
		return nil, err
	}
	return &DeviceCode{
		Nonce:     nonce,
		Verifier:  verifier,
		Challenge: challenge,
		MachineID: machineID,
		AuthURL:   authURL,
		ExpiresIn: int(pollTimeout / time.Second),
	}, nil
}

// buildAuthURL constructs the /device/selectAccounts URL, wrapped in the web
// sign-in page unless direct device flow is requested.
func (c *Client) buildAuthURL(challenge, nonce, machineID string) (string, error) {
	selectAccounts, err := url.Parse(c.authBase + "/device/selectAccounts")
	if err != nil {
		return "", fmt.Errorf("qoder-cn: parse selectAccounts URL: %w", err)
	}
	query := selectAccounts.Query()
	query.Set("challenge", challenge)
	query.Set("challenge_method", "S256")
	query.Set("nonce", nonce)
	query.Set("machine_id", machineID)
	query.Set("client_id", c.clientID)
	if c.redirectURI != "" {
		query.Set("redirect_uri", c.redirectURI)
	}
	selectAccounts.RawQuery = query.Encode()

	// The official client wraps the device URL in the web sign-in page so the
	// browser lands on the interactive login first. Direct device flow (used by
	// the test harness and headless clients) skips the wrapper.
	signIn, err := url.Parse(c.authBase + "/users/sign-in")
	if err != nil {
		return "", fmt.Errorf("qoder-cn: parse sign-in URL: %w", err)
	}
	signInQuery := signIn.Query()
	signInQuery.Set("biz_variant", BizVariant)
	signInQuery.Set("oauth_callback", selectAccounts.String())
	signIn.RawQuery = signInQuery.Encode()
	return signIn.String(), nil
}

// WaitForAuthorization polls the token endpoint until the browser login completes.
func (c *Client) WaitForAuthorization(ctx context.Context, device *DeviceCode) (*TokenData, error) {
	if c == nil {
		return nil, fmt.Errorf("qoder-cn: client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if device == nil || strings.TrimSpace(device.Nonce) == "" || strings.TrimSpace(device.Verifier) == "" {
		return nil, fmt.Errorf("qoder-cn: nonce and verifier are required")
	}

	deadline := time.Now().Add(pollTimeout)
	if device.ExpiresIn > 0 {
		deadline = time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("qoder-cn: authorization cancelled: %w", ctx.Err())
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("qoder-cn: authorization expired")
			}
			token, pending, err := c.poll(ctx, device)
			if err != nil {
				return nil, err
			}
			if !pending {
				return token, nil
			}
		}
	}
}

// poll performs a single device token poll. It returns pending=true when the
// browser has not authorized yet (HTTP 404 or an empty token).
func (c *Client) poll(ctx context.Context, device *DeviceCode) (*TokenData, bool, error) {
	endpoint, err := url.Parse(c.openAPIBase + "/api/v1/deviceToken/poll")
	if err != nil {
		return nil, false, fmt.Errorf("qoder-cn: parse poll URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("nonce", device.Nonce)
	query.Set("verifier", device.Verifier)
	query.Set("challenge_method", "S256")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("qoder-cn: create poll request: %w", err)
	}
	applyHeaders(req, false)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("qoder-cn: poll request failed: %w", err)
	}
	defer closeBody("poll", resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("qoder-cn: read poll response: %w", err)
	}

	// The server answers 404 while the browser has not yet approved the nonce.
	if resp.StatusCode == http.StatusNotFound {
		return nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("qoder-cn: poll failed with status %d: %s", resp.StatusCode, truncate(string(body)))
	}

	token, err := parseTokenResponse(body)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, true, nil
	}
	return token, false, nil
}

// Refresh exchanges a refresh token for a new token pair.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenData, error) {
	if c == nil {
		return nil, fmt.Errorf("qoder-cn: client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("qoder-cn: refresh token is required")
	}
	result, err, _ := refreshGroup.Do(refreshToken, func() (any, error) {
		return c.refresh(context.WithoutCancel(ctx), refreshToken)
	})
	if err != nil {
		return nil, err
	}
	token, ok := result.(*TokenData)
	if !ok || token == nil {
		return nil, fmt.Errorf("qoder-cn: invalid refresh result")
	}
	return token, nil
}

func (c *Client) refresh(ctx context.Context, refreshToken string) (*TokenData, error) {
	payload, err := json.Marshal(map[string]string{"refresh_token": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: encode refresh request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.openAPIBase+"/api/v1/deviceToken/refresh", strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: create refresh request: %w", err)
	}
	applyHeaders(req, true)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: refresh request failed: %w", err)
	}
	defer closeBody("refresh", resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: read refresh response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("qoder-cn: refresh rejected (%d): %s", resp.StatusCode, truncate(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("qoder-cn: refresh failed with status %d: %s", resp.StatusCode, truncate(string(body)))
	}
	return parseTokenResponse(body)
}

// parseTokenResponse accepts both the flat device-token shape and the wrapped
// {code,data} shape so it tolerates gateway variations.
func parseTokenResponse(body []byte) (*TokenData, error) {
	var flat struct {
		Token        string `json:"token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		ExpireTime   string `json:"expire_time"`
		ExpiresAt    string `json:"expires_at"`
		Code         *int   `json:"code"`
		Message      string `json:"message"`
		Msg          string `json:"msg"`
	}
	if err := json.Unmarshal(body, &flat); err != nil {
		return nil, fmt.Errorf("qoder-cn: parse token response: %w", err)
	}

	// A non-zero code indicates a rejection rather than a successful poll.
	if flat.Code != nil && *flat.Code != 0 {
		return nil, fmt.Errorf("qoder-cn: token response rejected (code %d): %s",
			*flat.Code, firstNonEmpty(flat.Message, flat.Msg))
	}

	accessToken := strings.TrimSpace(flat.Token)
	if accessToken == "" {
		accessToken = strings.TrimSpace(flat.AccessToken)
	}
	tokenType := strings.TrimSpace(flat.TokenType)
	if tokenType == "" {
		tokenType = "Bearer"
	}
	token := &TokenData{
		AccessToken:  accessToken,
		RefreshToken: strings.TrimSpace(flat.RefreshToken),
		TokenType:    tokenType,
		ExpiresIn:    flat.ExpiresIn,
	}
	if token.ExpiresAt.IsZero() {
		if expiry := parseExpiry(firstNonEmpty(flat.ExpiresAt, flat.ExpireTime)); !expiry.IsZero() {
			token.ExpiresAt = expiry
			if token.ExpiresIn <= 0 {
				token.ExpiresIn = int(time.Until(expiry).Seconds())
			}
		} else if token.ExpiresIn > 0 {
			token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
		}
	}
	return token, nil
}

func parseExpiry(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

// generatePKCE produces a verifier and its S256 challenge using the exact
// alphabet and length distribution of the official Qoder CN clients.
func generatePKCE() (verifier, challenge string, err error) {
	verifier, err = generateVerifier()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// generateVerifier mirrors the desktop client: a fixed 64-character string drawn
// from the 66-character alphabet with each byte reduced modulo the alphabet
// length.
func generateVerifier() (string, error) {
	raw := make([]byte, desktopVerifierLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("qoder-cn: generate PKCE verifier: %w", err)
	}
	var builder strings.Builder
	builder.Grow(desktopVerifierLength)
	for _, b := range raw {
		builder.WriteByte(pkceAlphabet[int(b)%len(pkceAlphabet)])
	}
	return builder.String(), nil
}

// applyHeaders sets the headers the official CN clients send. write indicates a
// request that carries a JSON body.
func applyHeaders(req *http.Request, write bool) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Cosy-Version", ClientVersion)
	if write {
		req.Header.Set("Content-Type", "application/json")
	}
}

func closeBody(operation string, body io.Closer) {
	if err := body.Close(); err != nil {
		log.Errorf("qoder-cn %s: close response body: %v", operation, err)
	}
}

func truncate(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 512 {
		return value
	}
	return value[:512] + "…"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// ErrAuthRejected indicates the service rejected the stored credentials.
var ErrAuthRejected = errors.New("qoder-cn: credentials rejected")

// IsAuthRejected reports whether err represents an authentication failure.
func IsAuthRejected(err error) bool {
	return errors.Is(err, ErrAuthRejected)
}
