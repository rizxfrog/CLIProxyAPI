package helps

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// DeepSeek web client's HIF (Human Interaction Fingerprint / client attestation)
// tokens. The web client does NOT compute these locally — it polls DeepSeek's own
// hif-* endpoints and forwards the returned value verbatim in request headers.
//
// Endpoints (from the minified frontend, variable names de-obfuscated):
//
//	leim → https://hif-leim.deepseek.com/query → x-hif-leim
//	dliq → https://hif-dliq.deepseek.com/query → x-hif-dliq
//
// The /query endpoint requires no auth (the frontend calls it withToken:false),
// returns {"data":{"biz_data":{"value":"..."}}} and a "x-hif-ttl" header (seconds,
// default 600) controlling how long the value is cached.
const (
	deepSeekWebHifLeimURL = "https://hif-leim.deepseek.com/query"
	deepSeekWebHifDliqURL = "https://hif-dliq.deepseek.com/query"

	deepSeekWebHifDefaultTTL = 600 * time.Second
)

// DeepSeekWebHifClient caches the HIF tokens and lazily refreshes them when they
// expire. It is safe for concurrent use: a single in-flight refresh is shared
// across callers (singleflight), and a failed refresh keeps the last known value
// (or none) while a short retry window elapses.
type DeepSeekWebHifClient struct {
	cfg *config.Config

	// leimURL/dliqURL default to the DeepSeek production endpoints; tests override
	// them with httptest server URLs.
	leimURL string
	dliqURL string

	mu         sync.Mutex
	leim       string
	dliq       string
	expiresAt  time.Time
	refreshing bool
	refreshErr error
	// lastAttempt bounds retry frequency on failure.
	lastAttempt time.Time
}

// NewDeepSeekWebHifClient constructs a HIF client bound to the given config.
func NewDeepSeekWebHifClient(cfg *config.Config) *DeepSeekWebHifClient {
	return &DeepSeekWebHifClient{
		cfg:     cfg,
		leimURL: deepSeekWebHifLeimURL,
		dliqURL: deepSeekWebHifDliqURL,
	}
}

// LeimHeader returns the value for the x-hif-leim header, refreshing the token if
// it has expired or has not been fetched yet. An empty string means "no token
// available" — callers should omit the header, matching the web client's
// degrade-on-miss behavior.
func (c *DeepSeekWebHifClient) LeimHeader(ctx context.Context, auth *cliproxyauth.Auth) string {
	c.ensureFresh(ctx, auth)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leim
}

// DliqHeader returns the value for the x-hif-dliq header (same semantics as LeimHeader).
func (c *DeepSeekWebHifClient) DliqHeader(ctx context.Context, auth *cliproxyauth.Auth) string {
	c.ensureFresh(ctx, auth)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dliq
}

func (c *DeepSeekWebHifClient) ensureFresh(ctx context.Context, auth *cliproxyauth.Auth) {
	c.mu.Lock()
	if time.Now().Before(c.expiresAt) {
		c.mu.Unlock()
		return
	}
	// Bound retry frequency only after a FAILURE: a failed refresh must not hammer
	// the endpoint, so enforce a short cooldown. A successful (or first) refresh
	// proceeds immediately once the TTL lapses.
	if c.refreshing || (c.refreshErr != nil && time.Since(c.lastAttempt) < 5*time.Second) {
		c.mu.Unlock()
		return
	}
	c.refreshing = true
	c.lastAttempt = time.Now()
	c.mu.Unlock()

	leim, errLeim := deepSeekWebFetchHif(ctx, c.cfg, auth, c.leimURL)
	dliq, errDliq := deepSeekWebFetchHif(ctx, c.cfg, auth, c.dliqURL)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshing = false
	now := time.Now()
	if errLeim == nil && errDliq == nil {
		c.leim = leim.value
		c.dliq = dliq.value
		ttl := leim.ttl
		if dliq.ttl < ttl {
			ttl = dliq.ttl
		}
		c.expiresAt = now.Add(ttl)
		c.refreshErr = nil
		return
	}
	// Partial success: keep whichever side succeeded, remember the error, and let
	// the retry window above govern the next attempt.
	if errLeim == nil {
		c.leim = leim.value
	}
	if errDliq == nil {
		c.dliq = dliq.value
	}
	if errLeim != nil {
		c.refreshErr = errLeim
	} else {
		c.refreshErr = errDliq
	}
}

type deepSeekWebHifValue struct {
	value string
	ttl   time.Duration
}

func deepSeekWebFetchHif(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, url string) (deepSeekWebHifValue, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return deepSeekWebHifValue{}, err
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
	request.Header.Set("Referer", "https://chat.deepseek.com/")

	client := NewProxyAwareHTTPClient(ctx, cfg, auth, 10*time.Second)
	response, err := client.Do(request)
	if err != nil {
		return deepSeekWebHifValue{}, err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return deepSeekWebHifValue{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return deepSeekWebHifValue{}, &deepSeekWebHifStatusError{status: response.StatusCode, body: string(body)}
	}
	if code := gjson.GetBytes(body, "code").Int(); code != 0 {
		return deepSeekWebHifValue{}, &deepSeekWebHifStatusError{status: http.StatusBadGateway, body: string(body)}
	}
	value := strings.TrimSpace(gjson.GetBytes(body, "data.biz_data.value").String())
	if value == "" {
		return deepSeekWebHifValue{}, &deepSeekWebHifStatusError{status: http.StatusBadGateway, body: "missing biz_data.value"}
	}
	ttl := deepSeekWebHifDefaultTTL
	if raw := strings.TrimSpace(response.Header.Get("x-hif-ttl")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			ttl = time.Duration(seconds) * time.Second
		}
	}
	return deepSeekWebHifValue{value: value, ttl: ttl}, nil
}

type deepSeekWebHifStatusError struct {
	status int
	body   string
}

func (e *deepSeekWebHifStatusError) Error() string {
	return "deepseek-web hif request failed: status " + strconv.Itoa(e.status) + ": " + e.body
}
