package qodercn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestPKCEAlphabetIsSixtySix pins the verifier alphabet to the exact 66-character
// set used by the official clients. Reducing bytes modulo 64 instead of 66 would
// change the distribution, so this guards against a well-meaning "fix".
func TestPKCEAlphabetIsSixtySix(t *testing.T) {
	if got := len(pkceAlphabet); got != 66 {
		t.Fatalf("pkceAlphabet length = %d, want 66", got)
	}
	if pkceAlphabet != "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" {
		t.Fatalf("pkceAlphabet = %q", pkceAlphabet)
	}
}

// TestChallengeMatchesCapturedPair replays the verifier/challenge pair captured
// from the real Qoder CN desktop client and asserts the S256 derivation.
func TestChallengeMatchesCapturedPair(t *testing.T) {
	const (
		verifier  = "OA4fbkVnTZvG4PbGv3gGzXfWuXy0UwtyspDcl4UBq1sY1X9~VSuxWBXPMPVFZLoI"
		challenge = "j63LEi9alCrvCQ5uxUmC3qy66sbZq-7PHr-LWlqK8tU"
	)
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != challenge {
		t.Fatalf("challenge = %q, want %q", got, challenge)
	}
	// And the same derivation must flow through the client's own helper.
	generated, derived, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}
	if len(generated) != desktopVerifierLength {
		t.Fatalf("verifier length = %d, want %d", len(generated), desktopVerifierLength)
	}
	for _, r := range generated {
		if !strings.ContainsRune(pkceAlphabet, r) {
			t.Fatalf("verifier %q contains character %q outside the alphabet", generated, r)
		}
	}
	sum2 := sha256.Sum256([]byte(generated))
	if want := base64.RawURLEncoding.EncodeToString(sum2[:]); derived != want {
		t.Fatalf("derived challenge = %q, want %q", derived, want)
	}
}

// TestStartDeviceFlowBuildsWrappedAuthorizeURL verifies the authorize URL shape
// observed from the official client: the device URL is wrapped in /users/sign-in
// with biz_variant and oauth_callback.
func TestStartDeviceFlowBuildsWrappedAuthorizeURL(t *testing.T) {
	client := NewClientWithOptions(nil, Options{AuthBaseURL: "https://qoder.cn"})
	device, err := client.StartDeviceFlow(context.Background(), "")
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if !strings.HasPrefix(device.AuthURL, "https://qoder.cn/users/sign-in?") {
		t.Fatalf("auth URL = %q, want the sign-in wrapper", device.AuthURL)
	}
	if !strings.Contains(device.AuthURL, "biz_variant=qoder") {
		t.Fatalf("auth URL missing biz_variant: %q", device.AuthURL)
	}
	if !strings.Contains(device.AuthURL, "oauth_callback=") {
		t.Fatalf("auth URL missing oauth_callback: %q", device.AuthURL)
	}
	// The callback must itself carry the PKCE parameters. Parse the outer URL so
	// net/url performs the percent-decoding, then inspect the callback URL.
	outer, err := url.Parse(device.AuthURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	callback := outer.Query().Get("oauth_callback")
	if callback == "" {
		t.Fatalf("oauth_callback missing from %q", device.AuthURL)
	}
	inner, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("parse oauth_callback %q: %v", callback, err)
	}
	innerQuery := inner.Query()
	for key, want := range map[string]string{
		"challenge":        device.Challenge,
		"challenge_method": "S256",
		"nonce":            device.Nonce,
		"client_id":        ClientID,
	} {
		if got := innerQuery.Get(key); got != want {
			t.Fatalf("callback %s = %q, want %q", key, got, want)
		}
	}
	if innerQuery.Get("machine_id") == "" {
		t.Fatalf("callback missing machine_id: %q", callback)
	}
	if inner.Path != "/device/selectAccounts" {
		t.Fatalf("callback path = %q, want /device/selectAccounts", inner.Path)
	}
	// A generated machine ID must be a plain UUID, not the umid machine token.
	if len(device.MachineID) != 36 {
		t.Fatalf("machine id = %q, want a UUID", device.MachineID)
	}
}

// TestPollTreats404AsPending reproduces the documented pending semantics: the
// gateway answers 404 until the browser approves the nonce.
func TestPollTreats404AsPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/deviceToken/poll" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("verifier") == "" || query.Get("nonce") == "" || query.Get("challenge_method") != "S256" {
			t.Errorf("poll query incomplete: %v", query)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"pending"}`))
	}))
	defer server.Close()

	client := NewClientWithOptions(nil, Options{OpenAPIBaseURL: server.URL})
	token, pending, err := client.poll(context.Background(), &DeviceCode{Nonce: "n", Verifier: "v"})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if token != nil {
		t.Fatalf("token = %+v, want nil", token)
	}
	if !pending {
		t.Fatal("pending = false, want true for HTTP 404")
	}
}

// TestPollParsesFlatDeviceTokenShape verifies the captured success payload shape.
func TestPollParsesFlatDeviceTokenShape(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":         "access-token",
			"refresh_token": "refresh-token",
			"expires_at":    expiry,
		})
	}))
	defer server.Close()

	client := NewClientWithOptions(nil, Options{OpenAPIBaseURL: server.URL})
	token, pending, err := client.poll(context.Background(), &DeviceCode{Nonce: "n", Verifier: "v"})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if pending {
		t.Fatal("pending = true, want false")
	}
	if token.AccessToken != "access-token" || token.RefreshToken != "refresh-token" {
		t.Fatalf("token = %+v", token)
	}
	if token.TokenType != "Bearer" {
		t.Fatalf("token type = %q, want Bearer", token.TokenType)
	}
	if token.ExpiresAt.IsZero() {
		t.Fatal("expiry was not parsed from expires_at")
	}
}

// TestRefreshSendsBearerlessJSONBody checks the refresh request contract.
func TestRefreshSendsBearerlessJSONBody(t *testing.T) {
	var gotBody map[string]string
	var gotUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/deviceToken/refresh" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		gotUA = r.Header.Get("User-Agent")
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer server.Close()

	client := NewClientWithOptions(nil, Options{OpenAPIBaseURL: server.URL})
	token, err := client.Refresh(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if gotBody["refresh_token"] != "old-refresh" {
		t.Fatalf("refresh body = %v", gotBody)
	}
	if gotUA != UserAgent {
		t.Fatalf("user-agent = %q, want %q", gotUA, UserAgent)
	}
	if token.AccessToken != "new-access" || token.ExpiresIn != 3600 {
		t.Fatalf("token = %+v", token)
	}
}

// TestParseTokenResponseRejectsErrorCode ensures a non-zero code is surfaced
// rather than silently treated as a token.
func TestParseTokenResponseRejectsErrorCode(t *testing.T) {
	if _, err := parseTokenResponse([]byte(`{"code":101,"message":"Signature invalid"}`)); err == nil {
		t.Fatal("expected an error for a non-zero code")
	}
	if _, err := parseTokenResponse([]byte(`not-json`)); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func decodeQueryValue(value string) (string, error) {
	// The value is percent-encoded twice (once for the callback, once for the
	// outer query), so unescape until stable.
	decoded := value
	for i := 0; i < 2; i++ {
		next, err := url.QueryUnescape(decoded)
		if err != nil {
			return "", err
		}
		if next == decoded {
			break
		}
		decoded = next
	}
	return decoded, nil
}
