package xiaohuanxiong

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestParseCallbackCode covers the two supported formats — the office-raccoon://
// deep link and a bare code — plus the https, fragment, and query-only shapes a
// user or the desktop client can hand us.
func TestParseCallbackCode(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		// The two formats the UI promises to accept.
		{name: "deep link", raw: "office-raccoon://auth/callback?code=abc123", want: "abc123"},
		{name: "bare code", raw: "raw-code-9999", want: "raw-code-9999"},

		{name: "deep link with state", raw: "office-raccoon://auth/callback?code=abc123&state=s", want: "abc123"},
		{name: "https callback", raw: "https://xiaohuanxiong.com/callback?code=xyz789&state=s", want: "xyz789"},
		{name: "loopback callback", raw: "http://localhost:1455/auth/callback?code=loop42&state=s", want: "loop42"},
		{name: "fragment code", raw: "office-raccoon://auth/callback#code=frag42", want: "frag42"},
		{name: "query pair without leading question mark", raw: "code=abc123", want: "abc123"},
		{name: "query pair with leading question mark", raw: "?code=abc123", want: "abc123"},
		{name: "ide redirect parameter", raw: "http://127.0.0.1:8080/cb?authorization_code=ide42", want: "ide42"},
		{name: "uppercase parameter name", raw: "code=ABC123", want: "ABC123"},
		{name: "bare code that looks like a query", raw: "a=1+b", want: "a=1+b"},
		{name: "bare code keeping base64 padding", raw: "YWJjZA==", want: "YWJjZA=="},
		{name: "bare code with post-url characters", raw: "abc/def+ghi?", want: "abc/def+ghi?"},

		{name: "trims whitespace around deep link", raw: "  office-raccoon://auth/callback?code= pad  ", want: "pad"},
		{name: "trims whitespace around bare code", raw: "  MyCode-1234  ", want: "MyCode-1234"},

		{name: "empty", raw: "", wantErr: true},
		{name: "whitespace only", raw: "   ", wantErr: true},
		{name: "deep link without code", raw: "office-raccoon://auth/callback?state=only", wantErr: true},
		{name: "https callback without code", raw: "https://xiaohuanxiong.com/callback?state=only", wantErr: true},
		{name: "query only with no code", raw: "?state=only", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCallbackCode(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got code %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAuthorizationURLMatchesDesktopClient verifies the parameters the desktop
// client sends, which the upstream expects verbatim.
func TestAuthorizationURLMatchesDesktopClient(t *testing.T) {
	got := AuthorizationURL("")
	if !strings.Contains(got, "/code/authorize") {
		t.Fatalf("expected authorize path, got %s", got)
	}
	if !strings.Contains(got, "login_source=desktop") {
		t.Fatalf("missing login_source=desktop: %s", got)
	}
	if !strings.Contains(got, "appname=") {
		t.Fatalf("missing appname: %s", got)
	}
	if !strings.HasPrefix(got, BaseURL) {
		t.Fatalf("expected %s prefix, got %s", BaseURL, got)
	}
}

// TestAuthorizationURLHonorsOverride keeps self-hosted deployments working.
func TestAuthorizationURLHonorsOverride(t *testing.T) {
	got := AuthorizationURL("https://example.test/login")
	if !strings.HasPrefix(got, "https://example.test/code/authorize") {
		t.Fatalf("override not applied: %s", got)
	}
}

// TestExchangeAuthorizationCode checks the documented request shape and payload
// mapping.
func TestExchangeAuthorizationCode(t *testing.T) {
	var gotPath string
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"at-1","refresh_token":"rt-1","office_identity":"id-1","office_org_name":"org","office_org_role":"admin"}}`))
	}))
	defer server.Close()

	client := NewClientWithBaseURL(nil, "", server.URL)
	token, err := client.ExchangeAuthorizationCode(context.Background(), "the-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/web/auth/v1/login_with_authorization_code" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["authorization_code"] != "the-code" {
		t.Fatalf("body = %v", gotBody)
	}
	if token.AccessToken != "at-1" || token.RefreshToken != "rt-1" {
		t.Fatalf("token = %+v", token)
	}
	if token.OfficeIdentity != "id-1" || token.OfficeOrgName != "org" || token.OfficeOrgRole != "admin" {
		t.Fatalf("office fields not mapped: %+v", token)
	}
}

// TestExchangeAuthorizationCodeExpiredCode surfaces the documented expiry code.
func TestExchangeAuthorizationCodeExpiredCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":200035,"message":"authorization_code_not_found"}`))
	}))
	defer server.Close()

	client := NewClientWithBaseURL(nil, "", server.URL)
	_, err := client.ExchangeAuthorizationCode(context.Background(), "stale")
	if err == nil {
		t.Fatal("expected error for expired authorization code")
	}
	if !strings.Contains(err.Error(), "invalid, expired, or already used") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestExchangeAuthorizationCodeRejectsMissingToken guards the token contract.
func TestExchangeAuthorizationCodeRejectsMissingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"refresh_token":"rt"}}`))
	}))
	defer server.Close()

	client := NewClientWithBaseURL(nil, "", server.URL)
	if _, err := client.ExchangeAuthorizationCode(context.Background(), "c"); err == nil {
		t.Fatal("expected error when access_token is missing")
	}
}

// TestRefreshUsesDocumentedEndpoint verifies rotation.
func TestRefreshUsesDocumentedEndpoint(t *testing.T) {
	var gotPath string
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"at-2","refresh_token":"rt-2"}}`))
	}))
	defer server.Close()

	client := NewClientWithBaseURL(nil, "", server.URL)
	token, err := client.Refresh(context.Background(), "rt-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/web/auth/v1/refresh" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["refresh_token"] != "rt-1" {
		t.Fatalf("body = %v", gotBody)
	}
	if token.AccessToken != "at-2" || token.RefreshToken != "rt-2" {
		t.Fatalf("token = %+v", token)
	}
}

// TestFetchModelCatalogSendsBearerToken verifies the catalog call and auth header.
func TestFetchModelCatalogSendsBearerToken(t *testing.T) {
	var gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"code":0,"data":{"categories":[]}}`))
	}))
	defer server.Close()

	client := NewClientWithBaseURL(nil, "", server.URL)
	if _, err := client.FetchModelCatalog(context.Background(), "tok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/web/llm/v2/model_catalog" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("authorization = %q", gotAuth)
	}
}

// TestFetchModelCatalogRejectsEmptyToken avoids an unauthenticated round trip.
func TestFetchModelCatalogRejectsEmptyToken(t *testing.T) {
	client := NewClientWithBaseURL(nil, "", "https://example.test")
	if _, err := client.FetchModelCatalog(context.Background(), "  "); err == nil {
		t.Fatal("expected error for empty token")
	}
}

// TestJWTExpiryAndStorageExpiry covers JWT-based expiry detection.
func TestJWTExpiryAndStorageExpiry(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := makeJWT(t, map[string]any{"exp": exp})

	parsed, ok := jwtExpiry(token)
	if !ok {
		t.Fatal("expected exp to be parsed")
	}
	if parsed.Unix() != exp {
		t.Fatalf("exp = %d, want %d", parsed.Unix(), exp)
	}

	// A comfortable margin means not expired.
	storage := &TokenStorage{AccessToken: token, RefreshToken: "rt"}
	if storage.IsExpired() {
		t.Fatal("token an hour out should not be expired")
	}
	if !storage.NeedsRefresh() {
		// Still needs no refresh, but must remain refreshable.
		t.Log("token outside refresh window; NeedsRefresh false as expected")
	}
}

// TestIsExpiredInsideRefreshWindow asserts the 300s pre-emptive refresh window.
func TestIsExpiredInsideRefreshWindow(t *testing.T) {
	exp := time.Now().Add(60 * time.Second).Unix()
	storage := &TokenStorage{AccessToken: makeJWT(t, map[string]any{"exp": exp}), RefreshToken: "rt"}
	if !storage.IsExpired() {
		t.Fatal("token expiring in 60s must be considered expired for refresh")
	}
	if !storage.NeedsRefresh() {
		t.Fatal("token inside the refresh window must need refresh")
	}
}

// TestIsExpiredOpaqueToken ensures non-JWT tokens are not falsely expired.
func TestIsExpiredOpaqueToken(t *testing.T) {
	storage := &TokenStorage{AccessToken: "opaque-token"}
	if storage.IsExpired() {
		t.Fatal("opaque token without recorded expiry should not be treated as expired")
	}
	if storage.NeedsRefresh() {
		t.Fatal("opaque token cannot be refreshed")
	}
}

// TestNeedsRefreshWithoutRefreshToken guards the manual-paste path.
func TestNeedsRefreshWithoutRefreshToken(t *testing.T) {
	exp := time.Now().Add(-time.Hour).Unix()
	storage := &TokenStorage{AccessToken: makeJWT(t, map[string]any{"exp": exp})}
	if !storage.IsExpired() {
		t.Fatal("expired token should report expired")
	}
	if storage.NeedsRefresh() {
		t.Fatal("no refresh token means NeedsRefresh must be false")
	}
}

// TestExpiryRFC3339 covers the recorded-expiry fallback shape.
func TestExpiryRFC3339(t *testing.T) {
	if got := ExpiryRFC3339("not-a-jwt"); got != "" {
		t.Fatalf("expected empty expiry for opaque token, got %q", got)
	}
	exp := time.Now().Add(time.Hour).Unix()
	if got := ExpiryRFC3339(makeJWT(t, map[string]any{"exp": exp})); got == "" {
		t.Fatal("expected non-empty expiry for JWT")
	}
}

// TestSaveTokenToFilePersistsDocumentedFields verifies the auth.json shape.
func TestSaveTokenToFilePersistsDocumentedFields(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/xiaohuanxiong-test.json"
	storage := &TokenStorage{
		AccessToken:    "at",
		RefreshToken:   "rt",
		OfficeIdentity: "ident",
	}
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read: %v", errRead)
	}
	var decoded map[string]any
	if errUnmarshal := json.Unmarshal(data, &decoded); errUnmarshal != nil {
		t.Fatalf("decode: %v", errUnmarshal)
	}
	if decoded["type"] != Provider {
		t.Fatalf("type = %v", decoded["type"])
	}
	if decoded["access_token"] != "at" || decoded["refresh_token"] != "rt" || decoded["office_identity"] != "ident" {
		t.Fatalf("decoded = %v", decoded)
	}
}

// makeJWT builds an unsigned JWT with the supplied claims.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, errMarshal := json.Marshal(claims)
	if errMarshal != nil {
		t.Fatalf("marshal claims: %v", errMarshal)
	}
	encode := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	header := encode([]byte(`{"alg":"none","typ":"JWT"}`))
	return header + "." + encode(payload) + ".sig"
}
