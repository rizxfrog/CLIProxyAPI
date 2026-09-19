package qodercn

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveQuotaUsage exercises the real OpenAPI origin with the credential from
// QODERCN_LIVE_AUTH_FILE (a data/auth_files/*.json path). It is skipped unless
// that variable is set, so the default suite stays offline.
//
// Unlike the model catalog, the quota reads are plain bearer-token GETs and are
// therefore reachable with an operator's stored credential. Run with:
//
//	QODERCN_LIVE_AUTH_FILE=data/auth_files/qoder-cn-*.json \
//	  go test ./internal/auth/qodercn/ -run TestLiveQuotaUsage -v
func TestLiveQuotaUsage(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("QODERCN_LIVE_AUTH_FILE"))
	if path == "" {
		t.Skip("set QODERCN_LIVE_AUTH_FILE to a data/auth_files/*.json path to run this live test")
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read auth file: %v", errRead)
	}
	var cred struct {
		AccessToken string `json:"access_token"`
		BaseURL     string `json:"base_url"`
	}
	if errUnmarshal := json.Unmarshal(raw, &cred); errUnmarshal != nil {
		t.Fatalf("parse auth file: %v", errUnmarshal)
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		t.Fatal("auth file has no access_token")
	}

	client := NewClientWithOptions(nil, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	usage, errUsage := client.FetchQuotaUsage(ctx, cred.AccessToken)
	if errUsage != nil {
		t.Fatalf("FetchQuotaUsage: %v", errUsage)
	}
	// Log the observable shape, never the token.
	t.Logf("usage: type=%q unit=%q total=%.4f used=%.4f remaining=%.4f exceeded=%v expiresAt(raw)=%d",
		usage.UsageType, usage.UserQuota.Unit, usage.UserQuota.Total,
		usage.UserQuota.Used, usage.UserQuota.Remaining, usage.IsQuotaExceeded, usage.ExpiresAt)
	if strings.TrimSpace(usage.UserQuota.Unit) == "" {
		t.Error("ledger carried no unit")
	}
	// expiresAt is a "never" sentinel on the Free tier and must normalize away.
	if reset := NormalizeResetAt(usage.ExpiresAt); reset != 0 && usage.ExpiresAt != reset {
		t.Errorf("sentinel expiry %d normalized to %d, want 0", usage.ExpiresAt, reset)
	}

	status, errStatus := client.FetchAccountStatus(ctx, cred.AccessToken)
	if errStatus != nil {
		t.Fatalf("FetchAccountStatus: %v", errStatus)
	}
	t.Logf("status: plan=%q tag=%q nextResetAt=%d", status.Plan, status.UserTag, status.NextResetAt)
	if strings.TrimSpace(status.Plan) == "" {
		t.Error("account status carried no plan tier")
	}
	if reset := NormalizeResetAt(status.NextResetAt); reset != 0 {
		t.Logf("next reset: %s", time.UnixMilli(reset).UTC().Format(time.RFC3339))
	}
}

// TestLiveQuotaUsageRejectsBogusToken pins the rejection envelope the management
// handler maps to a 401, so a future gateway change fails here rather than in
// production diagnostics.
func TestLiveQuotaUsageRejectsBogusToken(t *testing.T) {
	if strings.TrimSpace(os.Getenv("QODERCN_LIVE_AUTH_FILE")) == "" {
		t.Skip("set QODERCN_LIVE_AUTH_FILE to run live OpenAPI tests")
	}
	client := NewClientWithOptions(nil, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, errUsage := client.FetchQuotaUsage(ctx, "dt-definitely-not-a-real-token")
	if errUsage == nil {
		t.Fatal("expected a rejection for a bogus token")
	}
	if !IsAuthError(errUsage) {
		t.Fatalf("bogus token should surface as an auth error, got %v", errUsage)
	}
	var apiErr *Error
	if !errors.As(errUsage, &apiErr) {
		t.Fatalf("error is not *Error: %T", errUsage)
	}
	t.Logf("rejection: status=%d code=%q message=%q", apiErr.StatusCode, apiErr.Code, apiErr.Message)
}
