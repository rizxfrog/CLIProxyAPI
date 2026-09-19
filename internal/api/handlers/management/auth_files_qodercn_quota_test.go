package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	qodercnauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// registerQoderCNAuth builds a manager carrying one Qoder CN credential.
// When expiresInPast is false the token is treated as fresh, so the quota
// handler never attempts a refresh.
func registerQoderCNAuth(t *testing.T, accessToken string) (*coreauth.Manager, *coreauth.Auth) {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "qoder-cn:oauth:test",
		Provider: constant.QoderCN,
		Metadata: map[string]any{
			"type":          constant.QoderCN,
			"auth_kind":     coreauth.AuthKindOAuth,
			"access_token":  accessToken,
			"refresh_token": "drt-test",
			"expired":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register qoder-cn auth: %v", errRegister)
	}
	return manager, auth
}

// withQoderCNTestOpenAPIBase points the quota handler's OpenAPI origin at a stub
// server for the duration of one test.
func withQoderCNTestOpenAPIBase(t *testing.T, baseURL string) func() {
	t.Helper()
	previous := qoderCNQuotaOpenAPIBase
	qoderCNQuotaOpenAPIBase = baseURL
	return func() { qoderCNQuotaOpenAPIBase = previous }
}

// newQoderCNQuotaServer serves the two OpenAPI reads the quota handler performs.
// statusCode/body let a test simulate a rejection envelope.
func newQoderCNQuotaServer(t *testing.T, usageBody, statusBody string, statusCode int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"TOKEN_EXPIRE","message":"token is not active"}`))
			return
		}
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte(usageBody))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/quota/usage"):
			_, _ = w.Write([]byte(usageBody))
		case strings.HasSuffix(r.URL.Path, "/api/v3/user/status"):
			_, _ = w.Write([]byte(statusBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestBuildQoderCNQuotaMergesLedgerAndStatus(t *testing.T) {
	usage := &qodercnauth.QuotaUsage{
		UsageType:            "credits",
		IsQuotaExceeded:      true,
		ExpiresAt:            253402214400000, // year-9999 sentinel
		TotalUsagePercentage: 12.5,
		UserQuota:            qodercnauth.UserQuota{Total: 1000, Used: 250, Remaining: 750, Percentage: 25, Unit: "credits"},
	}
	status := &qodercnauth.AccountStatus{
		Plan:        "PLAN_TIER_PRO",
		UserTag:     "Pro",
		NextResetAt: 1785166151983,
	}

	got := buildQoderCNQuota(usage, status)

	if got.Plan != "Pro" || got.PlanTier != "PLAN_TIER_PRO" {
		t.Fatalf("plan = %q / tier = %q, want Pro / PLAN_TIER_PRO", got.Plan, got.PlanTier)
	}
	if got.Total != 1000 || got.Used != 250 || got.Remaining != 750 {
		t.Fatalf("ledger = %v/%v/%v, want 1000/250/750", got.Total, got.Used, got.Remaining)
	}
	if got.Percentage != 25 {
		t.Fatalf("percentage = %v, want the ledger's 25 rather than totalUsagePercentage 12.5", got.Percentage)
	}
	if got.ResetAt != 1785166151983 {
		t.Fatalf("reset_at = %d, want 1785166151983", got.ResetAt)
	}
	if got.ExpiresAt != 0 {
		t.Fatalf("expires_at = %d, want 0 for the year-9999 sentinel", got.ExpiresAt)
	}
	if !got.IsQuotaExceeded {
		t.Fatal("is_quota_exceeded should be true")
	}
}

func TestBuildQoderCNQuotaFallsBackToTotalUsagePercentage(t *testing.T) {
	usage := &qodercnauth.QuotaUsage{TotalUsagePercentage: 33.3}
	got := buildQoderCNQuota(usage, nil)
	if got.Percentage != 33.3 {
		t.Fatalf("percentage = %v, want fallback 33.3", got.Percentage)
	}
	if got.Plan != "" {
		t.Fatalf("plan = %q, want empty when status is absent", got.Plan)
	}
	if got.Unit != "" {
		// Unit defaulting happens in the handler path, not this pure builder.
		return
	}
}

func TestNormalizeResetAtDropsAbsentAndSentinel(t *testing.T) {
	for _, millis := range []int64{0, -1, 253402214400000, 9999999999999999} {
		if got := qodercnauth.NormalizeResetAt(millis); got != 0 {
			t.Fatalf("NormalizeResetAt(%d) = %d, want 0", millis, got)
		}
	}
	if got := qodercnauth.NormalizeResetAt(1785166151983); got != 1785166151983 {
		t.Fatalf("real reset instant must survive, got %d", got)
	}
}

func TestGetQoderCNQuotaRequiresAuthIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{authManager: coreauth.NewManager(nil, nil, nil)}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder-cn-quota", nil)

	h.GetQoderCNQuota(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestGetQoderCNQuotaRejectsUnknownAuthIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{authManager: coreauth.NewManager(nil, nil, nil)}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder-cn-quota?auth_index=nope", nil)

	h.GetQoderCNQuota(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestGetQoderCNQuotaRejectsWrongProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "codearts:oauth:test",
		Provider: "codearts",
		Metadata: map[string]any{"access_token": "x"},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	h := &Handler{authManager: manager}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder-cn-quota?auth_index="+auth.EnsureIndex(), nil)

	h.GetQoderCNQuota(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a non-qoder-cn credential", recorder.Code)
	}
}

func TestQoderCNAccessTokenPrefersMetadataThenAttribute(t *testing.T) {
	withMeta := &coreauth.Auth{
		Metadata:   map[string]any{"access_token": "dt-from-meta"},
		Attributes: map[string]string{"api_key": "dt-from-attr"},
	}
	if got := qoderCNAccessToken(withMeta); got != "dt-from-meta" {
		t.Fatalf("got %q, want dt-from-meta", got)
	}
	attrOnly := &coreauth.Auth{Attributes: map[string]string{"api_key": "dt-from-attr"}}
	if got := qoderCNAccessToken(attrOnly); got != "dt-from-attr" {
		t.Fatalf("got %q, want dt-from-attr", got)
	}
	if got := qoderCNAccessToken(&coreauth.Auth{}); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestQoderCNQuotaErrorMessageCarriesStatus(t *testing.T) {
	quotaErr := &qodercnauth.Error{StatusCode: http.StatusUnauthorized, Code: "TOKEN_EXPIRE", Message: "token is not active"}
	if !strings.Contains(quotaErr.Error(), "TOKEN_EXPIRE") || !strings.Contains(quotaErr.Error(), "401") {
		t.Fatalf("error text should carry code and status, got %q", quotaErr.Error())
	}
	if !qodercnauth.IsAuthError(quotaErr) {
		t.Fatal("401 must be reported as an auth error")
	}
	if qodercnauth.IsAuthError(&qodercnauth.Error{StatusCode: http.StatusBadGateway}) {
		t.Fatal("502 must not be reported as an auth error")
	}
}

// TestGetQoderCNQuotaSurfacesUpstreamPayload exercises the full handler against a
// stubbed OpenAPI origin, which is how the console path is validated without a
// live credential.
func TestGetQoderCNQuotaSurfacesUpstreamPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	usageBody := `{"userId":"u1","usageType":"credits","isQuotaExceeded":false,"expiresAt":253402214400000,
		"userQuota":{"total":2000,"used":500,"remaining":1500,"percentage":25,"unit":"credits"}}`
	statusBody := `{"id":"u1","plan":"PLAN_TIER_PRO","userTag":"Pro","nextResetAt":1785166151983,"isQuotaExceeded":false}`

	// The handler builds its client from cfg; point the OpenAPI origin at the stub.
	server := newQoderCNQuotaServer(t, usageBody, statusBody, http.StatusOK)
	restore := withQoderCNTestOpenAPIBase(t, server.URL)
	defer restore()

	manager, auth := registerQoderCNAuth(t, "dt-live")
	h := &Handler{authManager: manager}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder-cn-quota?auth_index="+auth.EnsureIndex(), nil)

	h.GetQoderCNQuota(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var got QoderCNQuota
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Total != 2000 || got.Used != 500 || got.Remaining != 1500 {
		t.Fatalf("unexpected ledger: %+v", got)
	}
	if got.Plan != "Pro" || got.PlanTier != "PLAN_TIER_PRO" {
		t.Fatalf("unexpected plan: %+v", got)
	}
	if got.Unit != "credits" {
		t.Fatalf("unit = %q, want credits", got.Unit)
	}
	if got.ExpiresAt != 0 {
		t.Fatalf("expires_at = %d, want 0 for the sentinel", got.ExpiresAt)
	}
}
