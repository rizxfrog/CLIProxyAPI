package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
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

// TestBuildQoderCNQuotaMergesLedgerAndStatus pins the two-bucket shape that the
// official client renders: the plan allowance and the add-on resource pack. This
// is the regression guard for the original bug where only userQuota was read and
// the 资源包 meter never appeared.
func TestBuildQoderCNQuotaMergesLedgerAndStatus(t *testing.T) {
	usage := &qodercnauth.QuotaUsage{
		UsageType:            "credits",
		IsQuotaExceeded:      true,
		ExpiresAt:            253402214400000, // year-9999 sentinel
		TotalUsagePercentage: 12.5,
		UserQuota:            qodercnauth.UserQuota{Total: 1000, Used: 250, Remaining: 750, Percentage: 25, Unit: "credits"},
		AddOnQuota:           &qodercnauth.UserQuota{Total: 200, Used: 0, Remaining: 200, Unit: "credits"},
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
	if len(got.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (plan + addon): %+v", len(got.Rows), got.Rows)
	}
	// The plan allowance must come first, matching the client's 套餐内 then 资源包 order.
	plan, addon := got.Rows[0], got.Rows[1]
	if plan.Kind != "plan" || addon.Kind != "addon" {
		t.Fatalf("row kinds = %q,%q, want plan,addon", plan.Kind, addon.Kind)
	}
	if plan.Total != 1000 || plan.Used != 250 || plan.Remaining != 750 {
		t.Fatalf("plan ledger = %v/%v/%v, want 1000/250/750", plan.Total, plan.Used, plan.Remaining)
	}
	if plan.ResetAt != 1785166151983 {
		t.Fatalf("plan reset_at = %d, want 1785166151983", plan.ResetAt)
	}
	if addon.Total != 200 || addon.Remaining != 200 {
		t.Fatalf("addon pack = %v/%v, want 200/200", addon.Total, addon.Remaining)
	}
	if addon.Unit != "credits" {
		t.Fatalf("addon unit = %q, want credits", addon.Unit)
	}
	if got.ExpiresAt != 0 {
		t.Fatalf("expires_at = %d, want 0 for the year-9999 sentinel", got.ExpiresAt)
	}
	if !got.IsQuotaExceeded {
		t.Fatal("is_quota_exceeded should be true")
	}
}

// TestBuildQoderCNQuotaAlwaysEmitsPlanRow covers the exhausted Free account: an
// empty plan bucket is still a row, because 0/0 is the answer to "what does the
// plan grant", not missing data.
func TestBuildQoderCNQuotaAlwaysEmitsPlanRow(t *testing.T) {
	got := buildQoderCNQuota(&qodercnauth.QuotaUsage{UsageType: "credits"}, nil)
	if len(got.Rows) != 1 {
		t.Fatalf("rows = %d, want 1 plan row: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0].Kind != "plan" {
		t.Fatalf("row kind = %q, want plan", got.Rows[0].Kind)
	}
	if got.Unit != "credits" {
		t.Fatalf("unit = %q, want the credits default", got.Unit)
	}
}

// TestBuildQoderCNQuotaEmitsOrgAndDedicatedPacks covers the remaining buckets.
func TestBuildQoderCNQuotaEmitsOrgAndDedicatedPacks(t *testing.T) {
	usage := &qodercnauth.QuotaUsage{
		UsageType: "credits",
		UserQuota: qodercnauth.UserQuota{Unit: "credits"},
		OrgResourcePackage: &qodercnauth.UserQuota{
			Total: 5000, Used: 1000, Remaining: 4000, Unit: "credits",
		},
		DedicatedResourcePackages: []qodercnauth.ResourcePackage{
			{ID: "pack-a", Name: "Sign-in bonus", Total: 150, Used: 50, Remaining: 100, Unit: "credits", ExpiresAt: 1800000000000, Available: true, Status: "available"},
			{ID: "pack-b", Total: 0, Remaining: 0, Unit: "credits", Available: false, Status: "expired"},
		},
	}

	got := buildQoderCNQuota(usage, nil)

	if len(got.Rows) != 4 {
		t.Fatalf("rows = %d, want 4 (plan, org, pack-a, pack-b): %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[1].Kind != "org" || got.Rows[1].Total != 5000 {
		t.Fatalf("org row = %+v, want kind org total 5000", got.Rows[1])
	}
	packA := got.Rows[2]
	if packA.Kind != "pack" || packA.ID != "pack-a" || packA.Name != "Sign-in bonus" {
		t.Fatalf("pack A = %+v", packA)
	}
	if packA.ExpiresAt != 1800000000000 {
		t.Fatalf("pack A expires_at = %d, want 1800000000000", packA.ExpiresAt)
	}
	if packA.Available == nil || !*packA.Available {
		t.Fatalf("pack A available = %v, want true", packA.Available)
	}
	if packA.Status != "available" {
		t.Fatalf("pack A status = %q", packA.Status)
	}
	packB := got.Rows[3]
	if packB.Available == nil || *packB.Available {
		t.Fatalf("pack B available = %v, want false", packB.Available)
	}
}

// TestBuildQoderCNQuotaGeneratesPackIDWhenMissing keeps the row key stable even
// for a malformed pack with no id.
func TestBuildQoderCNQuotaGeneratesPackIDWhenMissing(t *testing.T) {
	usage := &qodercnauth.QuotaUsage{
		UserQuota: qodercnauth.UserQuota{Unit: "credits"},
		DedicatedResourcePackages: []qodercnauth.ResourcePackage{
			{Total: 10, Remaining: 10},
			{Total: 20, Remaining: 20},
		},
	}
	got := buildQoderCNQuota(usage, nil)
	if got.Rows[1].ID != "pack-0" || got.Rows[2].ID != "pack-1" {
		t.Fatalf("generated ids = %q,%q, want pack-0,pack-1", got.Rows[1].ID, got.Rows[2].ID)
	}
}

func TestBuildQoderCNQuotaOmitsAbsentBuckets(t *testing.T) {
	got := buildQoderCNQuota(&qodercnauth.QuotaUsage{UserQuota: qodercnauth.UserQuota{Unit: "credits"}}, nil)
	for _, row := range got.Rows {
		if row.Kind == "addon" || row.Kind == "org" || row.Kind == "pack" {
			t.Fatalf("absent bucket %q must not produce a phantom meter", row.Kind)
		}
	}
	if got.Plan != "" {
		t.Fatalf("plan = %q, want empty when status is absent", got.Plan)
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
// live credential. The stubbed body mirrors the real shape, including the add-on
// resource pack, so a regression to plan-only would fail here.
func TestGetQoderCNQuotaSurfacesUpstreamPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	usageBody := `{"userId":"u1","usageType":"credits","isQuotaExceeded":false,"expiresAt":253402214400000,
		"userQuota":{"total":2000,"used":500,"remaining":1500,"percentage":25,"unit":"credits"},
		"addOnQuota":{"total":200,"used":0,"remaining":200,"percentage":0,"unit":"credits","detailUrl":"https://qoder.com/account/usage"}}`
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
	if got.Plan != "Pro" || got.PlanTier != "PLAN_TIER_PRO" {
		t.Fatalf("unexpected plan: %+v", got)
	}
	if got.Unit != "credits" {
		t.Fatalf("unit = %q, want credits", got.Unit)
	}
	if got.ExpiresAt != 0 {
		t.Fatalf("expires_at = %d, want 0 for the sentinel", got.ExpiresAt)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (plan + addon resource pack): %+v", len(got.Rows), got.Rows)
	}
	plan, addon := got.Rows[0], got.Rows[1]
	if plan.Kind != "plan" || plan.Total != 2000 || plan.Used != 500 || plan.Remaining != 1500 {
		t.Fatalf("unexpected plan row: %+v", plan)
	}
	if addon.Kind != "addon" || addon.Total != 200 || addon.Remaining != 200 {
		t.Fatalf("unexpected add-on row: %+v", addon)
	}
}

// TestLiveGetQoderCNQuotaEndToEnd runs the real handler against the live OpenAPI
// origin using a stored credential, then asserts on the *serialized* JSON — the
// exact bytes the console receives.
//
// This is the regression guard for the observed "额度加载失败: empty_data" card: the
// assertion is that the plan scalars are present alongside `rows`, because the
// published management panel is versioned independently from this binary
// (remote-management.panel-github-repository). A panel that predates the
// multi-bucket shape reads only `total`/`used`/`remaining`, so omitting them
// makes such a panel fail with no rows rather than showing a plan-only meter.
//
// Skipped unless QODERCN_LIVE_AUTH_FILE points at a data/auth_files/*.json file.
func TestLiveGetQoderCNQuotaEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)
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
	}
	if errUnmarshal := json.Unmarshal(raw, &cred); errUnmarshal != nil {
		t.Fatalf("parse auth file: %v", errUnmarshal)
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		t.Fatal("auth file has no access_token")
	}

	manager, auth := registerQoderCNAuth(t, cred.AccessToken)
	h := &Handler{authManager: manager}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/qoder-cn-quota?auth_index="+auth.EnsureIndex(), nil)

	h.GetQoderCNQuota(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	// Decode generically first so a shape change is visible in the failure output
	// rather than swallowed by a typed unmarshal error.
	var rawBody map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &rawBody); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	for _, key := range []string{"total", "used", "remaining"} {
		if _, ok := rawBody[key]; !ok {
			t.Fatalf("payload is missing the legacy %q scalar; a published panel would report empty_data. keys=%v",
				key, sortedKeys(rawBody))
		}
	}

	var got QoderCNQuota
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal typed: %v", err)
	}
	if len(got.Rows) == 0 {
		t.Fatalf("no rows returned: %s", recorder.Body.String())
	}
	t.Logf("plan scalars: total=%.2f used=%.2f remaining=%.2f", got.Total, got.Used, got.Remaining)
	for _, row := range got.Rows {
		t.Logf("row kind=%-6s id=%-12s total=%-8.2f used=%-8.2f remaining=%-8.2f resetAt=%d expiresAt=%d",
			row.Kind, row.ID, row.Total, row.Used, row.Remaining, row.ResetAt, row.ExpiresAt)
	}

	// The plan row is authoritative; the scalars must agree with it, or a panel
	// rendering one and a card rendering the other would disagree.
	plan := got.Rows[0]
	if plan.Kind != "plan" {
		t.Fatalf("first row kind = %q, want plan", plan.Kind)
	}
	if got.Total != plan.Total || got.Used != plan.Used || got.Remaining != plan.Remaining {
		t.Fatalf("legacy scalars (%v/%v/%v) disagree with the plan row (%v/%v/%v)",
			got.Total, got.Used, got.Remaining, plan.Total, plan.Used, plan.Remaining)
	}
	if got.Plan == "" {
		t.Error("payload carried no plan label")
	}
}

// sortedKeys returns a map's keys in a deterministic order for failure messages.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
