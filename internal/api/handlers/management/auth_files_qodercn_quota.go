package management

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	qodercnauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// QoderCNQuotaRow is one credit meter on the console card.
//
// An account's credit entitlement is split across buckets, which is why the
// official client renders more than one meter per account:
//
//	plan  — the plan allowance            (套餐内 Credits)
//	addon — purchased top-up credits      (资源包)
//	org   — the shared organization pool
//	pack  — a personal pack (one row each, with its own expiry)
//
// Kind lets the console localize the row label without the backend guessing a
// locale, and the row carries no pre-rendered text.
type QoderCNQuotaRow struct {
	// Kind is "plan", "addon", "org" or "pack".
	Kind string `json:"kind"`
	// ID is unique within the payload (the pack id for packs, else the kind).
	ID string `json:"id"`
	// Name is an upstream-supplied pack name, when the pack has one.
	Name string `json:"name,omitempty"`
	// Total, Used and Remaining are amounts in Unit.
	Total     float64 `json:"total"`
	Used      float64 `json:"used"`
	Remaining float64 `json:"remaining"`
	// Unit is the denomination; "credits" on every account observed.
	Unit string `json:"unit"`
	// ResetAt is the plan bucket's next reset (epoch ms), 0 when not applicable.
	ResetAt int64 `json:"reset_at"`
	// ExpiresAt is a pack's own deadline (epoch ms), 0 when absent/sentinel.
	ExpiresAt int64 `json:"expires_at"`
	// Available mirrors the upstream availability flag (packs only).
	Available *bool `json:"available,omitempty"`
	// Status is the upstream pack status string, when present.
	Status string `json:"status,omitempty"`
}

// QoderCNQuota is the credit ledger of one Qoder CN credential, shaped for the
// management console quota page.
//
// The payload comes from two OpenAPI reads: the ledger itself
// (/api/v2/quota/usage) and the plan tier plus reset instant (/api/v3/user/status).
// Both are plain bearer-token GETs; unlike the model catalog they are not
// signature-gated.
//
// Rows are the authoritative shape: the plan allowance followed by every
// resource pack, one entry each. New clients render one meter per row.
//
// The flat Total/Used/Remaining below mirror the *plan allowance* row for older
// panels. The management panel is published and auto-updated independently from
// this binary (remote-management.panel-github-repository), so a panel build that
// predates the multi-bucket shape would otherwise find no numbers at all and
// report "empty_data" rather than a plan-only meter. They are display
// compatibility, not a second source of truth: the resource packs are only ever
// represented in Rows.
type QoderCNQuota struct {
	// Plan is the human-facing tier label (e.g. "Free"), from userTag.
	Plan string `json:"plan"`
	// PlanTier is the internal tier identifier (e.g. "PLAN_TIER_FREE").
	PlanTier string `json:"plan_tier"`
	// UsageType is the ledger denomination, "credits" on every account observed.
	UsageType string `json:"usage_type"`
	// Unit labels the amounts (the upstream sends "credits").
	Unit string `json:"unit"`
	// IsQuotaExceeded reports that the account cannot consume more credits.
	IsQuotaExceeded bool `json:"is_quota_exceeded"`
	// ResetAt is the next plan reset in epoch milliseconds, 0 when unknown.
	ResetAt int64 `json:"reset_at"`
	// ExpiresAt is the plan deadline in epoch milliseconds, 0 when unknown or
	// sentinel ("never").
	ExpiresAt int64 `json:"expires_at"`
	// Total, Used and Remaining mirror the plan-allowance row (see the note above).
	Total     float64 `json:"total"`
	Used      float64 `json:"used"`
	Remaining float64 `json:"remaining"`
	// Rows are the plan allowance followed by every resource pack.
	Rows []QoderCNQuotaRow `json:"rows"`
}

// qoderCNQuotaOpenAPIBase is the OpenAPI origin the quota handler talks to. It
// is a variable so tests can point the handler at a stub origin; production
// always leaves it at the package default.
var qoderCNQuotaOpenAPIBase = qodercnauth.OpenAPIBaseURL

// GetQoderCNQuota returns the credit ledger for one Qoder CN credential,
// identified by auth_index.
//
// A 401 from the gateway usually means the stored access token went stale, so
// the credential is refreshed once through the stored refresh token and the read
// is retried. A successful refresh is persisted through the auth manager so
// subsequent inference calls reuse the rotated token.
func (h *Handler) GetQoderCNQuota(c *gin.Context) {
	authIndex := strings.TrimSpace(c.Query("auth_index"))
	if authIndex == "" {
		writeQuotaError(c, http.StatusBadRequest, "auth_index is required")
		return
	}
	auth := h.authByIndex(authIndex)
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), constant.QoderCN) {
		writeQuotaError(c, http.StatusNotFound, "qoder-cn credential not found")
		return
	}
	accessToken := qoderCNAccessToken(auth)
	if accessToken == "" {
		writeQuotaError(c, http.StatusBadRequest, "qoder-cn credential has no access token")
		return
	}

	client := qodercnauth.NewClientWithOptions(h.cfg, qodercnauth.Options{
		ProxyURL:       auth.ProxyURL,
		OpenAPIBaseURL: qoderCNQuotaOpenAPIBase,
	})

	usage, status, errFetch := h.fetchQoderCNQuotaPair(c.Request.Context(), client, auth, accessToken)
	if errFetch != nil {
		statusCode := http.StatusBadGateway
		if qodercnauth.IsAuthError(errFetch) {
			statusCode = http.StatusUnauthorized
		}
		writeQuotaError(c, statusCode, errFetch.Error())
		return
	}

	c.JSON(http.StatusOK, buildQoderCNQuota(usage, status))
}

// fetchQoderCNQuotaPair reads the ledger and the account status, refreshing the
// credential and retrying once when the gateway rejects the stored token.
func (h *Handler) fetchQoderCNQuotaPair(ctx context.Context, client *qodercnauth.Client, auth *coreauth.Auth, accessToken string) (*qodercnauth.QuotaUsage, *qodercnauth.AccountStatus, error) {
	usage, status, errFetch := fetchQoderCNQuotaPair(ctx, client, accessToken)
	if errFetch == nil || !qodercnauth.IsAuthError(errFetch) {
		return usage, status, errFetch
	}

	// The ledger read is the authoritative check; only retry when the failure is
	// an authentication one and a refresh token is available to rotate with.
	refreshToken := qoderCNMetaString(auth, "refresh_token")
	if refreshToken == "" {
		return nil, nil, errFetch
	}
	token, errRefresh := client.Refresh(ctx, refreshToken)
	if errRefresh != nil {
		// Surface the original rejection: the stale token is the root cause and
		// the refresh failure (often the same 401) adds no actionable detail.
		return nil, nil, errFetch
	}
	h.persistQoderCNToken(ctx, auth, token)
	return fetchQoderCNQuotaPair(ctx, client, token.AccessToken)
}

// fetchQoderCNQuotaPair performs the two upstream reads. The status read is
// best-effort: a ledger without a plan tier is still worth showing, so a status
// failure is not propagated as long as the ledger succeeded.
func fetchQoderCNQuotaPair(ctx context.Context, client *qodercnauth.Client, accessToken string) (*qodercnauth.QuotaUsage, *qodercnauth.AccountStatus, error) {
	usage, errUsage := client.FetchQuotaUsage(ctx, accessToken)
	if errUsage != nil {
		return nil, nil, errUsage
	}
	status, errStatus := client.FetchAccountStatus(ctx, accessToken)
	if errStatus != nil {
		if qodercnauth.IsAuthError(errStatus) {
			return nil, nil, errStatus
		}
		status = nil
	}
	return usage, status, nil
}

// buildQoderCNQuota merges the ledger and status reads into the console payload,
// emitting one row per credit bucket: the plan allowance first, then the add-on
// resource pack, the organization pool, and finally each personal pack.
//
// Ordering matters for display: the official client lists 套餐内 Credits above 资源包,
// so the plan row is always first. Empty buckets are skipped (an account without a
// pack should not get a phantom 0/0 meter), except that the plan row is always
// present so the card never renders with no rows at all.
func buildQoderCNQuota(usage *qodercnauth.QuotaUsage, status *qodercnauth.AccountStatus) QoderCNQuota {
	quota := QoderCNQuota{
		UsageType:       strings.TrimSpace(usage.UsageType),
		Unit:            ledgerUnit(usage),
		IsQuotaExceeded: usage.IsQuotaExceeded,
		ExpiresAt:       qodercnauth.NormalizeResetAt(usage.ExpiresAt),
	}
	if status != nil {
		quota.PlanTier = strings.TrimSpace(status.Plan)
		// userTag is the display label ("Free"); fall back to the tier id.
		quota.Plan = firstNonEmptyString(&status.UserTag, &status.Plan)
		quota.IsQuotaExceeded = quota.IsQuotaExceeded || status.IsQuotaExceeded
		quota.ResetAt = qodercnauth.NormalizeResetAt(status.NextResetAt)
	}

	// Plan allowance (套餐内 Credits). Always present: a Free account legitimately
	// reports 0/0 here, and the zero is the answer to "what does the plan give me".
	quota.Total = usage.UserQuota.Total
	quota.Used = usage.UserQuota.Used
	quota.Remaining = usage.UserQuota.Remaining
	quota.Rows = append(quota.Rows, QoderCNQuotaRow{
		Kind:      "plan",
		ID:        "plan",
		Total:     usage.UserQuota.Total,
		Used:      usage.UserQuota.Used,
		Remaining: usage.UserQuota.Remaining,
		Unit:      ledgerUnitOf(usage.UserQuota, quota.Unit),
		ResetAt:   quota.ResetAt,
	})

	// Add-on resource pack (资源包).
	if usage.AddOnQuota != nil {
		quota.Rows = append(quota.Rows, QoderCNQuotaRow{
			Kind:      "addon",
			ID:        "addon",
			Total:     usage.AddOnQuota.Total,
			Used:      usage.AddOnQuota.Used,
			Remaining: usage.AddOnQuota.Remaining,
			Unit:      ledgerUnitOf(*usage.AddOnQuota, quota.Unit),
		})
	}

	// Shared organization pool, when the account belongs to an organization.
	if usage.OrgResourcePackage != nil {
		quota.Rows = append(quota.Rows, QoderCNQuotaRow{
			Kind:      "org",
			ID:        "org",
			Total:     usage.OrgResourcePackage.Total,
			Used:      usage.OrgResourcePackage.Used,
			Remaining: usage.OrgResourcePackage.Remaining,
			Unit:      ledgerUnitOf(*usage.OrgResourcePackage, quota.Unit),
			Available: orgAvailable(usage.OrgResourcePackage),
		})
	}

	// Personal packs, each with its own expiry and availability.
	for i, pack := range usage.DedicatedResourcePackages {
		id := strings.TrimSpace(pack.ID)
		if id == "" {
			id = fmt.Sprintf("pack-%d", i)
		}
		available := pack.Available
		quota.Rows = append(quota.Rows, QoderCNQuotaRow{
			Kind:      "pack",
			ID:        id,
			Name:      strings.TrimSpace(pack.Name),
			Total:     pack.Total,
			Used:      pack.Used,
			Remaining: pack.Remaining,
			Unit:      packUnit(pack, quota.Unit),
			ExpiresAt: qodercnauth.NormalizeResetAt(pack.ExpiresAt),
			Available: &available,
			Status:    strings.TrimSpace(pack.Status),
		})
	}
	return quota
}

// ledgerUnit returns the denomination for the payload, preferring the plan
// bucket's unit and defaulting to "credits".
func ledgerUnit(usage *qodercnauth.QuotaUsage) string {
	for _, candidate := range []string{usage.UserQuota.Unit} {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed
		}
	}
	if usage.AddOnQuota != nil {
		if trimmed := strings.TrimSpace(usage.AddOnQuota.Unit); trimmed != "" {
			return trimmed
		}
	}
	return "credits"
}

// ledgerUnitOf returns a bucket's own unit, falling back to the payload default.
func ledgerUnitOf(bucket qodercnauth.UserQuota, fallback string) string {
	if trimmed := strings.TrimSpace(bucket.Unit); trimmed != "" {
		return trimmed
	}
	return fallback
}

// packUnit returns a resource pack's own unit, falling back to the payload default.
func packUnit(pack qodercnauth.ResourcePackage, fallback string) string {
	if trimmed := strings.TrimSpace(pack.Unit); trimmed != "" {
		return trimmed
	}
	return fallback
}

// orgAvailable mirrors the official client's reading of the shared organization
// pool: an explicit availability flag when present, otherwise "has capacity".
func orgAvailable(pool *qodercnauth.UserQuota) *bool {
	if pool == nil {
		return nil
	}
	available := pool.Total > 0
	return &available
}

// qoderCNAccessToken reads the bearer token from metadata, falling back to the
// api_key attribute that the synthesizer seeds for inference.
func qoderCNAccessToken(auth *coreauth.Auth) string {
	if token := qoderCNMetaString(auth, "access_token"); token != "" {
		return token
	}
	if auth == nil {
		return ""
	}
	return strings.TrimSpace(auth.Attributes["api_key"])
}

// persistQoderCNToken writes a rotated token pair into the auth record and asks
// the auth manager to persist it, mirroring the executor's transparent refresh.
func (h *Handler) persistQoderCNToken(ctx context.Context, auth *coreauth.Auth, token *qodercnauth.TokenData) {
	if auth == nil || token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = token.AccessToken
	if trimmed := strings.TrimSpace(token.RefreshToken); trimmed != "" {
		auth.Metadata["refresh_token"] = trimmed
	}
	if trimmed := strings.TrimSpace(token.TokenType); trimmed != "" {
		auth.Metadata["token_type"] = trimmed
	}
	if token.ExpiresIn > 0 {
		auth.Metadata["expires_in"] = token.ExpiresIn
	}
	if !token.ExpiresAt.IsZero() {
		auth.Metadata["expired"] = token.ExpiresAt.UTC().Format(time.RFC3339)
	}
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["api_key"] = token.AccessToken

	if h.authManager != nil {
		if _, errUpdate := h.authManager.Update(ctx, auth); errUpdate != nil {
			// A persistence failure is not fatal for this read; the rotated token
			// is still used for the retry below.
			_ = errUpdate
		}
	}
}

// qoderCNMetaString reads a trimmed string value from auth metadata.
func qoderCNMetaString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

// writeQuotaError emits a quota failure in the shape the console renders.
func writeQuotaError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}
