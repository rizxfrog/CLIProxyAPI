package management

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	qodercnauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// QoderCNQuota is the credit ledger of one Qoder CN credential, shaped for the
// management console quota page.
//
// The fields come from two OpenAPI reads: the ledger itself
// (/api/v2/quota/usage) and the plan tier plus reset instant (/api/v3/user/status).
// Both are plain bearer-token GETs; unlike the model catalog they are not
// signature-gated.
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
	// Total, Used and Remaining are ledger amounts in Unit.
	Total     float64 `json:"total"`
	Used      float64 `json:"used"`
	Remaining float64 `json:"remaining"`
	// Percentage is the upstream-reported share of the ledger consumed.
	Percentage float64 `json:"percentage"`
	// ResetAt is the next quota reset in epoch milliseconds, 0 when unknown.
	ResetAt int64 `json:"reset_at"`
	// ExpiresAt is the plan deadline in epoch milliseconds, 0 when unknown or
	// sentinel ("never").
	ExpiresAt int64 `json:"expires_at"`
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

// buildQoderCNQuota merges the ledger and status reads into the console payload.
func buildQoderCNQuota(usage *qodercnauth.QuotaUsage, status *qodercnauth.AccountStatus) QoderCNQuota {
	quota := QoderCNQuota{
		UsageType:       strings.TrimSpace(usage.UsageType),
		Unit:            strings.TrimSpace(usage.UserQuota.Unit),
		IsQuotaExceeded: usage.IsQuotaExceeded,
		Total:           usage.UserQuota.Total,
		Used:            usage.UserQuota.Used,
		Remaining:       usage.UserQuota.Remaining,
		Percentage:      usage.UserQuota.Percentage,
		ExpiresAt:       qodercnauth.NormalizeResetAt(usage.ExpiresAt),
	}
	if quota.Unit == "" {
		quota.Unit = "credits"
	}
	if status != nil {
		quota.PlanTier = strings.TrimSpace(status.Plan)
		// userTag is the display label ("Free"); fall back to the tier id.
		quota.Plan = firstNonEmptyString(&status.UserTag, &status.Plan)
		quota.IsQuotaExceeded = quota.IsQuotaExceeded || status.IsQuotaExceeded
		quota.ResetAt = qodercnauth.NormalizeResetAt(status.NextResetAt)
	}
	// The ledger's own percentage is authoritative; totalUsagePercentage is a
	// rounded display copy, so it is only consulted when the ledger is silent.
	if quota.Percentage == 0 && usage.TotalUsagePercentage > 0 {
		quota.Percentage = usage.TotalUsagePercentage
	}
	return quota
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
