package qodercn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// quotaExpirySentinel is the year cut-off above which an expiresAt millisecond
// timestamp is treated as "never". The live Free-tier account reports
// 253402214400000 (9999-12-31), which is a sentinel rather than a real deadline,
// so it must not surface as a countdown in the console.
const quotaExpirySentinelYear = 9000

// UserQuota is the credit ledger carried by /api/v2/quota/usage.
type UserQuota struct {
	Total      float64 `json:"total"`
	Used       float64 `json:"used"`
	Remaining  float64 `json:"remaining"`
	Percentage float64 `json:"percentage"`
	Unit       string  `json:"unit"`
}

// QuotaUsage is the payload of GET {openApiBaseUrl}/api/v2/quota/usage.
//
// Verified against the CN Free-tier account, which reports usageType "credits"
// with an exhausted ledger (total/used/remaining all zero) and
// isQuotaExceeded true.
type QuotaUsage struct {
	UserID               string    `json:"userId"`
	UserType             string    `json:"userType"`
	UsageType            string    `json:"usageType"`
	TotalUsagePercentage float64   `json:"totalUsagePercentage"`
	IsQuotaExceeded      bool      `json:"isQuotaExceeded"`
	ExpiresAt            int64     `json:"expiresAt"`
	UpgradeURL           string    `json:"upgradeUrl"`
	UserQuota            UserQuota `json:"userQuota"`
	IsPlanQuotaProrated  bool      `json:"isPlanQuotaProrated"`
}

// AccountStatus is the subset of GET {openApiBaseUrl}/api/v3/user/status the
// management console needs: the plan tier and the reset instant.
type AccountStatus struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	UserType        string `json:"userType"`
	Quota           int64  `json:"quota"`
	IsQuotaExceeded bool   `json:"isQuotaExceeded"`
	Plan            string `json:"plan"`
	UserTag         string `json:"userTag"`
	Email           string `json:"email"`
	NextResetAt     int64  `json:"nextResetAt"`
}

// Error is a Qoder CN API failure carrying the upstream status so management
// handlers can mirror it instead of collapsing every failure into a 502.
type Error struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	if e == nil {
		return "qoder-cn: quota request failed"
	}
	detail := strings.TrimSpace(e.Message)
	if detail == "" {
		detail = http.StatusText(e.StatusCode)
	}
	if strings.TrimSpace(e.Code) != "" {
		return fmt.Sprintf("qoder-cn: %s (%s, HTTP %d)", detail, e.Code, e.StatusCode)
	}
	return fmt.Sprintf("qoder-cn: %s (HTTP %d)", detail, e.StatusCode)
}

// FetchQuotaUsage reads the account credit ledger.
func (c *Client) FetchQuotaUsage(ctx context.Context, accessToken string) (*QuotaUsage, error) {
	body, err := c.getQuotaJSON(ctx, "/api/v2/quota/usage", accessToken)
	if err != nil {
		return nil, err
	}
	var usage QuotaUsage
	if errUnmarshal := json.Unmarshal(body, &usage); errUnmarshal != nil {
		return nil, fmt.Errorf("qoder-cn: parse quota usage: %w", errUnmarshal)
	}
	return &usage, nil
}

// FetchAccountStatus reads the account plan tier and reset instant.
func (c *Client) FetchAccountStatus(ctx context.Context, accessToken string) (*AccountStatus, error) {
	body, err := c.getQuotaJSON(ctx, "/api/v3/user/status", accessToken)
	if err != nil {
		return nil, err
	}
	var status AccountStatus
	if errUnmarshal := json.Unmarshal(body, &status); errUnmarshal != nil {
		return nil, fmt.Errorf("qoder-cn: parse account status: %w", errUnmarshal)
	}
	return &status, nil
}

// getQuotaJSON performs an authenticated GET against the OpenAPI origin.
//
// Only the bearer token is required: /api/v2/quota/usage answers 200 with no
// User-Agent, Cosy-Version or machine identifier. The client user agent is still
// sent so these reads are indistinguishable from ordinary CLI traffic.
func (c *Client) getQuotaJSON(ctx context.Context, path, accessToken string) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("qoder-cn: client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("qoder-cn: access token is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.openAPIBase+path, nil)
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: create quota request: %w", err)
	}
	applyHeaders(req, false)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: quota request failed: %w", err)
	}
	defer closeBody("quota", resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("qoder-cn: read quota response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, quotaErrorFromResponse(resp.StatusCode, body)
	}
	return body, nil
}

// quotaErrorFromResponse extracts the {code,message} rejection envelope the
// OpenAPI gateway returns for an expired or invalid bearer token, e.g.
// {"code":"TOKEN_EXPIRE","message":"token is not active"}.
func quotaErrorFromResponse(status int, body []byte) *Error {
	var envelope struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Msg     string `json:"msg"`
		Error   string `json:"error"`
	}
	apiErr := &Error{StatusCode: status}
	if errUnmarshal := json.Unmarshal(body, &envelope); errUnmarshal == nil {
		apiErr.Code = strings.TrimSpace(envelope.Code)
		apiErr.Message = firstNonEmpty(envelope.Message, envelope.Msg, envelope.Error)
	}
	if apiErr.Message == "" {
		apiErr.Message = truncate(string(body))
	}
	return apiErr
}

// NormalizeResetAt converts a millisecond reset instant into a value the console
// can count down to, returning 0 for absent or sentinel timestamps.
func NormalizeResetAt(millis int64) int64 {
	if millis <= 0 {
		return 0
	}
	// 253402214400000 (year 9999) is the Free tier's "never expires" sentinel.
	if millis/1000 > quotaSentinelEpochSeconds {
		return 0
	}
	return millis
}

// quotaSentinelEpochSeconds is 2262-04-11T23:47:16Z, comfortably past every real
// plan deadline but far below the 9999 sentinel. Kept below the int64 nanosecond
// overflow so the comparison stays a plain integer one.
const quotaSentinelEpochSeconds int64 = 9223372036

// IsAuthError reports whether err represents a rejected credential, which the
// management layer surfaces as 401/403 rather than a gateway error.
func IsAuthError(err error) bool {
	apiErr, ok := err.(*Error)
	if !ok || apiErr == nil {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}
