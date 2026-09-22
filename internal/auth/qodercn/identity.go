package qodercn

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// CosyProfile is the account identity the COSY signature envelope binds. The
// gateway derives the tenant from these fields, so a blank uid/name makes the
// request fail (verified live: a blank-identity signature never completes).
type CosyProfile struct {
	Name             string
	AID              string
	UID              string
	YXUID            string
	OrganizationID   string
	OrganizationName string
	UserType         string
}

// userInfoPayload is the subset of GET /api/v1/userinfo used for the profile.
type userInfoPayload struct {
	ID               string `json:"id"`
	UID              string `json:"uid"`
	UserID           string `json:"userId"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
}

// accountStatusPayload is the subset of GET /api/v3/user/status used for the profile.
type accountStatusPayload struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	UserType         string `json:"userType"`
	OrgID            string `json:"orgId"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	YXUID            string `json:"yxUid"`
}

// FetchCosyProfile reads the account identity needed to sign inference requests.
//
// Both endpoints only require the plain bearer token (verified live: userinfo
// answers 200 with just Authorization), so this reuses the quota HTTP path.
func (c *Client) FetchCosyProfile(ctx context.Context, accessToken string) (*CosyProfile, error) {
	if c == nil {
		return nil, fmt.Errorf("qoder-cn: client is nil")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("qoder-cn: access token is required")
	}

	profile := &CosyProfile{UserType: "personal_standard"}

	if body, err := c.getQuotaJSON(ctx, "/api/v1/userinfo", accessToken); err == nil {
		var info userInfoPayload
		if errUnmarshal := json.Unmarshal(body, &info); errUnmarshal == nil {
			profile.Name = firstNonEmpty(info.Name, info.Username)
			profile.UID = firstNonEmpty(info.ID, info.UID, info.UserID)
			profile.AID = profile.UID
			profile.OrganizationID = strings.TrimSpace(info.OrganizationID)
			profile.OrganizationName = strings.TrimSpace(info.OrganizationName)
		}
	}

	if body, err := c.getQuotaJSON(ctx, "/api/v3/user/status", accessToken); err == nil {
		var status accountStatusPayload
		if errUnmarshal := json.Unmarshal(body, &status); errUnmarshal == nil {
			if trimmed := strings.TrimSpace(status.Name); trimmed != "" {
				profile.Name = trimmed
			}
			if trimmed := firstNonEmpty(status.ID); trimmed != "" {
				profile.UID = trimmed
			}
			if trimmed := strings.TrimSpace(status.UserType); trimmed != "" {
				profile.UserType = trimmed
			}
			if trimmed := firstNonEmpty(status.OrgID, status.OrganizationID); trimmed != "" {
				profile.OrganizationID = trimmed
			}
			if trimmed := strings.TrimSpace(status.OrganizationName); trimmed != "" {
				profile.OrganizationName = trimmed
			}
			if trimmed := strings.TrimSpace(status.YXUID); trimmed != "" {
				profile.YXUID = trimmed
			}
		}
	}

	if strings.TrimSpace(profile.Name) == "" || strings.TrimSpace(profile.UID) == "" {
		return nil, fmt.Errorf("qoder-cn: could not resolve account identity for signing")
	}
	profile.AID = profile.UID
	return profile, nil
}
