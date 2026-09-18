package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qodercn"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var qoderCNRefreshLead = 5 * time.Minute

// qoderCNModelBaseURL is the model-server origin recorded on each Qoder CN auth
// entry. Inference requests target {base}/model/v1/chat/completions.
const qoderCNModelBaseURL = qodercn.ModelBaseURL

// QoderCNAuthenticator implements the Qoder CN browser + PKCE device polling flow.
type QoderCNAuthenticator struct{}

// NewQoderCNAuthenticator constructs a Qoder CN authenticator.
func NewQoderCNAuthenticator() Authenticator { return &QoderCNAuthenticator{} }

// Provider returns the Qoder CN provider key.
func (QoderCNAuthenticator) Provider() string { return constant.QoderCN }

// RefreshLead instructs the runtime to refresh shortly before expiry.
func (QoderCNAuthenticator) RefreshLead() *time.Duration { return &qoderCNRefreshLead }

// Login starts browser authorization and waits for Qoder CN to issue tokens.
//
// machineID comes from LoginOptions when provided (so a caller can pin a stable
// device identity); otherwise a random UUID is generated, matching the official
// client behaviour.
func (a QoderCNAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	client := newQoderCNClient(cfg, opts)
	fmt.Println("Starting Qoder CN authentication...")

	device, err := client.StartDeviceFlow(ctx, "")
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nTo authenticate, please visit:\n%s\n\n", device.AuthURL)
	if !opts.NoBrowser && browser.IsAvailable() {
		if errOpen := browser.OpenURL(device.AuthURL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
		} else {
			fmt.Println("Browser opened automatically.")
		}
	}
	fmt.Println("Waiting for authorization...")

	token, err := client.WaitForAuthorization(ctx, device)
	if err != nil {
		return nil, err
	}

	fileName := fmt.Sprintf("qoder-cn-%d.json", time.Now().UnixMilli())
	return &coreauth.Auth{
		ID:       fileName,
		Provider: constant.QoderCN,
		FileName: fileName,
		Label:    "Qoder CN",
		Metadata: qoderCNTokenMetadata(token),
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"base_url":                 qoderCNModelBaseURL,
		},
	}, nil
}

// newQoderCNClient builds an OAuth client. LoginOptions carries no proxy or
// endpoint fields, so optional overrides are read from the Metadata map using
// the same keys the management handler accepts ("proxy_url", "openapi_base_url",
// "client_id").
func newQoderCNClient(cfg *config.Config, opts *LoginOptions) *qodercn.Client {
	clientOpts := qodercn.Options{}
	if opts != nil && opts.Metadata != nil {
		clientOpts.ProxyURL = strings.TrimSpace(opts.Metadata["proxy_url"])
		clientOpts.OpenAPIBaseURL = strings.TrimSpace(opts.Metadata["openapi_base_url"])
		clientOpts.AuthBaseURL = strings.TrimSpace(opts.Metadata["auth_base_url"])
		clientOpts.ClientID = strings.TrimSpace(opts.Metadata["client_id"])
		clientOpts.RedirectURI = strings.TrimSpace(opts.Metadata["redirect_uri"])
	}
	return qodercn.NewClientWithOptions(cfg, clientOpts)
}

// qoderCNTokenMetadata builds the persisted auth-file metadata for a login.
func qoderCNTokenMetadata(token *qodercn.TokenData) map[string]any {
	metadata := map[string]any{
		"type":         constant.QoderCN,
		"auth_kind":    coreauth.AuthKindOAuth,
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"base_url":     qoderCNModelBaseURL,
		"timestamp":    time.Now().UnixMilli(),
	}
	if strings.TrimSpace(token.RefreshToken) != "" {
		metadata["refresh_token"] = token.RefreshToken
	}
	if token.ExpiresIn > 0 {
		metadata["expires_in"] = token.ExpiresIn
	}
	if !token.ExpiresAt.IsZero() {
		metadata["expired"] = token.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return metadata
}
