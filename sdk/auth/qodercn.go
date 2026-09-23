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

// qoderCNModelBaseURL is the CN agent gateway origin recorded on each Qoder CN
// auth entry. Inference posts a COSY-signed body to
// {base}/algo/api/v2/service/pro/sse/agent_chat_generation.
const qoderCNModelBaseURL = qodercn.GatewayBaseURL

// qoderAIModelBaseURL is the international (Qoder AI) agent gateway origin.
const qoderAIModelBaseURL = qodercn.AIGatewayBaseURL

// qoderAuthenticatorSpec captures the values that differ between the Qoder CN
// and international Qoder AI login flows. Both share the browser + PKCE device
// polling flow, token metadata shape and refresh behavior.
type qoderAuthenticatorSpec struct {
	provider   string
	label      string
	filePrefix string
	baseURL    string
	newClient  func(cfg *config.Config, opts *LoginOptions) *qodercn.Client
}

var qoderCNAuthenticatorSpec = qoderAuthenticatorSpec{
	provider:   constant.QoderCN,
	label:      "Qoder CN",
	filePrefix: "qoder-cn",
	baseURL:    qoderCNModelBaseURL,
	newClient:  newQoderCNClient,
}

var qoderAIAuthenticatorSpec = qoderAuthenticatorSpec{
	provider:   constant.QoderAI,
	label:      "Qoder AI",
	filePrefix: "qoder-ai",
	baseURL:    qoderAIModelBaseURL,
	newClient:  newQoderAIClient,
}

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
	return loginQoder(ctx, cfg, opts, qoderCNAuthenticatorSpec)
}

// QoderAIAuthenticator implements the international Qoder AI browser + PKCE
// device polling flow. The flow is identical to Qoder CN; only the hosts differ.
type QoderAIAuthenticator struct{}

// NewQoderAIAuthenticator constructs an international Qoder AI authenticator.
func NewQoderAIAuthenticator() Authenticator { return &QoderAIAuthenticator{} }

// Provider returns the Qoder AI provider key.
func (QoderAIAuthenticator) Provider() string { return constant.QoderAI }

// RefreshLead instructs the runtime to refresh shortly before expiry.
func (QoderAIAuthenticator) RefreshLead() *time.Duration { return &qoderCNRefreshLead }

// Login starts international Qoder AI browser authorization and waits for tokens.
func (a QoderAIAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	return loginQoder(ctx, cfg, opts, qoderAIAuthenticatorSpec)
}

// loginQoder runs the shared browser + PKCE device polling login for one Qoder
// environment and builds the persisted auth entry.
func loginQoder(ctx context.Context, cfg *config.Config, opts *LoginOptions, spec qoderAuthenticatorSpec) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	client := spec.newClient(cfg, opts)
	fmt.Printf("Starting %s authentication...\n", spec.label)

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

	fileName := fmt.Sprintf("%s-%d.json", spec.filePrefix, time.Now().UnixMilli())
	return &coreauth.Auth{
		ID:       fileName,
		Provider: spec.provider,
		FileName: fileName,
		Label:    spec.label,
		Metadata: qoderTokenMetadata(token, spec),
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"base_url":                 spec.baseURL,
		},
	}, nil
}

// newQoderCNClient builds an OAuth client. LoginOptions carries no proxy or
// endpoint fields, so optional overrides are read from the Metadata map using
// the same keys the management handler accepts ("proxy_url", "openapi_base_url",
// "client_id").
func newQoderCNClient(cfg *config.Config, opts *LoginOptions) *qodercn.Client {
	return qodercn.NewClientWithOptions(cfg, qoderClientOptions(opts))
}

// newQoderAIClient builds an international Qoder AI OAuth client with the same
// operator overrides applied on top of the AI environment defaults.
func newQoderAIClient(cfg *config.Config, opts *LoginOptions) *qodercn.Client {
	clientOpts := qoderClientOptions(opts)
	if strings.TrimSpace(clientOpts.AuthBaseURL) == "" {
		clientOpts.AuthBaseURL = qodercn.AIAuthBaseURL
	}
	if strings.TrimSpace(clientOpts.OpenAPIBaseURL) == "" {
		clientOpts.OpenAPIBaseURL = qodercn.AIOpenAPIBaseURL
	}
	if strings.TrimSpace(clientOpts.GatewayBaseURL) == "" {
		clientOpts.GatewayBaseURL = qodercn.AIGatewayBaseURL
	}
	return qodercn.NewClientWithOptions(cfg, clientOpts)
}

// qoderClientOptions reads the optional endpoint/proxy overrides from the login
// metadata shared by both environments.
func qoderClientOptions(opts *LoginOptions) qodercn.Options {
	clientOpts := qodercn.Options{}
	if opts != nil && opts.Metadata != nil {
		clientOpts.ProxyURL = strings.TrimSpace(opts.Metadata["proxy_url"])
		clientOpts.OpenAPIBaseURL = strings.TrimSpace(opts.Metadata["openapi_base_url"])
		clientOpts.AuthBaseURL = strings.TrimSpace(opts.Metadata["auth_base_url"])
		clientOpts.GatewayBaseURL = strings.TrimSpace(opts.Metadata["gateway_base_url"])
		clientOpts.ClientID = strings.TrimSpace(opts.Metadata["client_id"])
		clientOpts.RedirectURI = strings.TrimSpace(opts.Metadata["redirect_uri"])
	}
	return clientOpts
}

// qoderTokenMetadata builds the persisted auth-file metadata for a login.
func qoderTokenMetadata(token *qodercn.TokenData, spec qoderAuthenticatorSpec) map[string]any {
	metadata := map[string]any{
		"type":         spec.provider,
		"auth_kind":    coreauth.AuthKindOAuth,
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"base_url":     spec.baseURL,
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
