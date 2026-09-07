package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var traeRefreshLead = 24 * time.Hour

// TraeAuthenticator implements the TRAE SOLO CN manual-paste OAuth login flow.
//
// TRAE has no device-code endpoint. Its desktop login page forces a loopback
// auth_callback_url, so remote CLIProxyAPI deployments cannot receive the
// callback automatically. The user signs in, copies the full callback URL from
// the browser address bar, and pastes it back (either in the Web UI or through
// the terminal prompt).
type TraeAuthenticator struct{}

// NewTraeAuthenticator constructs a TRAE SOLO CN authenticator.
func NewTraeAuthenticator() Authenticator { return &TraeAuthenticator{} }

// Provider returns the TRAE provider key.
func (TraeAuthenticator) Provider() string { return "trae" }

// RefreshLead instructs the runtime to refresh shortly before expiry.
func (TraeAuthenticator) RefreshLead() *time.Duration { return &traeRefreshLead }

// Login drives the TRAE SOLO CN manual-paste login flow.
func (a TraeAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	client := trae.NewClient(cfg)
	machineID, deviceID := trae.ConfigIdentity(cfg)
	loginURL, errBuild := client.BuildLoginURLWithIdentity(machineID, deviceID)
	if errBuild != nil {
		return nil, errBuild
	}
	if machineID != "" || deviceID != "" {
		log.Debugf("cliproxy auth: reusing configured trae identity machine_id=%s device_id=%s", machineID, deviceID)
	}

	fmt.Println("Starting TRAE SOLO CN authentication...")
	if !opts.NoBrowser && browser.IsAvailable() {
		if errOpen := browser.OpenURL(loginURL.URL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
			fmt.Printf("Please open this URL manually:\n%s\n", loginURL.URL)
		} else {
			fmt.Println("Browser opened automatically.")
		}
	} else {
		util.PrintSSHTunnelInstructions(18080)
		fmt.Printf("Please open this URL to continue authentication:\n%s\n", loginURL.URL)
	}

	fmt.Println("After signing in, TRAE redirects to a 127.0.0.1 address. Copy that full URL from the address bar.")
	if opts.Prompt == nil {
		return nil, fmt.Errorf("cliproxy auth: trae login requires an interactive prompt to paste the callback URL")
	}
	callbackURL, errPrompt := opts.Prompt("Paste the TRAE callback URL: ")
	if errPrompt != nil {
		return nil, errPrompt
	}
	if strings.TrimSpace(callbackURL) == "" {
		return nil, fmt.Errorf("cliproxy auth: trae login cancelled")
	}

	token, errParse := client.ParseCallback(callbackURL)
	if errParse != nil {
		return nil, errParse
	}

	fileName := fmt.Sprintf("trae-%s.json", token.UID)
	metadata := map[string]any{
		"type":          "trae",
		"auth_kind":     "oauth",
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"expires_at":    token.ExpiresAt,
		"api_host":      token.APIHost,
		"uid":           token.UID,
		"machine_id":    loginURL.MachineID,
		"device_id":     loginURL.DeviceID,
		"timestamp":     time.Now().UnixMilli(),
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		delete(metadata, "refresh_token")
	}
	if token.ExpiresAt <= 0 {
		delete(metadata, "expires_at")
	}

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    "TRAE SOLO CN",
		Metadata: metadata,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"api_key":                  token.AccessToken,
			"uid":                      token.UID,
			"machine_id":               loginURL.MachineID,
			"device_id":                loginURL.DeviceID,
			"base_url":                 trae.AgentHost,
		},
	}, nil
}
