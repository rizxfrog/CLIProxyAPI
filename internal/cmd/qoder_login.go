package cmd

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	log "github.com/sirupsen/logrus"
)

// DoQoderCNLogin starts Qoder CN browser + PKCE device authorization and saves
// the resulting tokens to the configured auth directory.
func DoQoderCNLogin(cfg *config.Config, options *LoginOptions) {
	doQoderLogin(cfg, options, constant.QoderCN, "Qoder CN")
}

// DoQoderAILogin starts international Qoder AI browser + PKCE device
// authorization and saves the resulting tokens.
func DoQoderAILogin(cfg *config.Config, options *LoginOptions) {
	doQoderLogin(cfg, options, constant.QoderAI, "Qoder AI")
}

// doQoderLogin runs the shared device-polling login for one Qoder environment.
func doQoderLogin(cfg *config.Config, options *LoginOptions, provider, label string) {
	if options == nil {
		options = &LoginOptions{}
	}
	record, savedPath, err := newAuthManager().Login(
		context.Background(),
		provider,
		cfg,
		&sdkAuth.LoginOptions{
			NoBrowser: options.NoBrowser,
			Metadata:  map[string]string{},
			Prompt:    options.Prompt,
		},
	)
	if err != nil {
		log.Errorf("%s authentication failed: %v", label, err)
		return
	}
	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	if record != nil && record.Label != "" {
		fmt.Printf("Authenticated as %s\n", record.Label)
	}
	fmt.Printf("%s authentication successful!\n", label)
}
