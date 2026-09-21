package auth

import (
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func init() {
	registerRefreshLead("codex", func() Authenticator { return NewCodexAuthenticator() })
	registerRefreshLead("claude", func() Authenticator { return NewClaudeAuthenticator() })
	registerRefreshLead("antigravity", func() Authenticator { return NewAntigravityAuthenticator() })
	registerRefreshLead("kimi", func() Authenticator { return NewKimiAuthenticator() })
	registerRefreshLead("codebuddy-cn", func() Authenticator { return NewCodeBuddyCNAuthenticator() })
	registerRefreshLead("codebuddy-ai", func() Authenticator { return NewCodeBuddyAIAuthenticator() })
	registerRefreshLead("qoder-cn", func() Authenticator { return NewQoderCNAuthenticator() })
	registerRefreshLead("kimi-ai", func() Authenticator { return NewKimiAIAuthenticator() })
	registerRefreshLead("kimi.ai", func() Authenticator { return NewKimiAIDotAuthenticator() })
	registerRefreshLead("xai", func() Authenticator { return NewXAIAuthenticator() })
	registerRefreshLead("devin", func() Authenticator { return NewDevinAuthenticator() })
	registerRefreshLead("meta", func() Authenticator { return NewMetaAuthenticator() })
	registerRefreshLead("trae", func() Authenticator { return NewTraeAuthenticator() })

	// Providers whose credential rotation lives in the runtime executor rather
	// than an Authenticator (no sdk/auth type exists for them). Registering a
	// fixed lead here lets the auto-refresh loop schedule their Refresh calls
	// proactively instead of waiting for a request to hit the executor.
	cliproxyauth.RegisterRefreshLeadProvider("codearts", func() *time.Duration {
		lead := 300 * time.Second // codearts.RefreshWindowSeconds
		return &lead
	})
	cliproxyauth.RegisterRefreshLeadProvider("qwen-web", func() *time.Duration {
		lead := 7 * 24 * time.Hour // QwenWebExecutor.RefreshLead
		return &lead
	})
	cliproxyauth.RegisterRefreshLeadProvider("xiaohuanxiong", func() *time.Duration {
		lead := 300 * time.Second // xiaohuanxiong.RefreshWindowSeconds
		return &lead
	})
	cliproxyauth.RegisterRefreshLeadProvider("deepseek-web", func() *time.Duration {
		lead := 24 * time.Hour // keep the userToken-derived access token warm
		return &lead
	})
}

func registerRefreshLead(provider string, factory func() Authenticator) {
	cliproxyauth.RegisterRefreshLeadProvider(provider, func() *time.Duration {
		if factory == nil {
			return nil
		}
		auth := factory()
		if auth == nil {
			return nil
		}
		return auth.RefreshLead()
	})
}
