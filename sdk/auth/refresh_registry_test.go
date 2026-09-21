package auth

import (
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestProviderRefreshLeads(t *testing.T) {
	tests := []struct {
		name          string
		authenticator Authenticator
		want          time.Duration
		wantNil       bool
	}{
		{name: "codex", authenticator: NewCodexAuthenticator(), want: 24 * time.Hour},
		{name: "claude", authenticator: NewClaudeAuthenticator(), want: 4 * time.Hour},
		{name: "antigravity", authenticator: NewAntigravityAuthenticator(), want: 30 * time.Minute},
		{name: "kimi", authenticator: NewKimiAuthenticator(), want: 5 * time.Minute},
		{name: "kimi-ai", authenticator: NewKimiAIAuthenticator(), want: 5 * time.Minute},
		{name: "kimi.ai", authenticator: NewKimiAIDotAuthenticator(), want: 5 * time.Minute},
		{name: "xai", authenticator: NewXAIAuthenticator(), want: 5 * time.Minute},
		{name: "devin", authenticator: NewDevinAuthenticator(), wantNil: true},
		{name: "meta", authenticator: NewMetaAuthenticator(), wantNil: true},
		{name: "trae", authenticator: NewTraeAuthenticator(), want: 24 * time.Hour},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.authenticator.Provider(); got != test.name {
				t.Fatalf("Provider() = %q, want %q", got, test.name)
			}
			lead := test.authenticator.RefreshLead()
			if test.wantNil {
				if lead != nil {
					t.Fatalf("RefreshLead() = %v, want nil", lead)
				}
				return
			}
			if lead == nil || *lead != test.want {
				t.Fatalf("RefreshLead() = %v, want %v", lead, test.want)
			}
		})
	}
}

// TestExecutorRefreshLeadCoverage verifies that providers whose rotation lives
// in the runtime executor (no sdk/auth Authenticator) are still registered in
// the shared refresh-lead registry, so the auto-refresh loop can schedule them
// proactively instead of relying on lazy per-request refresh.
func TestExecutorRefreshLeadCoverage(t *testing.T) {
	tests := []struct {
		provider string
		want     time.Duration
	}{
		{provider: "codearts", want: 300 * time.Second},
		{provider: "qwen-web", want: 7 * 24 * time.Hour},
		{provider: "xiaohuanxiong", want: 300 * time.Second},
		{provider: "deepseek-web", want: 24 * time.Hour},
	}
	for _, test := range tests {
		t.Run(test.provider, func(t *testing.T) {
			lead := cliproxyauth.ProviderRefreshLead(test.provider, nil)
			if lead == nil {
				t.Fatalf("ProviderRefreshLead(%q) = nil, want %v", test.provider, test.want)
			}
			if *lead != test.want {
				t.Fatalf("ProviderRefreshLead(%q) = %v, want %v", test.provider, *lead, test.want)
			}
		})
	}
}
