package synthesizer

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
)

func TestConfigSynthesizerDeepSeekWebKey(t *testing.T) {
	auths, err := NewConfigSynthesizer().Synthesize(&SynthesisContext{
		Config: &config.Config{DeepSeekWebKey: []config.DeepSeekWebKey{{
			APIKey: `{"value":"token"}`, Prefix: "ds", ProxyURL: "http://proxy.example",
		}}},
		Now: time.Unix(1, 0), IDGenerator: NewStableIDGenerator(),
	})
	if err != nil {
		t.Fatalf("Synthesize() error = %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("auth count = %d, want 1", len(auths))
	}
	auth := auths[0]
	if auth.Provider != constant.DeepSeekWeb || auth.Prefix != "ds" {
		t.Fatalf("auth = %#v", auth)
	}
	if auth.Attributes["base_url"] != "https://chat.deepseek.com" {
		t.Fatalf("base_url = %q", auth.Attributes["base_url"])
	}
}
