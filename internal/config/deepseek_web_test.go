package config

import "testing"

func TestParseDeepSeekWebAPIKey(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
deepseek-web-api-key:
  - api-key: '{"value":"token","__version":"0"}'
    prefix: ds-web
    base-url: https://chat.deepseek.com/
    models:
      - name: deepseek-chat
        alias: ds-chat
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if len(cfg.DeepSeekWebKey) != 1 {
		t.Fatalf("key count = %d", len(cfg.DeepSeekWebKey))
	}
	entry := cfg.DeepSeekWebKey[0]
	if entry.APIKey != `{"value":"token","__version":"0"}` || entry.Prefix != "ds-web" {
		t.Fatalf("entry = %#v", entry)
	}
}
