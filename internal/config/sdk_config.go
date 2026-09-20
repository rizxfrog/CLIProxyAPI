// Package config provides configuration management for the CLI Proxy API server.
// It handles loading and parsing YAML configuration files, and provides structured
// access to application settings including server port, authentication directory,
// debug settings, proxy configuration, and API keys.
package config

// SDKConfig represents the application's configuration, loaded from a YAML file.
type SDKConfig struct {
	// CodexResponseSteering mirrors the provider-wide runtime setting for API handlers.
	CodexResponseSteering bool `yaml:"-" json:"-"`

	// ProxyURL is the URL of an optional proxy server to use for outbound requests.
	ProxyURL string `yaml:"proxy-url" json:"proxy-url"`

	// DisableImageGeneration controls whether the built-in image_generation tool is injected/allowed.
	//
	// Supported values:
	//   - false (default): image_generation is enabled everywhere (normal behavior).
	//   - true: image_generation is disabled everywhere. The server stops injecting it, removes it from request payloads,
	//     and returns 404 for /v1/images/generations and /v1/images/edits.
	//   - "chat": disable image_generation injection for all non-images endpoints (e.g. /v1/responses, /v1/chat/completions),
	//     while keeping /v1/images/generations and /v1/images/edits enabled and preserving image_generation there.
	//   - "passthrough": do not modify the tool list on non-images endpoints — keep image_generation if the client
	//     sent it and do not inject it otherwise; on /v1/images/generations and /v1/images/edits behave like "chat".
	DisableImageGeneration DisableImageGenerationMode `yaml:"disable-image-generation" json:"disable-image-generation"`

	// GPTImage2BaseModel sets the base (mainline) model used by the legacy hosted
	// image_generation tool path when a Codex image request is not proxied directly
	// through the Image API.
	//
	// The value must start with "gpt-" (case-insensitive). If empty or invalid, the
	// default base model ("gpt-5.4-mini") is used.
	GPTImage2BaseModel string `yaml:"gpt-image-2-base-model,omitempty" json:"gpt-image-2-base-model,omitempty"`

	// VideoResultAuthCacheTTL controls how long video IDs stay pinned to the credential
	// that created them. Accepts duration strings like "30m" or "3h".
	// Empty or invalid values use the default 3h.
	VideoResultAuthCacheTTL string `yaml:"video-result-auth-cache-ttl,omitempty" json:"video-result-auth-cache-ttl,omitempty"`

	// ForceModelPrefix requires explicit model prefixes (e.g., "teamA/gemini-3-pro-preview")
	// to target prefixed credentials. When false, unprefixed model requests may use prefixed
	// credentials as well.
	ForceModelPrefix bool `yaml:"force-model-prefix" json:"force-model-prefix"`

	// RequestLog enables or disables detailed request logging functionality.
	RequestLog bool `yaml:"request-log" json:"request-log"`

	// CodexOptimizeMultiAgentV2 mirrors the provider-wide runtime setting for API handlers.
	CodexOptimizeMultiAgentV2 bool `yaml:"-" json:"-"`

	// CodexOrphanDelegationCompatibility mirrors the provider-wide runtime setting for API handlers.
	CodexOrphanDelegationCompatibility bool `yaml:"-" json:"-"`

	// ClaudeCode configures Claude Code compatibility behavior.
	ClaudeCode ClaudeCodeConfig `yaml:"claude-code" json:"claude-code"`

	// APIKeys is a list of keys for authenticating clients to this proxy server.
	APIKeys []string `yaml:"api-keys" json:"api-keys"`

	// PassthroughHeaders controls whether upstream response headers are forwarded to downstream clients.
	// Default is false (disabled).
	PassthroughHeaders bool `yaml:"passthrough-headers" json:"passthrough-headers"`

	// Streaming configures server-side streaming behavior (keep-alives and safe bootstrap retries).
	Streaming StreamingConfig `yaml:"streaming" json:"streaming"`

	// NonStreamKeepAliveInterval controls how often blank lines are emitted for non-streaming responses.
	// <= 0 disables keep-alives. Value is in seconds.
	NonStreamKeepAliveInterval int `yaml:"nonstream-keepalive-interval,omitempty" json:"nonstream-keepalive-interval,omitempty"`

	// SystemPromptOverride appends a configured prompt section to the system
	// prompt of requests routed to matching providers. It runs after credential
	// selection, so provider-level and model-level matching apply to the actual
	// upstream that will serve the request.
	SystemPromptOverride SystemPromptOverrideConfig `yaml:"system-prompt-override" json:"system-prompt-override"`
}

// SystemPromptOverrideConfig defines the system prompt override feature.
type SystemPromptOverrideConfig struct {
	// Enabled toggles the override. Default false: requests pass through unchanged.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Prompt is the text appended to the system prompt of matching requests.
	// It is appended after any client-provided system content to preserve
	// upstream prompt-cache prefixes. Takes precedence over prompt-file.
	Prompt string `yaml:"prompt" json:"prompt"`
	// PromptFile is a path to a file whose content is used as the prompt when
	// prompt is empty. Relative paths resolve against the process working
	// directory. The file is re-read when its mtime/size changes, so edits do
	// not require a config reload.
	PromptFile string `yaml:"prompt-file,omitempty" json:"prompt-file,omitempty"`
	// Providers restricts the override to these provider identifiers
	// (e.g. "claude", "codex", "gemini", "codebuddy-cn"). Empty means all providers.
	Providers []string `yaml:"providers,omitempty" json:"providers,omitempty"`
	// ExcludedProviders excludes these providers even when Providers is empty
	// or would match. Exclusion wins over inclusion.
	ExcludedProviders []string `yaml:"excluded-providers,omitempty" json:"excluded-providers,omitempty"`
	// Models restricts the override to model names or wildcard patterns
	// (e.g. "gemini-*"). Empty means all models.
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
	// Replacements applies find→replace rules to the client-provided system
	// prompt text before the prompt section is appended. Runs even when the
	// prompt/prompt-file is empty.
	Replacements []PromptReplacementRule `yaml:"replacements,omitempty" json:"replacements,omitempty"`
	// ToolDescriptionReplacements applies find→replace rules to tool
	// descriptions in the request (tools[].description,
	// tools[].function.description, and Gemini
	// tools[].functionDeclarations[].description). Runs even when the
	// prompt/prompt-file is empty.
	ToolDescriptionReplacements []PromptReplacementRule `yaml:"tool-description-replacements,omitempty" json:"tool-description-replacements,omitempty"`
}

// PromptReplacementRule is a literal find→replace rule applied to system prompt
// or tool description text. Matching is exact substring; rules apply in order.
type PromptReplacementRule struct {
	// Find is the exact substring to replace. Empty rules are ignored.
	Find string `yaml:"find" json:"find"`
	// Replace is the replacement text (may be empty to delete the match).
	Replace string `yaml:"replace" json:"replace"`
}

// ClaudeCodeConfig configures Claude Code compatibility behavior.
type ClaudeCodeConfig struct {
	// DisableCloakingModelList disables model ID cloaking in Anthropic model list responses.
	DisableCloakingModelList bool `yaml:"disable-cloaking-model-list" json:"disable-cloaking-model-list"`
}

// StreamingConfig holds server streaming behavior configuration.
type StreamingConfig struct {
	// KeepAliveSeconds controls how often the server emits SSE heartbeats (": keep-alive\n\n")
	// or WebSocket Ping control frames.
	// <= 0 disables keep-alives. Default is 0.
	KeepAliveSeconds int `yaml:"keepalive-seconds,omitempty" json:"keepalive-seconds,omitempty"`

	// BootstrapRetries controls how many times the server may retry a streaming request before any bytes are sent,
	// to allow auth rotation / transient recovery.
	// <= 0 disables bootstrap retries. Default is 0.
	BootstrapRetries int `yaml:"bootstrap-retries,omitempty" json:"bootstrap-retries,omitempty"`
}
