package synthesizer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/diff"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ConfigSynthesizer generates Auth entries from configuration API keys.
// It handles Gemini, Interactions, Claude, Codex, xAI, OpenAI-compat, and Vertex-compat providers.
type ConfigSynthesizer struct{}

// codeBuddyCNDefaultBaseURL is the Tencent CodeBuddy CN OpenAI-compatible gateway host
// prefix used when a codebuddy-cn-api-key entry does not specify its own base-url.
// The OpenAI-compatible executor appends "/chat/completions" to this value, yielding
// https://copilot.tencent.com/v2/chat/completions.
const codeBuddyCNDefaultBaseURL = "https://copilot.tencent.com/v2"

// codeBuddyAIDefaultBaseURL is the international CodeBuddy AI OpenAI-compatible
// gateway host prefix used when a codebuddy-ai-api-key entry does not specify its
// own base-url. The executor appends "/chat/completions", yielding
// https://www.codebuddy.ai/v2/chat/completions.
const codeBuddyAIDefaultBaseURL = "https://www.codebuddy.ai/v2"

const deepSeekWebDefaultBaseURL = "https://chat.deepseek.com"

// xiaohuanxiongDefaultBaseURL is the Xiaohuanxiong (Raccoon) OpenAI-compatible
// LLM gateway used when a xiaohuanxiong-api-key entry does not set base-url.
const xiaohuanxiongDefaultBaseURL = "https://xiaohuanxiong.com/api/web/llm/v2"

// traeDefaultBaseURL is the TRAE SOLO CN desktop agent gateway used when a
// trae-api-key entry does not specify its own base-url.
// codeArtsDefaultBaseURL is the CodeArts InferHub OpenAI-compatible gateway used
// when a codearts-api-key entry does not set base-url. The executor appends
// "/chat/completions", yielding .../api/v2/chat/completions.
const codeArtsDefaultBaseURL = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2"

const traeDefaultBaseURL = "https://trae-api-cn.mchost.guru"

// qoderCNDefaultBaseURL is the Qoder model-server origin used when a
// qoder-cn-api-key entry does not specify its own base-url. The Qoder CN
// executor appends "/model/v1/chat/completions" to it.
const qoderCNDefaultBaseURL = "https://api2-v2.qoder.sh"

// traeDefaultAPIHost is the ExchangeToken / GetUserInfo host used when a
// trae-api-key entry does not specify its own api-host.
const traeDefaultAPIHost = "https://api.trae.com.cn"

// NewConfigSynthesizer creates a new ConfigSynthesizer instance.
func NewConfigSynthesizer() *ConfigSynthesizer {
	return &ConfigSynthesizer{}
}

func addWeightToAttrs(weight *int, attrs map[string]string) {
	if weight == nil {
		return
	}
	normalized := *weight
	if normalized <= 0 {
		normalized = 0
	}
	attrs[coreauth.AttributeWeight] = strconv.Itoa(normalized)
}

// Synthesize generates Auth entries from config API keys.
func (s *ConfigSynthesizer) Synthesize(ctx *SynthesisContext) ([]*coreauth.Auth, error) {
	out := make([]*coreauth.Auth, 0, 32)
	if ctx == nil || ctx.Config == nil {
		return out, nil
	}
	if errValidate := ctx.Config.ValidateCredentialWeights(); errValidate != nil {
		return nil, fmt.Errorf("synthesize config API key auths: %w", errValidate)
	}

	// Gemini API Keys
	out = append(out, s.synthesizeGeminiKeys(ctx)...)
	// Native Interactions API Keys
	out = append(out, s.synthesizeInteractionsKeys(ctx)...)
	// Claude API Keys
	out = append(out, s.synthesizeClaudeKeys(ctx)...)
	// Codex API Keys
	out = append(out, s.synthesizeCodexKeys(ctx)...)
	// xAI API Keys
	out = append(out, s.synthesizeXAIKeys(ctx)...)
	// CodeBuddy CN API Keys
	out = append(out, s.synthesizeCodeBuddyCNKeys(ctx)...)
	// CodeBuddy AI (international) API Keys
	out = append(out, s.synthesizeCodeBuddyAIKeys(ctx)...)
	// DeepSeek Web userTokens
	out = append(out, s.synthesizeDeepSeekWebKeys(ctx)...)
	// Xiaohuanxiong (SenseTime Raccoon) credentials
	out = append(out, s.synthesizeXiaohuanxiongKeys(ctx)...)
	// CodeArts (Huawei Cloud CodeArts Work) credentials
	out = append(out, s.synthesizeCodeArtsKeys(ctx)...)
	// TRAE SOLO CN desktop credentials
	out = append(out, s.synthesizeTraeKeys(ctx)...)
	// Qoder CN (qoder.cn / qoder.com.cn) credentials
	out = append(out, s.synthesizeQoderCNKeys(ctx)...)
	// Meta API Keys
	out = append(out, s.synthesizeMetaKeys(ctx)...)
	// OpenAI-compat
	out = append(out, s.synthesizeOpenAICompat(ctx)...)
	// Vertex-compat
	out = append(out, s.synthesizeVertexCompat(ctx)...)

	return out, nil
}

// synthesizeGeminiKeys creates Auth entries for Gemini API keys.
func (s *ConfigSynthesizer) synthesizeGeminiKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return s.synthesizeGeminiKeyEntries(ctx, ctx.Config.GeminiKey, "gemini:apikey", "gemini", "gemini-apikey", constant.Gemini)
}

// synthesizeInteractionsKeys creates Auth entries for native Interactions API keys.
func (s *ConfigSynthesizer) synthesizeInteractionsKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return s.synthesizeGeminiKeyEntries(ctx, ctx.Config.InteractionsKey, "gemini-interactions:apikey", "interactions", "interactions-apikey", constant.GeminiInteractions)
}

func (s *ConfigSynthesizer) synthesizeGeminiKeyEntries(ctx *SynthesisContext, entries []config.GeminiKey, idKind, sourceName, label, provider string) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		key := strings.TrimSpace(entry.APIKey)
		base := strings.TrimSpace(entry.BaseURL)
		if key == "" && base == "" {
			continue
		}
		prefix := strings.TrimSpace(entry.Prefix)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		id, token := idGen.Next(idKind, key, base, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:%s[%s]", sourceName, token),
			"config_index": strconv.Itoa(i),
		}
		if key != "" {
			attrs["api_key"] = key
		}
		metadata := map[string]any{}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		addRequestRetryToMetadata(entry.RequestRetry, metadata)
		addRequestScopedErrorsToMetadata(entry.RequestScopedErrors, metadata)
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		if base != "" {
			attrs["base_url"] = base
		}
		if hash := diff.ComputeGeminiModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID:         id,
			Provider:   provider,
			Label:      label,
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   proxyURL,
			Attributes: attrs,
			Metadata:   metadata,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeClaudeKeys creates Auth entries for Claude API keys.
func (s *ConfigSynthesizer) synthesizeClaudeKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.ClaudeKey))
	for i := range cfg.ClaudeKey {
		ck := cfg.ClaudeKey[i]
		key := strings.TrimSpace(ck.APIKey)
		base := strings.TrimSpace(ck.BaseURL)
		if key == "" && base == "" {
			continue
		}
		prefix := strings.TrimSpace(ck.Prefix)
		proxyURL := strings.TrimSpace(ck.ProxyURL)
		id, token := idGen.Next("claude:apikey", key, base, proxyURL, prefix, config.FormatSortedHeaders(ck.Headers))
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:claude[%s]", token),
			"config_index": strconv.Itoa(i),
		}
		if key != "" {
			attrs["api_key"] = key
		}
		metadata := map[string]any{}
		if ck.DisableCooling != nil {
			metadata["disable_cooling"] = *ck.DisableCooling
		}
		addRequestRetryToMetadata(ck.RequestRetry, metadata)
		addRequestScopedErrorsToMetadata(ck.RequestScopedErrors, metadata)
		if ck.Priority != 0 {
			attrs["priority"] = strconv.Itoa(ck.Priority)
		}
		addWeightToAttrs(ck.Weight, attrs)
		if base != "" {
			attrs["base_url"] = base
		}
		if ck.RebuildMidSystemMessage {
			attrs["rebuild_mid_system_message"] = "true"
		}
		if profile := strings.ToLower(strings.TrimSpace(ck.FingerprintProfile)); profile != "" {
			attrs["fingerprint_profile"] = profile
		}
		if hash := diff.ComputeClaudeModelsHash(ck.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(ck.Headers, attrs)
		a := &coreauth.Auth{
			ID:         id,
			Provider:   "claude",
			Label:      "claude-apikey",
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   proxyURL,
			Attributes: attrs,
			Metadata:   metadata,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, ck.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeCodexKeys creates Auth entries for Codex API keys.
func (s *ConfigSynthesizer) synthesizeCodexKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return s.synthesizeCodexStyleKeys(ctx, ctx.Config.CodexKey, "codex")
}

// synthesizeXAIKeys creates Auth entries for xAI API keys.
func (s *ConfigSynthesizer) synthesizeXAIKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return s.synthesizeCodexStyleKeys(ctx, ctx.Config.XAIKey, "xai")
}

// synthesizeCodeBuddyCNKeys creates Auth entries for CodeBuddy CN (Tencent) API keys.
func (s *ConfigSynthesizer) synthesizeCodeBuddyCNKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return synthesizeCodeBuddyStyleKeys(ctx, ctx.Config.CodeBuddyCNKey, codeBuddyStyleKeySpec{
		idKind:      "codebuddy-cn:apikey",
		sourceName:  "codebuddy-cn",
		provider:    constant.CodeBuddyCN,
		label:       "codebuddy-cn-apikey",
		defaultBase: codeBuddyCNDefaultBaseURL,
		hash:        diff.ComputeCodeBuddyCNModelsHash,
	})
}

// synthesizeCodeBuddyAIKeys creates Auth entries for CodeBuddy AI (international) API keys.
func (s *ConfigSynthesizer) synthesizeCodeBuddyAIKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return synthesizeCodeBuddyStyleKeys(ctx, ctx.Config.CodeBuddyAIKey, codeBuddyStyleKeySpec{
		idKind:      "codebuddy-ai:apikey",
		sourceName:  "codebuddy-ai",
		provider:    constant.CodeBuddyAI,
		label:       "codebuddy-ai-apikey",
		defaultBase: codeBuddyAIDefaultBaseURL,
		hash:        diff.ComputeCodeBuddyAIModelsHash,
	})
}

// codeBuddyStyleKeySpec parameterizes the CodeBuddy-style API-key synthesizer so
// the CN and international gateways share identical auth-entry construction.
type codeBuddyStyleKeySpec struct {
	idKind      string
	sourceName  string
	provider    string
	label       string
	defaultBase string
	hash        func(models []config.CodeBuddyCNModel) string
}

// synthesizeCodeBuddyStyleKeys creates Auth entries for CodeBuddy-style API keys
// (CodeBuddy CN and CodeBuddy AI share the same OpenAI-compatible entry shape).
func synthesizeCodeBuddyStyleKeys(ctx *SynthesisContext, entries []config.CodeBuddyCNKey, spec codeBuddyStyleKeySpec) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		prefix := strings.TrimSpace(entry.Prefix)
		baseURL := strings.TrimSpace(entry.BaseURL)
		id, token := idGen.Next(spec.idKind, key, baseURL)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:%s[%s]", spec.sourceName, token),
			"api_key":      key,
			"config_index": strconv.Itoa(i),
		}
		metadata := map[string]any{}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		if baseURL != "" {
			attrs["base_url"] = baseURL
		} else {
			attrs["base_url"] = spec.defaultBase
		}
		if spec.hash != nil {
			if hash := spec.hash(entry.Models); hash != "" {
				attrs["models_hash"] = hash
			}
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID:         id,
			Provider:   spec.provider,
			Label:      spec.label,
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs,
			Metadata:   metadata,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeDeepSeekWebKeys creates Auth entries for DeepSeek browser userTokens.
func (s *ConfigSynthesizer) synthesizeDeepSeekWebKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.DeepSeekWebKey))
	for i := range cfg.DeepSeekWebKey {
		entry := cfg.DeepSeekWebKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		baseURL := strings.TrimSpace(entry.BaseURL)
		if baseURL == "" {
			baseURL = deepSeekWebDefaultBaseURL
		}
		prefix := strings.TrimSpace(entry.Prefix)
		id, token := idGen.Next("deepseek-web:apikey", key, baseURL)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:deepseek-web[%s]", token),
			"api_key":      key,
			"base_url":     baseURL,
			"config_index": strconv.Itoa(i),
		}
		metadata := map[string]any{}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		if hash := diff.ComputeCodeBuddyCNModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID: id, Provider: constant.DeepSeekWeb, Label: "deepseek-web-usertoken",
			Prefix: prefix, Status: coreauth.StatusActive, ProxyURL: strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs, Metadata: metadata, CreatedAt: now, UpdatedAt: now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeXiaohuanxiongKeys creates Auth entries for Xiaohuanxiong (Raccoon)
// access tokens acquired from the desktop OAuth flow, or pasted manually.
func (s *ConfigSynthesizer) synthesizeXiaohuanxiongKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.XiaohuanxiongKey))
	for i := range cfg.XiaohuanxiongKey {
		entry := cfg.XiaohuanxiongKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		baseURL := strings.TrimSpace(entry.BaseURL)
		if baseURL == "" {
			baseURL = xiaohuanxiongDefaultBaseURL
		}
		prefix := strings.TrimSpace(entry.Prefix)
		id, token := idGen.Next("xiaohuanxiong:apikey", key, baseURL)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:xiaohuanxiong[%s]", token),
			"api_key":      key,
			"base_url":     baseURL,
			"config_index": strconv.Itoa(i),
		}
		metadata := map[string]any{}
		// The executor reads refresh_token from metadata to rotate the access
		// token; without this a configured refresh-token would be unused.
		if refreshToken := strings.TrimSpace(entry.RefreshToken); refreshToken != "" {
			metadata["refresh_token"] = refreshToken
			metadata["auth_kind"] = coreauth.AuthKindOAuth
		}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		if hash := diff.ComputeCodeBuddyCNModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID: id, Provider: constant.Xiaohuanxiong, Label: "xiaohuanxiong-access-token",
			Prefix: prefix, Status: coreauth.StatusActive, ProxyURL: strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs, Metadata: metadata, CreatedAt: now, UpdatedAt: now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeCodeArtsKeys creates Auth entries for Huawei Cloud CodeArts
// credentials produced by the OAuth login flow (or pasted manually).
func (s *ConfigSynthesizer) synthesizeCodeArtsKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.CodeArtsKey))
	for i := range cfg.CodeArtsKey {
		entry := cfg.CodeArtsKey[i]
		accessKey := strings.TrimSpace(entry.APIKey)
		secretKey := strings.TrimSpace(entry.SecretKey)
		if accessKey == "" || secretKey == "" {
			continue
		}
		baseURL := strings.TrimSpace(entry.BaseURL)
		if baseURL == "" {
			baseURL = codeArtsDefaultBaseURL
		}
		prefix := strings.TrimSpace(entry.Prefix)
		id, token := idGen.Next("codearts:apikey", accessKey, baseURL)
		attrs := map[string]string{
			"source":         fmt.Sprintf("config:codearts[%s]", token),
			"api_key":        accessKey,
			"secret_key":     secretKey,
			"security_token": strings.TrimSpace(entry.SecurityToken),
			"base_url":       baseURL,
			"config_index":   strconv.Itoa(i),
		}
		metadata := map[string]any{
			"type":           constant.CodeArts,
			"auth_kind":      coreauth.AuthKindOAuth,
			"access_key":     accessKey,
			"secret_key":     secretKey,
			"security_token": strings.TrimSpace(entry.SecurityToken),
			"base_url":       baseURL,
		}
		if refreshToken := strings.TrimSpace(entry.RefreshToken); refreshToken != "" {
			metadata["refresh_token"] = refreshToken
		}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		if hash := diff.ComputeCodeBuddyCNModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID: id, Provider: constant.CodeArts, Label: "codearts-credentials",
			Prefix: prefix, Status: coreauth.StatusActive, ProxyURL: strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs, Metadata: metadata, CreatedAt: now, UpdatedAt: now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		out = append(out, a)
	}
	return out
}

// synthesizeTraeKeys creates Auth entries for TRAE SOLO CN desktop credentials.
func (s *ConfigSynthesizer) synthesizeTraeKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.TraeKey))
	for i := range cfg.TraeKey {
		entry := cfg.TraeKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		baseURL := strings.TrimSpace(entry.BaseURL)
		if baseURL == "" {
			baseURL = traeDefaultBaseURL
		}
		apiHost := strings.TrimSpace(entry.ApiHost)
		if apiHost == "" {
			apiHost = traeDefaultAPIHost
		}
		prefix := strings.TrimSpace(entry.Prefix)
		id, token := idGen.Next("trae:apikey", key, baseURL, apiHost)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:trae[%s]", token),
			"api_key":      key,
			"base_url":     baseURL,
			"config_index": strconv.Itoa(i),
			"uid":          entry.UID,
			"machine_id":   entry.MachineID,
			"device_id":    entry.DeviceID,
		}
		metadata := map[string]any{
			"access_token": key,
			"api_host":     apiHost,
		}
		if strings.TrimSpace(entry.RefreshToken) != "" {
			metadata["refresh_token"] = entry.RefreshToken
		}
		if strings.TrimSpace(entry.UID) != "" {
			metadata["uid"] = entry.UID
		}
		if strings.TrimSpace(entry.MachineID) != "" {
			metadata["machine_id"] = entry.MachineID
		}
		if strings.TrimSpace(entry.DeviceID) != "" {
			metadata["device_id"] = entry.DeviceID
		}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID: id, Provider: constant.Trae, Label: "trae-solo-cn-apikey",
			Prefix: prefix, Status: coreauth.StatusActive, ProxyURL: strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs, Metadata: metadata, CreatedAt: now, UpdatedAt: now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeQoderCNKeys creates Auth entries for Qoder CN (qoder.cn) credentials.
//
// The stored base_url is the model-server origin. The Qoder CN executor appends
// "/model/v1/chat/completions" to it, correcting for a base URL that already
// carries that full path.
func (s *ConfigSynthesizer) synthesizeQoderCNKeys(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.QoderCNKey))
	for i := range cfg.QoderCNKey {
		entry := cfg.QoderCNKey[i]
		key := strings.TrimSpace(entry.APIKey)
		if key == "" {
			continue
		}
		baseURL := strings.TrimSpace(entry.BaseURL)
		if baseURL == "" {
			baseURL = qoderCNDefaultBaseURL
		}
		prefix := strings.TrimSpace(entry.Prefix)
		id, token := idGen.Next("qoder-cn:apikey", key, baseURL, entry.MachineID)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:qoder-cn[%s]", token),
			"api_key":      key,
			"base_url":     baseURL,
			"config_index": strconv.Itoa(i),
		}
		metadata := map[string]any{
			"type":         "qoder-cn",
			"auth_kind":    "oauth",
			"access_token": key,
			"base_url":     baseURL,
		}
		if strings.TrimSpace(entry.RefreshToken) != "" {
			metadata["refresh_token"] = strings.TrimSpace(entry.RefreshToken)
		}
		if strings.TrimSpace(entry.MachineID) != "" {
			metadata["machine_id"] = strings.TrimSpace(entry.MachineID)
			attrs["machine_id"] = strings.TrimSpace(entry.MachineID)
		}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID: id, Provider: constant.QoderCN, Label: "qoder-cn-apikey",
			Prefix: prefix, Status: coreauth.StatusActive, ProxyURL: strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs, Metadata: metadata, CreatedAt: now, UpdatedAt: now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		out = append(out, a)
	}
	return out
}

// synthesizeMetaKeys creates Auth entries for Meta API keys.
func (s *ConfigSynthesizer) synthesizeMetaKeys(ctx *SynthesisContext) []*coreauth.Auth {
	return s.synthesizeCodexStyleKeys(ctx, ctx.Config.MetaKey, "meta")
}

func (s *ConfigSynthesizer) synthesizeCodexStyleKeys(ctx *SynthesisContext, entries []config.CodexKey, provider string) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		key := strings.TrimSpace(entry.APIKey)
		baseURL := strings.TrimSpace(entry.BaseURL)
		if key == "" && baseURL == "" {
			continue
		}
		prefix := strings.TrimSpace(entry.Prefix)
		proxyURL := strings.TrimSpace(entry.ProxyURL)
		id, token := idGen.Next(provider+":apikey", key, baseURL, proxyURL, prefix, config.FormatSortedHeaders(entry.Headers))
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:%s[%s]", provider, token),
			"config_index": strconv.Itoa(i),
		}
		if key != "" {
			attrs["api_key"] = key
		}
		metadata := map[string]any{}
		if entry.DisableCooling != nil {
			metadata["disable_cooling"] = *entry.DisableCooling
		}
		addRequestRetryToMetadata(entry.RequestRetry, metadata)
		addRequestScopedErrorsToMetadata(entry.RequestScopedErrors, metadata)
		if entry.Priority != 0 {
			attrs["priority"] = strconv.Itoa(entry.Priority)
		}
		addWeightToAttrs(entry.Weight, attrs)
		if baseURL != "" {
			attrs["base_url"] = baseURL
		}
		if entry.Websockets {
			attrs["websockets"] = "true"
		}
		if provider == "codex" && entry.AlphaSearch {
			attrs[coreauth.AttributeCodexAlphaSearch] = "true"
		}
		if hash := diff.ComputeCodexModelsHash(entry.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(entry.Headers, attrs)
		a := &coreauth.Auth{
			ID:         id,
			Provider:   provider,
			Label:      provider + "-apikey",
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   strings.TrimSpace(entry.ProxyURL),
			Attributes: attrs,
			Metadata:   metadata,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, entry.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}

// synthesizeOpenAICompat creates Auth entries for OpenAI-compatible providers.
func (s *ConfigSynthesizer) synthesizeOpenAICompat(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0)
	for i := range cfg.OpenAICompatibility {
		compat := &cfg.OpenAICompatibility[i]
		if compat.Disabled {
			continue
		}
		prefix := strings.TrimSpace(compat.Prefix)
		providerName := strings.ToLower(strings.TrimSpace(compat.Name))
		if providerName == "" {
			providerName = "openai-compatibility"
		}
		internalProviderKey := util.OpenAICompatibleProviderKey(providerName)
		base := strings.TrimSpace(compat.BaseURL)
		disableCooling := compat.DisableCooling

		// Handle new APIKeyEntries format (preferred)
		createdEntries := 0
		for j := range compat.APIKeyEntries {
			entry := &compat.APIKeyEntries[j]
			key := strings.TrimSpace(entry.APIKey)
			proxyURL := strings.TrimSpace(entry.ProxyURL)
			idKind := fmt.Sprintf("openai-compatibility:%s", providerName)
			id, token := idGen.Next(idKind, key, base, proxyURL)
			attrs := map[string]string{
				"source":       fmt.Sprintf("config:%s[%s]", providerName, token),
				"base_url":     base,
				"compat_name":  compat.Name,
				"provider_key": internalProviderKey,
				"config_index": strconv.Itoa(i),
			}
			metadata := map[string]any{}
			if disableCooling != nil {
				metadata["disable_cooling"] = *disableCooling
			}
			addRequestRetryToMetadata(compat.RequestRetry, metadata)
			addRequestScopedErrorsToMetadata(compat.RequestScopedErrors, metadata)
			if compat.Priority != 0 {
				attrs["priority"] = strconv.Itoa(compat.Priority)
			}
			addWeightToAttrs(entry.Weight, attrs)
			if key != "" {
				attrs["api_key"] = key
			}
			if hash := diff.ComputeOpenAICompatModelsHash(compat.Models); hash != "" {
				attrs["models_hash"] = hash
			}
			addConfigHeadersToAttrs(compat.Headers, attrs)
			a := &coreauth.Auth{
				ID:         id,
				Provider:   internalProviderKey,
				Label:      compat.Name,
				Prefix:     prefix,
				Status:     coreauth.StatusActive,
				ProxyURL:   proxyURL,
				Attributes: attrs,
				Metadata:   metadata,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if len(a.Metadata) == 0 {
				a.Metadata = nil
			}
			out = append(out, a)
			createdEntries++
		}
		// Fallback: create entry without API key if no APIKeyEntries
		if createdEntries == 0 {
			idKind := fmt.Sprintf("openai-compatibility:%s", providerName)
			id, token := idGen.Next(idKind, base)
			attrs := map[string]string{
				"source":       fmt.Sprintf("config:%s[%s]", providerName, token),
				"base_url":     base,
				"compat_name":  compat.Name,
				"provider_key": internalProviderKey,
				"config_index": strconv.Itoa(i),
			}
			metadata := map[string]any{}
			if disableCooling != nil {
				metadata["disable_cooling"] = *disableCooling
			}
			addRequestRetryToMetadata(compat.RequestRetry, metadata)
			addRequestScopedErrorsToMetadata(compat.RequestScopedErrors, metadata)
			if compat.Priority != 0 {
				attrs["priority"] = strconv.Itoa(compat.Priority)
			}
			if hash := diff.ComputeOpenAICompatModelsHash(compat.Models); hash != "" {
				attrs["models_hash"] = hash
			}
			addConfigHeadersToAttrs(compat.Headers, attrs)
			a := &coreauth.Auth{
				ID:         id,
				Provider:   internalProviderKey,
				Label:      compat.Name,
				Prefix:     prefix,
				Status:     coreauth.StatusActive,
				Attributes: attrs,
				Metadata:   metadata,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if len(a.Metadata) == 0 {
				a.Metadata = nil
			}
			out = append(out, a)
		}
	}
	return out
}

// synthesizeVertexCompat creates Auth entries for Vertex-compatible providers.
func (s *ConfigSynthesizer) synthesizeVertexCompat(ctx *SynthesisContext) []*coreauth.Auth {
	cfg := ctx.Config
	now := ctx.Now
	idGen := ctx.IDGenerator

	out := make([]*coreauth.Auth, 0, len(cfg.VertexCompatAPIKey))
	for i := range cfg.VertexCompatAPIKey {
		compat := &cfg.VertexCompatAPIKey[i]
		providerName := "vertex"
		base := strings.TrimSpace(compat.BaseURL)

		key := strings.TrimSpace(compat.APIKey)
		prefix := strings.TrimSpace(compat.Prefix)
		proxyURL := strings.TrimSpace(compat.ProxyURL)
		idKind := "vertex:apikey"
		id, token := idGen.Next(idKind, key, base, proxyURL)
		attrs := map[string]string{
			"source":       fmt.Sprintf("config:vertex-apikey[%s]", token),
			"base_url":     base,
			"provider_key": providerName,
			"config_index": strconv.Itoa(i),
		}
		if compat.Priority != 0 {
			attrs["priority"] = strconv.Itoa(compat.Priority)
		}
		addWeightToAttrs(compat.Weight, attrs)
		if key != "" {
			attrs["api_key"] = key
		}
		if hash := diff.ComputeVertexCompatModelsHash(compat.Models); hash != "" {
			attrs["models_hash"] = hash
		}
		addConfigHeadersToAttrs(compat.Headers, attrs)
		metadata := map[string]any{}
		if compat.DisableCooling != nil {
			metadata["disable_cooling"] = *compat.DisableCooling
		}
		addRequestRetryToMetadata(compat.RequestRetry, metadata)
		a := &coreauth.Auth{
			ID:         id,
			Provider:   providerName,
			Label:      "vertex-apikey",
			Prefix:     prefix,
			Status:     coreauth.StatusActive,
			ProxyURL:   proxyURL,
			Attributes: attrs,
			Metadata:   metadata,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, compat.ExcludedModels, "apikey")
		if len(a.Metadata) == 0 {
			a.Metadata = nil
		}
		out = append(out, a)
	}
	return out
}
