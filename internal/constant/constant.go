// Package constant defines provider name constants used throughout the CLI Proxy API.
// These constants identify different AI service providers and their variants,
// ensuring consistent naming across the application.
package constant

const (
	// Gemini represents the Google Gemini provider identifier.
	Gemini = "gemini"

	// GeminiInteractions represents the native Google Interactions API provider identifier.
	GeminiInteractions = "gemini-interactions"

	// Codex represents the OpenAI Codex provider identifier.
	Codex = "codex"

	// Claude represents the Anthropic Claude provider identifier.
	Claude = "claude"

	// OpenAI represents the OpenAI provider identifier.
	OpenAI = "openai"

	// OpenaiResponse represents the OpenAI response format identifier.
	OpenaiResponse = "openai-response"

	// Antigravity represents the Antigravity response format identifier.
	Antigravity = "antigravity"

	// CodeBuddyCN represents the CodeBuddy CN (Tencent) provider identifier.
	CodeBuddyCN = "codebuddy-cn"

	// CodeBuddyAI represents the CodeBuddy AI (international) provider identifier.
	CodeBuddyAI = "codebuddy-ai"

	// DeepSeekWeb represents the DeepSeek authenticated web-session provider identifier.
	DeepSeekWeb = "deepseek-web"

	// Trae represents the TRAE SOLO CN desktop client provider identifier.
	Trae = "trae"

	// Interactions represents the Google Interactions API format identifier.
	Interactions = "interactions"

	// Xiaohuanxiong represents the SenseTime Xiaohuanxiong (Raccoon) office
	// assistant provider identifier. It authenticates with the desktop-app
	// OAuth authorization-code flow against xiaohuanxiong.com.
	Xiaohuanxiong = "xiaohuanxiong"

	// CodeArts represents the Huawei Cloud CodeArts (CodeArts Work desktop
	// client) provider identifier. It authenticates with an OAuth2 + PKCE +
	// DPoP flow against Huawei Cloud STS, which returns a temporary AK/SK
	// credential triple used to sign every subsequent request.
	CodeArts = "codearts"

	// QoderCN represents the Qoder CN (qoder.cn / qoder.com.cn) provider
	// identifier. It authenticates with a browser + PKCE device polling flow
	// (/device/selectAccounts followed by /api/v1/deviceToken/poll), then sends
	// inference requests to the Qoder model server's OpenAI-compatible
	// /model/v1/chat/completions endpoint.
	QoderCN = "qoder-cn"
)
