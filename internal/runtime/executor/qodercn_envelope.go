package executor

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// Qoder CN's /algo agent transport does not speak OpenAI. The executor rewrites
// the translated OpenAI request into the `agent_chat_generation` envelope and
// folds the upstream SSE back into OpenAI chat.completion chunks. The envelope
// shape mirrors the official CLI (and the interoperable qoder2api bridge).

const (
	// qoderCNAgentSignPath is the path bound into the COSY signature. It omits
	// the "/algo" gateway prefix even though the request URL includes it.
	qoderCNAgentSignPath = "/api/v2/service/pro/sse/agent_chat_generation"
	// qoderCNAgentQuery is the fixed query the gateway expects.
	qoderCNAgentQuery = "?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	// qoderCNAgentID / qoderCNSessionType identify the CLI agent channel.
	qoderCNAgentID    = "agent_common"
	qoderCNSessionTyp = "qodercli"
	// qoderCNDefaultMaxTokens is used when the client omits max_tokens.
	qoderCNDefaultMaxTokens = 32768
)

// qoderCNBuildEnvelope converts a translated OpenAI request body into the Qoder
// agent_chat_generation envelope. userType is bound into aliyun_user_type.
func qoderCNBuildEnvelope(openAIBody []byte, model, userType string) ([]byte, error) {
	if strings.TrimSpace(userType) == "" {
		userType = "personal_standard"
	}
	messages, vision := qoderCNMessages(openAIBody)
	prompt := qoderCNLastUserPrompt(openAIBody)
	maxTokens := int(gjson.GetBytes(openAIBody, "max_tokens").Int())
	if maxTokens <= 0 {
		maxTokens = qoderCNDefaultMaxTokens
	}
	reasoning := strings.TrimSpace(gjson.GetBytes(openAIBody, "reasoning_effort").String()) != ""

	requestID := uuid.NewString()
	businessName := prompt
	if len(businessName) > 30 {
		businessName = businessName[:30]
	}

	envelope := map[string]any{
		"request_id":     requestID,
		"request_set_id": uuid.NewString(),
		"chat_record_id": requestID,
		"stream":         true,
		"chat_task":      "FREE_INPUT",
		"chat_context": map[string]any{
			"chatPrompt": "",
			"extra": map[string]any{
				"context": []any{},
				"modelConfig": map[string]any{
					"is_reasoning": reasoning,
					"key":          model,
				},
				"originalContent": map[string]any{"type": "text", "text": prompt},
			},
			"features":  []any{},
			"imageUrls": nil,
			"text":      map[string]any{"type": "text", "text": prompt},
		},
		"image_urls":       nil,
		"is_reply":         true,
		"is_retry":         false,
		"session_id":       uuid.NewString(),
		"code_language":    "",
		"source":           1,
		"version":          "3",
		"chat_prompt":      "",
		"parameters":       map[string]any{"max_tokens": maxTokens},
		"aliyun_user_type": userType,
		"session_type":     qoderCNSessionTyp,
		"agent_id":         qoderCNAgentID,
		"task_id":          "common",
		"model_config": map[string]any{
			"key":              model,
			"display_name":     model,
			"model":            "",
			"format":           "openai",
			"is_vl":            vision,
			"is_reasoning":     reasoning,
			"api_key":          "",
			"url":              "",
			"source":           "system",
			"max_input_tokens": 180000,
		},
		"business": map[string]any{
			"id":          uuid.NewString(),
			"begin_at":    time.Now().UnixMilli(),
			"scene":       "chat",
			"type":        "chat",
			"sub_type":    "free_input",
			"name":        businessName,
			"language":    "",
			"parent_type": "",
		},
		"messages": messages,
		"tools":    qoderCNTools(openAIBody),
	}
	return json.Marshal(envelope)
}

// qoderCNMessages maps OpenAI messages to the Qoder message shape. It reports
// whether any image part was present so model_config.is_vl can be set.
func qoderCNMessages(body []byte) ([]any, bool) {
	raw := gjson.GetBytes(body, "messages")
	if !raw.IsArray() {
		return []any{}, false
	}
	out := make([]any, 0, len(raw.Array()))
	vision := false
	for _, msg := range raw.Array() {
		switch strings.TrimSpace(msg.Get("role").String()) {
		case "assistant":
			entry := map[string]any{"role": "assistant", "content": qoderCNText(msg.Get("content"))}
			if tc := msg.Get("tool_calls"); tc.Exists() && tc.IsArray() {
				entry["tool_calls"] = tc.Value()
			}
			if strings.TrimSpace(qoderCNAssertString(entry["content"])) == "" && entry["tool_calls"] == nil {
				continue
			}
			out = append(out, entry)
		case "tool":
			text := qoderCNText(msg.Get("content"))
			if strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, map[string]any{
				"role":         "tool",
				"tool_call_id": strings.TrimSpace(msg.Get("tool_call_id").String()),
				"content":      text,
			})
		case "system", "developer":
			text := qoderCNText(msg.Get("content"))
			if strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, map[string]any{"role": "system", "content": text})
		default: // user
			contents, hasImage := qoderCNUserContents(msg.Get("content"))
			if len(contents) == 0 {
				continue
			}
			if hasImage {
				vision = true
			}
			out = append(out, map[string]any{
				"role":     "user",
				"content":  "",
				"contents": contents,
				"response_meta": map[string]any{
					"id": "",
					"usage": map[string]any{
						"prompt_tokens":     0,
						"completion_tokens": 0,
						"total_tokens":      0,
					},
				},
				"reasoning_content_signature": "",
			})
		}
	}
	return out, vision
}

// qoderCNUserContents maps an OpenAI user content value (string or parts array)
// into the Qoder `contents` array, tracking image parts.
func qoderCNUserContents(content gjson.Result) ([]any, bool) {
	if !content.Exists() {
		return nil, false
	}
	if content.Type == gjson.String {
		text := content.String()
		if strings.TrimSpace(text) == "" {
			return nil, false
		}
		return []any{map[string]any{"type": "text", "text": text}}, false
	}
	out := make([]any, 0, len(content.Array()))
	hasImage := false
	for _, part := range content.Array() {
		switch strings.TrimSpace(part.Get("type").String()) {
		case "text", "input_text":
			text := part.Get("text").String()
			if strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, map[string]any{"type": "text", "text": text})
		case "image_url", "input_image":
			imageURL := strings.TrimSpace(part.Get("image_url.url").String())
			if imageURL == "" {
				imageURL = strings.TrimSpace(part.Get("image_url").String())
			}
			if imageURL == "" {
				imageURL = strings.TrimSpace(part.Get("image_url").Get("url").String())
			}
			if imageURL == "" {
				continue
			}
			hasImage = true
			out = append(out, map[string]any{"type": "image_url", "image_url": map[string]any{"url": imageURL}})
		case "file":
			fileURL := strings.TrimSpace(part.Get("file_url").String())
			if fileURL == "" {
				fileURL = strings.TrimSpace(part.Get("data").String())
			}
			if fileURL == "" {
				continue
			}
			hasImage = true
			out = append(out, map[string]any{"type": "image_url", "image_url": map[string]any{"url": fileURL}})
		}
	}
	if len(out) == 0 {
		text := qoderCNText(content)
		if strings.TrimSpace(text) == "" {
			return nil, false
		}
		return []any{map[string]any{"type": "text", "text": text}}, false
	}
	return out, hasImage
}

// qoderCNTools passes OpenAI tool definitions through unchanged (the gateway
// accepts the OpenAI function shape).
func qoderCNTools(body []byte) []any {
	tools := gjson.GetBytes(body, "tools")
	if !tools.IsArray() {
		return []any{}
	}
	out := make([]any, 0, len(tools.Array()))
	for _, tool := range tools.Array() {
		out = append(out, tool.Value())
	}
	return out
}

// qoderCNText flattens an OpenAI content value into plain text.
func qoderCNText(content gjson.Result) string {
	if !content.Exists() {
		return ""
	}
	if content.Type == gjson.String {
		return content.String()
	}
	if content.IsArray() {
		var b strings.Builder
		for _, part := range content.Array() {
			if text := part.Get("text").String(); text != "" {
				if b.Len() > 0 {
					b.WriteString("\n")
				}
				b.WriteString(text)
			}
		}
		return b.String()
	}
	return content.String()
}

// qoderCNLastUserPrompt returns the most recent user text, used for the
// chat_context text fields and the business label.
func qoderCNLastUserPrompt(body []byte) string {
	messages := gjson.GetBytes(body, "messages")
	if !messages.IsArray() {
		return ""
	}
	items := messages.Array()
	for i := len(items) - 1; i >= 0; i-- {
		if strings.TrimSpace(items[i].Get("role").String()) != "user" {
			continue
		}
		if text := qoderCNText(items[i].Get("content")); strings.TrimSpace(text) != "" {
			return text
		}
	}
	return ""
}

func qoderCNAssertString(v any) string {
	s, _ := v.(string)
	return s
}

// qoderCNExtractInner unwraps one upstream SSE frame of the form
// {"headers":{…},"body":"<json string or [DONE]>"} and returns the inner body.
// It returns ok=false for the timing-only footer frames the gateway appends.
func qoderCNExtractInner(dataLine []byte) (inner []byte, done bool, ok bool) {
	if len(dataLine) == 0 {
		return nil, false, false
	}
	body := gjson.GetBytes(dataLine, "body")
	if !body.Exists() {
		return nil, false, false
	}
	if body.String() == "[DONE]" {
		return nil, true, true
	}
	return []byte(body.String()), false, true
}

// qoderCNAPIError reports the {code,message} rejection envelope the gateway
// returns inside a 200 SSE frame for a bad signature or missing permission.
func qoderCNAPIError(inner []byte) string {
	if len(inner) == 0 || gjson.GetBytes(inner, "choices").Exists() {
		return ""
	}
	code := strings.TrimSpace(gjson.GetBytes(inner, "code").String())
	message := strings.TrimSpace(gjson.GetBytes(inner, "message").String())
	if code == "" && message == "" {
		return ""
	}
	if message == "" {
		return code
	}
	if code == "" {
		return message
	}
	return code + ": " + message
}
