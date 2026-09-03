package helps_test

import (
	"context"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	helps "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/thinking/provider/openai"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// oauthThinkingExecutor models an OAuth provider (like codebuddy-cn) whose
// models carry thinking capabilities resolved through the global registry
// instead of a configured API-key definition.
type oauthThinkingExecutor struct {
	seenModel string
}

func (*oauthThinkingExecutor) Identifier() string { return "openai" }

func (e *oauthThinkingExecutor) Execute(_ context.Context, _ *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.seenModel = req.Model
	body := req.Payload
	out, err := helps.ApplyRequestThinking(body, req, opts, opts.SourceFormat.String(), "openai", "openai")
	return cliproxyexecutor.Response{Payload: out}, err
}

func (e *oauthThinkingExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	response, err := e.Execute(ctx, auth, req, opts)
	if err != nil {
		return nil, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: response.Payload}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (*oauthThinkingExecutor) Refresh(_ context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

func (e *oauthThinkingExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (*oauthThinkingExecutor) HttpRequest(context.Context, *cliproxyauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// setupPrefixedOAuth registers an OAuth credential with prefix "tenant" that
// serves "shared-model" with thinking support.
func setupPrefixedOAuth(t *testing.T, force bool) (*cliproxyauth.Manager, *oauthThinkingExecutor, *cliproxyauth.Auth) {
	t.Helper()
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{ForceModelPrefix: force},
	})
	executor := &oauthThinkingExecutor{}
	manager.RegisterExecutor(executor)
	auth := &cliproxyauth.Auth{
		ID:       "tenant-oauth-auth",
		Provider: "openai",
		Prefix:   "tenant",
		Attributes: map[string]string{
			cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindOAuth,
		},
	}
	modelRegistry := registry.GetGlobalRegistry()
	// Both the native name and the alias are registered, sharing capabilities.
	modelRegistry.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{
		{ID: "shared-model", Type: "openai", Thinking: &registry.ThinkingSupport{Levels: []string{"high"}}},
		{ID: "tenant/shared-model", Type: "openai", Thinking: &registry.ThinkingSupport{Levels: []string{"high"}}},
	})
	t.Cleanup(func() { modelRegistry.UnregisterClient(auth.ID) })
	if _, errRegister := manager.Register(t.Context(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	return manager, executor, auth
}

func TestForcedPrefixRejectsNativeModelName(t *testing.T) {
	manager, _, _ := setupPrefixedOAuth(t, true)
	original := []byte(`{"model":"shared-model","messages":[{"role":"user","content":"hi"}]}`)
	_, err := manager.Execute(t.Context(), []string{"openai"}, cliproxyexecutor.Request{
		Model:   "shared-model",
		Payload: original,
		Format:  sdktranslator.FormatOpenAI,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, OriginalRequest: original})
	if err == nil {
		t.Fatal("Execute(native name) succeeded, want rejection while force-model-prefix is enabled")
	}
}

func TestForcedPrefixAllowsAliasAndPreservesThinking(t *testing.T) {
	manager, executor, _ := setupPrefixedOAuth(t, true)
	original := []byte(`{"model":"tenant/shared-model","reasoning_effort":"high","messages":[{"role":"user","content":"hi"}]}`)
	response, err := manager.Execute(t.Context(), []string{"openai"}, cliproxyexecutor.Request{
		Model:   "tenant/shared-model",
		Payload: original,
		Format:  sdktranslator.FormatOpenAI,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, OriginalRequest: original})
	if err != nil {
		t.Fatalf("Execute(alias) error = %v", err)
	}
	if executor.seenModel != "shared-model" {
		t.Fatalf("executor model = %q, want upstream native name shared-model", executor.seenModel)
	}
	if got := gjson.GetBytes(response.Payload, "reasoning_effort").String(); got != "high" {
		t.Fatalf("reasoning_effort = %q, want high preserved; body=%s", got, response.Payload)
	}
}

func TestForcedPrefixRejectsAuthWithoutPrefix(t *testing.T) {
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{ForceModelPrefix: true},
	})
	executor := &oauthThinkingExecutor{}
	manager.RegisterExecutor(executor)
	auth := &cliproxyauth.Auth{
		ID:       "unprefixed-oauth-auth",
		Provider: "openai",
		Attributes: map[string]string{
			cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindOAuth,
		},
	}
	modelRegistry := registry.GetGlobalRegistry()
	modelRegistry.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{
		{ID: "shared-model", Type: "openai", Thinking: &registry.ThinkingSupport{Levels: []string{"high"}}},
	})
	t.Cleanup(func() { modelRegistry.UnregisterClient(auth.ID) })
	if _, errRegister := manager.Register(t.Context(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	original := []byte(`{"model":"shared-model","messages":[{"role":"user","content":"hi"}]}`)
	_, err := manager.Execute(t.Context(), []string{"openai"}, cliproxyexecutor.Request{
		Model:   "shared-model",
		Payload: original,
		Format:  sdktranslator.FormatOpenAI,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, OriginalRequest: original})
	if err == nil {
		t.Fatal("Execute() succeeded for auth without prefix, want rejection while force-model-prefix is enabled")
	}
}

func TestPrefixDisabledAllowsNativeAndAlias(t *testing.T) {
	for _, model := range []string{"shared-model", "tenant/shared-model"} {
		manager, executor, _ := setupPrefixedOAuth(t, false)
		original := []byte(`{"model":"` + model + `","reasoning_effort":"high","messages":[{"role":"user","content":"hi"}]}`)
		response, err := manager.Execute(t.Context(), []string{"openai"}, cliproxyexecutor.Request{
			Model:   model,
			Payload: original,
			Format:  sdktranslator.FormatOpenAI,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, OriginalRequest: original})
		if err != nil {
			t.Fatalf("Execute(%s) error = %v", model, err)
		}
		if executor.seenModel != "shared-model" {
			t.Fatalf("Execute(%s) executor model = %q, want shared-model", model, executor.seenModel)
		}
		if got := gjson.GetBytes(response.Payload, "reasoning_effort").String(); got != "high" {
			t.Fatalf("Execute(%s) reasoning_effort = %q, want high; body=%s", model, got, response.Payload)
		}
	}
}
