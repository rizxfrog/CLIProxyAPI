package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRegisterDeepSeekWebExecutor(t *testing.T) {
	service := &Service{cfg: &config.Config{}, coreManager: coreauth.NewManager(nil, nil, nil)}
	service.registerExecutorForAuth(&coreauth.Auth{ID: "deepseek-web", Provider: constant.DeepSeekWeb}, false)
	registered, ok := service.coreManager.Executor(constant.DeepSeekWeb)
	if !ok {
		t.Fatal("deepseek-web executor was not registered")
	}
	if _, okType := registered.(*runtimeexecutor.DeepSeekWebExecutor); !okType {
		t.Fatalf("executor type = %T, want *executor.DeepSeekWebExecutor", registered)
	}
}

func TestRegisterDeepSeekWebModels(t *testing.T) {
	const authID = "deepseek-web-model-test"
	modelRegistry := registry.GetGlobalRegistry()
	modelRegistry.UnregisterClient(authID)
	t.Cleanup(func() { modelRegistry.UnregisterClient(authID) })

	service := &Service{cfg: &config.Config{}}
	service.registerModelsForAuth(context.Background(), &coreauth.Auth{
		ID: authID, Provider: constant.DeepSeekWeb,
		Attributes: map[string]string{"api_key": "token", "base_url": runtimeexecutor.DeepSeekWebBaseURL},
	})
	got := modelRegistry.GetModelsForClient(authID)
	want := registry.GetDeepSeekWebModels()
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("registered models = %d, want %d", len(got), len(want))
	}
}
