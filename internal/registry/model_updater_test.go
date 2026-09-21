package registry

import (
	"reflect"
	"testing"
)

func TestConfiguredModelsSource(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv("MODELS_FILE", "")
		t.Setenv("MODELS_URL", "")

		modelsFile, urls := configuredModelsSource()
		if modelsFile != "" {
			t.Fatalf("modelsFile = %q, want empty", modelsFile)
		}
		if !reflect.DeepEqual(urls, modelsURLs) {
			t.Fatalf("urls = %v, want %v", urls, modelsURLs)
		}
	})

	t.Run("custom URL", func(t *testing.T) {
		t.Setenv("MODELS_FILE", "")
		t.Setenv("MODELS_URL", " https://example.com/models.json ")

		modelsFile, urls := configuredModelsSource()
		if modelsFile != "" {
			t.Fatalf("modelsFile = %q, want empty", modelsFile)
		}
		want := []string{"https://example.com/models.json"}
		if !reflect.DeepEqual(urls, want) {
			t.Fatalf("urls = %v, want %v", urls, want)
		}
	})

	t.Run("file takes precedence", func(t *testing.T) {
		t.Setenv("MODELS_FILE", " /data/models.json ")
		t.Setenv("MODELS_URL", "https://example.com/models.json")

		modelsFile, urls := configuredModelsSource()
		if modelsFile != "/data/models.json" {
			t.Fatalf("modelsFile = %q, want %q", modelsFile, "/data/models.json")
		}
		if urls != nil {
			t.Fatalf("urls = %v, want nil", urls)
		}
	})
}

func TestDetectChangedProvidersIncludesLocalProviders(t *testing.T) {
	oldData := &staticModelsJSON{
		CodeBuddyCN: []*ModelInfo{{ID: "codebuddy-old"}},
		DeepSeekWeb: []*ModelInfo{{ID: "deepseek-old"}},
	}
	newData := &staticModelsJSON{
		CodeBuddyCN: []*ModelInfo{{ID: "codebuddy-new"}},
		DeepSeekWeb: []*ModelInfo{{ID: "deepseek-new"}},
	}

	got := detectChangedProviders(oldData, newData)
	want := []string{"codebuddy-cn", "deepseek-web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectChangedProviders() = %v, want %v", got, want)
	}
}

func TestDetectChangedProviders_KimiAliases(t *testing.T) {
	oldData := &staticModelsJSON{
		Kimi: []*ModelInfo{{ID: "kimi-k2"}},
	}
	newData := &staticModelsJSON{
		Kimi: []*ModelInfo{{ID: "kimi-k2"}, {ID: "kimi-k3"}},
	}

	changed := detectChangedProviders(oldData, newData)
	expected := map[string]bool{
		"kimi":     false,
		"kimi-ai":  false,
		"kimi.ai":  false,
		"kimi.com": false,
	}

	for _, p := range changed {
		if _, ok := expected[p]; ok {
			expected[p] = true
		}
	}

	for p, found := range expected {
		if !found {
			t.Errorf("expected changed provider %q to be reported, got %v", p, changed)
		}
	}
}
