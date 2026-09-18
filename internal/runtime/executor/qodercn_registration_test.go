package executor

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

// TestQoderCNProviderIsFullyRegistered is an integration check that the provider
// is discoverable through every registry the runtime consults.
func TestQoderCNProviderIsFullyRegistered(t *testing.T) {
	if constant.QoderCN != "qoder-cn" {
		t.Fatalf("provider key = %q", constant.QoderCN)
	}
	models := registry.GetQoderCNModels()
	if len(models) == 0 {
		t.Fatal("registry.GetQoderCNModels returned no models")
	}
	// A canonical model must survive the built-in merge.
	found := false
	for _, m := range models {
		if m.ID == "claude-opus-4-6" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("claude-opus-4-6 missing from the Qoder CN catalog")
	}
	// GetStaticModelDefinitionsByChannel must dispatch to the same list.
	byChannel := registry.GetStaticModelDefinitionsByChannel(constant.QoderCN)
	if len(byChannel) != len(models) {
		t.Fatalf("GetStaticModelDefinitionsByChannel(%q) = %d models, want %d", constant.QoderCN, len(byChannel), len(models))
	}
}
