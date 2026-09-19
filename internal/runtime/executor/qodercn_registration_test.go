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
	// The catalog is server-driven and decrypted from the CN CLI's
	// model_cache_decrypt payload (see the comment on qoderCNBuiltinModels), so the
	// assertion tracks the canonical free-tier identifier rather than the older
	// static-analysis names that never appeared in the decrypted catalog.
	const canonical = "qmodel_38max"
	found := false
	for _, m := range models {
		if m.ID == canonical {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("%s missing from the Qoder CN catalog", canonical)
	}
	// GetStaticModelDefinitionsByChannel must dispatch to the same list.
	byChannel := registry.GetStaticModelDefinitionsByChannel(constant.QoderCN)
	if len(byChannel) != len(models) {
		t.Fatalf("GetStaticModelDefinitionsByChannel(%q) = %d models, want %d", constant.QoderCN, len(byChannel), len(models))
	}
}
