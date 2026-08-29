package tests

import (
	"testing"
	"zerotrust/registry"
)

func TestLiveClientNetworkFallback(t *testing.T) {
	client := registry.NewLiveClient(nil)

	// Test invalid ecosystem or unreachable host
	exists, confirmed, err := client.CheckPackageExistence("invalid_ecosystem", "some-pkg")
	if err == nil {
		t.Errorf("Expected error for invalid ecosystem, got nil")
	}
	if confirmed || exists {
		t.Errorf("Expected exists=false, confirmed=false on error fallback, got exists=%t, confirmed=%t", exists, confirmed)
	}
}
