package tests

import (
	"path/filepath"
	"testing"

	"zerotrust/manifest"
)

func TestParseNPM(t *testing.T) {
	path := filepath.Join("testdata", "malicious_package.json")
	deps, err := manifest.ParseNPM(path)
	if err != nil {
		t.Fatalf("ParseNPM failed: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]manifest.Dependency)
	for _, d := range deps {
		depMap[d.Name] = d
	}

	if d, ok := depMap["express"]; !ok || d.IsDev {
		t.Errorf("express missing or incorrectly marked as dev")
	}

	if d, ok := depMap["lodahs"]; !ok || !d.IsDev {
		t.Errorf("lodahs missing or not marked as dev")
	}
}
