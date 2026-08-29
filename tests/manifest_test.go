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

func TestParsePip(t *testing.T) {
	path := filepath.Join("testdata", "requirements_sample.txt")
	deps, err := manifest.ParsePip(path)
	if err != nil {
		t.Fatalf("ParsePip failed: %v", err)
	}
	if len(deps) != 3 {
		t.Errorf("expected 3 dependencies in requirements_sample.txt, got %d", len(deps))
	}

	line1Name, line1Ver := manifest.ParsePipLine("requests==2.31.0")
	if line1Name != "requests" || line1Ver != "==2.31.0" {
		t.Errorf("parsePipLine requests failed: got %s, %s", line1Name, line1Ver)
	}

	line2Name, line2Ver := manifest.ParsePipLine("flask[async]>=2.0.0")
	if line2Name != "flask" || line2Ver != ">=2.0.0" {
		t.Errorf("parsePipLine extras failed: got %s, %s", line2Name, line2Ver)
	}
}

func TestParseGoMod(t *testing.T) {
	deps, err := manifest.ParseGoMod("../go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod failed on root go.mod: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 dependencies in root go.mod, got %d", len(deps))
	}
}

func TestParseCargo(t *testing.T) {
	name, ver := manifest.ParseCargoDependencyLine("serde = \"1.0.195\"")
	if name != "serde" || ver != "1.0.195" {
		t.Errorf("cargo simple line failed: got %s, %s", name, ver)
	}

	name2, ver2 := manifest.ParseCargoDependencyLine("tokio = { version = \"1.35.1\", features = [\"full\"] }")
	if name2 != "tokio" || ver2 != "1.35.1" {
		t.Errorf("cargo inline table failed: got %s, %s", name2, ver2)
	}
}
