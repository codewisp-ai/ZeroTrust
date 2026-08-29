package manifest

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Dependency represents a declared dependency in a project manifest.
type Dependency struct {
	Name              string
	VersionConstraint string
	Ecosystem         string // "npm", "pypi", "crates", "gomod"
	LineNumber        int
	SourceFile        string
	IsDev             bool
}

// ParseManifest auto-detects the manifest type by filename and parses it.
func ParseManifest(path string) ([]Dependency, error) {
	filename := strings.ToLower(filepath.Base(path))

	switch {
	case filename == "package.json" || strings.HasSuffix(filename, ".json"):
		return ParseNPM(path)
	case filename == "requirements.txt" || strings.HasSuffix(filename, "requirements.txt") || strings.HasSuffix(filename, ".req") || strings.HasSuffix(filename, "requirements.in"):
		return ParsePip(path)
	case filename == "go.mod":
		return ParseGoMod(path)
	case filename == "cargo.toml":
		return ParseCargo(path)
	default:
		return nil, fmt.Errorf("unsupported manifest file: %s", filepath.Base(path))
	}
}
