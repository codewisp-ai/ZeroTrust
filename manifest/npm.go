package manifest

import (
	"encoding/json"
	"fmt"
	"os"
)

type npmManifestRaw struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// ParseNPM parses a package.json file into Dependency structs using encoding/json.
func ParseNPM(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	var raw npmManifestRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	var deps []Dependency
	addDeps := func(m map[string]string, isDev bool) {
		for name, version := range m {
			deps = append(deps, Dependency{
				Name:              name,
				VersionConstraint: version,
				Ecosystem:         "npm",
				SourceFile:        path,
				IsDev:             isDev,
			})
		}
	}

	addDeps(raw.Dependencies, false)
	addDeps(raw.DevDependencies, true)
	addDeps(raw.PeerDependencies, false)
	addDeps(raw.OptionalDependencies, false)

	return deps, nil
}
