package manifest

import (
	"bufio"
	"os"
	"strings"
)

// ParseCargo parses Cargo.toml files for dependency declarations using a hand-rolled TOML tokenizer.
func ParseCargo(path string) ([]Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(file)
	lineNum := 0

	currentSection := ""

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		// Detect section headers e.g. [dependencies], [dev-dependencies], [build-dependencies]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}

		if isDependencySection(currentSection) {
			pkgName, pkgVer := ParseCargoDependencyLine(line)
			if pkgName != "" {
				isDev := strings.Contains(currentSection, "dev-dependencies")
				deps = append(deps, Dependency{
					Name:              pkgName,
					VersionConstraint: pkgVer,
					Ecosystem:         "crates",
					LineNumber:        lineNum,
					SourceFile:        path,
					IsDev:             isDev,
				})
			}
		}
	}

	return deps, scanner.Err()
}

func isDependencySection(sec string) bool {
	sec = strings.ToLower(sec)
	return sec == "dependencies" || sec == "dev-dependencies" || sec == "build-dependencies" ||
		strings.HasSuffix(sec, ".dependencies")
}

// ParseCargoDependencyLine parses a key-value dependency line from Cargo.toml.
func ParseCargoDependencyLine(line string) (name, version string) {
	eqIdx := strings.Index(line, "=")
	if eqIdx == -1 {
		return "", ""
	}

	rawName := strings.TrimSpace(line[:eqIdx])
	rawValue := strings.TrimSpace(line[eqIdx+1:])

	name = strings.Trim(rawName, "\"'\t ")
	if name == "" {
		return "", ""
	}

	// Simple string value: serde = "1.0.195"
	if strings.HasPrefix(rawValue, "\"") || strings.HasPrefix(rawValue, "'") {
		version = strings.Trim(rawValue, "\"'\t ")
		return name, version
	}

	// Inline table: tokio = { version = "1.35.1", features = ["full"] }
	if strings.HasPrefix(rawValue, "{") && strings.HasSuffix(rawValue, "}") {
		inner := rawValue[1 : len(rawValue)-1]
		pairs := strings.Split(inner, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(kv[0])
				v := strings.TrimSpace(kv[1])
				if k == "version" {
					version = strings.Trim(v, "\"'\t ")
					return name, version
				}
			}
		}
		return name, "*"
	}

	return name, rawValue
}
