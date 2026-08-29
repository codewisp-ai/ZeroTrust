package manifest

import (
	"bufio"
	"os"
	"strings"
)

// ParseGoMod parses a go.mod file for require statements.
func ParseGoMod(path string) ([]Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(file)
	lineNum := 0
	inRequireBlock := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Remove inline comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}

		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if inRequireBlock {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:              parts[0],
					VersionConstraint: parts[1],
					Ecosystem:         "gomod",
					LineNumber:        lineNum,
					SourceFile:        path,
				})
			}
			continue
		}

		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line[7:])
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:              parts[0],
					VersionConstraint: parts[1],
					Ecosystem:         "gomod",
					LineNumber:        lineNum,
					SourceFile:        path,
				})
			}
		}
	}

	return deps, scanner.Err()
}
