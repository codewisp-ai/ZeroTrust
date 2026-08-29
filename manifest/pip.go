package manifest

import (
	"bufio"
	"os"
	"strings"
)

// ParsePip parses requirements.txt files into Dependency structs.
func ParsePip(path string) ([]Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, empty lines, and options (-r, -e, --extra-index-url)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		name, version := ParsePipLine(line)
		if name != "" {
			deps = append(deps, Dependency{
				Name:              name,
				VersionConstraint: version,
				Ecosystem:         "pypi",
				LineNumber:        lineNum,
				SourceFile:        path,
				IsDev:             false,
			})
		}
	}

	return deps, scanner.Err()
}

// ParsePipLine parses a single requirements.txt line.
func ParsePipLine(line string) (name, version string) {
	// Handle extras syntax e.g., package[extra]==1.0
	namePart := line
	verPart := "*"

	operators := []string{"==", ">=", "<=", "~=", "!=", ">", "<", "==="}
	for _, op := range operators {
		if idx := strings.Index(line, op); idx != -1 {
			namePart = line[:idx]
			verPart = line[idx:]
			break
		}
	}

	namePart = strings.TrimSpace(namePart)
	// Strip extras if present e.g. requests[security] -> requests
	if idx := strings.Index(namePart, "["); idx != -1 {
		namePart = namePart[:idx]
	}

	return strings.TrimSpace(namePart), strings.TrimSpace(verPart)
}
