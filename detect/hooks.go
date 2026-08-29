package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HookFinding represents a detected lifecycle install hook.
type HookFinding struct {
	SourceFile string
	Ecosystem  string
	HookName   string
	Command    string
	Details    string
}

type npmPackageRaw struct {
	Scripts map[string]string `json:"scripts"`
}

// CheckInstallHooks inspects a directory or manifest file for lifecycle hooks (npm postinstall, setup.py cmdclass, etc.).
func CheckInstallHooks(path string) ([]HookFinding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return checkFileHook(path)
	}

	var findings []HookFinding
	err = filepath.Walk(path, func(p string, f os.FileInfo, err error) error {
		if err != nil || f.IsDir() {
			return nil
		}
		res, err := checkFileHook(p)
		if err == nil && len(res) > 0 {
			findings = append(findings, res...)
		}
		return nil
	})

	return findings, err
}

func checkFileHook(path string) ([]HookFinding, error) {
	base := strings.ToLower(filepath.Base(path))

	switch {
	case base == "package.json" || strings.HasSuffix(base, ".json"):
		return checkNPMHooks(path)
	case base == "setup.py":
		return checkPyPIHooks(path)
	case base == "pyproject.toml":
		return checkPyprojectHooks(path)
	default:
		return nil, nil
	}
}

func checkNPMHooks(path string) ([]HookFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw npmPackageRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil
	}

	suspiciousHooks := []string{"preinstall", "postinstall", "install", "prepare"}
	var findings []HookFinding

	for _, hook := range suspiciousHooks {
		if cmd, exists := raw.Scripts[hook]; exists && strings.TrimSpace(cmd) != "" {
			findings = append(findings, HookFinding{
				SourceFile: path,
				Ecosystem:  "npm",
				HookName:   hook,
				Command:    cmd,
				Details:    fmt.Sprintf("NPM lifecycle install hook '%s' detected running command: '%s'", hook, cmd),
			})
		}
	}

	return findings, nil
}

func checkPyPIHooks(path string) ([]HookFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	var findings []HookFinding
	if strings.Contains(content, "cmdclass") || strings.Contains(content, "install.run") || strings.Contains(content, "develop.run") {
		findings = append(findings, HookFinding{
			SourceFile: path,
			Ecosystem:  "pypi",
			HookName:   "custom_cmdclass",
			Command:    "setup.py custom install build hook override",
			Details:    "Python setup.py contains custom cmdclass install hook override",
		})
	}

	return findings, nil
}

func checkPyprojectHooks(path string) ([]HookFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	var findings []HookFinding
	if strings.Contains(content, "build-backend") && (strings.Contains(content, "custom") || strings.Contains(content, "exec")) {
		findings = append(findings, HookFinding{
			SourceFile: path,
			Ecosystem:  "pypi",
			HookName:   "build_backend_hook",
			Command:    "custom pyproject.toml build-backend hook",
			Details:    "Pyproject.toml contains custom build-backend execution hook",
		})
	}

	return findings, nil
}
