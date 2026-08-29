package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"zerotrust/bloom"
	"zerotrust/cache"
	"zerotrust/data"
	"zerotrust/detect"
	"zerotrust/internal/build"
	"zerotrust/manifest"
	"zerotrust/registry"
	"zerotrust/trie"
	"zerotrust/ui"
)

func main() {
	var (
		targetPath string
		liveFlag   bool
		htmlPath   string
		format     string
		failOn     string
		threshold  float64
		workers    int
		noColor    bool
		verFlag    bool
	)

	flag.StringVar(&targetPath, "path", ".", "Path to project manifest file or directory to scan")
	flag.StringVar(&targetPath, "p", ".", "Path to project manifest file or directory to scan (shorthand)")
	flag.BoolVar(&liveFlag, "live", false, "Opt-in live HTTP verification against official registries (default false/offline-first)")
	flag.BoolVar(&liveFlag, "l", false, "Opt-in live HTTP verification (shorthand)")
	flag.StringVar(&htmlPath, "html", "", "Generate static HTML report at specified output file path")
	flag.StringVar(&htmlPath, "o", "", "Generate static HTML report (shorthand)")
	flag.StringVar(&format, "format", "text", "Output format: text, json, sarif (default text)")
	flag.StringVar(&format, "f", "text", "Output format: text, json, sarif (shorthand)")
	flag.StringVar(&failOn, "fail-on", "low", "Minimum finding severity to trigger exit code 1: low, medium, high, none (default low)")
	flag.Float64Var(&threshold, "threshold", 7.2, "Shannon entropy threshold in bits/byte for obfuscated payload scanner")
	flag.Float64Var(&threshold, "t", 7.2, "Shannon entropy threshold (shorthand)")
	flag.IntVar(&workers, "workers", 4, "Number of concurrent worker goroutines")
	flag.IntVar(&workers, "w", 4, "Number of concurrent worker goroutines (shorthand)")
	flag.BoolVar(&noColor, "no-color", false, "Disable ANSI color escape sequences in terminal output")
	flag.BoolVar(&verFlag, "version", false, "Print version metadata and exit")
	flag.BoolVar(&verFlag, "v", false, "Print version metadata (shorthand)")

	flag.Parse()

	if verFlag {
		fmt.Println(build.String())
		os.Exit(0)
	}

	useColor := !noColor && format == "text"

	if format == "text" {
		fmt.Println(ui.Colorize("Initializing ZeroTrust engine & loading offline corpora...", ui.BoldCyan, useColor))
	} else {
		fmt.Fprintln(os.Stderr, "Initializing ZeroTrust engine & loading offline corpora...")
	}

	// 1. Load Corpora
	corporaMap, err := data.LoadAllCorpora()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading embedded package corpora: %v\n", err)
		os.Exit(1)
	}

	// 2. Build Data Structures (Bloom Filter & Prefix Trie per ecosystem)
	combinedBF := bloom.New(10000, 0.001)
	combinedTrie := trie.New()
	for _, names := range corporaMap {
		for _, name := range names {
			combinedBF.Add(name)
			combinedTrie.Insert(name)
		}
	}

	phantomDet := detect.NewPhantomDetector(combinedBF, combinedTrie)
	typosquatDet := detect.NewTyposquatDetector(combinedTrie)
	entropyScan := detect.NewEntropyScanner(threshold, workers)
	tokenScan := detect.NewTokenScanner(workers)

	engine := detect.NewEngine(phantomDet, typosquatDet, entropyScan, tokenScan, workers)

	// 3. Locate and Parse Manifests
	var allDeps []manifest.Dependency
	info, err := os.Stat(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Target path error: %v\n", err)
		os.Exit(1)
	}

	if !info.IsDir() {
		deps, err := manifest.ParseManifest(targetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning parsing manifest %s: %v\n", targetPath, err)
		} else {
			allDeps = append(allDeps, deps...)
		}
	} else {
		// Scan directory recursively for manifest files
		_ = filepath.Walk(targetPath, func(p string, f os.FileInfo, err error) error {
			if err != nil || f.IsDir() {
				return nil
			}
			base := strings.ToLower(f.Name())
			if base == "package.json" || base == "requirements.txt" || base == "go.mod" || base == "cargo.toml" ||
				strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".req") || strings.HasSuffix(base, "requirements.in") || strings.HasSuffix(base, "requirements.txt") {
				deps, err := manifest.ParseManifest(p)
				if err == nil && len(deps) > 0 {
					allDeps = append(allDeps, deps...)
				}
			}
			return nil
		})
	}

	// 4. Execute Engine Audit
	report, err := engine.FullAudit(allDeps, targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(1)
	}

	// 5. Opt-in Live Verification
	if liveFlag && len(report.PhantomFindings) > 0 {
		if format == "text" {
			fmt.Println(ui.Colorize("Running opt-in live registry verification over net/http...", ui.Yellow, useColor))
		} else {
			fmt.Fprintln(os.Stderr, "Running opt-in live registry verification over net/http...")
		}

		kvStore, _ := cache.NewKVStore(".zerotrust-cache.kv")
		liveClient := registry.NewLiveClient(kvStore)

		var updatedPhantoms []detect.PhantomFinding
		for _, pf := range report.PhantomFindings {
			exists, confirmed, err := liveClient.CheckPackageExistence(pf.Dependency.Ecosystem, pf.Dependency.Name)
			if err != nil {
				if format == "text" {
					fmt.Printf(ui.Colorize("Live check warning for %s: %v (falling back to offline result)\n", ui.Yellow, useColor), pf.Dependency.Name, err)
				}
				updatedPhantoms = append(updatedPhantoms, pf)
			} else if confirmed && !exists {
				pf.Confidence = "HIGH (confirmed non-existent via live registry)"
				pf.Details = fmt.Sprintf("Confirmed non-existent package '%s' on official %s registry", pf.Dependency.Name, pf.Dependency.Ecosystem)
				updatedPhantoms = append(updatedPhantoms, pf)
			}
		}
		report.PhantomFindings = updatedPhantoms
	}

	// 6. Render Outputs
	switch strings.ToLower(format) {
	case "json":
		if err := ui.RenderJSONReport(report, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering JSON report: %v\n", err)
		}
	case "sarif":
		if err := ui.RenderSARIFReport(report, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering SARIF report: %v\n", err)
		}
	default:
		ui.RenderTerminalReport(report, useColor)
	}

	if htmlPath != "" {
		if err := ui.RenderHTMLReport(report, htmlPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering HTML report: %v\n", err)
		} else {
			if format == "text" {
				fmt.Println(ui.Colorize("HTML report written to: "+htmlPath, ui.BoldGreen, useColor))
			} else {
				fmt.Fprintf(os.Stderr, "HTML report written to: %s\n", htmlPath)
			}
		}
	}

	// 7. Severity-Aware Exit Code Evaluation
	var highCount, mediumCount, lowCount int

	for _, pf := range report.PhantomFindings {
		if strings.HasPrefix(pf.Confidence, "HIGH") {
			highCount++
		} else {
			lowCount++
		}
	}
	for range report.TyposquatFindings {
		mediumCount++
	}
	for range report.HookFindings {
		highCount++
	}
	for range report.EntropyFindings {
		highCount++
	}
	for range report.TokenFindings {
		mediumCount++
	}

	totalIssues := highCount + mediumCount + lowCount

	switch strings.ToLower(failOn) {
	case "none":
		os.Exit(0)
	case "high":
		if highCount > 0 {
			os.Exit(1)
		}
	case "medium":
		if highCount > 0 || mediumCount > 0 {
			os.Exit(1)
		}
	case "low":
		fallthrough
	default:
		if totalIssues > 0 {
			os.Exit(1)
		}
	}
}
