package detect

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TokenFinding represents a lexical match for dynamic execution patterns.
type TokenFinding struct {
	FilePath    string
	LineNumber  int
	Pattern     string
	LineSnippet string
	Details     string
}

// TokenScanner performs line-by-line lexical pattern matching for high-risk calls.
type TokenScanner struct {
	numWorkers int
}

// NewTokenScanner creates a new TokenScanner.
func NewTokenScanner(numWorkers int) *TokenScanner {
	if numWorkers <= 0 {
		numWorkers = 4
	}
	return &TokenScanner{numWorkers: numWorkers}
}

var dangerousPatterns = []string{
	"eval(",
	"new Function(",
	"child_process.exec(",
	"child_process.execSync(",
	"Buffer.from(",
	"exec(",
	"os.system(",
	"subprocess.Popen(",
	"shell=True",
}

// ScanFile scans a source file line-by-line for high-risk tokens.
func (s *TokenScanner) ScanFile(path string) ([]TokenFinding, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".js" && ext != ".py" && ext != ".ts" && ext != ".sh" && ext != ".cjs" && ext != ".mjs" {
		return nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []TokenFinding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip pure comment lines
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, pat := range dangerousPatterns {
			if strings.Contains(line, pat) {
				findings = append(findings, TokenFinding{
					FilePath:    path,
					LineNumber:  lineNum,
					Pattern:     pat,
					LineSnippet: strings.TrimSpace(line),
					Details:     fmt.Sprintf("High-risk execution pattern '%s' detected at %s:%d", pat, filepath.Base(path), lineNum),
				})
				break
			}
		}
	}

	return findings, scanner.Err()
}

// ScanDirectory walks a directory concurrently with a bounded worker pool.
func (s *TokenScanner) ScanDirectory(root string) ([]TokenFinding, error) {
	var filesToScan []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			base := strings.ToLower(info.Name())
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".idea" || base == ".vscode" || base == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".js" || ext == ".py" || ext == ".ts" || ext == ".sh" || ext == ".cjs" || ext == ".mjs" {
			filesToScan = append(filesToScan, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	jobs := make(chan string, len(filesToScan))
	results := make(chan []TokenFinding, len(filesToScan))

	for _, f := range filesToScan {
		jobs <- f
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < s.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				f, err := s.ScanFile(path)
				if err == nil && len(f) > 0 {
					results <- f
				}
			}
		}()
	}

	wg.Wait()
	close(results)

	var allFindings []TokenFinding
	for res := range results {
		allFindings = append(allFindings, res...)
	}

	return allFindings, nil
}
