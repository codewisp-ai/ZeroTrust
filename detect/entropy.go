package detect

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// EntropyFinding represents a detected high-entropy payload block.
type EntropyFinding struct {
	FilePath   string
	MaxEntropy float64
	Offset     int64
	WindowSize int
	Threshold  float64
	Details    string
}

// EntropyScanner scans files for obfuscated high-entropy binary/encoded chunks.
type EntropyScanner struct {
	threshold  float64
	windowSize int
	numWorkers int
}

// NewEntropyScanner creates a new EntropyScanner.
func NewEntropyScanner(threshold float64, numWorkers int) *EntropyScanner {
	if threshold <= 0 {
		threshold = 7.2
	}
	if numWorkers <= 0 {
		numWorkers = 4
	}
	return &EntropyScanner{
		threshold:  threshold,
		windowSize: 256,
		numWorkers: numWorkers,
	}
}

// CalculateShannonEntropy calculates Shannon entropy in bits per byte for a byte slice.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]int, 256)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	dataLen := float64(len(data))

	for _, count := range freq {
		p := float64(count) / dataLen
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

var skippedExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".svg": true,
	".mp4": true, ".mp3": true, ".wav": true, ".zip": true, ".gz": true, ".tar": true,
	".tgz": true, ".7z": true, ".rar": true, ".exe": true, ".dll": true, ".so": true,
	".dylib": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".pdf": true,
	".pyc": true, ".wasm": true,
}

// ShouldSkipFile checks extension allowlist/denylist heuristic.
func ShouldSkipFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return skippedExtensions[ext]
}

// ScanFile scans a single file for sliding windows with entropy > threshold.
func (s *EntropyScanner) ScanFile(path string) ([]EntropyFinding, error) {
	if ShouldSkipFile(path) {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) < s.windowSize {
		ent := CalculateShannonEntropy(data)
		if ent > s.threshold {
			return []EntropyFinding{{
				FilePath:   path,
				MaxEntropy: ent,
				Offset:     0,
				WindowSize: len(data),
				Threshold:  s.threshold,
				Details:    fmt.Sprintf("High entropy block (%.2f > %.2f bits/byte) in %s", ent, s.threshold, filepath.Base(path)),
			}}, nil
		}
		return nil, nil
	}

	var findings []EntropyFinding
	step := 128 // 50% overlap for windowing speed

	for i := 0; i+s.windowSize <= len(data); i += step {
		window := data[i : i+s.windowSize]
		ent := CalculateShannonEntropy(window)
		if ent > s.threshold {
			findings = append(findings, EntropyFinding{
				FilePath:   path,
				MaxEntropy: ent,
				Offset:     int64(i),
				WindowSize: s.windowSize,
				Threshold:  s.threshold,
				Details:    fmt.Sprintf("High entropy payload block (%.2f > %.2f bits/byte at offset %d) in %s", ent, s.threshold, i, filepath.Base(path)),
			})
			// Jump past this high-entropy region to avoid duplicate alerts in same file
			i += s.windowSize
		}
	}

	return findings, nil
}

// ScanDirectory walks root concurrently using a bounded worker pool.
func (s *EntropyScanner) ScanDirectory(root string) ([]EntropyFinding, error) {
	var filesToScan []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			base := strings.ToLower(info.Name())
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".idea" || base == ".vscode" || base == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if !ShouldSkipFile(path) {
			filesToScan = append(filesToScan, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	jobs := make(chan string, len(filesToScan))
	results := make(chan []EntropyFinding, len(filesToScan))

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

	var allFindings []EntropyFinding
	for res := range results {
		allFindings = append(allFindings, res...)
	}

	return allFindings, nil
}
