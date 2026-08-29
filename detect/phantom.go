package detect

import (
	"fmt"

	"zerotrust/bloom"
	"zerotrust/manifest"
	"zerotrust/trie"
)

// PhantomFinding represents a flagged non-existent or hallucinated package finding.
type PhantomFinding struct {
	Dependency manifest.Dependency
	Confidence string // "LOW (not in offline corpus)" or "HIGH (confirmed non-existent via live registry)"
	Details    string
}

// PhantomDetector detects non-existent or AI-hallucinated package names.
type PhantomDetector struct {
	bloomFilter *bloom.Filter
	trie        *trie.Trie
}

// NewPhantomDetector creates a new detector populated with offline corpus data.
func NewPhantomDetector(bf *bloom.Filter, tr *trie.Trie) *PhantomDetector {
	return &PhantomDetector{
		bloomFilter: bf,
		trie:        tr,
	}
}

// Check evaluates a dependency against the offline corpus.
func (d *PhantomDetector) Check(dep manifest.Dependency) *PhantomFinding {
	name := dep.Name

	// If found in Bloom filter or Trie search, high probability it is real
	if d.bloomFilter.Contains(name) || d.trie.Search(name) {
		return nil
	}

	// Not found in offline corpus -> flag with low confidence (offline)
	return &PhantomFinding{
		Dependency: dep,
		Confidence: "LOW (not in offline corpus)",
		Details:    fmt.Sprintf("Package '%s' not found in offline top package corpus for ecosystem '%s'", name, dep.Ecosystem),
	}
}
