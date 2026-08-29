package detect

import (
	"fmt"
	"strings"

	"zerotrust/manifest"
	"zerotrust/trie"
)

// TyposquatFinding represents a detected typosquatted package name.
type TyposquatFinding struct {
	Dependency    manifest.Dependency
	TargetPackage string
	EditDistance  int
	Details       string
}

// TyposquatDetector analyzes dependencies for typosquat similarity.
type TyposquatDetector struct {
	trie *trie.Trie
}

// NewTyposquatDetector creates a new TyposquatDetector.
func NewTyposquatDetector(tr *trie.Trie) *TyposquatDetector {
	return &TyposquatDetector{trie: tr}
}

// Check evaluates a single dependency against candidate corpus package names.
func (d *TyposquatDetector) Check(dep manifest.Dependency) *TyposquatFinding {
	name := strings.ToLower(dep.Name)

	candidates := d.trie.FindCandidatesForWord(name, 50)
	minDist := 999
	bestMatch := ""

	for _, cand := range candidates {
		candLower := strings.ToLower(cand)

		// CRITICAL RULE: Exact matches MUST NEVER flag as typosquats
		if name == candLower {
			return nil
		}

		dist := LevenshteinDistance(name, candLower)
		if dist > 0 && dist <= 2 && dist < minDist {
			minDist = dist
			bestMatch = cand
		}
	}

	if bestMatch != "" && minDist <= 2 {
		return &TyposquatFinding{
			Dependency:    dep,
			TargetPackage: bestMatch,
			EditDistance:  minDist,
			Details:       fmt.Sprintf("Dependency '%s' is suspiciously close to popular package '%s' (Levenshtein distance: %d)", dep.Name, bestMatch, minDist),
		}
	}

	return nil
}

// LevenshteinDistance computes classic dynamic-programming edit distance O(n*m) using stdlib slices.
func LevenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	len1, len2 := len(r1), len(r2)

	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}

	// Matrix rows
	dp := make([][]int, len1+1)
	for i := range dp {
		dp[i] = make([]int, len2+1)
		dp[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		dp[0][j] = j
	}

	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}

			dp[i][j] = min3(
				dp[i-1][j]+1,      // deletion
				dp[i][j-1]+1,      // insertion
				dp[i-1][j-1]+cost, // substitution
			)
		}
	}

	return dp[len1][len2]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
