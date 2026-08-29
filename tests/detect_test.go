package tests

import (
	"path/filepath"
	"testing"

	"zerotrust/bloom"
	"zerotrust/detect"
	"zerotrust/manifest"
	"zerotrust/trie"
)

func TestPhantomAndTyposquatDetectors(t *testing.T) {
	bf := bloom.New(1000, 0.01)
	tr := trie.New()

	realPkgs := []string{"express", "requests", "lodash", "react"}
	for _, p := range realPkgs {
		bf.Add(p)
		tr.Insert(p)
	}

	phantomDet := detect.NewPhantomDetector(bf, tr)
	typosquatDet := detect.NewTyposquatDetector(tr)

	// Test 1: Real package exact match (must NOT flag phantom OR typosquat)
	realDep := manifest.Dependency{Name: "requests", Ecosystem: "pypi"}
	if pf := phantomDet.Check(realDep); pf != nil {
		t.Errorf("Real package 'requests' incorrectly flagged as phantom: %v", pf)
	}
	if tf := typosquatDet.Check(realDep); tf != nil {
		t.Errorf("CRITICAL ERROR: Exact match package 'requests' incorrectly flagged as typosquat: %v", tf)
	}

	// Test 2: Typosquat candidate 'reqeusts' (should flag as typosquat)
	typoDep := manifest.Dependency{Name: "reqeusts", Ecosystem: "pypi"}
	tf := typosquatDet.Check(typoDep)
	if tf == nil {
		t.Errorf("Typosquat package 'reqeusts' was not flagged")
	} else if tf.TargetPackage != "requests" || tf.EditDistance != 2 {
		t.Errorf("Unexpected typosquat finding: target=%s, dist=%d", tf.TargetPackage, tf.EditDistance)
	}

	// Test 3: Hallucinated / Phantom package
	slopDep := manifest.Dependency{Name: "express-ai-super-helper-xyz", Ecosystem: "npm"}
	pf := phantomDet.Check(slopDep)
	if pf == nil {
		t.Errorf("Phantom package 'express-ai-super-helper-xyz' was not flagged")
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1, s2 string
		want   int
	}{
		{"requests", "requests", 0},
		{"reqeusts", "requests", 2},
		{"lodahs", "lodash", 2},
		{"express", "exps", 3},
	}

	for _, tc := range tests {
		got := detect.LevenshteinDistance(tc.s1, tc.s2)
		if got != tc.want {
			t.Errorf("LevenshteinDistance(%q, %q) = %d, want %d", tc.s1, tc.s2, got, tc.want)
		}
	}
}

func TestInstallHooksDetector(t *testing.T) {
	path := filepath.Join("testdata", "malicious_package.json")
	findings, err := detect.CheckInstallHooks(path)
	if err != nil {
		t.Fatalf("CheckInstallHooks failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected postinstall hook finding in %s, got 0", path)
	}

	foundPostinstall := false
	for _, f := range findings {
		if f.HookName == "postinstall" {
			foundPostinstall = true
		}
	}
	if !foundPostinstall {
		t.Errorf("postinstall hook not identified in findings")
	}
}

func TestEntropyScanner(t *testing.T) {
	scanner := detect.NewEntropyScanner(7.2, 2)

	highEntropyPath := filepath.Join("testdata", "entropy_sample", "high_entropy.dat")
	findings, err := scanner.ScanFile(highEntropyPath)
	if err != nil {
		t.Fatalf("ScanFile high entropy failed: %v", err)
	}
	if len(findings) == 0 {
		t.Errorf("High entropy file %s was not flagged (> 7.2 bits/byte threshold)", highEntropyPath)
	}

	normalPath := filepath.Join("testdata", "entropy_sample", "normal.txt")
	normalFindings, err := scanner.ScanFile(normalPath)
	if err != nil {
		t.Fatalf("ScanFile normal failed: %v", err)
	}
	if len(normalFindings) > 0 {
		t.Errorf("Normal low entropy text file %s incorrectly flagged", normalPath)
	}

	// Verify extension skip list
	if !detect.ShouldSkipFile("image.png") || !detect.ShouldSkipFile("binary.exe") {
		t.Errorf("ShouldSkipFile failed to skip binary asset extensions")
	}
}

func TestTokenScanner(t *testing.T) {
	scanner := detect.NewTokenScanner(2)

	jsPath := filepath.Join("testdata", "token_sample", "suspicious.js")
	jsFindings, err := scanner.ScanFile(jsPath)
	if err != nil {
		t.Fatalf("Token scan JS failed: %v", err)
	}
	if len(jsFindings) == 0 {
		t.Errorf("Expected token findings in %s", jsPath)
	}

	pyPath := filepath.Join("testdata", "token_sample", "suspicious.py")
	pyFindings, err := scanner.ScanFile(pyPath)
	if err != nil {
		t.Fatalf("Token scan PY failed: %v", err)
	}
	if len(pyFindings) == 0 {
		t.Errorf("Expected token findings in %s", pyPath)
	}
}

func TestConcurrentEngineScan(t *testing.T) {
	bf := bloom.New(100, 0.01)
	tr := trie.New()
	bf.Add("express")
	tr.Insert("express")

	phantomDet := detect.NewPhantomDetector(bf, tr)
	typosquatDet := detect.NewTyposquatDetector(tr)
	entropyScan := detect.NewEntropyScanner(7.2, 4)
	tokenScan := detect.NewTokenScanner(4)

	engine := detect.NewEngine(phantomDet, typosquatDet, entropyScan, tokenScan, 4)

	deps := []manifest.Dependency{
		{Name: "express", Ecosystem: "npm"},
		{Name: "reqeusts", Ecosystem: "pypi"},
		{Name: "slop-ai-package", Ecosystem: "npm"},
	}

	report, err := engine.FullAudit(deps, filepath.Join("testdata", "token_sample"))
	if err != nil {
		t.Fatalf("FullAudit failed: %v", err)
	}

	if len(report.PhantomFindings) == 0 {
		t.Errorf("Concurrent audit missed phantom finding")
	}
	if len(report.TokenFindings) == 0 {
		t.Errorf("Concurrent audit missed token findings")
	}
}
