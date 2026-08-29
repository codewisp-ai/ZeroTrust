package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("%X", h), nil
}

func main() {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	p1 := filepath.Join(".", "bin", "repro_1", "zerotrust"+ext)
	p2 := filepath.Join(".", "bin", "repro_2", "zerotrust"+ext)

	h1, err1 := hashFile(p1)
	h2, err2 := hashFile(p2)

	if err1 != nil || err2 != nil {
		fmt.Printf("Error reading binaries for reproducible build check: %v / %v\n", err1, err2)
		os.Exit(1)
	}

	fmt.Printf("Build 1 SHA256 (%s): %s\n", runtime.GOOS, h1)
	fmt.Printf("Build 2 SHA256 (%s): %s\n", runtime.GOOS, h2)

	if h1 == h2 {
		fmt.Println("REPRODUCIBLE BUILD VERIFICATION: PASS")
	} else {
		fmt.Println("REPRODUCIBLE BUILD VERIFICATION: FAIL")
		os.Exit(1)
	}
}
