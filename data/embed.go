package data

import (
	"bufio"
	"compress/gzip"
	"embed"
	"fmt"
	"strings"
)

//go:embed npm_curated.txt.gz pypi_curated.txt.gz crates_curated.txt.gz
var corpusFS embed.FS

// LoadCorpus decompresses and parses a corpus file into a slice of package name strings.
func LoadCorpus(filename string) ([]string, error) {
	file, err := corpusFS.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening embedded corpus %s: %w", filename, err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("decompressing corpus %s: %w", filename, err)
	}
	defer gzReader.Close()

	var names []string
	scanner := bufio.NewScanner(gzReader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			names = append(names, line)
		}
	}

	return names, scanner.Err()
}

// LoadAllCorpora loads all three ecosystems' embedded corpora into maps keyed by ecosystem.
func LoadAllCorpora() (map[string][]string, error) {
	corpora := make(map[string][]string)

	npm, err := LoadCorpus("npm_curated.txt.gz")
	if err != nil {
		return nil, err
	}
	corpora["npm"] = npm

	pypi, err := LoadCorpus("pypi_curated.txt.gz")
	if err != nil {
		return nil, err
	}
	corpora["pypi"] = pypi

	crates, err := LoadCorpus("crates_curated.txt.gz")
	if err != nil {
		return nil, err
	}
	corpora["crates"] = crates

	return corpora, nil
}
