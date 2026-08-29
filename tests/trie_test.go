package tests

import (
	"testing"

	"zerotrust/trie"
)

func TestTrieBasic(t *testing.T) {
	tr := trie.New()
	words := []string{"requests", "request", "require", "react", "redux"}

	for _, w := range words {
		tr.Insert(w)
	}

	for _, w := range words {
		if !tr.Search(w) {
			t.Errorf("Trie failed to search inserted word: %s", w)
		}
	}

	if tr.Search("nonexistent") {
		t.Errorf("Trie found uninserted word 'nonexistent'")
	}
}

func TestTriePrefixCandidates(t *testing.T) {
	tr := trie.New()
	tr.Insert("requests")
	tr.Insert("request")
	tr.Insert("reqeusts")
	tr.Insert("react")

	candidates := tr.FindCandidatesByPrefix("req", 10)
	if len(candidates) != 3 {
		t.Errorf("expected 3 candidates for prefix 'req', got %d: %v", len(candidates), candidates)
	}
}
