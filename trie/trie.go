package trie

import "sync"

// Node represents a single node in the prefix trie.
type Node struct {
	children map[rune]*Node
	isEnd    bool
	word     string
}

// Trie is a thread-safe hand-rolled prefix tree for fast candidate package lookups.
type Trie struct {
	mu   sync.RWMutex
	root *Node
}

// New initializes and returns an empty Trie.
func New() *Trie {
	return &Trie{
		root: &Node{children: make(map[rune]*Node)},
	}
}

// Insert adds a word to the trie.
func (t *Trie) Insert(word string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	curr := t.root
	for _, r := range word {
		if curr.children[r] == nil {
			curr.children[r] = &Node{children: make(map[rune]*Node)}
		}
		curr = curr.children[r]
	}
	curr.isEnd = true
	curr.word = word
}

// Search checks if an exact word exists in the trie.
func (t *Trie) Search(word string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	curr := t.root
	for _, r := range word {
		if curr.children[r] == nil {
			return false
		}
		curr = curr.children[r]
	}
	return curr.isEnd
}

// FindCandidatesByPrefix returns up to maxResults words starting with prefix.
func (t *Trie) FindCandidatesByPrefix(prefix string, maxResults int) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	curr := t.root
	for _, r := range prefix {
		if curr.children[r] == nil {
			return nil
		}
		curr = curr.children[r]
	}

	var results []string
	t.collectWords(curr, &results, maxResults)
	return results
}

// FindCandidatesForWord retrieves likely candidate package names for similarity checking.
// It searches by prefix (first 1-3 characters) to quickly prune non-matching branches.
func (t *Trie) FindCandidatesForWord(word string, maxResults int) []string {
	if len(word) == 0 {
		return nil
	}

	prefixLen := 3
	if len(word) < prefixLen {
		prefixLen = len(word)
	}

	for prefixLen > 0 {
		candidates := t.FindCandidatesByPrefix(word[:prefixLen], maxResults)
		if len(candidates) > 0 {
			return candidates
		}
		prefixLen--
	}

	// Fallback to top words if prefix matches nothing
	t.mu.RLock()
	defer t.mu.RUnlock()

	var results []string
	t.collectWords(t.root, &results, maxResults)
	return results
}

func (t *Trie) collectWords(n *Node, results *[]string, maxResults int) {
	if n == nil || len(*results) >= maxResults {
		return
	}
	if n.isEnd {
		*results = append(*results, n.word)
	}
	for _, child := range n.children {
		t.collectWords(child, results, maxResults)
		if len(*results) >= maxResults {
			break
		}
	}
}
