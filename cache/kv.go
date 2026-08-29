package cache

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KVStore represents an append-only file-based key-value store for live lookup results.
type KVStore struct {
	mu       sync.RWMutex
	filePath string
	mem      map[string]cacheEntry
}

type cacheEntry struct {
	Exists    bool
	Timestamp int64
}

// NewKVStore initializes or opens an append-only cache store.
func NewKVStore(path string) (*KVStore, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			path = ".zerotrust-cache.kv"
		} else {
			path = filepath.Join(home, ".zerotrust-cache.kv")
		}
	}

	store := &KVStore{
		filePath: path,
		mem:      make(map[string]cacheEntry),
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		// Log warning but continue with in-memory map
	}

	return store, nil
}

func makeKey(ecosystem, pkgName string) string {
	return strings.ToLower(ecosystem) + ":" + strings.ToLower(pkgName)
}

func (s *KVStore) Get(ecosystem, pkgName string) (exists bool, found bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := makeKey(ecosystem, pkgName)
	entry, ok := s.mem[key]
	if !ok {
		return false, false
	}
	// Expire cache after 7 days
	if time.Now().Unix()-entry.Timestamp > 7*84600 {
		return false, false
	}
	return entry.Exists, true
}

func (s *KVStore) Set(ecosystem, pkgName string, exists bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := makeKey(ecosystem, pkgName)
	now := time.Now().Unix()
	s.mem[key] = cacheEntry{Exists: exists, Timestamp: now}

	line := fmt.Sprintf("%s|%t|%d\n", key, exists, now)

	f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

func (s *KVStore) load() error {
	f, err := os.Open(s.filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			k := parts[0]
			exists, _ := strconv.ParseBool(parts[1])
			ts, _ := strconv.ParseInt(parts[2], 10, 64)
			s.mem[k] = cacheEntry{Exists: exists, Timestamp: ts}
		}
	}
	return scanner.Err()
}
