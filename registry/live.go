package registry

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"zerotrust/cache"
)

// LiveClient queries real package registries over HTTP using stdlib net/http.
type LiveClient struct {
	client      *http.Client
	rateLimiter *RateLimiter
	kvCache     *cache.KVStore
}

// NewLiveClient creates a new opt-in live verification client.
func NewLiveClient(kv *cache.KVStore) *LiveClient {
	return &LiveClient{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		rateLimiter: NewRateLimiter(2, 2.0), // Conservative 2 requests per second rate limit to prevent registry throttling
		kvCache:     kv,
	}
}

// CheckPackageExistence queries the appropriate registry to confirm if a package exists.
func (c *LiveClient) CheckPackageExistence(ecosystem, pkgName string) (exists bool, confirmed bool, err error) {
	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return false, false, nil
	}

	// 1. Check KV Cache first
	if c.kvCache != nil {
		if cachedExists, found := c.kvCache.Get(ecosystem, pkgName); found {
			return cachedExists, true, nil
		}
	}

	url := ""
	switch strings.ToLower(ecosystem) {
	case "npm":
		url = fmt.Sprintf("https://registry.npmjs.org/%s", pkgName)
	case "pypi":
		url = fmt.Sprintf("https://pypi.org/pypi/%s/json", pkgName)
	case "crates":
		url = fmt.Sprintf("https://crates.io/api/v1/crates/%s", pkgName)
	default:
		return false, false, fmt.Errorf("unsupported live registry ecosystem: %s", ecosystem)
	}

	c.rateLimiter.Wait()

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Set("User-Agent", "ZeroTrust-Supply-Chain-Scanner/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		// Network unavailable or timeout -> fail gracefully
		return false, false, fmt.Errorf("network connection warning: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if c.kvCache != nil {
			_ = c.kvCache.Set(ecosystem, pkgName, true)
		}
		return true, true, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		if c.kvCache != nil {
			_ = c.kvCache.Set(ecosystem, pkgName, false)
		}
		return false, true, nil
	}

	// Any other HTTP code (500, 429, etc.)
	return false, false, fmt.Errorf("registry HTTP status %d", resp.StatusCode)
}
