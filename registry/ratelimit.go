package registry

import (
	"sync"
	"time"
)

// RateLimiter is a thread-safe token bucket rate limiter built with stdlib primitives.
type RateLimiter struct {
	mu           sync.Mutex
	capacity     int
	tokens       float64
	refillRate   float64 // tokens per second
	lastRefillTs time.Time
}

// NewRateLimiter creates a RateLimiter with capacity and refill rate (requests/sec).
func NewRateLimiter(capacity int, refillRate float64) *RateLimiter {
	return &RateLimiter{
		capacity:     capacity,
		tokens:       float64(capacity),
		refillRate:   refillRate,
		lastRefillTs: time.Now(),
	}
}

// Wait blocks until a token is available.
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(r.lastRefillTs).Seconds()
	r.lastRefillTs = now

	r.tokens += elapsed * r.refillRate
	if r.tokens > float64(r.capacity) {
		r.tokens = float64(r.capacity)
	}

	if r.tokens >= 1.0 {
		r.tokens -= 1.0
		r.mu.Unlock()
		return
	}

	needed := 1.0 - r.tokens
	sleepDuration := time.Duration((needed / r.refillRate) * float64(time.Second))
	r.tokens = 0
	r.mu.Unlock()

	time.Sleep(sleepDuration)
}
