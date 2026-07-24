package server

import (
	"sync"
	"time"
)

// SlidingWindowLimiter tracks request counts per key within a sliding time window.
//
// Use it for per-IP, per-session, or per-key rate limiting.
//
//   limiter := NewSlidingWindowLimiter(100, time.Minute)  // 100 req/min per key
//   limiter.Allow("user:42")        // true/false
//
// The limiter prunes expired entries on each Allow() call and runs
// background GC when CleanupEvery is called.
type SlidingWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
	stopCh  chan struct{}
}

// NewSlidingWindowLimiter creates a limiter with the given limit per window.
// window is the sliding time window (e.g. time.Minute, time.Second*10).
func NewSlidingWindowLimiter(limit int, window time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string][]time.Time),
	}
}

// Allow checks if key is within the rate limit.
// Returns true if the request is allowed, false if rate limited.
func (l *SlidingWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	timestamps := l.entries[key]

	// Prune expired timestamps
	firstValid := 0
	for i, t := range timestamps {
		if t.After(cutoff) {
			firstValid = i
			break
		}
		firstValid = i + 1
	}
	if firstValid > 0 {
		timestamps = timestamps[firstValid:]
	}

	if len(timestamps) >= l.limit {
		l.entries[key] = timestamps
		return false
	}

	timestamps = append(timestamps, now)
	l.entries[key] = timestamps
	return true
}

// CleanupEvery starts a background goroutine that removes stale entries.
// Call Stop() to stop it. Idempotent — multiple calls are safe.
func (l *SlidingWindowLimiter) CleanupEvery(interval time.Duration) {
	l.mu.Lock()
	if l.stopCh != nil {
		l.mu.Unlock()
		return // already running
	}
	l.stopCh = make(chan struct{})
	ch := l.stopCh
	l.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				l.gc()
			case <-ch:
				return
			}
		}
	}()
}

// Stop halts the background cleanup goroutine.
func (l *SlidingWindowLimiter) Stop() {
	l.mu.Lock()
	ch := l.stopCh
	l.stopCh = nil
	l.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (l *SlidingWindowLimiter) gc() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-l.window)
	for key, timestamps := range l.entries {
		firstValid := 0
		for i, t := range timestamps {
			if t.After(cutoff) {
				firstValid = i
				break
			}
			firstValid = i + 1
		}
		if firstValid >= len(timestamps) {
			delete(l.entries, key)
		} else {
			l.entries[key] = timestamps[firstValid:]
		}
	}
}

// ── Pre-built limiters for common scenarios ──────────────

// LimiterConfig defines rate limits at different levels.
// Zero values disable that level.
type LimiterConfig struct {
	RequestsPerSecondPerKey   int           // per API key / session
	RequestsPerMinutePerKey   int           // per API key / session
	BurstSize                 int           // burst allowance
	CleanupInterval           time.Duration // how often to GC stale entries
}

// DefaultLimiterConfig returns sensible defaults:
//   - 10 req/s per key
//   - 600 req/min per key
//   - burst of 20
//   - cleanup every 5 minutes
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		RequestsPerSecondPerKey: 10,
		RequestsPerMinutePerKey: 600,
		BurstSize:               20,
		CleanupInterval:         5 * time.Minute,
	}
}

// NewDefaultLimiter creates a multi-level rate limiter from config.
// It returns a per-second limiter and a per-minute limiter.
func NewDefaultLimiter(cfg LimiterConfig) (second *SlidingWindowLimiter, minute *SlidingWindowLimiter) {
	second = NewSlidingWindowLimiter(cfg.RequestsPerSecondPerKey+cfg.BurstSize, time.Second)
	minute = NewSlidingWindowLimiter(cfg.RequestsPerMinutePerKey+cfg.BurstSize, time.Minute)
	second.CleanupEvery(cfg.CleanupInterval)
	minute.CleanupEvery(cfg.CleanupInterval)
	return
}
