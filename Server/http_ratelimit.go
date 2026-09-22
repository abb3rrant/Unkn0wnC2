// Package main implements per-client rate limiting for the HTTP listener.
//
// The DNS side limits how often it forwards non-authoritative queries upstream
// (ForwardingRateLimiter). That limiter is global and stateful about upstream
// health, which is the wrong shape for a web listener: what matters here is one
// noisy client not being able to enumerate or flood the listener. Hence a small
// per-IP token bucket.
package main

import (
	"sync"
	"time"
)

const (
	// httpRatePerSecond is the sustained per-client request rate.
	httpRatePerSecond = 20.0
	// httpRateBurst is how many requests a client may make back-to-back.
	httpRateBurst = 40.0
	// httpRateIdleTTL is how long an idle client's bucket is kept before pruning.
	httpRateIdleTTL = 10 * time.Minute
)

// tokenBucket is one client's allowance.
type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// httpRateLimiter is a per-client token bucket. Entries are pruned lazily so a
// long-running listener does not accumulate one bucket per scanner IP forever.
type httpRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64
	burst   float64
	now     func() time.Time
}

// newHTTPRateLimiter returns a limiter with the package defaults.
func newHTTPRateLimiter() *httpRateLimiter {
	return &httpRateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    httpRatePerSecond,
		burst:   httpRateBurst,
		now:     time.Now,
	}
}

// allow reports whether a client may make a request now, consuming a token when
// it can.
func (l *httpRateLimiter) allow(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	bucket, ok := l.buckets[client]
	if !ok {
		l.prune(now)
		bucket = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[client] = bucket
	}

	// Refill by elapsed time, capped at the burst size.
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * l.rate
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		bucket.last = now
	}
	bucket.lastSeen = now

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// prune drops buckets that have been idle past the TTL. Called only when a new
// client appears, which keeps the common path free of a full map walk.
func (l *httpRateLimiter) prune(now time.Time) {
	for client, bucket := range l.buckets {
		if now.Sub(bucket.lastSeen) > httpRateIdleTTL {
			delete(l.buckets, client)
		}
	}
}
