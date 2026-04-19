package dns

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	rrlCleanupInterval = 2 * time.Minute
	rrlIdleExpiry      = 5 * time.Minute
)

// dnsRRL implements per-client-IP Response Rate Limiting (RRL) for the DNS server.
// Each unique client IP gets its own token-bucket limiter.
// When Allow returns false, the caller should silently drop the response to prevent
// DNS amplification attacks (BCP 140 / RFC 8932).
//
// Zero value (entries == nil) is the disabled state — Allow always returns true.
type dnsRRL struct {
	mu      sync.Mutex
	entries map[string]*rrlEntry
	lim     rate.Limit
	burst   int
	done    chan struct{}
}

type rrlEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newDNSRRL creates a per-IP rate limiter.
// ratePerSec <= 0 returns a disabled limiter (Allow always returns true).
// burst is the maximum token bucket depth; if burst <= 0 it defaults to ratePerSec.
func newDNSRRL(ratePerSec, burst int) *dnsRRL {
	r := &dnsRRL{done: make(chan struct{})}
	if ratePerSec <= 0 {
		return r // disabled
	}
	if burst <= 0 {
		burst = ratePerSec
	}
	r.entries = make(map[string]*rrlEntry)
	r.lim = rate.Limit(ratePerSec)
	r.burst = burst
	go r.cleanup()
	return r
}

// Allow reports whether a query from clientIP is within the configured rate limit.
// Always returns true when RRL is disabled (ratePerSec was 0).
func (r *dnsRRL) Allow(clientIP string) bool {
	if r.entries == nil {
		return true
	}
	r.mu.Lock()
	e, ok := r.entries[clientIP]
	if !ok {
		e = &rrlEntry{limiter: rate.NewLimiter(r.lim, r.burst)}
		r.entries[clientIP] = e
	}
	e.lastSeen = time.Now()
	r.mu.Unlock()
	return e.limiter.Allow()
}

// stop signals the cleanup goroutine to exit.
// Called when this dnsRRL is replaced by a new one via Handler.SetRRL.
func (r *dnsRRL) stop() {
	// Only close if the done channel was initialised (disabled instances skip cleanup).
	if r.done != nil {
		select {
		case <-r.done: // already closed
		default:
			close(r.done)
		}
	}
}

// cleanup periodically removes entries that have been idle for rrlIdleExpiry.
// This prevents unbounded memory growth when many unique IPs are seen over time.
func (r *dnsRRL) cleanup() {
	ticker := time.NewTicker(rrlCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			r.mu.Lock()
			for ip, e := range r.entries {
				if now.Sub(e.lastSeen) > rrlIdleExpiry {
					delete(r.entries, ip)
				}
			}
			r.mu.Unlock()
		case <-r.done:
			return
		}
	}
}
