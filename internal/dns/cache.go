package dns

import (
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// cacheMaxTTL caps the TTL stored in the cache to avoid stale entries
// lingering longer than 1 hour even when the upstream advertises a very high TTL.
const cacheMaxTTL uint32 = 3600

// cacheEntry holds a cached DNS response along with its cache metadata.
type cacheEntry struct {
	msg      *dns.Msg
	cachedAt time.Time
	minTTL   uint32 // minimum TTL across Answer + Ns RRs, capped at cacheMaxTTL
}

// ResponseCache is a thread-safe, TTL-aware LRU cache for upstream DNS responses.
// Only NOERROR and NXDOMAIN responses with a non-zero TTL are stored.
// Eviction happens both on LRU capacity overflow and on per-entry TTL expiry at read time.
type ResponseCache struct {
	lru *lru.Cache[string, *cacheEntry]
}

// NewResponseCache creates a ResponseCache bounded to maxEntries items.
// Returns an error only if maxEntries <= 0.
func NewResponseCache(maxEntries int) (*ResponseCache, error) {
	c, err := lru.New[string, *cacheEntry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &ResponseCache{lru: c}, nil
}

// Len returns the current number of entries in the cache.
func (c *ResponseCache) Len() int {
	return c.lru.Len()
}

// Get retrieves a cached response for (qname, qtype, doBit).
// Returns nil, false on a cache miss or if the entry has exceeded its TTL.
// The returned message is a clone with TTL fields decremented by elapsed time.
func (c *ResponseCache) Get(qname string, qtype uint16, doBit bool) (*dns.Msg, bool) {
	key := cacheKey(qname, qtype, doBit)
	entry, ok := c.lru.Get(key)
	if !ok {
		return nil, false
	}

	elapsed := uint32(time.Since(entry.cachedAt).Seconds())
	if elapsed >= entry.minTTL {
		c.lru.Remove(key)
		return nil, false
	}

	clone := entry.msg.Copy()
	subtractTTLs(clone, elapsed)
	return clone, true
}

// Set stores a DNS response in the cache keyed by (qname, qtype, doBit).
// Only RcodeSuccess and RcodeNameError responses with non-zero TTL are cached.
func (c *ResponseCache) Set(qname string, qtype uint16, doBit bool, msg *dns.Msg) {
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	ttl := extractMinTTL(msg)
	if ttl == 0 {
		return
	}
	key := cacheKey(qname, qtype, doBit)
	c.lru.Add(key, &cacheEntry{
		msg:      msg.Copy(),
		cachedAt: time.Now(),
		minTTL:   ttl,
	})
}

// cacheKey returns a string key for the (qname, qtype, doBit) tuple.
// Separating DO=1 and DO=0 queries prevents serving a RRSIG-less cached response
// to a DNSSEC-aware client (RFC 4035 §3.2.1) and vice versa.
func cacheKey(qname string, qtype uint16, doBit bool) string {
	if doBit {
		return fmt.Sprintf("%s|%d|do", qname, qtype)
	}
	return fmt.Sprintf("%s|%d", qname, qtype)
}

// extractMinTTL returns the TTL to use when caching a DNS response.
// For NXDOMAIN (RFC 2308 §5): the negative TTL is min(SOA header TTL, SOA MINIMUM field).
// For positive responses: uses the minimum TTL across Answer + Ns RRs.
// Caps at cacheMaxTTL. Returns 0 if there are no RRs to inspect.
func extractMinTTL(msg *dns.Msg) uint32 {
	min := cacheMaxTTL
	found := false
	for _, rr := range append(msg.Answer, msg.Ns...) {
		found = true
		ttl := rr.Header().Ttl
		// RFC 2308 §5: negative caching TTL = min(SOA.Ttl, SOA.Minimum).
		// Some upstreams set the SOA TTL correctly, but we enforce it regardless.
		if soa, ok := rr.(*dns.SOA); ok && msg.Rcode == dns.RcodeNameError {
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
		}
		if ttl < min {
			min = ttl
		}
	}
	if !found {
		return 0
	}
	return min
}

// subtractTTLs decrements the TTL of every RR in the message by elapsed seconds,
// flooring at 0 to avoid underflow.
func subtractTTLs(msg *dns.Msg, elapsed uint32) {
	for _, rr := range append(msg.Answer, append(msg.Ns, msg.Extra...)...) {
		hdr := rr.Header()
		if hdr.Ttl <= elapsed {
			hdr.Ttl = 0
		} else {
			hdr.Ttl -= elapsed
		}
	}
}
