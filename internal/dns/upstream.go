package dns

import (
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// UpstreamStrategy defines how queries are distributed across upstream resolvers.
type UpstreamStrategy string

const (
	StrategyRoundRobin UpstreamStrategy = "roundrobin"
	StrategyRandom     UpstreamStrategy = "random"
	StrategyRace       UpstreamStrategy = "race"
)

// Upstream manages a pool of DNS resolvers with a configurable dispatch strategy.
type Upstream struct {
	servers   []string
	strategy  UpstreamStrategy
	counter   atomic.Uint64
	client    *dns.Client
	tcpClient *dns.Client // used for TC (truncated) retry
	cache     *ResponseCache // nil = caching disabled
}

// NewUpstream creates an Upstream pool from the given server list and strategy string.
// Falls back to roundrobin for unknown strategy values.
// cache may be nil to disable response caching.
func NewUpstream(servers []string, strategy string, cache *ResponseCache) *Upstream {
	s := UpstreamStrategy(strategy)
	switch s {
	case StrategyRoundRobin, StrategyRandom, StrategyRace:
	default:
		s = StrategyRoundRobin
	}
	return &Upstream{
		servers:  servers,
		strategy: s,
		cache:    cache,
		client: &dns.Client{
			Net:            "udp",
			Timeout:        5 * time.Second,
			UDPSize:        4096,
			SingleInflight: true, // deduplicate identical in-flight queries
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: 5 * time.Second,
		},
	}
}

// Exchange sends the query using the configured strategy and returns the response.
// Kept for backward compatibility; use ExchangeTracked when RTT/server tracking is needed.
func (u *Upstream) Exchange(r *dns.Msg) (*dns.Msg, error) {
	res, err := u.ExchangeTracked(r)
	if err != nil {
		return nil, err
	}
	return res.Resp, nil
}

// exchangeOne sends a single query to addr, retrying via TCP if the UDP response is truncated.
// Returns the response, the actual RTT measured by the DNS client, and any error.
func (u *Upstream) exchangeOne(r *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	resp, rtt, err := u.client.Exchange(r.Copy(), addr)
	if err != nil {
		return nil, 0, err
	}
	if resp.Truncated {
		var rtt2 time.Duration
		resp, rtt2, err = u.tcpClient.Exchange(r.Copy(), addr)
		if err != nil {
			return nil, rtt, err
		}
		rtt += rtt2
	}
	return resp, rtt, nil
}

// ExchangeResult carries the result of a tracked upstream exchange.
type ExchangeResult struct {
	Resp   *dns.Msg
	Server string
	RTT    time.Duration
}

// exchangeRoundRobin picks the next server in rotation using an atomic counter.
func (u *Upstream) exchangeRoundRobin(r *dns.Msg) (ExchangeResult, error) {
	n := len(u.servers)
	idx := int(u.counter.Add(1)-1) % n
	resp, rtt, err := u.exchangeOne(r, u.servers[idx])
	if err != nil && n > 1 {
		// Fallback: try the next one
		next := u.servers[(idx+1)%n]
		resp, rtt, err = u.exchangeOne(r, next)
		if err == nil {
			return ExchangeResult{Resp: resp, Server: next, RTT: rtt}, nil
		}
		return ExchangeResult{}, err
	}
	if err != nil {
		return ExchangeResult{}, err
	}
	return ExchangeResult{Resp: resp, Server: u.servers[idx], RTT: rtt}, nil
}

// exchangeRandom picks a random server each time.
func (u *Upstream) exchangeRandom(r *dns.Msg) (ExchangeResult, error) {
	servers := make([]string, len(u.servers))
	copy(servers, u.servers)
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })

	var lastErr error
	for _, s := range servers {
		resp, rtt, err := u.exchangeOne(r, s)
		if err == nil {
			return ExchangeResult{Resp: resp, Server: s, RTT: rtt}, nil
		}
		lastErr = err
	}
	return ExchangeResult{}, lastErr
}

// exchangeRace sends to all servers simultaneously and returns the first successful response.
func (u *Upstream) exchangeRace(r *dns.Msg) (ExchangeResult, error) {
	type result struct {
		res ExchangeResult
		err error
	}
	ch := make(chan result, len(u.servers))

	for _, s := range u.servers {
		go func(addr string) {
			resp, rtt, err := u.exchangeOne(r, addr)
			ch <- result{ExchangeResult{Resp: resp, Server: addr, RTT: rtt}, err}
		}(s)
	}

	var lastErr error
	for range u.servers {
		res := <-ch
		if res.err == nil {
			return res.res, nil
		}
		lastErr = res.err
	}
	return ExchangeResult{}, lastErr
}

// ExchangeTracked sends the query using the configured strategy and returns
// the response along with the upstream server address and measured RTT.
// If a cache is configured, the cache is consulted first (RTT = 0, Server = "cache").
// The DO bit (DNSSEC OK) is included in the cache key so that DNSSEC-aware clients
// (DO=1) do not receive a cached response that lacks RRSIG records.
func (u *Upstream) ExchangeTracked(r *dns.Msg) (ExchangeResult, error) {
	var doBit bool
	if len(r.Question) > 0 {
		if opt := r.IsEdns0(); opt != nil {
			doBit = opt.Do()
		}
	}

	if u.cache != nil && len(r.Question) > 0 {
		qname := r.Question[0].Name
		qtype := r.Question[0].Qtype
		if cached, ok := u.cache.Get(qname, qtype, doBit); ok {
			return ExchangeResult{Resp: cached, Server: "cache", RTT: 0}, nil
		}
	}

	var (
		res ExchangeResult
		err error
	)
	switch u.strategy {
	case StrategyRandom:
		res, err = u.exchangeRandom(r)
	case StrategyRace:
		res, err = u.exchangeRace(r)
	default:
		res, err = u.exchangeRoundRobin(r)
	}

	if u.cache != nil && err == nil && len(r.Question) > 0 {
		u.cache.Set(r.Question[0].Name, r.Question[0].Qtype, doBit, res.Resp)
	}
	return res, err
}
