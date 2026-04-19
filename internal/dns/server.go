package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

// AXFRRecord is a single DNS record for outbound AXFR serving.
// Names must NOT include the zone suffix (the handler appends it).
type AXFRRecord struct {
	Name, RType, RData string
	TTL                int
}

// AXFRProvider serves zone records for outbound AXFR transfers.
// Implement and pass to Handler.SetAXFRProvider to enable slave-pull support.
type AXFRProvider interface {
	ListZoneRecordsForAXFR(ctx context.Context, zoneName string) (serial int64, records []AXFRRecord, err error)
}

// QueryLogger receives DNS query events for statistics collection.
// Implementations must be non-blocking to avoid slowing down query handling.
type QueryLogger interface {
	LogQuery(clientIP, domain, qtype, result, upstream string, rttMs int64)
}

// Handler handles incoming DNS queries with RPZ enforcement.
type Handler struct {
	index           Indexer
	acl             ACLChecker
	defaultAction   atomic.Value   // stores string: "nxdomain" or "nodata"
	upstream        unsafe.Pointer // *Upstream, swapped atomically
	authIdx         unsafe.Pointer // *AuthoritativeIndex, nil = disabled
	rrlPtr          unsafe.Pointer // *dnsRRL, swapped atomically; nil = RRL disabled
	logger          *slog.Logger
	auditLog        atomic.Bool           // when true, log every query at INFO level for audit purposes
	queryLog        atomic.Value          // stores QueryLogger; nil when disabled
	queriesReceived atomic.Int64          // total queries received since startup (resets on restart)
	axfrProvider    AXFRProvider          // optional; nil = AXFR not supported
	notifyTrigger   func(zoneName string) // optional; called when a valid NOTIFY is received
}

// Indexer is the interface for looking up RPZ entries.
// Implemented by the in-memory index.
type Indexer interface {
	Lookup(name string) (action string, ok bool)
}

// ACLChecker checks whether a client IP is allowed to use recursion.
type ACLChecker interface {
	IsAllowed(ip net.IP) bool
}

// NewHandler creates a new DNS query handler.
// auditLog enables per-query INFO logging for audit purposes, independent of LOG_LEVEL.
func NewHandler(index Indexer, acl ACLChecker, defaultAction string, upstream *Upstream, logger *slog.Logger, auditLog bool) *Handler {
	h := &Handler{
		index:  index,
		acl:    acl,
		logger: logger,
	}
	h.defaultAction.Store(defaultAction)
	atomic.StorePointer(&h.upstream, unsafe.Pointer(upstream))
	h.auditLog.Store(auditLog)
	return h
}

// SetUpstream atomically replaces the upstream pool. Safe to call at runtime.
func (h *Handler) SetUpstream(u *Upstream) {
	atomic.StorePointer(&h.upstream, unsafe.Pointer(u))
}

// getUpstream returns the current upstream pool.
func (h *Handler) getUpstream() *Upstream {
	return (*Upstream)(atomic.LoadPointer(&h.upstream))
}

// SetAuthoritativeIndex atomically sets (or replaces) the authoritative index.
// Pass nil to disable authoritative serving.
func (h *Handler) SetAuthoritativeIndex(ai *AuthoritativeIndex) {
	atomic.StorePointer(&h.authIdx, unsafe.Pointer(ai))
}

// getAuthIndex returns the current AuthoritativeIndex, or nil if not set.
func (h *Handler) getAuthIndex() *AuthoritativeIndex {
	return (*AuthoritativeIndex)(atomic.LoadPointer(&h.authIdx))
}

// SetAuditLog toggles audit logging at runtime without restarting the service.
func (h *Handler) SetAuditLog(v bool) {
	h.auditLog.Store(v)
}

// getRRL returns the current RRL limiter, or nil if RRL is disabled.
func (h *Handler) getRRL() *dnsRRL {
	return (*dnsRRL)(atomic.LoadPointer(&h.rrlPtr))
}

// SetRRL replaces the response rate limiter at runtime (safe to call during SIGHUP).
// ratePerSec is the maximum number of queries per second per client IP.
// burst is the token-bucket burst size; if <= 0 it defaults to ratePerSec.
// Set ratePerSec=0 to disable RRL.
func (h *Handler) SetRRL(ratePerSec, burst int) {
	newRRL := newDNSRRL(ratePerSec, burst)
	old := (*dnsRRL)(atomic.SwapPointer(&h.rrlPtr, unsafe.Pointer(newRRL)))
	if old != nil {
		old.stop()
	}
}

// AuditLog returns the current audit log setting.
func (h *Handler) AuditLog() bool {
	return h.auditLog.Load()
}

// SetAXFRProvider registers a provider for outbound AXFR zone transfers.
// When set, this node can serve AXFR to slave nodes in the trust network.
// Pass nil to disable AXFR serving.
func (h *Handler) SetAXFRProvider(p AXFRProvider) {
	h.axfrProvider = p
}

// SetQueryLogger sets the query logger used for statistics collection.
// Pass nil to disable query logging.
func (h *Handler) SetQueryLogger(ql QueryLogger) {
	h.queryLog.Store(&ql)
}

// logQuery calls the query logger if one is set.
// For blocked/refused queries pass upstream="" and rttMs=0.
func (h *Handler) logQuery(clientIP, domain, qtype, result, upstream string, rttMs int64) {
	v := h.queryLog.Load()
	if v == nil {
		return
	}
	if qlp, ok := v.(*QueryLogger); ok && qlp != nil {
		(*qlp).LogQuery(clientIP, domain, qtype, result, upstream, rttMs)
	}
}

// SetDefaultAction updates the RPZ default action at runtime. Safe to call concurrently.
func (h *Handler) SetDefaultAction(action string) {
	h.defaultAction.Store(action)
}

// DefaultAction returns the current RPZ default action.
func (h *Handler) DefaultAction() string {
	if v, ok := h.defaultAction.Load().(string); ok {
		return v
	}
	return "nxdomain"
}

// QueryCount returns the total number of DNS queries received since startup.
// This counter is incremented atomically for every query before any processing,
// giving an accurate received count independent of the query log buffer.
// Resets to zero on process restart.
func (h *Handler) QueryCount() int64 {
	return h.queriesReceived.Load()
}

// ServeDNS handles a single DNS query.
// Implements dns.Handler interface.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.RecursionAvailable = true

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// RFC 1035 §4.1.2: only one question per query is defined.
	// Clients sending multiple questions are non-compliant; return FORMERR.
	if len(r.Question) > 1 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// EDNS0 (RFC 6891): read OPT record from client request and negotiate UDP buffer size.
	// If the client advertises a buffer size, honour it (capped at 4096).
	// Always echo back an OPT record in the response so the client knows we support EDNS0.
	// For non-EDNS clients, do not add OPT (would break older resolvers).
	const maxUDPSize = 4096
	if opt := r.IsEdns0(); opt != nil {
		clientBuf := opt.UDPSize()
		if clientBuf < dns.MinMsgSize {
			clientBuf = dns.MinMsgSize
		}
		if clientBuf > maxUDPSize {
			clientBuf = maxUDPSize
		}
		m.SetEdns0(clientBuf, false)
	}

	// Count every valid query regardless of ACL/RPZ outcome or log buffer state.
	h.queriesReceived.Add(1)

	// Extract client IP for ACL check
	clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// RRL (Response Rate Limiting): silently drop queries that exceed per-IP rate.
	// Prevents DNS amplification abuse. Only active if SetRRL was called with ratePerSec > 0.
	if rrl := h.getRRL(); rrl != nil && !rrl.Allow(clientIP) {
		h.logger.Warn("rrl: query rate exceeded, dropping", "client", clientIP)
		return
	}

	ip := net.ParseIP(clientIP)

	q := r.Question[0]
	qname := dns.Fqdn(q.Name)

	h.logger.Debug("dns query",
		"client", clientIP,
		"name", qname,
		"type", dns.TypeToString[q.Qtype],
	)

	// AXFR/IXFR — handled separately (zone transfer, not a regular query).
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		h.handleAXFR(w, r, qname)
		return
	}

	// NOTIFY (RFC 1996): master signals that a zone has changed.
	// Respond with NOERROR immediately, then trigger an async sync.
	// RA must be 0 in NOTIFY responses (RFC 1996 §3.7).
	// We do not validate the source IP here — the syncer will verify via TSIG/serial.
	if r.Opcode == dns.OpcodeNotify {
		m.RecursionAvailable = false
		m.SetRcode(r, dns.RcodeSuccess)
		m.Opcode = dns.OpcodeNotify
		m.Authoritative = true
		w.WriteMsg(m) //nolint:errcheck
		zoneName := strings.TrimSuffix(qname, ".")
		h.logger.Info("notify received", "zone", zoneName, "from", clientIP)
		if h.notifyTrigger != nil {
			go h.notifyTrigger(zoneName)
		}
		return
	}

	// ACL check — only allowed IPs may recurse
	if !h.acl.IsAllowed(ip) {
		h.logger.Warn("query refused: client not in acl", "client", clientIP)
		if h.auditLog.Load() {
			h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", "refused")
		}
		h.logQuery(clientIP, qname, dns.TypeToString[q.Qtype], "refused", "", 0)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// Authoritative check — serve from our own zone records (domain / reverse_ptr).
	// Must come BEFORE the RPZ check so our own zones are never blocked by RPZ.
	if ai := h.getAuthIndex(); ai != nil {
		answer, isAuth, nxdomain, soa := ai.Lookup(qname, q.Qtype)
		if isAuth {
			if h.auditLog.Load() {
				result := "authoritative"
				if nxdomain {
					result = "authoritative:nxdomain"
				} else if len(answer) == 0 {
					result = "authoritative:nodata"
				}
				h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", result)
			}
			h.serveAuthoritative(w, r, m, qname, q.Qtype, answer, nxdomain, soa, clientIP)
			return
		}
	}

	// RPZ check — exact match, then wildcard walk up labels
	action, matched := h.index.Lookup(qname)
	if !matched {
		action, matched = h.lookupWildcard(qname)
	}
	if matched {
		if h.auditLog.Load() {
			h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", "blocked", "action", action)
		}
		h.logQuery(clientIP, qname, dns.TypeToString[q.Qtype], "blocked", "", 0)
		h.applyRPZAction(w, r, m, qname, action, clientIP)
		return
	}

	if h.auditLog.Load() {
		h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", "allowed")
	}
	// Pass-through: forward to upstream resolver, then log with upstream stats.
	h.forward(w, r, m, clientIP, qname, dns.TypeToString[q.Qtype])
}

// serveAuthoritative builds and sends an authoritative DNS response.
// NOERROR+answer, NODATA (NOERROR+SOA), or NXDOMAIN+SOA.
func (h *Handler) serveAuthoritative(w dns.ResponseWriter, r, m *dns.Msg, qname string, qtype uint16, answer []dns.RR, nxdomain bool, soa dns.RR, clientIP string) {
	m.Authoritative = true
	qtypeStr := dns.TypeToString[qtype]
	switch {
	case nxdomain:
		m.SetRcode(r, dns.RcodeNameError)
		if soa != nil {
			m.Ns = []dns.RR{soa}
		}
		h.logQuery(clientIP, qname, qtypeStr, "authoritative:nxdomain", "", 0)
	case len(answer) == 0:
		// NODATA: name exists but no records of the requested type.
		m.SetRcode(r, dns.RcodeSuccess)
		if soa != nil {
			m.Ns = []dns.RR{soa}
		}
		h.logQuery(clientIP, qname, qtypeStr, "authoritative:nodata", "", 0)
	default:
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = answer
		h.logQuery(clientIP, qname, qtypeStr, "authoritative", "", 0)
	}
	w.WriteMsg(m) //nolint:errcheck
}

// forward sends the query to the upstream pool and relays the response.
// It calls logQuery with the upstream server address and RTT.
// The query forwarded to upstream has its EDNS0 buffer size capped at maxUDPSize
// so upstream never sends a UDP payload larger than our receive buffer.
func (h *Handler) forward(w dns.ResponseWriter, r, m *dns.Msg, clientIP, qname, qtype string) {
	// Cap the EDNS0 payload size in the query we send to upstream.
	// This prevents the upstream from sending a UDP response larger than we can receive,
	// avoiding unnecessary TC+TCP fallback cycles for oversized responses.
	const maxUDPSize = 4096
	upstreamReq := r
	if opt := r.IsEdns0(); opt != nil && opt.UDPSize() > maxUDPSize {
		upstreamReq = r.Copy()
		upstreamReq.IsEdns0().SetUDPSize(maxUDPSize)
	}
	res, err := h.getUpstream().ExchangeTracked(upstreamReq)
	if err != nil {
		h.logger.Warn("upstream error", "err", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m) //nolint:errcheck
		h.logQuery(clientIP, qname, qtype, "allowed", "", 0)
		return
	}
	res.Resp.Id = r.Id
	w.WriteMsg(res.Resp) //nolint:errcheck
	h.logQuery(clientIP, qname, qtype, "allowed", res.Server, res.RTT.Milliseconds())
}

// lookupWildcard walks up the labels looking for a wildcard entry.
// e.g. "sub.example.com." checks "*.sub.example.com.", "*.example.com.", "*.com."
func (h *Handler) lookupWildcard(qname string) (action string, ok bool) {
	for off, end := 0, false; !end; off, end = dns.NextLabel(qname, off) {
		parent := qname[off:]
		if parent == "." {
			break
		}
		if action, ok = h.index.Lookup("*." + parent); ok {
			return
		}
	}
	return "", false
}

// applyRPZAction sends the appropriate DNS response based on the RPZ CNAME action.
// ".."    → NXDOMAIN (blocked, domain does not exist)
// "*."   → NODATA  (NOERROR, no answer records)
// other  → CNAME redirect (walled garden)
// ""     → use defaultAction from config
func (h *Handler) applyRPZAction(w dns.ResponseWriter, r, m *dns.Msg, qname, action, clientIP string) {
	// Empty action means no CNAME in zone — fall back to configured default
	if action == "" {
		action = h.DefaultAction()
	}

	h.logger.Info("rpz block", "client", clientIP, "name", qname, "action", action)

	switch action {
	case "*.":
		// NODATA: name exists but no records of requested type
		m.SetRcode(r, dns.RcodeSuccess)
		m.Ns = []dns.RR{rpzSOA(qname)}
	case ".", "nxdomain":
		// NXDOMAIN: name does not exist
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = []dns.RR{rpzSOA(qname)}
	default:
		// Walled garden: redirect via CNAME
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
			Target: dns.Fqdn(action),
		}}
	}
	w.WriteMsg(m) //nolint:errcheck
}

// rpzSOA returns a minimal SOA record for the authority section of RPZ NXDOMAIN responses.
func rpzSOA(name string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 30},
		Ns:      "rpz.localhost.",
		Mbox:    "hostmaster.rpz.localhost.",
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  30,
	}
}

// SetNotifyTrigger registers a callback invoked when a valid DNS NOTIFY is received.
// The callback receives the zone name (without trailing dot) and should trigger
// an immediate zone sync on that zone. Safe to call before starting the server.
func (h *Handler) SetNotifyTrigger(fn func(zoneName string)) {
	h.notifyTrigger = fn
}

// handleAXFR serves an outbound AXFR (zone transfer) for a zone stored in this node.
// Only available when an AXFRProvider has been set via SetAXFRProvider.
// The response format follows RFC 5936: SOA → records → SOA.
func (h *Handler) handleAXFR(w dns.ResponseWriter, r *dns.Msg, zoneFQDN string) {
	if h.axfrProvider == nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// Strip trailing dot for the DB lookup; zones are stored without trailing dot.
	zoneName := strings.TrimSuffix(zoneFQDN, ".")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	serial, recs, err := h.axfrProvider.ListZoneRecordsForAXFR(ctx, zoneName)
	if err != nil {
		h.logger.Warn("axfr: zone not found or DB error", "zone", zoneName, "err", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	h.logger.Info("axfr: serving zone transfer", "zone", zoneName, "records", len(recs))

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: zoneFQDN, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + zoneFQDN,
		Mbox:    "hostmaster." + zoneFQDN,
		Serial:  uint32(serial),
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  60,
	}

	// Build envelopes: first SOA, then batches of records, then trailing SOA.
	const batchSize = 500
	envelopes := []*dns.Envelope{{RR: []dns.RR{soa}}}

	batch := make([]dns.RR, 0, batchSize)
	for _, rec := range recs {
		rr, err := buildAXFRRecord(rec, zoneFQDN)
		if err != nil {
			h.logger.Debug("axfr: skip unparseable record", "name", rec.Name, "rtype", rec.RType, "err", err)
			continue
		}
		batch = append(batch, rr)
		if len(batch) >= batchSize {
			envelopes = append(envelopes, &dns.Envelope{RR: batch})
			batch = make([]dns.RR, 0, batchSize)
		}
	}
	if len(batch) > 0 {
		envelopes = append(envelopes, &dns.Envelope{RR: batch})
	}
	envelopes = append(envelopes, &dns.Envelope{RR: []dns.RR{soa}}) // trailing SOA

	ch := make(chan *dns.Envelope, len(envelopes))
	for _, env := range envelopes {
		ch <- env
	}
	close(ch)

	tr := new(dns.Transfer)
	if err := tr.Out(w, r, ch); err != nil {
		h.logger.Warn("axfr: transfer out failed", "zone", zoneName, "err", err)
	}
}

// buildAXFRRecord converts an AXFRRecord into a dns.RR for AXFR transmission.
// The zoneFQDN (e.g. "rpz.example.com.") is appended to the record name so
// that slaves receive fully qualified names in the AXFR stream.
func buildAXFRRecord(rec AXFRRecord, zoneFQDN string) (dns.RR, error) {
	// Records are stored without zone suffix: "pornhub.com."
	// AXFR requires full name: "pornhub.com.rpz.example.com."
	var fullName string
	if rec.Name == "" || rec.Name == "." {
		fullName = zoneFQDN
	} else {
		// rec.Name already has trailing dot: "pornhub.com."
		// zoneFQDN has trailing dot: "rpz.example.com."
		// Full name: "pornhub.com." + "rpz.example.com." = "pornhub.com.rpz.example.com."
		fullName = rec.Name + zoneFQDN
	}

	ttl := uint32(rec.TTL)
	if ttl == 0 {
		ttl = 300
	}

	switch strings.ToUpper(rec.RType) {
	case "CNAME":
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fullName, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: dns.Fqdn(rec.RData),
		}, nil
	case "A":
		ip := net.ParseIP(rec.RData).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 %q", rec.RData)
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: fullName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip,
		}, nil
	case "AAAA":
		ip := net.ParseIP(rec.RData)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid IPv6 %q", rec.RData)
		}
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fullName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ip,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported rtype %q", rec.RType)
	}
}

type Server struct {
	udpServer *dns.Server
	tcpServer *dns.Server
	logger    *slog.Logger
}

// NewServer creates UDP and TCP DNS servers bound to the given address.
func NewServer(addr string, handler dns.Handler, logger *slog.Logger) *Server {
	return &Server{
		udpServer: &dns.Server{
			Addr:    addr,
			Net:     "udp",
			Handler: handler,
		},
		tcpServer: &dns.Server{
			Addr:    addr,
			Net:     "tcp",
			Handler: handler,
		},
		logger: logger,
	}
}

// Start starts both UDP and TCP DNS listeners.
// Blocks until ctx is cancelled or a listener fails.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		s.logger.Info("dns server starting", "addr", s.udpServer.Addr, "proto", "udp")
		if err := s.udpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("udp server: %w", err)
		}
	}()

	go func() {
		s.logger.Info("dns server starting", "addr", s.tcpServer.Addr, "proto", "tcp")
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("tcp server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		s.udpServer.Shutdown() //nolint:errcheck
		s.tcpServer.Shutdown() //nolint:errcheck
		return nil
	case err := <-errCh:
		return err
	}
}

// Shutdown gracefully stops both DNS listeners.
func (s *Server) Shutdown() {
	s.udpServer.Shutdown() //nolint:errcheck
	s.tcpServer.Shutdown() //nolint:errcheck
}
