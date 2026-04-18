package store

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// QueryLogEntry represents a single DNS query event.
type QueryLogEntry struct {
	ClientIP  string
	Domain    string
	QType     string
	Result    string // "allowed", "blocked", "refused"
	Upstream  string // upstream server used (only for allowed); empty for blocked/refused
	RTTMs     int64  // round-trip time in milliseconds (only for allowed via upstream)
	QueriedAt time.Time
}

// BufferedQueryLogger buffers DNS query log entries and flushes to the database in batches.
// It implements the dns.QueryLogger interface.
type BufferedQueryLogger struct {
	db           *DB
	ch           chan QueryLogEntry
	logger       *slog.Logger
	dropped      atomic.Int64
	queryCountFn atomic.Value // stores func() int64; nil when not set
}

// SetQueryCountFunc sets a function that returns the total DNS queries received
// by the DNS server process since startup. Called on every flush to persist the
// count to the server_stats table so the dashboard can display it.
func (b *BufferedQueryLogger) SetQueryCountFunc(fn func() int64) {
	b.queryCountFn.Store(fn)
}

// NewBufferedQueryLogger creates a new BufferedQueryLogger with the given channel capacity.
func NewBufferedQueryLogger(db *DB, bufferSize int, logger *slog.Logger) *BufferedQueryLogger {
	return &BufferedQueryLogger{
		db:     db,
		ch:     make(chan QueryLogEntry, bufferSize),
		logger: logger,
	}
}

// LogQuery enqueues a query log entry. Non-blocking — silently drops if buffer is full.
func (b *BufferedQueryLogger) LogQuery(clientIP, domain, qtype, result, upstream string, rttMs int64) {
	select {
	case b.ch <- QueryLogEntry{
		ClientIP:  clientIP,
		Domain:    domain,
		QType:     qtype,
		Result:    result,
		Upstream:  upstream,
		RTTMs:     rttMs,
		QueriedAt: time.Now(),
	}:
	default:
		// Buffer full — drop to avoid blocking the DNS query path.
		b.dropped.Add(1)
	}
}

// Run starts the background goroutine that flushes buffered entries to the DB.
// Returns when ctx is cancelled, flushing any remaining entries first.
//
// Design: the goroutine drains the ENTIRE channel into buf before each flush so
// that in-flight entries are not left in the channel while the goroutine is
// blocked inside the PostgreSQL COPY call. This prevents the channel from
// filling up and silently dropping entries under high query rates.
func (b *BufferedQueryLogger) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	buf := make([]QueryLogEntry, 0, 5000)

	// drainAvailable drains all currently buffered channel entries into buf
	// without blocking. Must be called before every flush.
	drainAvailable := func() {
		for {
			select {
			case e := <-b.ch:
				buf = append(buf, e)
			default:
				return
			}
		}
	}

	doFlush := func(flushCtx context.Context) {
		drainAvailable()
		if len(buf) == 0 {
			return
		}
		if d := b.dropped.Swap(0); d > 0 {
			b.logger.Warn("query log entries dropped: channel was full",
				"dropped", d,
				"hint", "consider increasing buffer size or reducing query volume")
		}
		b.flush(flushCtx, buf)
		buf = buf[:0]
		// Persist live query counter so the dashboard can display true received count.
		if fn, ok := b.queryCountFn.Load().(func() int64); ok && fn != nil {
			if err := b.db.UpsertServerStat(flushCtx, "dns_queries_received", fn()); err != nil {
				b.logger.Warn("failed to persist query counter", "err", err)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			doFlush(context.Background())
			return
		case <-ticker.C:
			doFlush(ctx)
		case e := <-b.ch:
			buf = append(buf, e)
			drainAvailable()
			if len(buf) >= 2000 {
				doFlush(ctx)
			}
		}
	}
}

// flush batch-inserts query log entries into the database.
func (b *BufferedQueryLogger) flush(ctx context.Context, entries []QueryLogEntry) {
	if len(entries) == 0 {
		return
	}
	if err := b.db.InsertQueryLogBatch(ctx, entries); err != nil {
		b.logger.Warn("query log flush failed", "err", err, "count", len(entries))
	}
}

// InsertQueryLogBatch inserts a batch of query log entries using COPY protocol for efficiency.
func (db *DB) InsertQueryLogBatch(ctx context.Context, entries []QueryLogEntry) error {
	_, err := db.Pool.CopyFrom(
		ctx,
		pgx.Identifier{"dns_query_log"},
		[]string{"client_ip", "domain", "qtype", "result", "upstream", "rtt_ms", "queried_at"},
		pgx.CopyFromSlice(len(entries), func(i int) ([]any, error) {
			e := entries[i]
			var upstream any
			if e.Upstream != "" {
				upstream = e.Upstream
			}
			var rttMs any
			if e.RTTMs > 0 {
				rttMs = e.RTTMs
			}
			return []any{e.ClientIP, e.Domain, e.QType, e.Result, upstream, rttMs, e.QueriedAt}, nil
		}),
	)
	if err != nil {
		return fmt.Errorf("insert query log batch: %w", err)
	}
	return nil
}

// UpsertServerStat upserts a named integer counter in the server_stats table.
// Used by the DNS process to persist live counters for the dashboard.
func (db *DB) UpsertServerStat(ctx context.Context, key string, value int64) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO server_stats (key, value, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("upsert server stat %q: %w", key, err)
	}
	return nil
}

// GetServerStat reads a named counter from server_stats.
// Returns 0, nil when the key does not exist.
func (db *DB) GetServerStat(ctx context.Context, key string) (int64, error) {
	var value int64
	err := db.Pool.QueryRow(ctx,
		`SELECT value FROM server_stats WHERE key = $1`, key,
	).Scan(&value)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get server stat %q: %w", key, err)
	}
	return value, nil
}

// CleanupOldQueryLogs deletes query logs older than retentionDays.
// Safe to call periodically to prevent unbounded table growth.
func (db *DB) CleanupOldQueryLogs(ctx context.Context, retentionDays int) (int64, error) {
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM dns_query_log WHERE queried_at < NOW() - ($1 || ' days')::INTERVAL`,
		retentionDays,
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup old query logs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ─── Statistics ───────────────────────────────────────────────────────────────

// DomainCount holds a domain name with its query count.
type DomainCount struct {
	Domain string
	Count  int64
}

// ClientCount holds a client IP with its query count.
type ClientCount struct {
	ClientIP string
	Count    int64
}

// UpstreamStat holds per-upstream query count and average response time.
type UpstreamStat struct {
	Server  string
	Queries int64
	AvgRTT  float64 // milliseconds
}

// QueryStats holds aggregate DNS query statistics for a time period.
type QueryStats struct {
	TotalQueries        int64
	TotalBlocked        int64
	TotalAllowed        int64
	TotalRefused        int64
	CacheHits           int64
	BlockRate           float64
	CacheHitRate        float64
	AvgResponseTimeMs   float64
	LiveQueriesReceived int64 // total queries received by DNS process since last restart (from server_stats)
	TopDomains          []DomainCount
	TopClients          []ClientCount
	TopBlocks           []DomainCount
	UpstreamStats       []UpstreamStat
}

// GetQueryStats returns aggregate DNS query statistics since the given time.
func (db *DB) GetQueryStats(ctx context.Context, since time.Time) (QueryStats, error) {
	var s QueryStats

	// ── Totals by result type ──────────────────────────────────────────────────
	rows, err := db.Pool.Query(ctx,
		`SELECT result, COUNT(*) FROM dns_query_log WHERE queried_at >= $1 GROUP BY result`,
		since,
	)
	if err != nil {
		return s, fmt.Errorf("query stats totals: %w", err)
	}
	for rows.Next() {
		var result string
		var count int64
		if err := rows.Scan(&result, &count); err != nil {
			continue
		}
		switch result {
		case "blocked":
			s.TotalBlocked = count
		case "allowed":
			s.TotalAllowed = count
		case "refused":
			s.TotalRefused = count
		}
		s.TotalQueries += count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("query stats totals scan: %w", err)
	}
	if s.TotalQueries > 0 {
		s.BlockRate = float64(s.TotalBlocked) / float64(s.TotalQueries) * 100
	}

	// ── Cache hits (allowed queries answered from local response cache) ─────────
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM dns_query_log
		 WHERE queried_at >= $1 AND upstream = 'cache'`,
		since,
	).Scan(&s.CacheHits); err != nil {
		s.CacheHits = 0
	}
	if s.TotalAllowed > 0 {
		s.CacheHitRate = float64(s.CacheHits) / float64(s.TotalAllowed) * 100
	}

	// ── Top domains (all results) ──────────────────────────────────────────────
	rows, err = db.Pool.Query(ctx,
		`SELECT domain, COUNT(*) AS cnt FROM dns_query_log
		 WHERE queried_at >= $1
		 GROUP BY domain ORDER BY cnt DESC LIMIT 10`,
		since,
	)
	if err == nil {
		for rows.Next() {
			var d DomainCount
			if err := rows.Scan(&d.Domain, &d.Count); err == nil {
				s.TopDomains = append(s.TopDomains, d)
			}
		}
		rows.Close()
	}

	// ── Top clients (only IPs covered by an enabled IP filter) ───────────────
	rows, err = db.Pool.Query(ctx,
		`SELECT host(client_ip), COUNT(*) AS cnt FROM dns_query_log q
		 WHERE queried_at >= $1
		   AND EXISTS (
		         SELECT 1 FROM ip_filters f
		         WHERE f.enabled AND q.client_ip <<= f.cidr
		       )
		 GROUP BY client_ip ORDER BY cnt DESC LIMIT 10`,
		since,
	)
	if err == nil {
		for rows.Next() {
			var c ClientCount
			if err := rows.Scan(&c.ClientIP, &c.Count); err == nil {
				s.TopClients = append(s.TopClients, c)
			}
		}
		rows.Close()
	}

	// ── Top blocked domains ────────────────────────────────────────────────────
	rows, err = db.Pool.Query(ctx,
		`SELECT domain, COUNT(*) AS cnt FROM dns_query_log
		 WHERE queried_at >= $1 AND result = 'blocked'
		 GROUP BY domain ORDER BY cnt DESC LIMIT 10`,
		since,
	)
	if err == nil {
		for rows.Next() {
			var d DomainCount
			if err := rows.Scan(&d.Domain, &d.Count); err == nil {
				s.TopBlocks = append(s.TopBlocks, d)
			}
		}
		rows.Close()
	}

	// ── Average upstream response time (allowed queries only) ─────────────────
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(rtt_ms), 0) FROM dns_query_log
		 WHERE queried_at >= $1 AND rtt_ms IS NOT NULL AND rtt_ms > 0`,
		since,
	).Scan(&s.AvgResponseTimeMs); err != nil {
		s.AvgResponseTimeMs = 0
	}

	// ── Per-upstream: queries + avg RTT ───────────────────────────────────────
	rows, err = db.Pool.Query(ctx,
		`SELECT upstream, COUNT(*) AS queries, AVG(rtt_ms) AS avg_rtt
		 FROM dns_query_log
		 WHERE queried_at >= $1
		   AND upstream IS NOT NULL AND upstream != '' AND upstream != 'cache'
		 GROUP BY upstream
		 ORDER BY queries DESC`,
		since,
	)
	if err == nil {
		for rows.Next() {
			var u UpstreamStat
			if err := rows.Scan(&u.Server, &u.Queries, &u.AvgRTT); err == nil {
				if host, _, err := net.SplitHostPort(u.Server); err == nil {
					u.Server = host
				}
				s.UpstreamStats = append(s.UpstreamStats, u)
			}
		}
		rows.Close()
	}

	// ── Live queries received (from DNS process counter) ─────────────────────
	if v, err := db.GetServerStat(ctx, "dns_queries_received"); err == nil {
		s.LiveQueriesReceived = v
	}

	return s, nil
}
