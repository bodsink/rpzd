package store

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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
	db     *DB
	ch     chan QueryLogEntry
	logger *slog.Logger
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
	}
}

// Run starts the background goroutine that flushes buffered entries to the DB.
// Returns when ctx is cancelled, flushing any remaining entries first.
func (b *BufferedQueryLogger) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	buf := make([]QueryLogEntry, 0, 500)
	for {
		select {
		case <-ctx.Done():
			// Drain remaining buffered entries before exit.
			draining := true
			for draining {
				select {
				case e := <-b.ch:
					buf = append(buf, e)
				default:
					draining = false
				}
			}
			b.flush(context.Background(), buf)
			return
		case e := <-b.ch:
			buf = append(buf, e)
			if len(buf) >= 500 {
				b.flush(ctx, buf)
				buf = buf[:0]
			}
		case <-ticker.C:
			if len(buf) > 0 {
				b.flush(ctx, buf)
				buf = buf[:0]
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
	TotalQueries      int64
	TotalBlocked      int64
	TotalAllowed      int64
	TotalRefused      int64
	BlockRate         float64
	AvgResponseTimeMs float64
	TopDomains        []DomainCount
	TopClients        []ClientCount
	TopBlocks         []DomainCount
	UpstreamStats     []UpstreamStat
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

	return s, nil
}
