package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ZoneAXFRRecord is a lightweight record entry used for outbound AXFR serving.
// Names are stored without the zone suffix (e.g. "pornhub.com."); the AXFR
// handler is responsible for appending the zone FQDN before sending.
type ZoneAXFRRecord struct {
	Name  string
	RType string
	RData string
	TTL   int
}

// ZoneRecordPage is a record entry with its DB ID, used for cursor-based
// pagination when propagating zone records over the trust-network HTTP API.
type ZoneRecordPage struct {
	ID    int64
	Name  string
	RType string
	RData string
	TTL   int
}

// ListZoneRecordsPage returns up to limit records for a zone where id > afterID,
// ordered by id. Used by the trust-network HTTP API to serve paginated records
// so slave nodes can pull zone contents without DNS AXFR.
func (db *DB) ListZoneRecordsPage(ctx context.Context, zoneName string, afterID int64, limit int) ([]ZoneRecordPage, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT r.id, r.name, r.rtype, r.rdata, r.ttl
		FROM rpz_records r
		JOIN rpz_zones z ON z.id = r.zone_id
		WHERE z.name = $1 AND z.enabled = TRUE AND r.id > $2
		ORDER BY r.id
		LIMIT $3`,
		zoneName, afterID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list zone records page %q: %w", zoneName, err)
	}
	defer rows.Close()

	var records []ZoneRecordPage
	for rows.Next() {
		var r ZoneRecordPage
		if err := rows.Scan(&r.ID, &r.Name, &r.RType, &r.RData, &r.TTL); err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// ListZoneRecordsForAXFR returns the current SOA serial and all records for a
// zone, ordered by name, suitable for building an outbound AXFR response.
// Returns pgx.ErrNoRows if the zone is not found or not enabled.
func (db *DB) ListZoneRecordsForAXFR(ctx context.Context, zoneName string) (serial int64, records []ZoneAXFRRecord, err error) {
	if err = db.Pool.QueryRow(ctx,
		`SELECT serial FROM rpz_zones WHERE name = $1 AND enabled = TRUE`,
		zoneName,
	).Scan(&serial); err != nil {
		return 0, nil, err
	}

	rows, err := db.Pool.Query(ctx, `
		SELECT r.name, r.rtype, r.rdata, r.ttl
		FROM rpz_records r
		JOIN rpz_zones z ON z.id = r.zone_id
		WHERE z.name = $1 AND z.enabled = TRUE
		ORDER BY r.name`,
		zoneName,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("list zone records for axfr %q: %w", zoneName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var r ZoneAXFRRecord
		if err := rows.Scan(&r.Name, &r.RType, &r.RData, &r.TTL); err != nil {
			continue
		}
		records = append(records, r)
	}
	return serial, records, rows.Err()
}

// Record represents one row in the rpz_records table.
type Record struct {
	ID        int64
	ZoneID    int64
	Name      string
	RType     string
	RData     string
	TTL       int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateRecord inserts a single record into rpz_records and returns the new ID.
func (db *DB) CreateRecord(ctx context.Context, r *Record) (int64, error) {
	var id int64
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO rpz_records (zone_id, name, rtype, rdata, ttl)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		r.ZoneID, r.Name, r.RType, r.RData, r.TTL,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create record: %w", err)
	}
	return id, nil
}

// DeleteRecord removes a single record by ID, restricted to a given zone.
func (db *DB) DeleteRecord(ctx context.Context, zoneID, recordID int64) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM rpz_records WHERE id = $1 AND zone_id = $2`,
		recordID, zoneID,
	)
	if err != nil {
		return fmt.Errorf("delete record %d: %w", recordID, err)
	}
	return nil
}

// LookupRecord checks if a domain name matches any RPZ record.
// Returns the matching record or nil if not found.
// This is the hot path for DNS queries — uses the idx_rpz_records_name index.
func (db *DB) LookupRecord(ctx context.Context, name string) (*Record, error) {
	var r Record
	err := db.Pool.QueryRow(ctx, `
		SELECT r.id, r.zone_id, r.name, r.rtype, r.rdata, r.ttl, r.created_at, r.updated_at
		FROM rpz_records r
		JOIN rpz_zones z ON z.id = r.zone_id
		WHERE r.name = $1 AND z.enabled = TRUE
		LIMIT 1`,
		name,
	).Scan(&r.ID, &r.ZoneID, &r.Name, &r.RType, &r.RData, &r.TTL, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, nil // not found is not an error
	}
	return &r, nil
}

// BulkUpsertSession streams records into a temporary (no-index) staging table
// via the PostgreSQL COPY binary protocol, then atomically replaces all zone
// records in rpz_records when Finish() is called.
//
// Strategy: COPY → staging (no index) → DELETE old + INSERT fresh in one tx.
// This is faster than UPSERT because:
//   - COPY to staging has zero index maintenance cost
//   - The final INSERT has no ON CONFLICT lookup per row
//   - Only one index-write pass over rpz_records (insert, not lookup+update)
//
// Usage:
//
//	sess, err := db.NewBulkUpsertSession(ctx, zoneID)
//	for _, batch := range batches { sess.AddBatch(ctx, batch) }
//	added, removed, err := sess.Finish(ctx, sourceNodeID, batchSig) // or sess.Close() to abort
type BulkUpsertSession struct {
	conn   *pgxpool.Conn
	zoneID int64
	total  int
}

// NewBulkUpsertSession acquires a dedicated connection and prepares a temporary
// staging table on it (created once per connection, truncated between syncs).
func (db *DB) NewBulkUpsertSession(ctx context.Context, zoneID int64) (*BulkUpsertSession, error) {
	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for bulk upsert: %w", err)
	}

	// Create once per connection; harmless if it already exists.
	_, err = conn.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS rpz_stage (
			name  TEXT    NOT NULL,
			rtype TEXT    NOT NULL,
			rdata TEXT    NOT NULL,
			ttl   INTEGER NOT NULL
		)`)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("create temp stage table: %w", err)
	}

	// Clear leftovers from any previous sync on this connection.
	if _, err = conn.Exec(ctx, `TRUNCATE rpz_stage`); err != nil {
		conn.Release()
		return nil, fmt.Errorf("truncate temp stage: %w", err)
	}

	return &BulkUpsertSession{conn: conn, zoneID: zoneID}, nil
}

// AddBatch streams a slice of records into the staging table using COPY.
// No indexes are maintained on the staging table, so this is very fast.
func (s *BulkUpsertSession) AddBatch(ctx context.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	rows := make([][]any, len(records))
	for i, r := range records {
		rows[i] = []any{r.Name, r.RType, r.RData, int32(r.TTL)}
	}
	_, err := s.conn.CopyFrom(
		ctx,
		pgx.Identifier{"rpz_stage"},
		[]string{"name", "rtype", "rdata", "ttl"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("copy %d rows to stage: %w", len(records), err)
	}
	s.total += len(records)
	return nil
}

// Finish atomically replaces all zone records:
//  1. DELETE all existing records for the zone
//  2. INSERT all staged records with optional trust-network metadata
//
// sourceNodeID: UUID of the trust-network node that served this AXFR (empty = unknown/pre-trust).
// batchSig: Ed25519 signature over the AXFR batch (empty = not signed).
//
// Returns (added, removed, err). Releases the connection when done.
func (s *BulkUpsertSession) Finish(ctx context.Context, sourceNodeID, batchSig string) (added, removed int, err error) {
	defer s.conn.Release()

	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin transaction: %w", err)
	}
	// Use Background so ROLLBACK is always sent even if ctx is canceled.
	defer tx.Rollback(context.Background()) //nolint:errcheck

	// Delete all old records for the zone and capture count.
	tag, err := tx.Exec(ctx, `DELETE FROM rpz_records WHERE zone_id = $1`, s.zoneID)
	if err != nil {
		return 0, 0, fmt.Errorf("delete zone %d records: %w", s.zoneID, err)
	}
	removed = int(tag.RowsAffected())

	// Insert all staged records. Include trust-network metadata if provided.
	// source_node_id is a UUID — pass NULL when empty to avoid invalid UUID error.
	var nodeIDArg any
	if sourceNodeID != "" {
		nodeIDArg = sourceNodeID
	}
	var sigArg any
	if batchSig != "" {
		sigArg = batchSig
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO rpz_records (zone_id, name, rtype, rdata, ttl, updated_at, synced_at, source_node_id, axfr_batch_sig)
		SELECT $1, name, rtype, rdata, ttl, NOW(), NOW(), $2::uuid, $3
		FROM rpz_stage`,
		s.zoneID, nodeIDArg, sigArg,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("insert from stage to rpz_records: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit bulk replace: %w", err)
	}
	return s.total, removed, nil
}

// Close discards the session without writing to rpz_records. Safe to call after Finish.
func (s *BulkUpsertSession) Close() {
	s.conn.Release()
}

// ApplyIXFRDelta atomically applies an IXFR incremental delta to rpz_records:
// deletes the specified records (matched by zone_id + name + rtype + rdata) and
// inserts new records, all within a single transaction.
//
// Both slices may be empty — in that case the function is a no-op.
func (db *DB) ApplyIXFRDelta(ctx context.Context, zoneID int64, toDelete []Record, toAdd []Record) (added, removed int, err error) {
	if len(toDelete) == 0 && len(toAdd) == 0 {
		return 0, 0, nil
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin ixfr delta tx: %w", err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck

	if len(toDelete) > 0 {
		names := make([]string, len(toDelete))
		rtypes := make([]string, len(toDelete))
		rdatas := make([]string, len(toDelete))
		for i, r := range toDelete {
			names[i] = r.Name
			rtypes[i] = r.RType
			rdatas[i] = r.RData
		}
		tag, err := tx.Exec(ctx, `
			DELETE FROM rpz_records
			WHERE zone_id = $1
			  AND (name, rtype, rdata) IN (
			      SELECT * FROM unnest($2::text[], $3::text[], $4::text[])
			  )`,
			zoneID, names, rtypes, rdatas,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("ixfr delete: %w", err)
		}
		removed = int(tag.RowsAffected())
	}

	if len(toAdd) > 0 {
		batch := &pgx.Batch{}
		for _, r := range toAdd {
			batch.Queue(`
				INSERT INTO rpz_records (zone_id, name, rtype, rdata, ttl, updated_at, synced_at)
				VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
				ON CONFLICT (zone_id, name, rtype, rdata) DO UPDATE
				  SET ttl = EXCLUDED.ttl, updated_at = NOW(), synced_at = NOW()`,
				zoneID, r.Name, r.RType, r.RData, r.TTL,
			)
		}
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < len(toAdd); i++ {
			tag, batchErr := br.Exec()
			if batchErr != nil {
				br.Close()
				return 0, 0, fmt.Errorf("ixfr insert row %d: %w", i, batchErr)
			}
			added += int(tag.RowsAffected())
		}
		if err := br.Close(); err != nil {
			return 0, 0, fmt.Errorf("ixfr insert batch close: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit ixfr delta: %w", err)
	}
	return added, removed, nil
}

// CountRecords returns the total number of records across all zones.
func (db *DB) CountRecords(ctx context.Context) (int64, error) {
	var n int64
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM rpz_records`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count records: %w", err)
	}
	return n, nil
}

// CountRecordsByZone returns record count per zone as a map[zoneID]count.
func (db *DB) CountRecordsByZone(ctx context.Context) (map[int64]int64, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT zone_id, COUNT(*) FROM rpz_records GROUP BY zone_id`)
	if err != nil {
		return nil, fmt.Errorf("count records by zone: %w", err)
	}
	defer rows.Close()

	result := make(map[int64]int64)
	for rows.Next() {
		var zoneID, count int64
		if err := rows.Scan(&zoneID, &count); err != nil {
			return nil, fmt.Errorf("scan count row: %w", err)
		}
		result[zoneID] = count
	}
	return result, rows.Err()
}

// LoadAllNames loads all RPZ entries for a zone into memory via streaming.
// Used at startup to build the in-memory lookup index.
func (db *DB) LoadAllNames(ctx context.Context, zoneID int64, fn func(name, rdata string) error) error {
	rows, err := db.Pool.Query(ctx,
		`SELECT name, rdata FROM rpz_records WHERE zone_id = $1`, zoneID)
	if err != nil {
		return fmt.Errorf("load names for zone %d: %w", zoneID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, rdata string
		if err := rows.Scan(&name, &rdata); err != nil {
			return fmt.Errorf("scan name: %w", err)
		}
		if err := fn(name, rdata); err != nil {
			return err
		}
	}
	return rows.Err()
}

// LoadAuthRecords streams all records (name, rtype, rdata, ttl) for a non-RPZ
// zone. Used at startup and on SIGHUP to build the in-memory authoritative index
// for zone_type = 'domain' and 'reverse_ptr'.
func (db *DB) LoadAuthRecords(ctx context.Context, zoneID int64, fn func(name, rtype, rdata string, ttl int) error) error {
	rows, err := db.Pool.Query(ctx,
		`SELECT name, rtype, rdata, ttl FROM rpz_records WHERE zone_id = $1`, zoneID)
	if err != nil {
		return fmt.Errorf("load auth records for zone %d: %w", zoneID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, rtype, rdata string
		var ttl int
		if err := rows.Scan(&name, &rtype, &rdata, &ttl); err != nil {
			return fmt.Errorf("scan auth record: %w", err)
		}
		if err := fn(name, rtype, rdata, ttl); err != nil {
			return err
		}
	}
	return rows.Err()
}

// InjectedRecordSummary describes records injected by a minority node in a zone.
type InjectedRecordSummary struct {
	ZoneID       int64
	SourceNodeID string // UUID of the minority node
	RecordCount  int
}

// FindInjectedRecords detects records likely injected by a minority master node.
//
// Detection criteria (per design doc):
//  1. Multiple distinct source_node_ids exist for the same zone.
//  2. A source has fewer records than ceil(total_masters/2) — true minority.
//  3. Records have been present for > injectionGraceWindow (10 min) to avoid
//     false positives from normal AXFR propagation delays.
//
// Returns a list of (zone_id, source_node_id, count) for the caller to purge.
func (db *DB) FindInjectedRecords(ctx context.Context) ([]InjectedRecordSummary, error) {
	rows, err := db.Pool.Query(ctx, `
		WITH zone_sources AS (
		    -- Count records per (zone, source_node) — only aged records past grace window.
		    SELECT   zone_id,
		             source_node_id,
		             COUNT(*) AS record_count
		    FROM     rpz_records
		    WHERE    source_node_id IS NOT NULL
		      AND    synced_at < now() - INTERVAL '10 minutes'
		    GROUP BY zone_id, source_node_id
		),
		zone_stats AS (
		    SELECT   zone_id,
		             COUNT(DISTINCT source_node_id)                    AS total_sources,
		             CEIL(COUNT(DISTINCT source_node_id)::numeric / 2) AS majority_threshold
		    FROM     zone_sources
		    GROUP BY zone_id
		    HAVING   COUNT(DISTINCT source_node_id) > 1
		)
		SELECT  zs.zone_id,
		        zs.source_node_id::text,
		        zs.record_count
		FROM    zone_sources zs
		JOIN    zone_stats   zst ON zst.zone_id = zs.zone_id
		-- Minority: present in fewer than majority_threshold sources
		WHERE   zs.record_count < zst.majority_threshold
	`)
	if err != nil {
		return nil, fmt.Errorf("find injected records: %w", err)
	}
	defer rows.Close()

	var result []InjectedRecordSummary
	for rows.Next() {
		var s InjectedRecordSummary
		if err := rows.Scan(&s.ZoneID, &s.SourceNodeID, &s.RecordCount); err != nil {
			return nil, fmt.Errorf("scan injected record row: %w", err)
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// PurgeInjectedRecords deletes all rpz_records attributed to sourceNodeID in zoneID.
// Returns the number of rows deleted.
// The caller is responsible for writing a 'purge_injected' ledger entry.
func (db *DB) PurgeInjectedRecords(ctx context.Context, zoneID int64, sourceNodeID string) (int, error) {
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM rpz_records
		WHERE zone_id = $1 AND source_node_id = $2::uuid`,
		zoneID, sourceNodeID,
	)
	if err != nil {
		return 0, fmt.Errorf("purge injected records for zone %d node %s: %w", zoneID, sourceNodeID, err)
	}
	return int(tag.RowsAffected()), nil
}
