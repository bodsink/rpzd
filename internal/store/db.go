package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bodsink/rpzd/config"
)

// DB wraps a pgxpool connection pool.
type DB struct {
	Pool *pgxpool.Pool
}

// Connect creates a new pgxpool connection pool using the given config.
// It also runs a ping to verify connectivity before returning.
func Connect(ctx context.Context, cfg *config.DatabaseConfig) (*DB, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse database dsn: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close closes all connections in the pool.
func (db *DB) Close() {
	db.Pool.Close()
}

// Migrate runs the embedded schema SQL against the database.
// Uses IF NOT EXISTS so it is safe to run on every startup.
// Uses a PostgreSQL advisory lock to prevent concurrent migration races
// when multiple binaries (dns + dashboard) start at the same time.
func (db *DB) Migrate(ctx context.Context, schemaSQL string) error {
	const lockID = 7391824 // arbitrary fixed lock ID for rpzd migrations

	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for migration: %w", err)
	}
	defer conn.Release()

	// Block until we acquire the advisory lock, then release it automatically at end of session.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("acquire advisory lock: %w", err)
	}
	defer conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockID) //nolint:errcheck

	if _, err := conn.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("run schema migration: %w", err)
	}
	return nil
}
