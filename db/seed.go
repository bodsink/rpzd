package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Seed is a no-op placeholder. Default zones are no longer seeded automatically.
// Zones are added by the administrator via the dashboard or REST API.
func Seed(_ context.Context, _ *pgxpool.Pool) error {
	return nil
}

// SeedAdminUser creates the default admin user if no users exist (first run).
// If initPassword is non-empty, it is used as the initial password; otherwise falls back to "admin".
// Returns (created bool, password string, err error).
// The caller SHOULD log a prominent warning when created is true.
func SeedAdminUser(ctx context.Context, pool *pgxpool.Pool, initPassword string) (created bool, usedPassword string, err error) {
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, "", fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return false, "", nil
	}

	password := initPassword
	if password == "" {
		password = "admin"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return false, "", fmt.Errorf("generate default password hash: %w", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES ('admin', $1, 'admin')
		ON CONFLICT (username) DO NOTHING`, string(hash),
	)
	if err != nil {
		return false, "", fmt.Errorf("seed admin user: %w", err)
	}
	return true, password, nil
}
