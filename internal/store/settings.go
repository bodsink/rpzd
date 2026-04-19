package store

import (
	"context"
	"fmt"
	"strings"
)

// Setting represents one row in the settings table.
type Setting struct {
	Key   string
	Value string
}

// GetSetting fetches a single setting value by key.
// Returns an empty string and no error if the key does not exist.
func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := db.Pool.QueryRow(ctx,
		`SELECT value FROM settings WHERE key = $1`, key,
	).Scan(&value)
	if err != nil {
		// pgx returns pgx.ErrNoRows if not found — treat as empty
		return "", nil
	}
	return value, nil
}

// SetSetting upserts a setting value by key.
func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// GetAllSettings returns all settings as a map[key]value.
func (db *DB) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := db.Pool.Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("query settings: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan setting row: %w", err)
		}
		result[k] = v
	}
	return result, rows.Err()
}

// LoadAppSettings loads AppSettings from the database settings table.
// Falls back to defaults for missing keys.
func (db *DB) LoadAppSettings(ctx context.Context) (*AppSettingsRow, error) {
	m, err := db.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}

	s := &AppSettingsRow{
		Mode:             stringOrDefault(m["mode"], "slave"),
		MasterIP:         m["master_ip"],
		MasterPort:       intOrDefault(m["master_port"], 53),
		TSIGKey:          m["tsig_key"],
		TSIGSecret:       m["tsig_secret"],
		SyncInterval:     intOrDefault(m["sync_interval"], 86400),
		WebPort:          intOrDefault(m["web_port"], 8080),
		Timezone:         stringOrDefault(m["timezone"], "UTC"),
		DNSUpstreams:     stringOrDefault(m["dns_upstream"], "8.8.8.8:53,8.8.4.4:53"),
		DNSUpstreamStrat: stringOrDefault(m["dns_upstream_strategy"], "roundrobin"),
		DNSCacheSize:     intOrDefault(m["dns_cache_size"], 100000),
		RPZDefaultAction: stringOrDefault(m["rpz_default_action"], "nxdomain"),
		AuditLog:         boolOrDefault(m["dns_audit_log"], false),
		RRLRate:          intOrDefault(m["rrl_rate"], 0),
		RRLBurst:         intOrDefault(m["rrl_burst"], 0),
		LogLevel:         stringOrDefault(m["log_level"], "info"),
		LogFormat:        stringOrDefault(m["log_format"], "text"),
		LogFile:          boolOrDefault(m["log_file"], false),
		LogFilePath:      stringOrDefault(m["log_file_path"], "/var/log/rpzd/rpzd.log"),
		LogRotate:        boolOrDefault(m["log_rotate"], false),
		LogRotateSize:    stringOrDefault(m["log_rotate_size"], "100M"),
		LogRotateKeep:    intOrDefault(m["log_rotate_keep"], 7),
	}
	return s, nil
}

// AppSettingsRow mirrors config.AppSettings but is owned by the store layer.
type AppSettingsRow struct {
	Mode             string
	MasterIP         string
	MasterPort       int
	TSIGKey          string
	TSIGSecret       string
	SyncInterval     int
	WebPort          int    // web dashboard listen port (default: 8080)
	Timezone         string // system timezone, e.g. "Asia/Jakarta" (default: "UTC")
	DNSUpstreams     string // comma-separated upstream resolvers (default: "8.8.8.8:53,8.8.4.4:53")
	DNSUpstreamStrat string // roundrobin | random | race (default: roundrobin)
	DNSCacheSize     int    // dns_cache_size: upstream response cache entries, 0=disabled (default: 100000)
	RPZDefaultAction string // rpz_default_action: nxdomain|nodata (default: nxdomain)
	AuditLog         bool   // dns_audit_log: log every query at INFO level (default: false)
	RRLRate          int    // rrl_rate: max queries/sec per client IP, 0=disabled (default: 0)
	RRLBurst         int    // rrl_burst: token bucket burst size, 0=same as rrl_rate (default: 0)
	// Logging
	LogLevel      string // log_level: debug|info|warn|error (default: info)
	LogFormat     string // log_format: text|json (default: text)
	LogFile       bool   // log_file: write logs to file (default: false)
	LogFilePath   string // log_file_path: path to log file (default: /var/log/rpzd/rpzd.log)
	LogRotate     bool   // log_rotate: enable logrotate config generation (default: false)
	LogRotateSize string // log_rotate_size: rotate when file reaches this size, e.g. 100M (default: 100M)
	LogRotateKeep int    // log_rotate_keep: number of rotated files to keep (default: 7)
}

func stringOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func intOrDefault(v string, def int) int {
	if v == "" {
		return def
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	if n == 0 {
		return def
	}
	return n
}

func boolOrDefault(v string, def bool) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return def
}
