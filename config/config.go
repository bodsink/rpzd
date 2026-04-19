// Package config handles loading bootstrap configuration from a .env file.
// Only minimal settings needed to connect to the database are stored here.
// All application settings (RPZ master, zones, sync interval, etc.) are
// stored in the PostgreSQL `settings` table and managed via the dashboard.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// BootstrapConfig holds the minimal configuration loaded from the .env file.
// It contains only what is needed before the database connection is established.
type BootstrapConfig struct {
	Server   ServerConfig
	Database DatabaseConfig
	Log      LogConfig
	Node     NodeConfig
}

// ServerConfig holds the network listen addresses for the DNS and HTTP servers.
type ServerConfig struct {
	DNSAddress        string // DNS_ADDRESS, e.g. "0.0.0.0:53"
	HTTPAddress       string // HTTP_ADDRESS, e.g. "0.0.0.0:8080"
	PIDFile           string // PID_FILE: path where rpzd writes its PID (default: /run/rpzd/rpzd.pid)
	TLSCertFile       string // TLS_CERT_FILE: path to TLS certificate PEM file (default: ./certs/server.crt)
	TLSKeyFile        string // TLS_KEY_FILE: path to TLS private key PEM file (default: ./certs/server.key)
	AdminInitPassword string // ADMIN_INIT_PASSWORD: used only on first run to set admin password; ignored if users already exist
	DashboardAddr     string // DASHBOARD_ADDR: internal address of rpzd-dashboard for NOTIFY forwarding (default: 127.0.0.1:8080)
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	DSN      string // DATABASE_DSN, e.g. "postgres://user:pass@host:5432/dbname"
	MaxConns int32  // DATABASE_MAX_CONNS (default: 20)
	MinConns int32  // DATABASE_MIN_CONNS (default: 2)
}

// LogConfig holds minimal bootstrap logging configuration.
// Log format, file output, and rotation are managed via the dashboard (stored in DB).
type LogConfig struct {
	Level string // LOG_LEVEL: debug, info, warn, error (default: info)
}

// NodeConfig holds trust network identity settings loaded from the config file.
type NodeConfig struct {
	KeyPath       string // NODE_KEY_PATH: path to Ed25519 private key file (default: ./node.key)
	Role          string // NODE_ROLE: "genesis", "master", or "slave" (default: "slave")
	BootstrapIP   string // NODE_BOOTSTRAP_IP: IP:port of a trusted node to join via (e.g. "10.0.0.1:8080")
	AdvertiseAddr string // NODE_ADVERTISE_ADDR: public address reported to peers (e.g. "203.0.113.5:8080"); required for genesis/master behind wildcard bind
}

// AppSettings holds application settings stored in the database,
// editable at runtime via the dashboard.
type AppSettings struct {
	Mode         string // "master" or "slave"
	MasterIP     string // AXFR master IP (slave mode)
	MasterPort   int    // AXFR master port (default: 53)
	TSIGKey      string // TSIG key name (optional)
	TSIGSecret   string // TSIG secret base64 (optional)
	SyncInterval int    // zone sync interval in seconds (default: 300)
}

// Load reads and parses the bootstrap .env file at the given path.
// File format: KEY=VALUE, lines starting with # are comments, blank lines are ignored.
func Load(path string) (*BootstrapConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: invalid format, expected KEY=VALUE", lineNum)
		}
		env[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &BootstrapConfig{}
	cfg.Server.DNSAddress = env["DNS_ADDRESS"]
	cfg.Server.HTTPAddress = env["HTTP_ADDRESS"]
	cfg.Server.PIDFile = env["PID_FILE"]
	cfg.Server.TLSCertFile = env["TLS_CERT_FILE"]
	cfg.Server.TLSKeyFile = env["TLS_KEY_FILE"]
	cfg.Server.AdminInitPassword = env["ADMIN_INIT_PASSWORD"]
	cfg.Server.DashboardAddr = env["DASHBOARD_ADDR"]
	cfg.Database.DSN = env["DATABASE_DSN"]
	cfg.Log.Level = env["LOG_LEVEL"]
	cfg.Node.KeyPath = env["NODE_KEY_PATH"]
	cfg.Node.Role = env["NODE_ROLE"]
	cfg.Node.BootstrapIP = env["NODE_BOOTSTRAP_IP"]
	cfg.Node.AdvertiseAddr = env["NODE_ADVERTISE_ADDR"]

	if v, ok := env["DATABASE_MAX_CONNS"]; ok {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("DATABASE_MAX_CONNS must be an integer")
		}
		cfg.Database.MaxConns = int32(n)
	}
	if v, ok := env["DATABASE_MIN_CONNS"]; ok {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("DATABASE_MIN_CONNS must be an integer")
		}
		cfg.Database.MinConns = int32(n)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	cfg.setDefaults()
	return cfg, nil
}

func (c *BootstrapConfig) validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("DATABASE_DSN is required")
	}
	return nil
}

// ValidateDNS checks that all fields required by the DNS binary are set.
func (c *BootstrapConfig) ValidateDNS() error {
	if c.Server.DNSAddress == "" {
		return fmt.Errorf("DNS_ADDRESS is required")
	}
	return nil
}

func (c *BootstrapConfig) setDefaults() {
	if c.Database.MaxConns == 0 {
		c.Database.MaxConns = 20
	}
	if c.Database.MinConns == 0 {
		c.Database.MinConns = 2
	}
	if c.Server.HTTPAddress == "" {
		c.Server.HTTPAddress = "0.0.0.0:8080"
	}
	if c.Server.PIDFile == "" {
		c.Server.PIDFile = "/run/rpzd/rpzd.pid"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Server.TLSCertFile == "" {
		c.Server.TLSCertFile = "./certs/server.crt"
	}
	if c.Server.TLSKeyFile == "" {
		c.Server.TLSKeyFile = "./certs/server.key"
	}
	if c.Server.DashboardAddr == "" {
		c.Server.DashboardAddr = "127.0.0.1:8080"
	}
	if c.Node.KeyPath == "" {
		c.Node.KeyPath = "./node.key"
	}
	if c.Node.Role == "" {
		c.Node.Role = "slave"
	}
}

// DefaultAppSettings returns sane defaults used on first run
// before any settings are saved to the database.
func DefaultAppSettings() *AppSettings {
	return &AppSettings{
		Mode:         "slave",
		MasterPort:   53,
		SyncInterval: 86400,
	}
}
