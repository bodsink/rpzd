package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/bodsink/dns-rpz/config"
	dbschema "github.com/bodsink/dns-rpz/db"
	dnsserver "github.com/bodsink/dns-rpz/internal/dns"
	"github.com/bodsink/dns-rpz/internal/store"
)

func main() {
	// --- Config ---
	cfgPath := "dns-rpz.conf"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	logger, levelVar := newLogger(cfg.Log)

	// --- Database ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := store.Connect(ctx, &cfg.Database)
	if err != nil {
		logger.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run schema migration on every startup — all DDL uses IF NOT EXISTS, safe to run multiple times.
	if err := db.Migrate(ctx, dbschema.Schema); err != nil {
		logger.Error("schema migration failed", "err", err)
		os.Exit(1)
	}
	if err := dbschema.Seed(ctx, db.Pool); err != nil {
		logger.Error("seed failed", "err", err)
		os.Exit(1)
	}

	if n, err := db.CleanupStaleSyncHistory(ctx); err != nil {
		logger.Warn("cleanup stale sync history failed", "err", err)
	} else if n > 0 {
		logger.Warn("marked stale sync history as failed", "count", n)
	}
	logger.Info("database ready")

	// --- Load app settings from DB ---
	settings, err := db.LoadAppSettings(ctx)
	if err != nil {
		logger.Error("failed to load app settings", "err", err)
		os.Exit(1)
	}

	// Apply log level from DB (overrides bootstrap config)
	levelVar.Set(parseLevelVar(settings.LogLevel))

	// --- Write PID file so dns-rpz-dashboard can send SIGHUP after sync ---
	if err := writePIDFile(cfg.Server.PIDFile); err != nil {
		logger.Warn("failed to write pid file", "path", cfg.Server.PIDFile, "err", err)
	} else {
		defer os.Remove(cfg.Server.PIDFile)
	}

	// --- Register SIGHUP handler BEFORE the long index-load so an incoming
	// SIGHUP from the dashboard does not kill the process with default behaviour.
	// The handler goroutine is started now; it will safely no-op until the
	// DNS server and handler variables are fully initialised below.
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)

	// --- In-memory index ---
	index := dnsserver.NewIndex(1_000_000)
	acl := dnsserver.NewACL()

	// Load ACL from DB
	cidrs, err := db.LoadEnabledCIDRs(ctx)
	if err != nil {
		logger.Error("failed to load ip filters", "err", err)
		os.Exit(1)
	}
	acl.Load(cidrs)
	logger.Info("acl loaded", "entries", acl.Len())

	// Load all blocked names from DB into memory
	zones, err := db.ListZones(ctx)
	if err != nil {
		logger.Error("failed to list zones", "err", err)
		os.Exit(1)
	}
	totalLoaded := 0
	for _, z := range zones {
		if !z.Enabled {
			continue
		}
		if err := db.LoadAllNames(ctx, z.ID, func(name, rdata string) error {
			index.Add(name, rdata)
			totalLoaded++
			return nil
		}); err != nil {
			logger.Error("failed to load names", "zone", z.Name, "err", err)
		}
	}
	logger.Info("rpz index loaded", "entries", totalLoaded)

	// --- DNS response cache ---
	var responseCache *dnsserver.ResponseCache
	if settings.DNSCacheSize > 0 {
		responseCache, err = dnsserver.NewResponseCache(settings.DNSCacheSize)
		if err != nil {
			logger.Error("failed to create dns response cache", "err", err)
			os.Exit(1)
		}
		logger.Info("dns response cache enabled", "size", settings.DNSCacheSize)
	}

	// --- DNS server ---
	upstreamServers := splitServers(settings.DNSUpstreams)
	upstream := dnsserver.NewUpstream(upstreamServers, settings.DNSUpstreamStrat, responseCache)
	handler := dnsserver.NewHandler(index, acl, settings.RPZDefaultAction, upstream, logger, settings.AuditLog)
	if settings.AuditLog {
		logger.Info("dns audit log enabled: all queries will be logged at INFO level")
	}
	dnsServer := dnsserver.NewServer(cfg.Server.DNSAddress, handler, logger)

	go func() {
		if err := dnsServer.Start(ctx); err != nil {
			logger.Error("dns server error", "err", err)
			cancel()
		}
	}()

	logger.Info("dns-rpz started", "dns", cfg.Server.DNSAddress)

	// --- SIGHUP: reload config file + ACL + RPZ index (used by systemctl reload) ---
	go func() {
		for range reload {
			logger.Info("SIGHUP received, reloading...")

			// Reload config file — apply runtime-changeable settings.
			// Settings that require a full restart (DNS_ADDRESS, DATABASE_DSN, etc.)
			// are logged as a warning but not applied.
			newCfg, err := config.Load(cfgPath)
			if err != nil {
				logger.Error("config reload failed, keeping current config", "err", err)
			} else {
				// LOG_LEVEL — apply immediately via LevelVar
				newLevel := parseLevelVar(newCfg.Log.Level)
				if levelVar.Level() != newLevel {
					levelVar.Set(newLevel)
					logger.Info("log level updated", "level", newCfg.Log.Level)
				}
				// Settings that require restart
				if newCfg.Server.DNSAddress != cfg.Server.DNSAddress ||
					newCfg.Database.DSN != cfg.Database.DSN {
					logger.Warn("some config changes require a full restart to take effect (DNS_ADDRESS, DATABASE_DSN)")
				}
			}

			// Reload upstream + audit log from DB settings
			newSettings, err := db.LoadAppSettings(ctx)
			if err != nil {
				logger.Error("failed to reload app settings", "err", err)
			} else {
				newUpstream := dnsserver.NewUpstream(splitServers(newSettings.DNSUpstreams), newSettings.DNSUpstreamStrat, responseCache)
				handler.SetUpstream(newUpstream)
				logger.Info("upstream reloaded", "servers", newSettings.DNSUpstreams, "strategy", newSettings.DNSUpstreamStrat)
				// DNS audit log — apply immediately via atomic.Bool
				if newSettings.AuditLog != handler.AuditLog() {
					handler.SetAuditLog(newSettings.AuditLog)
					logger.Info("audit log updated", "enabled", newSettings.AuditLog)
				}				// RPZ default action — apply atomically
				if newSettings.RPZDefaultAction != handler.DefaultAction() {
					handler.SetDefaultAction(newSettings.RPZDefaultAction)
					logger.Info("rpz default action updated", "action", newSettings.RPZDefaultAction)
				}				// Log level from DB — overrides config file level
				newLevel := parseLevelVar(newSettings.LogLevel)
				if levelVar.Level() != newLevel {
					levelVar.Set(newLevel)
					logger.Info("log level updated from db", "level", newSettings.LogLevel)
				}
			}

			// Reload ACL from DB
			newCIDRs, err := db.LoadEnabledCIDRs(ctx)
			if err != nil {
				logger.Error("acl reload failed", "err", err)
			} else {
				acl.Load(newCIDRs)
				logger.Info("acl reloaded", "entries", acl.Len())
			}

			// Reload RPZ index from DB
			zoneList, err := db.ListZones(ctx)
			if err != nil {
				logger.Error("index reload failed", "err", err)
				continue
			}
			newIndex := make(map[string]string, 3_000_000)
			for _, z := range zoneList {
				if !z.Enabled {
					continue
				}
				db.LoadAllNames(ctx, z.ID, func(name, rdata string) error { //nolint:errcheck
					newIndex[name] = rdata
					return nil
				})
			}
			index.Replace(newIndex)
			logger.Info("reload complete", "index_entries", index.Len())
		}
	}()

	// --- Graceful shutdown ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	dnsServer.Shutdown()
	cancel()
	logger.Info("shutdown complete")
}

// writePIDFile writes the current process PID to the given file path.
func writePIDFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir pid dir: %w", err)
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// splitServers splits a comma-separated list of DNS server addresses and trims whitespace.
func splitServers(s string) []string {
	var servers []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			servers = append(servers, part)
		}
	}
	if len(servers) == 0 {
		return []string{"8.8.8.8:53"}
	}
	return servers
}

func newLogger(cfg config.LogConfig) (*slog.Logger, *slog.LevelVar) {
	levelVar := &slog.LevelVar{}
	levelVar.Set(parseLevelVar(cfg.Level))

	opts := &slog.HandlerOptions{Level: levelVar}
	handler := slog.Handler(slog.NewTextHandler(os.Stdout, opts))

	return slog.New(handler), levelVar
}

// parseLevelVar converts a level string to slog.Level.
func parseLevelVar(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
