package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bodsink/dns-rpz/config"
	dbschema "github.com/bodsink/dns-rpz/db"
	"github.com/bodsink/dns-rpz/internal/api"
	"github.com/bodsink/dns-rpz/internal/store"
	"github.com/bodsink/dns-rpz/internal/syncer"
)

// nopIndexer satisfies the syncer.Indexer interface with no-ops.
// The dashboard has no in-memory DNS index; after sync it signals
// the DNS service to reload its own index via SIGHUP.
type nopIndexer struct{}

func (n *nopIndexer) Add(name, action string)                       {}
func (n *nopIndexer) Remove(name string)                            {}
func (n *nopIndexer) Replace(newSet map[string]string)              {}
func (n *nopIndexer) ReplaceZone(zoneID int64, m map[string]string) {}

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

	if err := db.Migrate(ctx, dbschema.Schema); err != nil {
		logger.Error("schema migration failed", "err", err)
		os.Exit(1)
	}
	if err := dbschema.Seed(ctx, db.Pool); err != nil {
		logger.Error("seed failed", "err", err)
		os.Exit(1)
	}

	// Seed default admin user on first run.
	if created, err := dbschema.SeedAdminUser(ctx, db.Pool); err != nil {
		logger.Error("failed to seed admin user", "err", err)
		os.Exit(1)
	} else if created {
		logger.Warn("DEFAULT ADMIN CREATED — username: admin, password: admin — CHANGE IMMEDIATELY")
	}
	logger.Info("database ready")

	// --- Syncer (uses nop index; after sync signals DNS service via SIGHUP) ---
	zoneSyncer := syncer.NewZoneSyncer(db, &nopIndexer{}, logger)

	pidFile := cfg.Server.PIDFile
	zoneSyncer.SetPostSyncHook(func() {
		if err := signalPIDFile(pidFile, syscall.SIGHUP); err != nil {
			logger.Warn("failed to signal dns service after sync", "pid_file", pidFile, "err", err)
		} else {
			logger.Info("sent SIGHUP to dns service for index reload", "pid_file", pidFile)
		}
	})

	settings, err := db.LoadAppSettings(ctx)
	if err != nil {
		logger.Error("failed to load app settings", "err", err)
		os.Exit(1)
	}
	scheduler := syncer.NewScheduler(zoneSyncer, settings.SyncInterval, logger)
	go scheduler.Run(ctx)

	// --- Session cleanup (hourly) ---
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if n, err := db.CleanupExpiredSessions(ctx); err != nil {
					logger.Warn("session cleanup failed", "err", err)
				} else if n > 0 {
					logger.Debug("expired sessions removed", "count", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// --- Apply log level from DB settings (overrides bootstrap config) ---
	levelVar.Set(parseLevelVar(settings.LogLevel))

	// --- Apply timezone from DB settings ---
	if settings.Timezone != "" {
		if err := api.ApplyTimezone(settings.Timezone); err != nil {
			logger.Warn("timezone apply failed (requires root/sudo)", "timezone", settings.Timezone, "err", err)
		} else {
			logger.Info("system timezone applied", "timezone", settings.Timezone)
		}
	}

	// --- Resolve effective HTTP address (override port from DB web_port) ---
	httpAddr := cfg.Server.HTTPAddress
	if settings.WebPort > 0 {
		host, _, err := net.SplitHostPort(httpAddr)
		if err != nil {
			host = "0.0.0.0"
		}
		httpAddr = net.JoinHostPort(host, strconv.Itoa(settings.WebPort))
	}

	// --- TLS: always enabled — generate self-signed cert if not present ---
	if err := api.EnsureSelfSignedCert(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil {
		logger.Error("failed to generate TLS certificate", "err", err)
		os.Exit(1)
	}
	tlsCfg := &api.TLSConfig{
		CertFile: cfg.Server.TLSCertFile,
		KeyFile:  cfg.Server.TLSKeyFile,
	}
	logger.Info("TLS ready", "cert", cfg.Server.TLSCertFile, "key", cfg.Server.TLSKeyFile)

	// --- HTTP dashboard ---
	apiServer := api.NewServer(db, zoneSyncer, logger, "./assets/templates", "./assets/static")
	apiServer.SetDNSSignal(func() error {
		return signalPIDFile(pidFile, syscall.SIGHUP)
	})
	apiServer.SetSelfReload(func() error {
		// Send SIGHUP to self — the SIGHUP handler below will reload sync interval from DB.
		return syscall.Kill(os.Getpid(), syscall.SIGHUP)
	})
	apiServer.SetRestartWeb(func() error {
		out, err := exec.Command("systemctl", "restart", "dns-rpz-http").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart dns-rpz-http: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	})
	apiServer.SetDNSAddress(cfg.Server.DNSAddress)
	go func() {
		if err := apiServer.Start(ctx, httpAddr, tlsCfg); err != nil {
			logger.Error("dashboard error", "err", err)
			cancel()
		}
	}()

	logger.Info("dns-rpz-dashboard started", "addr", httpAddr, "tls", true)

	// --- SIGHUP: reload sync interval and log settings from DB ---
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			logger.Info("SIGHUP received, reloading settings...")

			newSettings, err := db.LoadAppSettings(ctx)
			if err != nil {
				logger.Error("settings reload failed", "err", err)
			} else {
				// Apply log level from DB
				newLevel := parseLevelVar(newSettings.LogLevel)
				if levelVar.Level() != newLevel {
					levelVar.Set(newLevel)
					logger.Info("log level updated from db", "level", newSettings.LogLevel)
				}
				// Apply sync interval if changed
				if newSettings.SyncInterval != settings.SyncInterval {
					settings.SyncInterval = newSettings.SyncInterval
					scheduler.SetInterval(newSettings.SyncInterval)
					logger.Info("sync interval updated", "interval_seconds", newSettings.SyncInterval)
				}
			}

			logger.Info("reload complete")
		}
	}()

	// --- Graceful shutdown ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	cancel()
	logger.Info("shutdown complete")
}

// signalPIDFile reads a PID from the given file and sends sig to that process.
func signalPIDFile(path string, sig os.Signal) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse pid: %w", err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	return proc.Signal(sig)
}
