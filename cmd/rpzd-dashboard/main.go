package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bodsink/rpzd/config"
	dbschema "github.com/bodsink/rpzd/db"
	"github.com/bodsink/rpzd/internal/api"
	"github.com/bodsink/rpzd/internal/store"
	"github.com/bodsink/rpzd/internal/syncer"
	"github.com/bodsink/rpzd/internal/trust"
	"github.com/jackc/pgx/v5/pgxpool"
)

// nopIndexer satisfies the syncer.Indexer interface with no-ops.
// The dashboard has no in-memory DNS index; after sync it signals
// the DNS service to reload its own index via SIGHUP.
type nopIndexer struct{}

func (n *nopIndexer) Add(name, action string)                       {}
func (n *nopIndexer) Remove(name string)                            {}
func (n *nopIndexer) Replace(newSet map[string]string)              {}
func (n *nopIndexer) ReplaceZone(zoneID int64, m map[string]string) {}

// zoneSyncMu prevents concurrent BulkUpsertSession for the same zone.
// Value type: *sync.Mutex (loaded via LoadOrStore).
var zoneSyncMu sync.Map

func main() {
	// --- Config ---
	cfgPath := "rpzd.conf"
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
	if created, usedPwd, err := dbschema.SeedAdminUser(ctx, db.Pool, cfg.Server.AdminInitPassword); err != nil {
		logger.Error("failed to seed admin user", "err", err)
		os.Exit(1)
	} else if created {
		logger.Warn("DEFAULT ADMIN CREATED — username: admin", "password", usedPwd)
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
		out, err := exec.Command("systemctl", "restart", "rpzd-dashboard").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart rpzd-dashboard: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	})
	apiServer.SetDNSAddress(cfg.Server.DNSAddress)
	// Wire DNS NOTIFY trigger: when rpzd receives a NOTIFY from a master,
	// it forwards the zone name here via POST /internal/notify, which calls
	// scheduler.TriggerZone — performing an immediate AXFR/IXFR for that zone.
	apiServer.SetNotifyScheduler(func(zoneName string) {
		scheduler.TriggerZone(ctx, zoneName)
	})

	// Compute the advertised DNS address for trust-network zone propagation.
	// Slaves use this address as master_ip when doing AXFR from this node.
	// Derives host from NODE_ADVERTISE_ADDR and port from DNS_ADDRESS.
	{
		advertiseHost, _, _ := net.SplitHostPort(cfg.Node.AdvertiseAddr)
		_, dnsPort, _ := net.SplitHostPort(cfg.Server.DNSAddress)
		if advertiseHost != "" && dnsPort != "" {
			apiServer.SetAdvertisedDNSAddr(advertiseHost + ":" + dnsPort)
		} else if cfg.Node.AdvertiseAddr != "" {
			// AdvertiseAddr without port, or fallback: use host + port 53
			if dnsPort == "" {
				dnsPort = "53"
			}
			apiServer.SetAdvertisedDNSAddr(cfg.Node.AdvertiseAddr + ":" + dnsPort)
		}
	}

	// Load or generate the Ed25519 node identity keypair.
	kp, err := trust.LoadOrCreate(cfg.Node.KeyPath)
	if err != nil {
		logger.Error("failed to load node keypair", "path", cfg.Node.KeyPath, "err", err)
		os.Exit(1)
	}

	// Bootstrap: create genesis entry if role==genesis and first start,
	// or validate existing genesis and return the network_id.
	networkID, trustBootErr := trust.Bootstrap(ctx, db.Pool, kp, cfg.Node.Role)
	if trustBootErr != nil {
		// If a bootstrap IP is configured, attempt to auto-join the trust network.
		if cfg.Node.BootstrapIP != "" {
			logger.Info("trust bootstrap failed — attempting auto-join via bootstrap IP",
				"bootstrap_ip", cfg.Node.BootstrapIP, "role", cfg.Node.Role)
			joinRequestID, joinErr := trustAutoJoin(ctx, db.Pool, kp, cfg.Node.Role, cfg.Node.BootstrapIP, logger)
			if joinErr != nil {
				logger.Warn("auto-join failed — trust features disabled until approved",
					"bootstrap_ip", cfg.Node.BootstrapIP, "err", joinErr)
				apiServer.SetTrustJoinState(api.TrustJoinFailed, cfg.Node.BootstrapIP)
			} else {
				logger.Info("auto-join request submitted — waiting for admin approval on bootstrap node",
					"bootstrap_ip", cfg.Node.BootstrapIP, "join_request_id", joinRequestID)
				apiServer.SetTrustJoinState(api.TrustJoinPending, cfg.Node.BootstrapIP)
				// Start background polling: activate trust subsystem once approved.
				selfAddr := resolveAnnounceAddr(cfg.Node.AdvertiseAddr, httpAddr, logger)
				go pollUntilApproved(ctx, db, kp, cfg.Node.Role, cfg.Node.BootstrapIP, joinRequestID, selfAddr, apiServer, zoneSyncer, scheduler, networkID, pidFile, logger)
			}
		} else {
			// Non-fatal: slave/master that haven't joined yet — dashboard still starts
			// so the operator can watch the join request status.
			logger.Warn("trust network not yet bootstrapped — trust features disabled until node joins",
				"role", cfg.Node.Role, "err", trustBootErr)
			apiServer.SetTrustJoinState(api.TrustJoinNotConfigured, "")
		}
	} else {
		ledger := trust.NewLedger(db.Pool)
		verifier := trust.NewVerifier(db.Pool)
		consensus := trust.NewConsensus(db.Pool, ledger)
		gossip := trust.NewGossip(db.Pool, ledger, verifier, consensus, kp, networkID)
		revocation := trust.NewRevocation(db.Pool, ledger, gossip)

		// Replay ledger → populate nodes table on every startup.
		// Non-genesis nodes (slave/master) have an empty nodes table after a fresh
		// install or DB migration; replaying the ledger is the only way to restore
		// the full node list without a full re-join.  Idempotent — safe for genesis too.
		if err := trust.SyncNodesFromLedger(ctx, db.Pool, networkID); err != nil {
			logger.Warn("startup nodes sync from ledger failed", "err", err)
		} else {
			logger.Info("nodes table synced from ledger", "network_id", networkID)
		}

		// Zone propagation: non-genesis nodes pull the zone list from their
		// bootstrap peer so that rpz_zones is always populated on startup/restart.
		// Genesis is the source of truth and never pulls zones from another node.
		if cfg.Node.Role != "genesis" {
			var bootstrapHost string
			_ = db.Pool.QueryRow(ctx,
				`SELECT host FROM trusted_fingerprints ORDER BY last_seen DESC LIMIT 1`,
			).Scan(&bootstrapHost)
			if bootstrapHost != "" {
				// Run in background so HTTP server starts immediately.
				go func(host string) {
					if names, err := fetchAndSyncZones(ctx, db.Pool, db, kp, networkID, host, logger); err != nil {
						logger.Warn("startup zone sync failed — zones may be stale", "err", err)
					} else {
						for _, name := range names {
							if err := fetchAndSyncZoneRecords(ctx, db, kp, networkID, host, name, logger); err != nil {
								logger.Warn("startup record sync failed", "zone", name, "err", err)
							}
						}
						if len(names) > 0 {
							if err := signalPIDFile(pidFile, syscall.SIGHUP); err != nil {
								logger.Warn("failed to signal dns after startup zone sync", "err", err)
							}
						}
					}
				}(bootstrapHost)
			}
		}

		trustAPIObj := api.NewTrustAPI(ledger, consensus, verifier, gossip, revocation, kp, networkID)
		apiServer.SetTrustAPI(trustAPIObj)

		// Wire AXFR whitelist check: skip AXFR only from BANNED master nodes.
		// SUSPENDED nodes still serve AXFR (per design doc: DNS service not disrupted).
		zoneSyncer.SetMasterTrustChecker(func(ip string) bool {
			var banned bool
			// Check nodes table directly: only status='banned' blocks AXFR.
			// peers.address is "ip:port" — join nodes on public_key to get status.
			_ = db.Pool.QueryRow(ctx, `
				SELECT EXISTS(
				    SELECT 1 FROM nodes n
				    JOIN peers p ON p.public_key = n.public_key
				    WHERE split_part(p.address, ':', 1) = $1
				      AND n.status = 'banned'
				      AND p.network_id = $2::uuid
				)`, ip, networkID,
			).Scan(&banned)
			return !banned
		})

		// Wire AXFR batch signer: stamps each AXFR batch with the local node's
		// Ed25519 signature so peers can cross-validate who contributed which records.
		zoneSyncer.SetBatchSigner(func(zoneID int64, serial int64, names []string) (nodeID string, sig string) {
			// Look up the local node's UUID from DB.
			var localNodeID string
			_ = db.Pool.QueryRow(ctx,
				`SELECT id::text FROM nodes WHERE public_key = $1 LIMIT 1`,
				kp.PublicKeyBase64(),
			).Scan(&localNodeID)
			if localNodeID == "" {
				return "", ""
			}
			batchSig, err := kp.SignBatch(zoneID, serial, names)
			if err != nil {
				logger.Warn("batch sign failed", "zone_id", zoneID, "err", err)
				return "", ""
			}
			return localNodeID, batchSig
		})

		// Start gossip loop — syncs ledger entries with peer nodes.
		go gossip.Run(ctx)

		// Non-genesis nodes announce their HTTP address to the bootstrap node so
		// genesis knows where to send zone-sync push notifications.
		// Genesis already announces itself via announceToNetwork (Step 7 below).
		if cfg.Node.Role != "genesis" {
			selfAddr := resolveAnnounceAddr(cfg.Node.AdvertiseAddr, httpAddr, logger)
			var bootstrapHost string
			_ = db.Pool.QueryRow(ctx,
				`SELECT host FROM trusted_fingerprints ORDER BY last_seen DESC LIMIT 1`,
			).Scan(&bootstrapHost)
			if bootstrapHost != "" {
				go func() {
					time.Sleep(3 * time.Second) // let HTTP server start
					announceSelfToBootstrap(ctx, kp, networkID, bootstrapHost, selfAddr, logger)
				}()
			}
		}

		// Periodic housekeeping: expire stale join requests and orphan grace periods.
		go func() {
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if _, err := consensus.ExpireStaleJoinRequests(ctx); err != nil {
						logger.Warn("expire stale join requests failed", "err", err)
					}
					if n, err := revocation.ProcessExpiredGracePeriods(ctx); err != nil {
						logger.Warn("process orphan grace periods failed", "err", err)
					} else if n > 0 {
						logger.Info("orphaned nodes suspended after grace period", "count", n)
					}
					if n, err := revocation.ProcessExpiredSuspensions(ctx); err != nil {
						logger.Warn("process expired suspensions failed", "err", err)
					} else if n > 0 {
						logger.Info("temporary suspensions auto-reinstated", "count", n)
					}
					if n, err := revocation.ExpireRevocationProposals(ctx); err != nil {
						logger.Warn("expire revocation proposals failed", "err", err)
					} else if n > 0 {
						logger.Info("revocation proposals expired", "count", n)
					}
					if n, err := revocation.ExpireGenesisRevocationProposals(ctx); err != nil {
						logger.Warn("expire genesis revocation proposals failed", "err", err)
					} else if n > 0 {
						logger.Info("genesis revocation proposals expired", "count", n)
					}
					if n, err := revocation.ExpireRoleUpgradeProposals(ctx); err != nil {
						logger.Warn("expire role upgrade proposals failed", "err", err)
					} else if n > 0 {
						logger.Info("role upgrade proposals expired", "count", n)
					}

					// Cross-node injection check: detect records from a minority
					// source_node_id and purge them, then record a purge_injected
					// ledger entry so every node in the network learns about it.
					if injected, err := db.FindInjectedRecords(ctx); err != nil {
						logger.Warn("find injected records failed", "err", err)
					} else {
						// Resolve local node UUID once per cycle (not per purge).
						var localNodeID string
						_ = db.Pool.QueryRow(ctx,
							`SELECT id::text FROM nodes WHERE public_key = $1 LIMIT 1`,
							kp.PublicKeyBase64(),
						).Scan(&localNodeID)

						for _, inj := range injected {
							purged, purgeErr := db.PurgeInjectedRecords(ctx, inj.ZoneID, inj.SourceNodeID)
							if purgeErr != nil {
								logger.Warn("purge injected records failed",
									"zone_id", inj.ZoneID,
									"source_node_id", inj.SourceNodeID,
									"err", purgeErr)
								continue
							}
							logger.Warn("injected records purged",
								"zone_id", inj.ZoneID,
								"source_node_id", inj.SourceNodeID,
								"purged_count", purged,
							)

							// Write purge_injected to the append-only ledger so
							// all peers can verify and cross-validate.
							nodeIDStr := inj.SourceNodeID
							payload, _ := json.Marshal(map[string]any{
								"zone_id":         inj.ZoneID,
								"source_node_id":  inj.SourceNodeID,
								"purged_count":    purged,
								"detection_basis": "minority_source",
								"automated":       true,
							})
							var actorArg *string
							if localNodeID != "" {
								actorArg = &localNodeID
							}
							if _, ledgerErr := ledger.Append(ctx, "purge_injected",
								&nodeIDStr, actorArg, payload, false,
							); ledgerErr != nil {
								logger.Warn("ledger purge_injected write failed", "err", ledgerErr)
							}

							// Design doc: node proven to inject → automatically
							// queued for SUSPEND (threshold still applies).
							if localNodeID != "" {
								netCfg, _ := trust.ReadNetworkConfig(ctx, db.Pool)
								_, _, suspendErr := revocation.ProposeRevocation(
									ctx,
									inj.SourceNodeID, localNodeID,
									"suspend",
									"automated: injected records detected via minority_source cross-validation",
									0, // indefinite — manual reinstate required
									netCfg,
								)
								if suspendErr != nil {
									logger.Warn("auto-suspend proposal failed",
										"source_node_id", inj.SourceNodeID,
										"err", suspendErr)
								} else {
									logger.Warn("auto-suspend proposal created for injection",
										"source_node_id", inj.SourceNodeID)
								}
							}
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		logger.Info("trust network initialized",
			"role", cfg.Node.Role,
			"network_id", networkID,
			"fingerprint", kp.Fingerprint(),
		)

		// Wire zone propagation callbacks.
		// Genesis/master: when admin changes a zone, notify all active peers to pull immediately.
		if cfg.Node.Role == "genesis" || cfg.Node.Role == "master" {
			apiServer.SetOnZoneChanged(func() {
				notifyPeersZoneChanged(ctx, db.Pool, kp, networkID, logger)
			})
		}
		// Slave/master: when a peer sends POST /trust/zones/sync, pull zones + trigger AXFR.
		if cfg.Node.Role != "genesis" {
			apiServer.SetOnTrustZonesSync(func() {
				var bootstrapHost string
				_ = db.Pool.QueryRow(ctx,
					`SELECT host FROM trusted_fingerprints ORDER BY last_seen DESC LIMIT 1`,
				).Scan(&bootstrapHost)
				if bootstrapHost == "" {
					return
				}
				if names, err := fetchAndSyncZones(ctx, db.Pool, db, kp, networkID, bootstrapHost, logger); err != nil {
					logger.Warn("push-triggered zone sync failed", "err", err)
				} else {
					for _, name := range names {
						if err := fetchAndSyncZoneRecords(ctx, db, kp, networkID, bootstrapHost, name, logger); err != nil {
							logger.Warn("push-triggered record sync failed", "zone", name, "err", err)
						}
					}
					if len(names) > 0 {
						if err := signalPIDFile(pidFile, syscall.SIGHUP); err != nil {
							logger.Warn("failed to signal dns after push zone sync", "err", err)
						}
					}
				}
			})
		}

		// Periodic zone propagation: slave/master nodes re-sync zone list from
		// a known genesis/master peer every 5 minutes so newly added zones are
		// automatically discovered without a manual restart.
		if cfg.Node.Role != "genesis" {
			go func() {
				ticker := time.NewTicker(5 * time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						var bootstrapHost string
						_ = db.Pool.QueryRow(ctx,
							`SELECT host FROM trusted_fingerprints ORDER BY last_seen DESC LIMIT 1`,
						).Scan(&bootstrapHost)
						if bootstrapHost == "" {
							continue
						}
						if names, err := fetchAndSyncZones(ctx, db.Pool, db, kp, networkID, bootstrapHost, logger); err != nil {
							logger.Warn("periodic zone sync failed", "err", err)
						} else {
							for _, name := range names {
								if err := fetchAndSyncZoneRecords(ctx, db, kp, networkID, bootstrapHost, name, logger); err != nil {
									logger.Warn("periodic record sync failed", "zone", name, "err", err)
								}
							}
							if len(names) > 0 {
								if err := signalPIDFile(pidFile, syscall.SIGHUP); err != nil {
									logger.Warn("failed to signal dns after periodic zone sync", "err", err)
								}
							}
						}
					}
				}
			}()
		}

		// Step 7 — Activate: master nodes announce their address to the network
		// so slave nodes can discover them as AXFR sources.
		if cfg.Node.Role == "master" || cfg.Node.Role == "genesis" {
			announceAddr := resolveAnnounceAddr(cfg.Node.AdvertiseAddr, httpAddr, logger)
			go announceToNetwork(ctx, kp, networkID, announceAddr, logger)
		}
	}

	go func() {
		if err := apiServer.Start(ctx, httpAddr, tlsCfg); err != nil {
			logger.Error("dashboard error", "err", err)
			cancel()
		}
	}()

	logger.Info("rpzd-dashboard started", "addr", httpAddr, "tls", true)

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

// trustAutoJoin contacts bootstrapAddr (ip:port) to:
//  1. Fetch network_id + genesis fingerprint from GET /trust/info
//  2. TOFU check: compare against stored fingerprint (if first time, log and store)
//  3. POST /trust/join with local public key, role, and network_id
//
// Returns the join_request_id so the caller can start a background poll goroutine.
func trustAutoJoin(ctx context.Context, pool *pgxpool.Pool, kp *trust.Keypair, role, bootstrapAddr string, logger *slog.Logger) (string, error) {
	// #nosec G402 — self-signed certs expected in trust bootstrapping (TOFU model).
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	base := "https://" + bootstrapAddr

	// Step 1: Fetch network info.
	infoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/trust/info", nil)
	if err != nil {
		return "", fmt.Errorf("create info request: %w", err)
	}
	infoResp, err := httpClient.Do(infoReq)
	if err != nil {
		return "", fmt.Errorf("fetch trust info from %s: %w", bootstrapAddr, err)
	}
	defer infoResp.Body.Close()
	if infoResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trust info endpoint returned %d", infoResp.StatusCode)
	}

	var info struct {
		NetworkID          string `json:"network_id"`
		GenesisFingerprint string `json:"genesis_fingerprint"`
	}
	if err := json.NewDecoder(infoResp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("decode trust info: %w", err)
	}
	if info.NetworkID == "" {
		return "", fmt.Errorf("bootstrap node returned empty network_id")
	}

	// Step 2: TOFU — check stored fingerprint against received one.
	var storedFingerprint string
	_ = pool.QueryRow(ctx,
		`SELECT fingerprint FROM trusted_fingerprints WHERE host = $1`, bootstrapAddr,
	).Scan(&storedFingerprint)

	if storedFingerprint == "" {
		// First contact — log for operator to verify, then store.
		logger.Warn("TOFU: first connection to bootstrap node — verify genesis fingerprint out-of-band",
			"bootstrap_ip", bootstrapAddr,
			"network_id", info.NetworkID,
			"genesis_fingerprint", info.GenesisFingerprint,
		)
		if _, err := pool.Exec(ctx, `
			INSERT INTO trusted_fingerprints (host, fingerprint, network_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (host) DO UPDATE
			  SET fingerprint = EXCLUDED.fingerprint,
			      network_id  = EXCLUDED.network_id,
			      last_seen   = now()`,
			bootstrapAddr, info.GenesisFingerprint, info.NetworkID,
		); err != nil {
			logger.Warn("TOFU: could not store fingerprint", "err", err)
		}
	} else if storedFingerprint != info.GenesisFingerprint {
		// Fingerprint mismatch — possible MITM or node key rotation.
		return "", fmt.Errorf(
			"TOFU fingerprint mismatch for %s: stored=%s received=%s — refusing connection",
			bootstrapAddr, storedFingerprint, info.GenesisFingerprint,
		)
	} else {
		// Known host — update last_seen silently.
		_, _ = pool.Exec(ctx,
			`UPDATE trusted_fingerprints SET last_seen = now() WHERE host = $1`, bootstrapAddr)
		logger.Debug("TOFU: bootstrap node fingerprint verified", "bootstrap_ip", bootstrapAddr)
	}

	// Step 3: Submit join request (self-auth: sign with own keypair).
	hostname, _ := os.Hostname()
	joinPayload, err := json.Marshal(map[string]string{
		"public_key": kp.PublicKeyBase64(),
		"name":       hostname,
		"role":       role,
		"network_id": info.NetworkID,
	})
	if err != nil {
		return "", fmt.Errorf("marshal join payload: %w", err)
	}

	joinReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/trust/join", bytes.NewReader(joinPayload))
	if err != nil {
		return "", fmt.Errorf("create join request: %w", err)
	}
	joinReq.Header.Set("Content-Type", "application/json")

	// Self-auth headers: sign with this node's own keypair so the genesis can verify
	// the request is genuinely from the owner of the claimed public key.
	tsJoin := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := sha256.Sum256(joinPayload)
	sigPayload := []byte("POST\n/trust/join\n" + hex.EncodeToString(bodyHash[:]) + "\n" + tsJoin)
	joinReq.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
	joinReq.Header.Set("X-Timestamp", tsJoin)
	joinReq.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(sigPayload)))

	joinResp, err := httpClient.Do(joinReq)
	if err != nil {
		return "", fmt.Errorf("POST /trust/join to %s: %w", bootstrapAddr, err)
	}
	defer joinResp.Body.Close()
	// handleTrustJoin returns 202 Accepted on success.
	if joinResp.StatusCode != http.StatusAccepted && joinResp.StatusCode != http.StatusOK {
		var body map[string]any
		_ = json.NewDecoder(joinResp.Body).Decode(&body)
		return "", fmt.Errorf("join request rejected (status %d): %v", joinResp.StatusCode, body)
	}

	var joinResult struct {
		JoinRequestID string `json:"join_request_id"`
	}
	_ = json.NewDecoder(joinResp.Body).Decode(&joinResult)

	logger.Info("join request submitted — awaiting admin approval",
		"bootstrap_ip", bootstrapAddr,
		"network_id", info.NetworkID,
		"join_request_id", joinResult.JoinRequestID,
		"local_fingerprint", kp.Fingerprint(),
	)
	return joinResult.JoinRequestID, nil
}

// fetchAndStoreLedger fetches the full ledger from bootstrapAddr (since seq 0)
// and upserts all entries into the local DB.  Called once after join approval
// so that the genesis entry is present before trust.Bootstrap is invoked.
// The node must already be active in the bootstrap node's DB (i.e. approved).
func fetchAndStoreLedger(ctx context.Context, pool *pgxpool.Pool, kp *trust.Keypair, networkID, bootstrapAddr string, logger *slog.Logger) error {
	// #nosec G402 — TOFU model: identity verified via Ed25519, not TLS cert.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+bootstrapAddr+"/trust/ledger?since_seq=0", nil)
	if err != nil {
		return fmt.Errorf("build ledger request: %w", err)
	}

	// Sign per middlewareTrustAuth: METHOD\nPATH\nhex(SHA256(body))\ntimestamp
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	emptyHash := sha256.Sum256([]byte{})
	signingPayload := []byte("GET\n/trust/ledger\n" + hex.EncodeToString(emptyHash[:]) + "\n" + tsStr)
	req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Network-ID", networkID)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(signingPayload)))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch ledger from %s: %w", bootstrapAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ledger endpoint returned HTTP %d", resp.StatusCode)
	}

	var entries []struct {
		Seq       int64           `json:"seq"`
		PrevHash  string          `json:"prev_hash"`
		EntryHash string          `json:"entry_hash"`
		Action    string          `json:"action"`
		SubjectID *string         `json:"subject_id"`
		ActorID   *string         `json:"actor_id"`
		Payload   json.RawMessage `json:"payload"`
		Priority  bool            `json:"priority"`
		CreatedAt time.Time       `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return fmt.Errorf("decode ledger entries: %w", err)
	}

	for _, e := range entries {
		// Store subject_id/actor_id as NULL to avoid FK violations on nodes(id).
		// These UUIDs are local DB artifacts from the originating node; the actual
		// identity data (pubkey, role) lives in the JSON payload and is used by
		// SyncNodesFromLedger to populate the local nodes table.
		_, err := pool.Exec(ctx, `
			INSERT INTO trust_ledger
				(seq, prev_hash, entry_hash, action, payload, priority, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (entry_hash) DO NOTHING`,
			e.Seq, e.PrevHash, e.EntryHash, e.Action,
			e.Payload, e.Priority, e.CreatedAt,
		)
		if err != nil {
			logger.Warn("fetchAndStoreLedger: failed to store entry",
				"seq", e.Seq, "action", e.Action, "err", err)
		}
	}
	logger.Info("ledger synced from bootstrap node",
		"entries", len(entries), "bootstrap_ip", bootstrapAddr)
	return nil
}

// fetchAndSyncZones pulls the zone list from bootstrapAddr via GET /trust/zones,
// then upserts each zone into the local rpz_zones table with mode='slave'.
// master_ip is intentionally left empty — zone records are propagated separately
// via fetchAndSyncZoneRecords (HTTP API), not DNS AXFR between trust nodes.
// Zones already configured with a non-slave mode are left untouched.
// Returns the slice of zone names that were upserted.
func fetchAndSyncZones(ctx context.Context, pool *pgxpool.Pool, db *store.DB, kp *trust.Keypair, networkID, bootstrapAddr string, logger *slog.Logger) ([]string, error) {
	// #nosec G402 — TOFU model: identity verified via Ed25519, not TLS cert.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+bootstrapAddr+"/trust/zones", nil)
	if err != nil {
		return nil, fmt.Errorf("build zones request: %w", err)
	}

	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	emptyHash := sha256.Sum256([]byte{})
	signingPayload := []byte("GET\n/trust/zones\n" + hex.EncodeToString(emptyHash[:]) + "\n" + tsStr)
	req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Network-ID", networkID)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(signingPayload)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch zones from %s: %w", bootstrapAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zones endpoint returned HTTP %d", resp.StatusCode)
	}

	var payload struct {
		NodeDNSAddr string `json:"node_dns_addr"`
		Zones       []struct {
			Name         string `json:"name"`
			SyncInterval int    `json:"sync_interval"`
		} `json:"zones"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode zones response: %w", err)
	}

	var synced []string
	for _, z := range payload.Zones {
		if z.Name == "" {
			continue
		}
		syncInterval := z.SyncInterval
		if syncInterval <= 0 {
			syncInterval = 300
		}
		// master_ip is left empty: records come via HTTP API (fetchAndSyncZoneRecords),
		// not DNS AXFR. The AXFR syncer skips zones with empty master_ip.
		if err := db.UpsertZoneFromTrust(ctx, &store.Zone{
			Name:         z.Name,
			SyncInterval: syncInterval,
		}); err != nil {
			logger.Warn("fetchAndSyncZones: upsert failed", "zone", z.Name, "err", err)
			continue
		}
		synced = append(synced, z.Name)
	}

	logger.Info("zones synced from bootstrap node",
		"total", len(payload.Zones), "upserted", len(synced), "bootstrap_ip", bootstrapAddr)
	return synced, nil
}

// fetchAndSyncZoneRecords pulls all records for a zone from bootstrapAddr via
// GET /trust/zones/{name}/records using cursor-based pagination (5000/page),
// then atomically replaces the zone's records in the local DB.
// This is the records propagation mechanism within the trust network — no DNS
// AXFR needed between nodes.
func fetchAndSyncZoneRecords(ctx context.Context, db *store.DB, kp *trust.Keypair, networkID, bootstrapAddr, zoneName string, logger *slog.Logger) error {
	// Prevent concurrent syncs for the same zone to avoid duplicate-key errors
	// from two BulkUpsertSessions running the DELETE+INSERT cycle simultaneously.
	muVal, _ := zoneSyncMu.LoadOrStore(zoneName, &sync.Mutex{})
	mu := muVal.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	zone, err := db.GetZoneByName(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("zone not found locally %q: %w", zoneName, err)
	}

	// #nosec G402 — TOFU model.
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	sess, err := db.NewBulkUpsertSession(ctx, zone.ID)
	if err != nil {
		return fmt.Errorf("bulk upsert session for %q: %w", zoneName, err)
	}

	var afterID int64
	totalFetched := 0
	const pageSize = 5000
	path := "/trust/zones/" + zoneName + "/records"

	for {
		urlStr := "https://" + bootstrapAddr + path + "?after_id=" + strconv.FormatInt(afterID, 10)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			sess.Close()
			return fmt.Errorf("build records request: %w", err)
		}

		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		emptyHash := sha256.Sum256([]byte{})
		// Sign only the PATH (no query string) — server middleware verifies c.Request.URL.Path.
		sigPayload := []byte("GET\n" + path + "\n" + hex.EncodeToString(emptyHash[:]) + "\n" + tsStr)
		req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
		req.Header.Set("X-Timestamp", tsStr)
		req.Header.Set("X-Network-ID", networkID)
		req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(sigPayload)))

		resp, err := client.Do(req)
		if err != nil {
			sess.Close()
			return fmt.Errorf("fetch records page from %s: %w", bootstrapAddr, err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			sess.Close()
			return fmt.Errorf("records endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		var page []struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			RType string `json:"rtype"`
			RData string `json:"rdata"`
			TTL   int    `json:"ttl"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decErr != nil {
			sess.Close()
			return fmt.Errorf("decode records page: %w", decErr)
		}

		if len(page) > 0 {
			batch := make([]store.Record, len(page))
			for i, r := range page {
				batch[i] = store.Record{Name: r.Name, RType: r.RType, RData: r.RData, TTL: r.TTL}
				if r.ID > afterID {
					afterID = r.ID
				}
			}
			if err := sess.AddBatch(ctx, batch); err != nil {
				sess.Close()
				return fmt.Errorf("add batch for %q: %w", zoneName, err)
			}
			totalFetched += len(page)
		}

		if len(page) < pageSize {
			break // last page
		}
	}

	added, removed, err := sess.Finish(ctx, "", "")
	if err != nil {
		return fmt.Errorf("finish bulk upsert for %q: %w", zoneName, err)
	}
	logger.Info("zone records synced from bootstrap",
		"zone", zoneName, "added", added, "removed", removed, "fetched", totalFetched)
	return nil
}

// pollUntilApproved polls GET /trust/status/{joinRequestID} on the bootstrap node
// every 30 seconds until the join request is approved or expires.
//
// When approved: syncs the full ledger from the bootstrap node, re-runs
// trust.Bootstrap (genesis entry now present locally), initialises all trust
// subsystems, wires the AXFR ban-checker, and starts the gossip loop.
// When expired: logs an actionable error and returns — operator must re-run join.
func pollUntilApproved(
	ctx context.Context,
	db *store.DB,
	kp *trust.Keypair,
	role, bootstrapAddr, joinRequestID string,
	selfAddr string, // this node's advertised HTTP address (for slave self-announce)
	apiServer *api.Server,
	zoneSyncer *syncer.ZoneSyncer,
	scheduler *syncer.Scheduler,
	_ string, // networkID placeholder — will be resolved after approval
	pidFile string,
	logger *slog.Logger,
) {
	// #nosec G402 — TOFU model: bootstrap node uses self-signed cert.
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}
	base := "https://" + bootstrapAddr

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	logger.Info("polling bootstrap node for join approval",
		"bootstrap_ip", bootstrapAddr,
		"join_request_id", joinRequestID,
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				base+"/trust/status/"+joinRequestID, nil)
			if err != nil {
				logger.Warn("poll: failed to build request", "err", err)
				continue
			}
			// Self-auth headers for /trust/status (node may not be active yet).
			tsPoll := strconv.FormatInt(time.Now().Unix(), 10)
			emptyHash := sha256.Sum256([]byte{})
			sigPollPayload := []byte("GET\n/trust/status/" + joinRequestID + "\n" + hex.EncodeToString(emptyHash[:]) + "\n" + tsPoll)
			req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
			req.Header.Set("X-Timestamp", tsPoll)
			req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(sigPollPayload)))

			resp, err := httpClient.Do(req)
			if err != nil {
				logger.Warn("poll: request to bootstrap node failed", "err", err,
					"bootstrap_ip", bootstrapAddr)
				continue
			}
			var result struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&result)
			resp.Body.Close()

			switch result.Status {
			case "approved":
				logger.Info("join request approved — activating trust subsystem",
					"join_request_id", joinRequestID)

				// Read network_id stored during auto-join (TOFU step).
				var networkID string
				_ = db.Pool.QueryRow(ctx,
					`SELECT COALESCE(network_id, '') FROM trusted_fingerprints WHERE host = $1`,
					bootstrapAddr,
				).Scan(&networkID)

				// Sync the full ledger from the bootstrap node so the genesis
				// entry exists in the local DB before trust.Bootstrap is called.
				// (The gossip loop hasn't started yet — this is a one-time pull.)
				if networkID != "" {
					if err := fetchAndStoreLedger(ctx, db.Pool, kp, networkID, bootstrapAddr, logger); err != nil {
						logger.Warn("post-approval ledger sync failed — will retry next poll", "err", err)
						continue
					}
					// Replay ledger → populate nodes table (genesis + all vouched nodes).
					// Without this, handleTrustNodesPage returns empty node list on the slave.
					if err := trust.SyncNodesFromLedger(ctx, db.Pool, networkID); err != nil {
						logger.Warn("post-approval nodes sync failed — continuing anyway", "err", err)
					} else {
						logger.Info("nodes table synced from ledger", "bootstrap_ip", bootstrapAddr)
					}
					// Pull zone list + records from bootstrap → upsert into local DB.
					if names, err := fetchAndSyncZones(ctx, db.Pool, db, kp, networkID, bootstrapAddr, logger); err != nil {
						logger.Warn("post-approval zone sync failed — slave zones may be missing", "err", err)
					} else {
						for _, name := range names {
							if err := fetchAndSyncZoneRecords(ctx, db, kp, networkID, bootstrapAddr, name, logger); err != nil {
								logger.Warn("post-approval record sync failed", "zone", name, "err", err)
							}
						}
						if len(names) > 0 {
							if err := signalPIDFile(pidFile, syscall.SIGHUP); err != nil {
								logger.Warn("failed to signal dns after post-approval zone sync", "err", err)
							}
						}
					}
				}

				// Now Bootstrap can find the genesis entry in the local DB.
				networkID, err := trust.Bootstrap(ctx, db.Pool, kp, role)
				if err != nil {
					logger.Warn("post-approval bootstrap failed — will retry next poll",
						"err", err)
					continue
				}

				ledger := trust.NewLedger(db.Pool)
				verifier := trust.NewVerifier(db.Pool)
				consensus := trust.NewConsensus(db.Pool, ledger)
				gossip := trust.NewGossip(db.Pool, ledger, verifier, consensus, kp, networkID)
				revocation := trust.NewRevocation(db.Pool, ledger, gossip)

				trustAPIObj := api.NewTrustAPI(ledger, consensus, verifier, gossip, revocation, kp, networkID)
				apiServer.SetTrustAPI(trustAPIObj)

				// Wire AXFR whitelist: block sync only from BANNED master nodes.
				zoneSyncer.SetMasterTrustChecker(func(ip string) bool {
					var banned bool
					_ = db.Pool.QueryRow(ctx, `
						SELECT EXISTS(
						    SELECT 1 FROM nodes n
						    JOIN peers p ON p.public_key = n.public_key
						    WHERE split_part(p.address, ':', 1) = $1
						      AND n.status = 'banned'
						      AND p.network_id = $2::uuid
						)`, ip, networkID,
					).Scan(&banned)
					return !banned
				})

				// Wire AXFR batch signer for cross-node injection detection.
				zoneSyncer.SetBatchSigner(func(zoneID int64, serial int64, names []string) (string, string) {
					var localNodeID string
					_ = db.Pool.QueryRow(ctx,
						`SELECT id::text FROM nodes WHERE public_key = $1 LIMIT 1`,
						kp.PublicKeyBase64(),
					).Scan(&localNodeID)
					if localNodeID == "" {
						return "", ""
					}
					batchSig, err := kp.SignBatch(zoneID, serial, names)
					if err != nil {
						return "", ""
					}
					return localNodeID, batchSig
				})

				go gossip.Run(ctx)

				// Slave announces its own HTTP address to genesis so genesis can
				// send zone-sync push notifications back.
				if role == "slave" {
					go func() {
						time.Sleep(3 * time.Second) // wait for HTTP server
						announceSelfToBootstrap(ctx, kp, networkID, bootstrapAddr, selfAddr, logger)
					}()
				}

				// Step 7 — master nodes must announce their address to the network
				// so slave nodes can discover them as AXFR sources.
				if role == "master" || role == "genesis" {
					go announceToNetwork(ctx, kp, networkID, bootstrapAddr, logger)
				}

				logger.Info("trust network activated", "network_id", networkID)
				return

			case "expired":
				logger.Error("join request expired — trust features disabled; re-run with NODE_BOOTSTRAP_IP to retry",
					"join_request_id", joinRequestID,
					"bootstrap_ip", bootstrapAddr,
				)
				return

			default:
				logger.Debug("poll: join request still pending",
					"status", result.Status,
					"join_request_id", joinRequestID,
				)
			}
		}
	}
}

// announceToNetwork sends POST /trust/announce to this node's own endpoint so a
// ledger 'announce' entry is created locally.  The gossip loop then propagates
// it to all peers, letting slave nodes discover this master as an AXFR source.
// This implements Step 7 — Activate (master role) from the design doc.

// resolveAnnounceAddr returns the address this node will advertise to peers.
// It prefers NODE_ADVERTISE_ADDR; if not set and the listen address binds to a
// wildcard (0.0.0.0 / ::), it logs a warning because peers will not be able to
// dial a wildcard address.
func resolveAnnounceAddr(advertise, listen string, logger *slog.Logger) string {
	if advertise != "" {
		return advertise
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		logger.Warn("NODE_ADVERTISE_ADDR not set and HTTP_ADDRESS uses a wildcard bind — set NODE_ADVERTISE_ADDR to the public IP:port so peers can reach this node",
			"http_address", listen,
		)
		// Fall back to listen addr; gossip will fail until fixed, but the
		// process should not be blocked entirely.
		return listen
	}
	return net.JoinHostPort(host, port)
}

// announceSelfToBootstrap registers this node's HTTP address on the bootstrap/genesis
// node so genesis knows where to reach this node for zone-sync push notifications.
// Must be called after trust is bootstrapped (node is active in genesis's nodes table).
func announceSelfToBootstrap(ctx context.Context, kp *trust.Keypair, networkID, bootstrapAddr, selfAddr string, logger *slog.Logger) {
	if selfAddr == "" {
		logger.Warn("announce: NODE_ADVERTISE_ADDR not set — peers cannot reach this node for zone-sync notifications")
		return
	}

	// #nosec G402 — TOFU model.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	payload, err := json.Marshal(map[string]string{
		"address":    selfAddr,
		"public_key": kp.PublicKeyBase64(),
		"network_id": networkID,
	})
	if err != nil {
		logger.Warn("announce: marshal payload failed", "err", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+bootstrapAddr+"/trust/announce",
		bytes.NewReader(payload))
	if err != nil {
		logger.Warn("announce: build request failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := sha256.Sum256(payload)
	sigPayload := []byte("POST\n/trust/announce\n" + hex.EncodeToString(bodyHash[:]) + "\n" + tsStr)
	req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Network-ID", networkID)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(sigPayload)))

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("announce: request to bootstrap failed", "bootstrap", bootstrapAddr, "err", err)
		return
	}
	resp.Body.Close()
	logger.Info("announced self address to bootstrap node",
		"bootstrap", bootstrapAddr, "self_addr", selfAddr, "status", resp.StatusCode)
}

// notifyPeersZoneChanged sends POST /trust/zones/sync to all known active peers
// so they re-pull the zone list immediately rather than waiting for the 5-min tick.
// Runs fire-and-forget: failures are logged but do not block the caller.
func notifyPeersZoneChanged(ctx context.Context, pool *pgxpool.Pool, kp *trust.Keypair, networkID string, logger *slog.Logger) {
	rows, err := pool.Query(ctx,
		`SELECT address FROM peers WHERE network_id = $1::uuid`, networkID)
	if err != nil {
		logger.Warn("notifyPeers: query peers failed", "err", err)
		return
	}
	defer rows.Close()

	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err == nil && addr != "" {
			addrs = append(addrs, addr)
		}
	}

	if len(addrs) == 0 {
		return
	}

	// #nosec G402 — TOFU model.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	for _, addr := range addrs {
		addr := addr // capture loop var
		go func() {
			url := "https://" + addr + "/trust/zones/sync"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
			if err != nil {
				return
			}
			tsStr := strconv.FormatInt(time.Now().Unix(), 10)
			emptyHash := sha256.Sum256([]byte{})
			sigPayload := []byte("POST\n/trust/zones/sync\n" + hex.EncodeToString(emptyHash[:]) + "\n" + tsStr)
			req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
			req.Header.Set("X-Timestamp", tsStr)
			req.Header.Set("X-Network-ID", networkID)
			req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(kp.Sign(sigPayload)))

			resp, err := client.Do(req)
			if err != nil {
				logger.Warn("notifyPeers: zone sync notify failed", "peer", addr, "err", err)
				return
			}
			resp.Body.Close()
			logger.Debug("notifyPeers: zone sync notify sent", "peer", addr, "status", resp.StatusCode)
		}()
	}
}

func announceToNetwork(ctx context.Context, kp *trust.Keypair, networkID, listenAddr string, logger *slog.Logger) {
	// Small delay to let the HTTP server finish starting before we POST to it.
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}

	// #nosec G402 — self-signed cert (TOFU model).
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TOFU
		},
	}

	payload, err := json.Marshal(map[string]string{
		"address":    listenAddr,
		"public_key": kp.PublicKeyBase64(),
		"network_id": networkID,
	})
	if err != nil {
		logger.Warn("announce: marshal payload failed", "err", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+listenAddr+"/trust/announce",
		bytes.NewReader(payload))
	if err != nil {
		logger.Warn("announce: build request failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Sign the request per middlewareTrustAuth protocol:
	// signing payload = METHOD\nPATH\nhex(SHA256(body))\ntimestamp
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := sha256.Sum256(payload)
	signingPayload := []byte("POST\n/trust/announce\n" + hex.EncodeToString(bodyHash[:]) + "\n" + tsStr)
	sigB64 := base64.StdEncoding.EncodeToString(kp.Sign(signingPayload))
	req.Header.Set("X-Node-Pubkey", kp.PublicKeyBase64())
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Network-ID", networkID)
	req.Header.Set("X-Signature", sigB64)

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Warn("announce: POST /trust/announce failed", "err", err)
		return
	}
	resp.Body.Close()
	logger.Info("trust announce sent", "addr", listenAddr, "status", resp.StatusCode)
}
