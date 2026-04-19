package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/bodsink/rpzd/internal/store"
)

// ZoneSyncer performs AXFR sync for a single RPZ zone from a master server.
type ZoneSyncer struct {
	db                 *store.DB
	index              Indexer
	logger             *slog.Logger
	postSyncHook       func()                                                                       // called after a successful zone sync (optional)
	masterTrustChecker func(ip string) bool                                                         // optional: returns false if master IP is banned/untrusted
	batchSigner        func(zoneID int64, serial int64, names []string) (nodeID string, sig string) // optional
}

// Indexer allows the syncer to update the in-memory DNS lookup index.
type Indexer interface {
	Add(name, action string)
	Remove(name string)
	Replace(newSet map[string]string)
	ReplaceZone(zoneID int64, newSet map[string]string)
}

// NewZoneSyncer creates a new ZoneSyncer.
func NewZoneSyncer(db *store.DB, index Indexer, logger *slog.Logger) *ZoneSyncer {
	return &ZoneSyncer{db: db, index: index, logger: logger}
}

// SetPostSyncHook registers a function to be called after every successful zone sync.
// Intended for the HTTP-only service to signal the DNS service to reload its index.
func (s *ZoneSyncer) SetPostSyncHook(fn func()) {
	s.postSyncHook = fn
}

// SetMasterTrustChecker registers a callback that is called before each zone sync.
// If the callback returns false for a zone's master IP, the zone sync is skipped.
// Use this to prevent AXFR from banned/revoked nodes in the trust network.
func (s *ZoneSyncer) SetMasterTrustChecker(fn func(ip string) bool) {
	s.masterTrustChecker = fn
}

// SetBatchSigner registers a callback that signs an AXFR batch after collection.
// The callback receives the zone ID, SOA serial, and sorted record names.
// It returns the signing node's UUID and the Ed25519 signature (base64-encoded).
// If not set, records are inserted without source_node_id or axfr_batch_sig.
func (s *ZoneSyncer) SetBatchSigner(fn func(zoneID int64, serial int64, names []string) (nodeID string, sig string)) {
	s.batchSigner = fn
}

// SyncAll performs AXFR sync for all enabled slave zones.
// Returns true if at least one zone failed to sync.
func (s *ZoneSyncer) SyncAll(ctx context.Context) (hasFailure bool) {
	zones, err := s.db.ListZones(ctx)
	if err != nil {
		s.logger.Error("list zones failed", "err", err)
		return true
	}

	for _, z := range zones {
		if !z.Enabled || z.Mode != "slave" {
			continue
		}
		// Skip zones with no master_ip — records come via trust-network HTTP API,
		// not DNS AXFR. These zones are synced by fetchAndSyncZoneRecords in main.
		if z.MasterIP == "" {
			continue
		}
		// Skip if master IP belongs to a revoked/banned node in the trust network.
		if s.masterTrustChecker != nil && z.MasterIP != "" {
			if !s.masterTrustChecker(z.MasterIP) {
				s.logger.Warn("axfr skipped: master IP is not trusted (node banned/suspended)",
					"zone", z.Name, "master_ip", z.MasterIP)
				hasFailure = true
				continue
			}
		}
		if err := s.SyncZone(ctx, &z); err != nil {
			s.logger.Error("axfr sync failed", "zone", z.Name, "err", err)
			hasFailure = true
		}
	}
	return
}

// SyncZone performs a full AXFR transfer for a single zone.
func (s *ZoneSyncer) SyncZone(ctx context.Context, z *store.Zone) error {
	histID, err := s.db.InsertSyncHistory(ctx, z.ID)
	if err != nil {
		return err
	}

	added, removed, newSerial, syncErr := s.doAXFR(ctx, z)

	status := "success"
	errMsg := ""
	if syncErr != nil {
		status = "failed"
		errMsg = syncErr.Error()
		s.logger.Error("axfr failed", "zone", z.Name, "err", syncErr)
	} else {
		s.logger.Info("axfr sync complete",
			"zone", z.Name,
			"added", added,
			"removed", removed,
		)
	}

	if err := s.db.FinishSyncHistory(ctx, histID, status, added, removed, errMsg); err != nil {
		s.logger.Warn("finish sync history failed", "err", err)
	}
	if syncErr == nil {
		// Store the actual SOA serial from AXFR so the next sync can skip
		// if the zone hasn't changed.
		s.db.UpdateZoneSerial(ctx, z.ID, newSerial, status) //nolint:errcheck
		if s.postSyncHook != nil {
			s.postSyncHook()
		}
	}

	return syncErr
}

// doAXFR executes the actual AXFR transfer and stores records to the DB.
// Tries the primary master first, then falls back to secondary if available.
// Returns number of records added, removed, the actual SOA serial, and any error.
func (s *ZoneSyncer) doAXFR(ctx context.Context, z *store.Zone) (added, removed int, serial int64, err error) {
	master := fmt.Sprintf("%s:%d", stripCIDR(z.MasterIP), z.MasterPort)
	added, removed, serial, err = s.doAXFRFromMaster(ctx, z, master)
	if err != nil && z.MasterIPSecondary != "" {
		s.logger.Warn("primary master failed, trying secondary",
			"zone", z.Name,
			"primary", stripCIDR(z.MasterIP),
			"secondary", stripCIDR(z.MasterIPSecondary),
			"err", err,
		)
		secondaryMaster := fmt.Sprintf("%s:%d", stripCIDR(z.MasterIPSecondary), z.MasterPort)
		added, removed, serial, err = s.doAXFRFromMaster(ctx, z, secondaryMaster)
	}
	return
}

// stripCIDR removes the CIDR prefix notation from a PostgreSQL INET value.
// PostgreSQL returns INET values as "1.2.3.4/32" — we need just "1.2.3.4".
func stripCIDR(ip string) string {
	if idx := strings.IndexByte(ip, '/'); idx != -1 {
		return ip[:idx]
	}
	return ip
}

// stripZoneSuffix removes the RPZ zone name suffix from a record name.
// e.g. "pornhub.com.trustpositifkominfo." with zone "trustpositifkominfo." → "pornhub.com."
func stripZoneSuffix(name, zoneFQDN string) string {
	suffix := "." + zoneFQDN
	if strings.HasSuffix(name, suffix) {
		return name[:len(name)-len(zoneFQDN)]
	}
	return name
}

// querySOASerial sends a SOA query to master and returns the zone serial.
// Returns 0, false if the query fails or no SOA is found.
func querySOASerial(zoneName, master string) (uint32, bool) {
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zoneName), dns.TypeSOA)
	r, _, err := c.Exchange(m, master)
	if err != nil {
		return 0, false
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

// doAXFRFromMaster performs the actual AXFR from a specific master address.
func (s *ZoneSyncer) doAXFRFromMaster(ctx context.Context, z *store.Zone, master string) (added, removed int, serial int64, err error) {
	// If we have a previous serial, try IXFR first (incremental transfer).
	// IXFR is orders of magnitude faster for large zones with small daily deltas.
	if z.Serial > 0 {
		iAdded, iRemoved, iSerial, incremental, ixfrErr := s.doIXFRFromMaster(ctx, z, master)
		switch {
		case ixfrErr == nil && incremental:
			// Successful incremental sync — done.
			return iAdded, iRemoved, iSerial, nil
		case ixfrErr == nil && !incremental:
			// Master returned a full AXFR downgrade.
			// If serial is unchanged there is nothing to do.
			if iSerial == z.Serial {
				return 0, 0, z.Serial, nil
			}
			// Serial changed — fall through to full AXFR below.
		default:
			// IXFR failed (connection refused, TSIG error, etc.).
			// Log and fall through to full AXFR with a SOA pre-check.
			s.logger.Debug("ixfr failed, falling back to axfr", "zone", z.Name, "err", ixfrErr)
			if masterSerial, ok := querySOASerial(z.Name, master); ok && int64(masterSerial) == z.Serial {
				s.logger.Debug("zone serial unchanged, skipping axfr", "zone", z.Name, "serial", masterSerial)
				return 0, 0, z.Serial, nil
			}
		}
	}

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(z.Name))

	// Apply TSIG if configured
	if z.TSIGKey != "" && z.TSIGSecret != "" {
		m.SetTsig(z.TSIGKey, dns.HmacSHA256, 300, time.Now().Unix())
		t.TsigSecret = map[string]string{z.TSIGKey: z.TSIGSecret}
	}

	ch, err := t.In(m, master)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("axfr connect to %s: %w", master, err)
	}

	// Open a bulk upsert session (COPY to temp table, then single INSERT SELECT at Finish).
	session, sessionErr := s.db.NewBulkUpsertSession(ctx, z.ID)
	if sessionErr != nil {
		return 0, 0, 0, fmt.Errorf("start bulk upsert session: %w", sessionErr)
	}

	// Collect all records from AXFR stream
	var records []store.Record
	var allNames []string // kept for batch signing only — not allocated if no signer registered
	var axfrSerial uint32 // SOA serial captured from the AXFR stream
	collectNames := s.batchSigner != nil

	for env := range ch {
		if env.Error != nil {
			session.Close()
			return added, 0, 0, fmt.Errorf("axfr receive error: %w", env.Error)
		}
		for _, rr := range env.RR {
			// Capture SOA serial; skip storing SOA as a record.
			if soa, ok := rr.(*dns.SOA); ok {
				if axfrSerial == 0 {
					axfrSerial = soa.Serial
				}
				continue
			}
			name := stripZoneSuffix(dns.CanonicalName(rr.Header().Name), dns.Fqdn(z.Name))
			rtype := dns.TypeToString[rr.Header().Rrtype]
			rdata := rdataString(rr)

			records = append(records, store.Record{
				ZoneID: z.ID,
				Name:   name,
				RType:  rtype,
				RData:  rdata,
				TTL:    int(rr.Header().Ttl),
			})
			if collectNames {
				allNames = append(allNames, name)
			}

			// Flush to staging table in batches of 10,000 to keep memory bounded.
			if len(records) >= 10_000 {
				if err := session.AddBatch(ctx, records); err != nil {
					session.Close()
					return 0, 0, 0, err
				}
				records = records[:0]
			}
		}
	}

	// Flush remaining records to staging table.
	if len(records) > 0 {
		if err := session.AddBatch(ctx, records); err != nil {
			session.Close()
			return 0, 0, 0, err
		}
	}

	// Sign the batch with the local node keypair if a signer is registered.
	// The signature covers: sorted record names + zone serial, binding the
	// entire batch to this node's identity for cross-node validation.
	var sourceNodeID, batchSig string
	if s.batchSigner != nil {
		sourceNodeID, batchSig = s.batchSigner(z.ID, int64(axfrSerial), allNames)
	}

	// DELETE old records + INSERT fresh from staging — atomic.
	added, removed, err = session.Finish(ctx, sourceNodeID, batchSig)
	if err != nil {
		return 0, 0, 0, err
	}
	return added, removed, int64(axfrSerial), nil
}

// doIXFRFromMaster attempts an IXFR (incremental zone transfer) from a specific master.
//
// Returns:
//   - (added, removed, newSerial, true, nil)  — incremental delta applied successfully
//   - (0, 0, newSerial, false, nil)            — master returned a full AXFR downgrade; caller should fall back
//   - (0, 0, 0, false, err)                    — connection or stream error
//
// IXFR stream format per RFC 1995:
//
//	SOA(new)  [SOA(old) <deletes> SOA(new_or_mid) <adds>]...  SOA(new)
//
// If the second record in the stream is NOT a SOA, the master is returning a
// full AXFR response (downgrade). The caller is responsible for doing a full AXFR.
func (s *ZoneSyncer) doIXFRFromMaster(ctx context.Context, z *store.Zone, master string) (added, removed int, serial int64, incremental bool, err error) {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetIxfr(dns.Fqdn(z.Name), uint32(z.Serial), "", "")

	if z.TSIGKey != "" && z.TSIGSecret != "" {
		m.SetTsig(z.TSIGKey, dns.HmacSHA256, 300, time.Now().Unix())
		t.TsigSecret = map[string]string{z.TSIGKey: z.TSIGSecret}
	}

	ch, err := t.In(m, master)
	if err != nil {
		return 0, 0, 0, false, fmt.Errorf("ixfr connect to %s: %w", master, err)
	}

	// Collect all RRs. For incremental deltas this is small (thousands of records).
	// Early detection: once we have 2+ RRs, check if the second is a SOA.
	// If not, it's a full AXFR downgrade — drain channel and return to caller.
	var allRRs []dns.RR
	detectedFullAXFR := false
	for env := range ch {
		if env.Error != nil {
			return 0, 0, 0, false, fmt.Errorf("ixfr receive: %w", env.Error)
		}
		allRRs = append(allRRs, env.RR...)
		if !detectedFullAXFR && len(allRRs) >= 2 {
			if _, ok := allRRs[1].(*dns.SOA); !ok {
				// Full AXFR downgrade: drain channel without storing records.
				for range ch {
				}
				detectedFullAXFR = true
			}
		}
	}

	if len(allRRs) == 0 {
		return 0, 0, z.Serial, true, nil // empty response = no changes
	}

	openSOA, ok := allRRs[0].(*dns.SOA)
	if !ok {
		return 0, 0, 0, false, fmt.Errorf("ixfr: first record is not SOA")
	}
	newSerial := int64(openSOA.Serial)

	// Already up to date.
	if newSerial == z.Serial {
		return 0, 0, z.Serial, true, nil
	}

	// Full AXFR downgrade detected — signal caller.
	if detectedFullAXFR {
		return 0, 0, newSerial, false, nil
	}
	if len(allRRs) >= 2 {
		if _, ok := allRRs[1].(*dns.SOA); !ok {
			return 0, 0, newSerial, false, nil
		}
	}

	// Parse IXFR delta sections.
	//
	// State machine:
	//   "expect_del_soa" → waiting for SOA(old) that opens a delete section
	//   "deleting"       → collecting records to remove until next SOA
	//   "adding"         → collecting records to add until next SOA
	//
	// A SOA with serial == newSerial is the final closing SOA.
	zoneFQDN := dns.Fqdn(z.Name)
	var deletes, adds []store.Record
	state := "expect_del_soa"

	for _, rr := range allRRs[1:] { // skip opening SOA
		soa, isSoa := rr.(*dns.SOA)
		switch state {
		case "expect_del_soa":
			if !isSoa {
				continue // unexpected; skip
			}
			if int64(soa.Serial) == newSerial {
				goto done // closing SOA = no records in delta
			}
			state = "deleting"

		case "deleting":
			if isSoa {
				state = "adding"
			} else {
				name := stripZoneSuffix(dns.CanonicalName(rr.Header().Name), zoneFQDN)
				deletes = append(deletes, store.Record{
					ZoneID: z.ID,
					Name:   name,
					RType:  dns.TypeToString[rr.Header().Rrtype],
					RData:  rdataString(rr),
					TTL:    int(rr.Header().Ttl),
				})
			}

		case "adding":
			if isSoa {
				if int64(soa.Serial) == newSerial {
					goto done // final closing SOA
				}
				state = "deleting" // next delta section begins
			} else {
				name := stripZoneSuffix(dns.CanonicalName(rr.Header().Name), zoneFQDN)
				adds = append(adds, store.Record{
					ZoneID: z.ID,
					Name:   name,
					RType:  dns.TypeToString[rr.Header().Rrtype],
					RData:  rdataString(rr),
					TTL:    int(rr.Header().Ttl),
				})
			}
		}
	}

done:
	added, removed, err = s.db.ApplyIXFRDelta(ctx, z.ID, deletes, adds)
	if err != nil {
		return 0, 0, 0, true, fmt.Errorf("apply ixfr delta: %w", err)
	}

	// Update in-memory index incrementally — no full reload needed.
	for _, r := range deletes {
		s.index.Remove(r.Name)
	}
	for _, r := range adds {
		s.index.Add(r.Name, r.RData)
	}

	s.logger.Info("ixfr sync complete",
		"zone", z.Name,
		"serial_from", z.Serial,
		"serial_to", newSerial,
		"added", added,
		"removed", removed,
	)
	return added, removed, newSerial, true, nil
}

// rdataString extracts the RDATA portion of a DNS record as a string.
func rdataString(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.CNAME:
		return v.Target
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.TXT:
		if len(v.Txt) > 0 {
			return v.Txt[0]
		}
		return ""
	default:
		return "."
	}
}

// Scheduler runs SyncAll periodically based on the configured interval.
type Scheduler struct {
	syncer        *ZoneSyncer
	interval      time.Duration
	retryInterval time.Duration
	resetCh       chan time.Duration
	triggerCh     chan struct{}
	logger        *slog.Logger
}

// defaultRetryInterval is the wait time before retrying zones that failed to sync.
const defaultRetryInterval = 5 * time.Minute

// NewScheduler creates a Scheduler that runs AXFR sync at the given interval (seconds).
func NewScheduler(syncer *ZoneSyncer, intervalSeconds int, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		syncer:        syncer,
		triggerCh:     make(chan struct{}, 1),
		interval:      time.Duration(intervalSeconds) * time.Second,
		retryInterval: defaultRetryInterval,
		resetCh:       make(chan time.Duration, 1),
		logger:        logger,
	}
}

// SetInterval updates the sync interval at runtime without restarting the service.
// The new interval takes effect after the current tick cycle completes.
func (sc *Scheduler) SetInterval(seconds int) {
	d := time.Duration(seconds) * time.Second
	// Non-blocking send: if a pending reset already exists, replace it.
	select {
	case sc.resetCh <- d:
	default:
		// Drain and replace with the latest value.
		<-sc.resetCh
		sc.resetCh <- d
	}
}

// TriggerNow requests an immediate SyncAll on the next select iteration.
// Non-blocking: if a trigger is already pending, this is a no-op.
func (sc *Scheduler) TriggerNow() {
	select {
	case sc.triggerCh <- struct{}{}:
	default:
	}
}

// TriggerZone performs an immediate AXFR/IXFR sync for a single zone by name.
// Intended for use with RFC 1996 DNS NOTIFY: when the master sends a NOTIFY,
// the DNS server forwards the zone name here and we sync that zone immediately
// without waiting for the next scheduled interval.
// Runs in the caller's goroutine — call via go if non-blocking behavior is needed.
func (sc *Scheduler) TriggerZone(ctx context.Context, zoneName string) {
	zones, err := sc.syncer.db.ListZones(ctx)
	if err != nil {
		sc.logger.Error("NOTIFY trigger: list zones failed", "err", err)
		return
	}
	// Normalise: strip trailing dot, lowercase.
	target := strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, z := range zones {
		zn := strings.ToLower(strings.TrimSuffix(z.Name, "."))
		if zn != target {
			continue
		}
		if !z.Enabled || z.Mode != "slave" || z.MasterIP == "" {
			sc.logger.Debug("NOTIFY trigger: zone not eligible for sync",
				"zone", z.Name, "enabled", z.Enabled, "mode", z.Mode)
			return
		}
		if sc.syncer.masterTrustChecker != nil {
			if !sc.syncer.masterTrustChecker(z.MasterIP) {
				sc.logger.Warn("NOTIFY trigger: master IP not trusted — skipping",
					"zone", z.Name, "master_ip", z.MasterIP)
				return
			}
		}
		sc.logger.Info("NOTIFY trigger: starting immediate zone sync", "zone", z.Name)
		if err := sc.syncer.SyncZone(ctx, &z); err != nil {
			sc.logger.Error("NOTIFY trigger: sync failed", "zone", z.Name, "err", err)
		}
		return
	}
	sc.logger.Warn("NOTIFY trigger: zone not found", "zone", zoneName)
}

// Run starts the sync scheduler loop. Blocks until ctx is cancelled.
// If any zone fails to sync, it retries every retryInterval (default 5 minutes)
// until all zones succeed, then resumes the normal interval.
func (sc *Scheduler) Run(ctx context.Context) {
	sc.logger.Info("sync scheduler started", "interval", sc.interval)

	// Run once immediately on startup
	if sc.syncer.SyncAll(ctx) {
		sc.logger.Warn("initial sync has failures, will retry", "in", sc.retryInterval)
	}

	ticker := time.NewTicker(sc.interval)
	defer ticker.Stop()

	// retryTimer is a nil channel (blocks forever) when there is nothing to retry.
	// It is set to a real timer when the previous SyncAll had at least one failure.
	var retryTimer <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			sc.logger.Info("sync scheduler stopped")
			return

		case newInterval := <-sc.resetCh:
			ticker.Reset(newInterval)
			sc.interval = newInterval
			sc.logger.Info("sync interval updated", "interval", newInterval)

		case <-sc.triggerCh:
			sc.logger.Info("sync triggered (zone propagation)")
			retryTimer = nil
			if sc.syncer.SyncAll(ctx) {
				sc.logger.Warn("triggered sync has failures, will retry", "in", sc.retryInterval)
				retryTimer = time.After(sc.retryInterval)
			}

		case <-retryTimer:
			sc.logger.Info("retrying failed zone syncs")
			if sc.syncer.SyncAll(ctx) {
				sc.logger.Warn("retry still has failures, will retry again", "in", sc.retryInterval)
				retryTimer = time.After(sc.retryInterval)
			} else {
				sc.logger.Info("all zones synced successfully after retry")
				retryTimer = nil
			}

		case <-ticker.C:
			// Normal interval tick — reset any pending retry.
			retryTimer = nil
			if sc.syncer.SyncAll(ctx) {
				sc.logger.Warn("periodic sync has failures, will retry", "in", sc.retryInterval)
				retryTimer = time.After(sc.retryInterval)
			}
		}
	}
}
