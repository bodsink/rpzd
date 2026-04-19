package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bodsink/rpzd/internal/trust"
)

// TrustAPI holds trust-network dependencies injected into the HTTP server.
// It is nil when trust networking is not configured.
type TrustAPI struct {
	ledger     *trust.Ledger
	consensus  *trust.Consensus
	verifier   *trust.Verifier
	gossip     *trust.Gossip
	revocation *trust.Revocation
	localKP    *trust.Keypair
	networkID  string
}

// NewTrustAPI constructs a TrustAPI ready to be passed to Server.SetTrustAPI.
func NewTrustAPI(
	ledger *trust.Ledger,
	consensus *trust.Consensus,
	verifier *trust.Verifier,
	gossip *trust.Gossip,
	revocation *trust.Revocation,
	kp *trust.Keypair,
	networkID string,
) *TrustAPI {
	return &TrustAPI{
		ledger:     ledger,
		consensus:  consensus,
		verifier:   verifier,
		gossip:     gossip,
		revocation: revocation,
		localKP:    kp,
		networkID:  networkID,
	}
}

// registerTrustRoutes mounts all /trust/* and /peers routes onto the router.
// Routes are public (node-to-node API), not behind the session middleware —
// they are authenticated via Ed25519 request signatures in the middleware below.
func (s *Server) registerTrustRoutes(t *TrustAPI) {
	if t == nil {
		return
	}
	s.trust = t

	// Public endpoint: returns network_id and genesis fingerprint.
	// Used by new nodes to discover network_id before submitting a join request.
	// No authentication required — network_id is not a secret.
	s.router.GET("/trust/info", s.handleTrustInfo)

	// Step 2 — Bootstrap: a new node submits a join request.
	// Uses self-auth: the caller signs with its own keypair but is NOT required to
	// be active in the nodes table yet (chicken-and-egg for first-time join).
	s.router.Group("/trust").Use(s.middlewareTrustSelfAuth()).POST("/join", s.handleTrustJoin)

	// Step 5 — Status polling by the joining node (self-auth, may not be active yet).
	s.router.Group("/trust").Use(s.middlewareTrustSelfAuth()).GET("/status/:request_id", s.handleTrustStatus)

	// Node-to-node API (no session required, identity verified by public-key sig).
	// Requires the calling node to be active in the nodes table.
	rg := s.router.Group("/trust")
	rg.Use(s.middlewareTrustAuth())
	{
		// Step 3 — Broadcast: receive a pending join_request from another node.
		rg.POST("/pending", s.handleTrustPending)

		// Step 4 — Voting: sign (approve) a join request.
		rg.POST("/sign/:request_id", s.handleTrustSign)

		// Step 6 — Gossip: serve ledger entries since a given seq.
		rg.GET("/ledger", s.handleTrustLedger)

		// Step 7 — Activate: master announces its address.
		rg.POST("/announce", s.handleTrustAnnounce)

		// Zone propagation: slave pulls zone list from a trusted master/genesis.
		rg.GET("/zones", s.handleTrustZones)

		// Zone records propagation: slave pulls all records for a zone via HTTP API.
		// Cursor-based pagination via ?after_id=0. No DNS AXFR needed between nodes.
		rg.GET("/zones/:name/records", s.handleTrustZoneRecords)

		// Push sync: a trusted peer notifies this node to re-pull zone list immediately.
		rg.POST("/zones/sync", s.handleTrustZonesSyncNotify)
	}

	// Peer list exchange (public within the trust network).
	s.router.Group("/peers").Use(s.middlewareTrustAuth()).GET("", s.handlePeerList)
}

// handleTrustInfo handles GET /trust/info — public network metadata endpoint.
// Returns network_id and genesis node fingerprint so a new node can discover
// network_id before submitting a join request.
func (s *Server) handleTrustInfo(c *gin.Context) {
	if s.trust == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "trust network not initialized"})
		return
	}
	var genesisPubKey string
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT public_key FROM nodes WHERE role = 'genesis' AND network_id = $1 LIMIT 1`,
		s.trust.networkID,
	).Scan(&genesisPubKey)

	// Compute fingerprint from the stored base64 public key for TOFU display.
	genesisFingerprint := trust.FingerprintFromPubKeyBase64(genesisPubKey)

	c.JSON(http.StatusOK, gin.H{
		"network_id":          s.trust.networkID,
		"genesis_fingerprint": genesisFingerprint,
	})
}

// handleTrustJoin handles POST /trust/join — Step 2 (Bootstrap).
// A new node submits a join request; this node broadcasts it to its peers.
func (s *Server) handleTrustJoin(c *gin.Context) {
	var req struct {
		PublicKey string `json:"public_key" binding:"required"`
		Name      string `json:"name"`
		Role      string `json:"role" binding:"required"`
		NetworkID string `json:"network_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role != "slave" && req.Role != "master" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be slave or master"})
		return
	}
	if req.NetworkID != s.trust.networkID {
		c.JSON(http.StatusForbidden, gin.H{"error": "network_id mismatch"})
		return
	}

	// Check permanent blacklist.
	var banned bool
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE public_key = $1)`,
		req.PublicKey,
	).Scan(&banned)
	if banned {
		c.JSON(http.StatusForbidden, gin.H{"error": "public key is permanently banned"})
		return
	}

	// Determine required signatures from genesis config.
	netCfg, err := s.loadNetworkConfig(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load network config"})
		return
	}
	reqSigs := netCfg.ThresholdJoinSlave
	if req.Role == "master" {
		reqSigs = netCfg.ThresholdJoinMaster
	}

	expires := time.Now().UTC().Add(72 * time.Hour)
	id, err := newUUIDStr()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "generate request id"})
		return
	}

	name := &req.Name
	if req.Name == "" {
		name = nil
	}

	_, err = s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO join_requests (id, public_key, name, role, required_sigs, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT DO NOTHING`,

		id, req.PublicKey, name, req.Role, reqSigs, expires,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "store join request"})
		return
	}

	// Async gossip broadcast — fire and forget.
	go s.trust.gossip.BroadcastJoinRequest(c.Request.Context(), id, req.PublicKey, req.Name, req.Role, expires)

	c.JSON(http.StatusAccepted, gin.H{
		"join_request_id":  id,
		"node_fingerprint": s.trust.localKP.Fingerprint(),
		"expires_at":       expires.Format(time.RFC3339),
	})
}

// handleTrustPending handles POST /trust/pending — Step 3 (Broadcast).
// Receives a pending join request broadcast from another node and stores it locally.
func (s *Server) handleTrustPending(c *gin.Context) {
	var req struct {
		Type          string    `json:"type"`
		ID            string    `json:"id"            binding:"required"`
		SubjectPubkey string    `json:"subject_pubkey" binding:"required"`
		SubjectName   string    `json:"subject_name"`
		SubjectRole   string    `json:"subject_role"   binding:"required"`
		RequestedAt   time.Time `json:"requested_at"`
		RequestedVia  string    `json:"requested_via"`
		ExpiresAt     time.Time `json:"expires_at"     binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	netCfg, err := s.loadNetworkConfig(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load network config"})
		return
	}
	reqSigs := netCfg.ThresholdJoinSlave
	if req.SubjectRole == "master" {
		reqSigs = netCfg.ThresholdJoinMaster
	}

	name := &req.SubjectName
	if req.SubjectName == "" {
		name = nil
	}

	_, err = s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO join_requests (id, public_key, name, role, required_sigs, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO NOTHING`,

		req.ID, req.SubjectPubkey, name, req.SubjectRole, reqSigs, req.ExpiresAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "store pending request"})
		return
	}
	c.Status(http.StatusAccepted)
}

// handleTrustSign handles POST /trust/sign/:request_id — Step 4 (Voting).
// A dashboard admin approves a pending join request by submitting a signature.
func (s *Server) handleTrustSign(c *gin.Context) {
	requestID := c.Param("request_id")
	var req struct {
		SignerID  string `json:"signer_id"  binding:"required"`
		Signature string `json:"signature"  binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Load join request to get subject info for signature verification.
	var jr struct {
		PublicKey string
		ExpiresAt time.Time
	}
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT public_key, expires_at FROM join_requests WHERE id = $1 AND status = 'pending'`,
		requestID,
	).Scan(&jr.PublicKey, &jr.ExpiresAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "join request not found or not pending"})
		return
	}

	// Get voter's public key.
	var voterPubKey string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT public_key FROM nodes WHERE id = $1 AND status = 'active'`,
		req.SignerID,
	).Scan(&voterPubKey)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "signer not found or not active"})
		return
	}

	// Verify the signature.
	if err := trust.VerifyJoinRequestSignature(
		voterPubKey, requestID, jr.PublicKey, jr.ExpiresAt, req.Signature,
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Increment signature counter.
	if err := s.trust.consensus.IncrementJoinRequestSignatures(c.Request.Context(), requestID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update signature count"})
		return
	}

	// Check if threshold is now met → auto-approve.
	netCfg, _ := s.loadNetworkConfig(c.Request.Context())
	approved, err := s.trust.consensus.ApproveJoinRequest(c.Request.Context(), s.trust.localKP, netCfg, requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "approve join request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"approved": approved})
}

// handleTrustStatus handles GET /trust/status/:request_id — Step 5 (Polling).
func (s *Server) handleTrustStatus(c *gin.Context) {
	requestID := c.Param("request_id")

	var status string
	var sigs, required int
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT status, signatures, required_sigs FROM join_requests WHERE id = $1`,
		requestID,
	).Scan(&status, &sigs, &required)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "join request not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":     status,
		"signatures": sigs,
		"required":   required,
	})
}

// handleTrustLedger handles GET /trust/ledger?since_seq=N — Step 6 (Gossip).
func (s *Server) handleTrustLedger(c *gin.Context) {
	sinceSeq, _ := strconv.ParseInt(c.Query("since_seq"), 10, 64)
	entries, err := s.trust.ledger.GetSince(c.Request.Context(), sinceSeq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query ledger"})
		return
	}
	if entries == nil {
		entries = []trust.LedgerEntry{}
	}
	c.JSON(http.StatusOK, entries)
}

// handleTrustAnnounce handles POST /trust/announce — Step 7 (Activate).
// Master/genesis nodes announce their AXFR-source address; slave nodes announce
// their HTTP address so peers can reach them for notifications (e.g. zone sync).
// All active nodes are allowed — role check is removed so slaves can register too.
func (s *Server) handleTrustAnnounce(c *gin.Context) {
	var req struct {
		Address   string `json:"address"    binding:"required"`
		PublicKey string `json:"public_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the announcing node is active (any role).
	var nodeID, nodeRole string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, role FROM nodes WHERE public_key = $1 AND status = 'active'`,
		req.PublicKey,
	).Scan(&nodeID, &nodeRole)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "announcing node is not active"})
		return
	}

	// Upsert into peers with trusted status.
	peer := trust.Peer{
		PublicKey:   req.PublicKey,
		Address:     req.Address,
		TrustStatus: "trusted",
		NetworkID:   s.trust.networkID,
	}
	if err := trust.StorePeer(c.Request.Context(), s.db.Pool, peer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "store peer"})
		return
	}

	// Only master/genesis nodes create a ledger entry — their address is published
	// as an AXFR source. Slaves register address for gossip/notification only.
	if nodeRole == "master" || nodeRole == "genesis" {
		payload, _ := json.Marshal(map[string]string{
			"action":     "announce",
			"public_key": req.PublicKey,
			"address":    req.Address,
		})
		if _, err := s.trust.ledger.Append(c.Request.Context(), "announce", &nodeID, nil, payload, false); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ledger append"})
			return
		}
	}

	c.Status(http.StatusAccepted)
}

// handleTrustZones handles GET /trust/zones — Zone Propagation.
// Returns the list of all enabled zones on this node so that slave nodes can
// discover which zones to sync and automatically upsert them into their local DB.
//
// The response includes node_dns_addr — the DNS host:port that slaves should
// use as master_ip for AXFR. This ensures slaves always pull records from this
// node (which has already pulled from the upstream provider), regardless of what
// master_ip is configured on each individual zone here.
func (s *Server) handleTrustZones(c *gin.Context) {
	zones, err := s.db.ListZones(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list zones"})
		return
	}

	type zoneInfo struct {
		Name         string `json:"name"`
		SyncInterval int    `json:"sync_interval"`
	}

	result := make([]zoneInfo, 0, len(zones))
	for _, z := range zones {
		if !z.Enabled {
			continue
		}
		result = append(result, zoneInfo{
			Name:         z.Name,
			SyncInterval: z.SyncInterval,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"node_dns_addr": s.advertisedDNSAddr,
		"zones":         result,
	})
}

// handleTrustZonesSyncNotify handles POST /trust/zones/sync.
// Called by a trusted peer (genesis/master) to notify this node that zones
// have changed and it should re-pull immediately.
// The actual sync runs in a background goroutine so the response is instant.
func (s *Server) handleTrustZonesSyncNotify(c *gin.Context) {
	if s.onTrustZonesSync != nil {
		go s.onTrustZonesSync()
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "sync scheduled"})
}

// handleTrustZoneRecords handles GET /trust/zones/:name/records — Records Propagation.
// Returns a paginated list of RPZ records for a zone so slave nodes can pull zone
// contents via the trust-network HTTP API without requiring DNS AXFR between nodes.
//
// Pagination: cursor-based via ?after_id=0 (default 0 = start from beginning).
// Page size is fixed at 5000 records. Caller repeats with after_id = last returned ID
// until the response contains fewer than 5000 records (end of zone).
func (s *Server) handleTrustZoneRecords(c *gin.Context) {
	zoneName := c.Param("name")
	afterID, _ := strconv.ParseInt(c.Query("after_id"), 10, 64)

	const pageSize = 5000
	records, err := s.db.ListZoneRecordsPage(c.Request.Context(), zoneName, afterID, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list zone records"})
		return
	}

	type recordItem struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		RType string `json:"rtype"`
		RData string `json:"rdata"`
		TTL   int    `json:"ttl"`
	}
	result := make([]recordItem, len(records))
	for i, r := range records {
		result[i] = recordItem{ID: r.ID, Name: r.Name, RType: r.RType, RData: r.RData, TTL: r.TTL}
	}
	c.JSON(http.StatusOK, result)
}

// handlePeerList handles GET /peers — Step 8 (Peer Discovery).
// Returns the list of known trusted peers for this network.
func (s *Server) handlePeerList(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, public_key, address, last_seen, trust_status, network_id
		 FROM peers WHERE trust_status = 'trusted' AND network_id = $1
		 ORDER BY last_seen DESC NULLS LAST
		 LIMIT 200`,
		s.trust.networkID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query peers"})
		return
	}
	defer rows.Close()

	var peers []trust.Peer
	for rows.Next() {
		var p trust.Peer
		if err := rows.Scan(&p.ID, &p.PublicKey, &p.Address, &p.LastSeen, &p.TrustStatus, &p.NetworkID); err != nil {
			continue
		}
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []trust.Peer{}
	}
	c.JSON(http.StatusOK, peers)
}

// middlewareTrustAuth authenticates node-to-node requests using Ed25519 signatures.
//
// The caller must include these HTTP headers:
//
//	X-Node-Pubkey   — base64-encoded Ed25519 public key of the calling node
//	X-Timestamp     — Unix seconds (int64, string); request is rejected if >60 s old
//	X-Network-ID    — network_id this node belongs to
//	X-Signature     — base64-encoded Ed25519 signature over SHA-256 of the signing payload
//
// Signing payload (UTF-8, newline separated):
//
//	{METHOD}\n{URL_PATH}\n{hex(SHA256(raw_body))}\n{X-Timestamp value}
//
// The public key must belong to a node in the nodes table with status "active".
func (s *Server) middlewareTrustAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.trust == nil {
			c.Next()
			return
		}

		// --- 1. Parse required headers ---
		pubKeyB64 := c.GetHeader("X-Node-Pubkey")
		tsStr := c.GetHeader("X-Timestamp")
		networkID := c.GetHeader("X-Network-ID")
		sigB64 := c.GetHeader("X-Signature")

		if pubKeyB64 == "" || tsStr == "" || networkID == "" || sigB64 == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing trust auth headers"})
			return
		}

		// --- 2. Network ID check ---
		if networkID != s.trust.networkID {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "network_id mismatch"})
			return
		}

		// --- 3. Timestamp replay prevention (±60 seconds) ---
		tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid X-Timestamp"})
			return
		}
		now := time.Now().Unix()
		if tsUnix < now-60 || tsUnix > now+60 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "request timestamp out of range"})
			return
		}

		// --- 4. Node must be active in DB ---
		var exists bool
		_ = s.db.Pool.QueryRow(c.Request.Context(), `
			SELECT EXISTS(
			    SELECT 1 FROM nodes
			    WHERE public_key = $1
			      AND status = 'active'
			      AND network_id = $2
			)`, pubKeyB64, networkID,
		).Scan(&exists)
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "node not found or not active"})
			return
		}

		// --- 5. Read body and re-inject for downstream handlers ---
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// --- 6. Compute signing payload and verify Ed25519 signature ---
		bodyHash := sha256.Sum256(bodyBytes)
		signingPayload := []byte(
			c.Request.Method + "\n" +
				c.Request.URL.Path + "\n" +
				hex.EncodeToString(bodyHash[:]) + "\n" +
				tsStr,
		)
		if ok, err := trust.VerifySignature(pubKeyB64, signingPayload, sigB64); err != nil || !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
			return
		}

		// Stash caller pubkey for downstream handlers.
		c.Set("trust_node_pubkey", pubKeyB64)
		c.Next()
	}
}

// middlewareTrustSelfAuth is a lighter version of middlewareTrustAuth for endpoints
// that must be reachable by nodes that are not yet active in the nodes table (e.g.
// /trust/join during first-time bootstrap).
//
// It verifies:
//  1. Required headers are present (X-Node-Pubkey, X-Timestamp, X-Signature).
//  2. Timestamp is within ±60 seconds (replay prevention).
//  3. Ed25519 signature is valid for the claimed public key.
//
// It does NOT check whether the public key is in the nodes table.
func (s *Server) middlewareTrustSelfAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.trust == nil {
			c.Next()
			return
		}

		pubKeyB64 := c.GetHeader("X-Node-Pubkey")
		tsStr := c.GetHeader("X-Timestamp")
		sigB64 := c.GetHeader("X-Signature")

		if pubKeyB64 == "" || tsStr == "" || sigB64 == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing trust auth headers"})
			return
		}

		tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid X-Timestamp"})
			return
		}
		now := time.Now().Unix()
		if tsUnix < now-60 || tsUnix > now+60 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "request timestamp out of range"})
			return
		}

		// Read body and re-inject for downstream handlers.
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		bodyHash := sha256.Sum256(bodyBytes)
		signingPayload := []byte(
			c.Request.Method + "\n" +
				c.Request.URL.Path + "\n" +
				hex.EncodeToString(bodyHash[:]) + "\n" +
				tsStr,
		)
		if ok, err := trust.VerifySignature(pubKeyB64, signingPayload, sigB64); err != nil || !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
			return
		}

		c.Set("trust_node_pubkey", pubKeyB64)
		c.Next()
	}
}

// newUUIDStr generates a random UUID v4 string via the trust package helper.
func newUUIDStr() (string, error) {
	return trust.NewUUID()
}
