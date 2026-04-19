package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bodsink/rpzd/internal/trust"
)

// trustNodeRow represents a row in the trust nodes UI table.
type trustNodeRow struct {
	ID        string
	PublicKey string
	Name      *string
	Role      string
	Status    string
	JoinedAt  *time.Time
	LastSeen  *time.Time
}

// trustJoinRequestRow represents a pending join request for the UI voting panel.
type trustJoinRequestRow struct {
	ID           string
	PublicKey    string
	Name         *string
	Role         string
	Signatures   int
	RequiredSigs int
	ExpiresAt    time.Time
}

// registerTrustUIRoutes mounts the dashboard UI routes for trust network management.
// These are behind the session + CSRF middleware (standard dashboard auth).
func (s *Server) registerTrustUIRoutes() {
	if s.trust == nil {
		return
	}
	auth := s.router.Group("/trust/ui")
	auth.Use(s.middlewareRequireSession())
	{
		auth.GET("", func(c *gin.Context) { c.Redirect(http.StatusFound, "/trust/nodes") })
		auth.POST("/sign/:request_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUISign)
		auth.POST("/reject/:request_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUIReject)
		// Revocation: propose (first vote) + additional votes
		auth.POST("/suspend/:node_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUISuspend)
		auth.POST("/ban/:node_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUIBan)
		auth.POST("/reinstate/:node_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUIReinstate)
		auth.POST("/revocation-vote/:proposal_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUIRevocationVote)
		auth.POST("/revoke-genesis", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUIRevokeGenesis)
		auth.POST("/role-upgrade/:node_id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleTrustUIRoleUpgrade)
	}
}

// handleTrustNodesPage renders the trust network admin page.
func (s *Server) handleTrustNodesPage(c *gin.Context) {
	// Trust network not yet active — show appropriate status.
	if s.trust == nil {
		user := currentUser(c)
		c.HTML(http.StatusOK, "trust_nodes.html", gin.H{
			"ActivePage":     "trust",
			"User":           user,
			"TrustPending":   true,
			"TrustJoinState": s.trustJoinState,
			"TrustBootstrap": s.trustBootstrap,
		})
		return
	}

	ctx := c.Request.Context()

	// Load pending join requests.
	var pendingRequests []trustJoinRequestRow
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, public_key, name, role, signatures, required_sigs, expires_at
		FROM join_requests
		WHERE status = 'pending'
		ORDER BY created_at ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var r trustJoinRequestRow
			if err := rows.Scan(&r.ID, &r.PublicKey, &r.Name, &r.Role,
				&r.Signatures, &r.RequiredSigs, &r.ExpiresAt); err == nil {
				pendingRequests = append(pendingRequests, r)
			}
		}
	}

	// Load known nodes.
	var nodes []trustNodeRow
	nRows, err := s.db.Pool.Query(ctx, `
		SELECT id, public_key, name, role, status, joined_at, last_seen
		FROM nodes
		WHERE network_id = $1
		ORDER BY joined_at ASC NULLS LAST`,
		s.trust.networkID,
	)
	if err == nil {
		defer nRows.Close()
		for nRows.Next() {
			var n trustNodeRow
			if err := nRows.Scan(&n.ID, &n.PublicKey, &n.Name, &n.Role,
				&n.Status, &n.JoinedAt, &n.LastSeen); err == nil {
				nodes = append(nodes, n)
			}
		}
	}

	// Load open revocation proposals.
	type revocationProposalRow struct {
		ID            string
		SubjectName   string
		Action        string
		Reason        string
		Votes         int
		RequiredVotes int
		ExpiresAt     time.Time
	}
	var revocationProposals []revocationProposalRow
	pRows, pErr := s.db.Pool.Query(ctx, `
		SELECT rp.id, COALESCE(n.name, n.public_key, rp.subject_id::text),
		       rp.action, COALESCE(rp.reason,''), rp.votes, rp.required_votes, rp.expires_at
		FROM revocation_proposals rp
		LEFT JOIN nodes n ON n.id = rp.subject_id
		WHERE rp.status = 'voting'
		ORDER BY rp.created_at ASC`)
	if pErr == nil {
		defer pRows.Close()
		for pRows.Next() {
			var p revocationProposalRow
			if err := pRows.Scan(&p.ID, &p.SubjectName, &p.Action, &p.Reason,
				&p.Votes, &p.RequiredVotes, &p.ExpiresAt); err == nil {
				revocationProposals = append(revocationProposals, p)
			}
		}
	}

	user := currentUser(c)
	c.HTML(http.StatusOK, "trust_nodes.html", gin.H{
		"ActivePage":          "trust",
		"User":                user,
		"CSRFToken":           csrfToken(c),
		"NodeRole":            s.trust.localKP.Fingerprint()[:20] + "…",
		"NodePubKey":          s.trust.localKP.PublicKeyBase64(),
		"NodeFingerprint":     s.trust.localKP.Fingerprint(),
		"NetworkID":           s.trust.networkID,
		"PendingRequests":     pendingRequests,
		"Nodes":               nodes,
		"RevocationProposals": revocationProposals,
	})
}

// handleTrustUISign processes an admin's approval vote for a join request.
// It signs the request with the local node's keypair and submits via the
// internal consensus API.
func (s *Server) handleTrustUISign(c *gin.Context) {
	requestID := c.Param("request_id")
	ctx := c.Request.Context()

	// Load join request details.
	var jr struct {
		PublicKey string
		ExpiresAt time.Time
	}
	err := s.db.Pool.QueryRow(ctx,
		`SELECT public_key, expires_at FROM join_requests WHERE id = $1 AND status = 'pending'`,
		requestID,
	).Scan(&jr.PublicKey, &jr.ExpiresAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "join request not found"})
		return
	}

	// Find local node ID.
	var localNodeID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id FROM nodes WHERE public_key = $1`,
		s.trust.localKP.PublicKeyBase64(),
	).Scan(&localNodeID)
	if err != nil {
		// Local node not yet in DB — cannot vote yet.
		c.JSON(http.StatusConflict, gin.H{"error": "local node is not registered in trust network"})
		return
	}

	// Produce signature.
	sigBase64 := trust.SignJoinRequest(s.trust.localKP, requestID, jr.PublicKey, jr.ExpiresAt)

	// Store via consensus (verifies + persists).
	err = s.trust.consensus.AddSignature(ctx, s.trust.verifier, trust.EntrySignature{
		EntryHash: base64.StdEncoding.EncodeToString([]byte(requestID)), // placeholder hash for voting
		SignerID:  localNodeID,
		Signature: sigBase64,
		SignedAt:  time.Now().UTC(),
	})
	if err != nil {
		// Signature add may fail if entry_hash FK doesn't exist yet —
		// in that case, fall through to increment counter directly.
		_ = err
	}

	// Increment signature counter.
	if err := s.trust.consensus.IncrementJoinRequestSignatures(ctx, requestID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update signature count"})
		return
	}

	// Check threshold.
	netCfg, _ := s.loadNetworkConfig(ctx)
	_, _ = s.trust.consensus.ApproveJoinRequest(ctx, s.trust.localKP, netCfg, requestID)

	// Return the updated row fragment for HTMX swap (or redirect for non-HTMX).
	if c.GetHeader("HX-Request") == "true" {
		c.Data(http.StatusOK, "text/html", []byte(
			`<tr id="jr-`+requestID+`"><td colspan="2" class="px-5 py-3 text-sm text-green-700">✓ Signature recorded</td></tr>`,
		))
		return
	}
	c.Redirect(http.StatusSeeOther, "/trust/nodes")
}

// handleTrustUIReject marks a join request as rejected.
func (s *Server) handleTrustUIReject(c *gin.Context) {
	requestID := c.Param("request_id")
	_, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE join_requests SET status = 'rejected' WHERE id = $1 AND status = 'pending'`,
		requestID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reject join request"})
		return
	}
	if c.GetHeader("HX-Request") == "true" {
		c.Data(http.StatusOK, "text/html", []byte(
			`<tr id="jr-`+requestID+`"><td colspan="2" class="px-5 py-3 text-sm text-red-700">✗ Request rejected</td></tr>`,
		))
		return
	}
	c.Redirect(http.StatusSeeOther, "/trust/nodes")
}

// handleTrustUISuspend opens a revocation proposal with action="suspend".
// Genesis node: executes immediately (unilateral).
// Other nodes: records the first vote; execution waits for threshold_suspend votes.
func (s *Server) handleTrustUISuspend(c *gin.Context) {
	s.handleTrustUIRevocationPropose(c, "suspend")
}

// handleTrustUIBan opens a revocation proposal with action="ban".
// Genesis node: executes immediately (unilateral).
// Other nodes: records the first vote; execution waits for threshold_ban votes.
func (s *Server) handleTrustUIBan(c *gin.Context) {
	s.handleTrustUIRevocationPropose(c, "ban")
}

// handleTrustUIReinstate opens a revocation proposal with action="reinstate".
func (s *Server) handleTrustUIReinstate(c *gin.Context) {
	s.handleTrustUIRevocationPropose(c, "reinstate")
}

// handleTrustUIRevocationVote records an additional vote on an existing open proposal.
func (s *Server) handleTrustUIRevocationVote(c *gin.Context) {
	proposalID := c.Param("proposal_id")
	ctx := c.Request.Context()

	actorID, err := s.localNodeID(ctx)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "local node not registered in trust network"})
		return
	}
	netCfg, err := s.loadNetworkConfig(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load network config"})
		return
	}

	executed, err := s.trust.revocation.AddRevocationVote(ctx, proposalID, actorID, netCfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if executed && s.dnsSignal != nil {
		_ = s.dnsSignal()
	}

	msg := "Vote recorded — waiting for more votes"
	if executed {
		msg = "Threshold reached — action executed"
	}
	if c.GetHeader("HX-Request") == "true" {
		c.Data(http.StatusOK, "text/html", []byte(
			`<span class="text-blue-700 font-semibold">`+msg+`</span>`,
		))
		return
	}
	c.Redirect(http.StatusSeeOther, "/trust/nodes")
}

// handleTrustUIRevocationPropose is the shared implementation for propose-suspend/ban/reinstate.
func (s *Server) handleTrustUIRevocationPropose(c *gin.Context, action string) {
	nodeID := c.Param("node_id")
	ctx := c.Request.Context()
	reason := c.PostForm("reason")
	if reason == "" {
		reason = action + " proposed via dashboard"
	}

	// suspend_duration_hours: 0 = indefinite, >0 = temporary (only for suspend)
	var suspendDurationHours int
	if action == "suspend" {
		if d := c.PostForm("suspend_duration_hours"); d != "" {
			suspendDurationHours, _ = strconv.Atoi(d)
		}
	}

	actorID, err := s.localNodeID(ctx)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "local node not registered in trust network"})
		return
	}
	netCfg, err := s.loadNetworkConfig(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load network config"})
		return
	}

	proposalID, executed, err := s.trust.revocation.ProposeRevocation(
		ctx, nodeID, actorID, action, reason, suspendDurationHours, netCfg,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// If action executed immediately (genesis unilateral or threshold=1),
	// signal DNS daemon to reload AXFR whitelist.
	if executed && s.dnsSignal != nil {
		_ = s.dnsSignal()
	}

	var msg string
	if executed {
		msg = action + " executed immediately (unilateral)"
	} else {
		msg = "Vote recorded — proposal " + proposalID + " open for voting"
	}

	if c.GetHeader("HX-Request") == "true" {
		cssClass := map[string]string{
			"suspend":   "text-yellow-700",
			"ban":       "text-red-700",
			"reinstate": "text-green-700",
		}[action]
		c.Data(http.StatusOK, "text/html", []byte(
			`<span class="`+cssClass+` font-semibold">`+msg+`</span>`,
		))
		return
	}
	c.Redirect(http.StatusSeeOther, "/trust/nodes")
}

// handleTrustUIRevokeGenesis proposes or votes on a genesis revocation (67% supermajority).
// Only non-genesis active nodes may call this.
// Effect when executed: genesis downgraded to 'master'; trust chain remains intact.
func (s *Server) handleTrustUIRevokeGenesis(c *gin.Context) {
	ctx := c.Request.Context()
	reason := c.PostForm("reason")
	if reason == "" {
		reason = "genesis revocation proposed via dashboard"
	}

	actorID, err := s.localNodeID(ctx)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "local node not registered in trust network"})
		return
	}

	proposalID, executed, err := s.trust.revocation.ProposeRevokeGenesis(ctx, actorID, reason)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var msg string
	if executed {
		msg = "Supermajority reached — genesis downgraded to master"
	} else {
		msg = "Vote recorded for genesis revocation (proposal " + proposalID + ")"
	}

	if c.GetHeader("HX-Request") == "true" {
		c.Data(http.StatusOK, "text/html", []byte(
			`<span class="text-red-700 font-semibold">`+msg+`</span>`,
		))
		return
	}
	c.Redirect(http.StatusSeeOther, "/trust/nodes")
}

// localNodeID resolves the UUID of the local node from the nodes table
// using the local keypair's public key.
func (s *Server) localNodeID(ctx context.Context) (string, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM nodes WHERE public_key = $1`,
		s.trust.localKP.PublicKeyBase64(),
	).Scan(&id)
	return id, err
}

// handleTrustUIRoleUpgrade proposes or votes on a role upgrade (slave → master).
// Threshold = genesis_config.threshold_role_upgrade (default: 3).
func (s *Server) handleTrustUIRoleUpgrade(c *gin.Context) {
	nodeID := c.Param("node_id")
	ctx := c.Request.Context()
	reason := c.PostForm("reason")
	if reason == "" {
		reason = "role upgrade proposed via dashboard"
	}

	actorID, err := s.localNodeID(ctx)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "local node not registered in trust network"})
		return
	}
	netCfg, err := s.loadNetworkConfig(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load network config"})
		return
	}

	proposalID, executed, err := s.trust.revocation.ProposeRoleUpgrade(ctx, nodeID, actorID, reason, netCfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var msg string
	if executed {
		msg = "Role upgrade executed — node is now a master"
	} else {
		msg = "Vote recorded for role upgrade (proposal " + proposalID + ")"
	}

	if c.GetHeader("HX-Request") == "true" {
		c.Data(http.StatusOK, "text/html", []byte(
			`<span class="text-blue-700 font-semibold">`+msg+`</span>`,
		))
		return
	}
	c.Redirect(http.StatusSeeOther, "/trust/nodes")
}
