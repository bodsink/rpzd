package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleInternalNotify is called by rpzd (the DNS server) when it receives a
// DNS NOTIFY message from a master server (RFC 1996). It triggers an immediate
// zone sync for the notified zone without waiting for the next scheduled interval.
//
// This endpoint is localhost-only (protected by middlewareLocalhostOnly).
// Request: POST /internal/notify?zone=<zone-name>
func (s *Server) handleInternalNotify(c *gin.Context) {
	zone := c.Query("zone")
	if zone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing zone parameter"})
		return
	}

	if s.notifyScheduler == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "notify scheduler not configured"})
		return
	}

	s.logger.Info("DNS NOTIFY received — triggering immediate sync", "zone", zone)
	go s.notifyScheduler(zone)

	c.JSON(http.StatusOK, gin.H{"status": "sync triggered", "zone": zone})
}
