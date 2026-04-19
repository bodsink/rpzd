package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/bodsink/rpzd/internal/store"
)

// recordFormFields holds the decomposed per-type form field values for re-rendering on error.
type recordFormFields struct {
	IP        string
	Target    string
	TXT       string
	MXPrio    string
	SRVPrio   string
	SRVWeight string
	SRVPort   string
	CAAFlag   string
	CAAValue  string
	Raw       string
}

// handleZoneList renders the zones list page.
func (s *Server) handleZoneList(c *gin.Context) {
	zones, err := s.db.ListZones(c.Request.Context())
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load zones", err)
		return
	}
	c.HTML(http.StatusOK, "zones.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "zones",
		"Zones":      zones,
	})
}

// handleZoneNew renders the new zone form.
func (s *Server) handleZoneNew(c *gin.Context) {
	c.HTML(http.StatusOK, "zone_form.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "zones",
		"Zone":       &store.Zone{ZoneType: "rpz", Mode: "slave", MasterPort: 53, SyncInterval: 86400, Enabled: true},
		"IsNew":      true,
	})
}

// handleZoneCreate processes the new zone form submission.
func (s *Server) handleZoneCreate(c *gin.Context) {
	z, formErr := parseZoneForm(c)
	if formErr != "" {
		c.HTML(http.StatusBadRequest, "zone_form.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Zone":      z,
			"IsNew":     true,
			"Error":     formErr,
		})
		return
	}

	id, err := s.db.CreateZone(c.Request.Context(), z)
	if err != nil {
		s.logger.Error("create zone failed", "err", err)
		c.HTML(http.StatusInternalServerError, "zone_form.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Zone":      z,
			"IsNew":     true,
			"Error":     "Failed to create zone: " + friendlyDBError(err),
		})
		return
	}

	s.logger.Info("zone created", "zone", z.Name, "id", id, "user", currentUser(c).Username)
	if s.onZoneChanged != nil {
		go s.onZoneChanged()
	}
	if s.dnsSignal != nil {
		go func() {
			if err := s.dnsSignal(); err != nil {
				s.logger.Warn("dns signal failed", "err", err)
			}
		}()
	}
	c.Redirect(http.StatusFound, "/zones")
}

// handleZoneDetail shows the detail/overview of a zone.
func (s *Server) handleZoneDetail(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}
	history, _ := s.db.ListSyncHistory(c.Request.Context(), zone.ID, 5)
	c.HTML(http.StatusOK, "zone_detail.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "zones",
		"Zone":       zone,
		"History":    history,
	})
}

// handleZoneEdit renders the edit zone form.
func (s *Server) handleZoneEdit(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}
	c.HTML(http.StatusOK, "zone_form.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "zones",
		"Zone":       zone,
		"IsNew":      false,
	})
}

// handleZoneUpdate processes the edit zone form submission.
func (s *Server) handleZoneUpdate(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}

	updated, formErr := parseZoneForm(c)
	if formErr != "" {
		updated.ID = zone.ID
		updated.Name = zone.Name
		c.HTML(http.StatusBadRequest, "zone_form.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Zone":      updated,
			"IsNew":     false,
			"Error":     formErr,
		})
		return
	}

	updated.ID = zone.ID
	updated.Name = zone.Name // name is immutable after creation
	if err := s.db.UpdateZone(c.Request.Context(), updated); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to update zone", err)
		return
	}

	s.logger.Info("zone updated", "zone", zone.Name, "user", currentUser(c).Username)
	if s.onZoneChanged != nil {
		go s.onZoneChanged()
	}
	if s.dnsSignal != nil {
		go func() {
			if err := s.dnsSignal(); err != nil {
				s.logger.Warn("dns signal failed", "err", err)
			}
		}()
	}
	c.Redirect(http.StatusFound, "/zones")
}

// handleZoneDelete deletes a zone and all its records.
func (s *Server) handleZoneDelete(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}
	if err := s.db.DeleteZone(c.Request.Context(), zone.ID); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to delete zone", err)
		return
	}
	s.logger.Info("zone deleted", "zone", zone.Name, "user", currentUser(c).Username)
	if s.onZoneChanged != nil {
		go s.onZoneChanged()
	}
	if s.dnsSignal != nil {
		go func() {
			if err := s.dnsSignal(); err != nil {
				s.logger.Warn("dns signal failed", "err", err)
			}
		}()
	}
	c.Redirect(http.StatusFound, "/zones")
}

// handleZoneToggle enables or disables a zone.
func (s *Server) handleZoneToggle(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}
	zone.Enabled = !zone.Enabled
	if err := s.db.UpdateZone(c.Request.Context(), zone); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to toggle zone", err)
		return
	}
	s.logger.Info("zone toggled", "zone", zone.Name, "enabled", zone.Enabled, "user", currentUser(c).Username)
	if s.dnsSignal != nil {
		go func() {
			if err := s.dnsSignal(); err != nil {
				s.logger.Warn("dns signal failed", "err", err)
			}
		}()
	}

	// HTMX partial response: return updated row instead of full redirect
	if c.GetHeader("HX-Request") == "true" {
		c.HTML(http.StatusOK, "zone_row.html", gin.H{
			"User":      currentUser(c),
			"CSRFToken": csrfToken(c),
			"Zone":      zone,
		})
		return
	}
	c.Redirect(http.StatusFound, "/zones")
}

// handleZoneTriggerSync triggers an immediate AXFR sync for a zone.
func (s *Server) handleZoneTriggerSync(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}

	go func() {
		if err := s.syncer.SyncZone(c.Request.Context(), zone); err != nil {
			s.logger.Error("manual sync failed", "zone", zone.Name, "err", err)
		}
	}()

	s.logger.Info("manual sync triggered", "zone", zone.Name, "user", currentUser(c).Username)

	if c.GetHeader("HX-Request") == "true" {
		c.String(http.StatusOK, `<span class="text-green-600 font-medium">Sync started...</span>`)
		return
	}
	c.Redirect(http.StatusFound, fmt.Sprintf("/zones/%d", zone.ID))
}

// handleZoneSyncHistory renders the sync history for a zone.
func (s *Server) handleZoneSyncHistory(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}
	history, err := s.db.ListSyncHistory(c.Request.Context(), zone.ID, 50)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load sync history", err)
		return
	}
	c.HTML(http.StatusOK, "sync_history.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "history",
		"Zone":       zone,
		"History":    history,
	})
}

// --- Records ---

// handleRecordList renders a paginated list of records for a zone.
func (s *Server) handleRecordList(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}

	page := max(1, parseIntParam(c.Query("page"), 1))
	pageSize := 100
	search := strings.TrimSpace(c.Query("q"))
	offset := (page - 1) * pageSize

	var (
		records []store.Record
		total   int64
		err     error
	)

	if search != "" {
		err = s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT COUNT(*) FROM rpz_records WHERE zone_id=$1 AND name ILIKE $2`,
			zone.ID, "%"+search+"%",
		).Scan(&total)
		if err == nil {
			rows, qerr := s.db.Pool.Query(c.Request.Context(),
				`SELECT id, zone_id, name, rtype, rdata, ttl, created_at, updated_at
				 FROM rpz_records WHERE zone_id=$1 AND name ILIKE $2
				 ORDER BY name LIMIT $3 OFFSET $4`,
				zone.ID, "%"+search+"%", pageSize, offset,
			)
			if qerr == nil {
				defer rows.Close()
				for rows.Next() {
					var r store.Record
					if serr := rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.RType, &r.RData, &r.TTL, &r.CreatedAt, &r.UpdatedAt); serr == nil {
						records = append(records, r)
					}
				}
			}
		}
	} else {
		err = s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT COUNT(*) FROM rpz_records WHERE zone_id=$1`, zone.ID,
		).Scan(&total)
		if err == nil {
			rows, qerr := s.db.Pool.Query(c.Request.Context(),
				`SELECT id, zone_id, name, rtype, rdata, ttl, created_at, updated_at
				 FROM rpz_records WHERE zone_id=$1
				 ORDER BY name LIMIT $2 OFFSET $3`,
				zone.ID, pageSize, offset,
			)
			if qerr == nil {
				defer rows.Close()
				for rows.Next() {
					var r store.Record
					if serr := rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.RType, &r.RData, &r.TTL, &r.CreatedAt, &r.UpdatedAt); serr == nil {
						records = append(records, r)
					}
				}
			}
		}
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	c.HTML(http.StatusOK, "records.html", gin.H{
		"User":       currentUser(c),
		"CSRFToken":  csrfToken(c),
		"ActivePage": "zones",
		"Zone":       zone,
		"Records":    records,
		"Total":      total,
		"Page":       page,
		"PageSize":   pageSize,
		"TotalPages": totalPages,
		"Search":     search,
	})
}

// handleRecordCreate adds a single record to a master zone.
func (s *Server) handleRecordCreate(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	rtype := strings.TrimSpace(c.PostForm("rtype"))
	ttl := parseIntParam(c.PostForm("ttl"), 300)

	// Collect per-type fields for error re-render
	fields := recordFormFields{
		IP:        strings.TrimSpace(c.PostForm("f_ip")),
		Target:    strings.TrimSpace(c.PostForm("f_target")),
		TXT:       strings.TrimSpace(c.PostForm("f_txt")),
		MXPrio:    strings.TrimSpace(c.PostForm("f_mx_prio")),
		SRVPrio:   strings.TrimSpace(c.PostForm("f_srv_prio")),
		SRVWeight: strings.TrimSpace(c.PostForm("f_srv_weight")),
		SRVPort:   strings.TrimSpace(c.PostForm("f_srv_port")),
		CAAFlag:   strings.TrimSpace(c.PostForm("f_caa_flag")),
		CAAValue:  strings.TrimSpace(c.PostForm("f_caa_value")),
		Raw:       strings.TrimSpace(c.PostForm("f_raw")),
	}

	renderFormError := func(msg string) {
		c.HTML(http.StatusBadRequest, "records.html", gin.H{
			"User":       currentUser(c),
			"CSRFToken":  csrfToken(c),
			"ActivePage": "zones",
			"Zone":       zone,
			"Records":    nil,
			"Total":      int64(0),
			"Page":       1,
			"PageSize":   100,
			"TotalPages": 0,
			"Search":     "",
			"FormError":  msg,
			"FormName":   name,
			"FormRType":  rtype,
			"FormFields": fields,
			"FormTTL":    ttl,
		})
	}

	if name == "" {
		renderFormError("Record name is required")
		return
	}
	if rtype == "" {
		rtype = "A"
	}
	if ttl < 0 {
		ttl = 300
	}

	// Compose rdata from per-type fields
	var rdata string
	switch rtype {
	case "A", "AAAA":
		rdata = fields.IP
		if rdata == "" {
			renderFormError("IP address is required")
			return
		}
	case "CNAME", "NS", "PTR":
		rdata = fields.Target
		if rdata == "" {
			renderFormError("Target is required")
			return
		}
	case "MX":
		prio := fields.MXPrio
		if prio == "" {
			prio = "10"
		}
		if fields.Target == "" {
			renderFormError("Mail server target is required")
			return
		}
		rdata = prio + " " + fields.Target
	case "TXT":
		txt := fields.TXT
		if txt == "" {
			renderFormError("Text value is required")
			return
		}
		// Auto-quote if not already quoted
		if !strings.HasPrefix(txt, `"`) {
			txt = `"` + strings.ReplaceAll(txt, `"`, `\"`) + `"`
		}
		rdata = txt
	case "SRV":
		prio := fields.SRVPrio
		if prio == "" {
			prio = "10"
		}
		weight := fields.SRVWeight
		if weight == "" {
			weight = "20"
		}
		if fields.SRVPort == "" {
			renderFormError("SRV port is required")
			return
		}
		if fields.Target == "" {
			renderFormError("SRV target is required")
			return
		}
		rdata = prio + " " + weight + " " + fields.SRVPort + " " + fields.Target
	case "CAA":
		flag := fields.CAAFlag
		if flag == "" {
			flag = "0"
		}
		tag := strings.TrimSpace(c.PostForm("f_caa_tag"))
		if tag == "" {
			tag = "issue"
		}
		if fields.CAAValue == "" {
			renderFormError("CAA value is required")
			return
		}
		rdata = flag + " " + tag + " " + fields.CAAValue
	case "SOA", "NAPTR":
		rdata = fields.Raw
		if rdata == "" {
			renderFormError("rdata is required")
			return
		}
	default:
		rdata = fields.Raw
		if rdata == "" {
			rdata = "."
		}
	}

	// Normalize name:
	//   @          → zone apex (e.g. "kejora.net.id")
	//   bare label → relative, prepend zone (e.g. "www" → "www.kejora.net.id")
	//   explicit FQDN with/without trailing dot → strip trailing dot
	zoneFQDN := zone.Name
	if !strings.HasSuffix(zoneFQDN, ".") {
		zoneFQDN += "."
	}
	switch {
	case name == "@":
		name = strings.TrimSuffix(zoneFQDN, ".")
	case strings.HasSuffix(name, "."):
		name = strings.TrimSuffix(name, ".")
	case !strings.Contains(name, "."):
		name = name + "." + strings.TrimSuffix(zoneFQDN, ".")
	}

	r := &store.Record{
		ZoneID: zone.ID,
		Name:   name,
		RType:  rtype,
		RData:  rdata,
		TTL:    ttl,
	}
	if _, err := s.db.CreateRecord(c.Request.Context(), r); err != nil {
		s.logger.Error("create record failed", "zone", zone.Name, "name", name, "err", err)
		renderFormError("Failed to create record: " + friendlyRecordDBError(err))
		return
	}

	s.logger.Info("record created", "zone", zone.Name, "name", name, "rtype", rtype, "user", currentUser(c).Username)
	if s.onZoneChanged != nil {
		go s.onZoneChanged()
	}
	if s.dnsSignal != nil {
		go func() {
			if err := s.dnsSignal(); err != nil {
				s.logger.Warn("failed to signal dns after record create", "err", err)
			}
		}()
	}
	c.Redirect(http.StatusFound, fmt.Sprintf("/zones/%d/records", zone.ID))
}

// handleRecordDelete deletes a single record from a zone.
func (s *Server) handleRecordDelete(c *gin.Context) {
	zone, ok := s.loadZone(c)
	if !ok {
		return
	}
	rid, err := strconv.ParseInt(c.Param("rid"), 10, 64)
	if err != nil || rid <= 0 {
		s.renderError(c, http.StatusBadRequest, "Invalid record ID", nil)
		return
	}
	if err := s.db.DeleteRecord(c.Request.Context(), zone.ID, rid); err != nil {
		s.logger.Error("delete record failed", "zone", zone.Name, "rid", rid, "err", err)
		s.renderError(c, http.StatusInternalServerError, "Failed to delete record", err)
		return
	}
	s.logger.Info("record deleted", "zone", zone.Name, "rid", rid, "user", currentUser(c).Username)
	if s.onZoneChanged != nil {
		go s.onZoneChanged()
	}
	if s.dnsSignal != nil {
		go func() {
			if err := s.dnsSignal(); err != nil {
				s.logger.Warn("failed to signal dns after record delete", "err", err)
			}
		}()
	}

	// Preserve current page & search query when redirecting back.
	redirectURL := fmt.Sprintf("/zones/%d/records", zone.ID)
	if q := c.Query("q"); q != "" {
		redirectURL += "?q=" + q
	} else if page := c.Query("page"); page != "" {
		redirectURL += "?page=" + page
	}
	c.Redirect(http.StatusFound, redirectURL)
}

// --- Helpers ---

// loadZone fetches a zone by the :id URL parameter.
// On error, renders an appropriate response and returns false.
func (s *Server) loadZone(c *gin.Context) (*store.Zone, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.renderError(c, http.StatusBadRequest, "Invalid zone ID", nil)
		return nil, false
	}
	zone, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load zone", err)
		return nil, false
	}
	if zone == nil {
		s.renderError(c, http.StatusNotFound, "Zone not found", nil)
		return nil, false
	}
	return zone, true
}

// parseZoneForm reads and validates a zone from the POST form.
func parseZoneForm(c *gin.Context) (*store.Zone, string) {
	z := &store.Zone{
		Name:              strings.TrimSpace(c.PostForm("name")),
		ZoneType:          c.PostForm("zone_type"),
		Mode:              c.PostForm("mode"),
		MasterIP:          strings.TrimSpace(c.PostForm("master_ip")),
		MasterIPSecondary: strings.TrimSpace(c.PostForm("master_ip_secondary")),
		TSIGKey:           strings.TrimSpace(c.PostForm("tsig_key")),
		TSIGSecret:        strings.TrimSpace(c.PostForm("tsig_secret")),
	}

	if z.ZoneType != "domain" && z.ZoneType != "rpz" && z.ZoneType != "reverse_ptr" {
		z.ZoneType = "rpz"
	}

	port := parseIntParam(c.PostForm("master_port"), 53)
	if port < 1 || port > 65535 {
		return z, "Master port must be between 1 and 65535."
	}
	z.MasterPort = int16(port)

	interval := parseIntParam(c.PostForm("sync_interval"), 86400)
	if interval < 60 {
		return z, "Sync interval must be at least 60 seconds."
	}
	z.SyncInterval = interval
	z.Enabled = c.PostForm("enabled") == "on" || c.PostForm("enabled") == "true"

	if z.Name == "" {
		return z, "Zone name is required."
	}
	if z.Mode != "master" && z.Mode != "slave" {
		return z, "Mode must be 'master' or 'slave'."
	}
	if z.Mode == "slave" && z.MasterIP == "" {
		return z, "Master IP is required for slave mode."
	}
	return z, ""
}

// parseIntParam parses an integer string, returning def on error.
func parseIntParam(s string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return v
}

// friendlyDBError returns a user-friendly message for common DB errors.
func friendlyDBError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") {
		return "A zone with this name already exists."
	}
	return "Database error. Please try again."
}

// friendlyRecordDBError returns a user-friendly message for record DB errors.
func friendlyRecordDBError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") {
		return "A record with this name already exists in this zone."
	}
	return "Database error. Please try again."
}
