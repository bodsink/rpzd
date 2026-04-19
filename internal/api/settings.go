package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// handleSettingsPage renders the application settings form.
func (s *Server) handleSettingsPage(c *gin.Context) {
	settings, err := s.db.LoadAppSettings(c.Request.Context())
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load settings", err)
		return
	}
	tab := c.Query("tab")
	if tab != "general" && tab != "dns" {
		tab = "dns"
	}
	c.HTML(http.StatusOK, "settings.html", gin.H{
		"User":          currentUser(c),
		"CSRFToken":     csrfToken(c),
		"ActivePage":    "settings",
		"ActiveSubPage": tab,
		"Tab":           tab,
		"Settings":      settings,
		"Saved":         c.Query("saved"),
	})
}

// handleSettingsSaveSync saves Sync-related settings (mode, master, TSIG, interval).
func (s *Server) handleSettingsSaveSync(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":          currentUser(c),
			"CSRFToken":     csrfToken(c),
			"ActivePage":    "settings",
			"ActiveSubPage": "dns",
			"Tab":           "dns",
			"Settings":      settings,
			"ErrorSync":     msg,
		})
	}

	mode := c.PostForm("mode")
	if mode != "master" && mode != "slave" {
		renderErr("Mode must be 'master' or 'slave'.")
		return
	}

	masterPort := strings.TrimSpace(c.PostForm("master_port"))
	if p, err := strconv.Atoi(masterPort); err != nil || p < 1 || p > 65535 {
		renderErr("Master port must be a number between 1 and 65535.")
		return
	}

	syncInterval := strings.TrimSpace(c.PostForm("sync_interval"))
	if si, err := strconv.Atoi(syncInterval); err != nil || si < 60 {
		renderErr("Sync interval must be at least 60 seconds.")
		return
	}

	kvs := map[string]string{
		"mode":          mode,
		"master_ip":     strings.TrimSpace(c.PostForm("master_ip")),
		"master_port":   masterPort,
		"tsig_key":      strings.TrimSpace(c.PostForm("tsig_key")),
		"tsig_secret":   strings.TrimSpace(c.PostForm("tsig_secret")),
		"sync_interval": syncInterval,
	}
	if err := saveSettingsMap(ctx, s, kvs); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	// Signal self to reload sync interval into the scheduler without restart.
	if s.selfReload != nil {
		if err := s.selfReload(); err != nil {
			s.logger.Warn("failed to trigger sync settings reload", "err", err)
		}
	}

	s.logger.Info("sync settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?tab=dns&saved=sync")
}

// handleSettingsSaveDNS saves DNS Upstream settings and signals the DNS process to reload.
func (s *Server) handleSettingsSaveDNS(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":          currentUser(c),
			"CSRFToken":     csrfToken(c),
			"ActivePage":    "settings",
			"ActiveSubPage": "dns",
			"Tab":           "dns",
			"Settings":      settings,
			"ErrorDNS":      msg,
		})
	}

	upstreams := strings.TrimSpace(c.PostForm("dns_upstream"))
	if upstreams == "" {
		renderErr("At least one upstream DNS server is required.")
		return
	}
	// Normalize: accept newline-separated IPs with optional port.
	// Port defaults to 53 if not specified. Store as comma-separated ip:port.
	var normalized []string
	for _, srv := range strings.FieldsFunc(upstreams, func(r rune) bool { return r == '\n' || r == '\r' }) {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !strings.Contains(srv, ":") {
			srv = srv + ":53"
		}
		normalized = append(normalized, srv)
	}
	if len(normalized) == 0 {
		renderErr("At least one valid upstream DNS server is required.")
		return
	}
	upstreams = strings.Join(normalized, ",")

	strategy := c.PostForm("dns_upstream_strategy")
	switch strategy {
	case "roundrobin", "random", "race":
	default:
		renderErr("Strategy must be one of: roundrobin, random, race.")
		return
	}

	rpzDefaultAction := c.PostForm("rpz_default_action")
	if rpzDefaultAction != "nxdomain" && rpzDefaultAction != "nodata" {
		renderErr("RPZ default action must be 'nxdomain' or 'nodata'.")
		return
	}

	dnsCacheSizeStr := strings.TrimSpace(c.PostForm("dns_cache_size"))
	if n, err := strconv.Atoi(dnsCacheSizeStr); err != nil || n < 0 {
		renderErr("DNS cache size must be a non-negative integer.")
		return
	}

	auditLog := "false"
	if c.PostForm("dns_audit_log") == "true" {
		auditLog = "true"
	}

	rrlRateStr := strings.TrimSpace(c.PostForm("rrl_rate"))
	if n, err := strconv.Atoi(rrlRateStr); err != nil || n < 0 {
		renderErr("RRL rate must be a non-negative integer.")
		return
	}

	rrlBurstStr := strings.TrimSpace(c.PostForm("rrl_burst"))
	if n, err := strconv.Atoi(rrlBurstStr); err != nil || n < 0 {
		renderErr("RRL burst must be a non-negative integer.")
		return
	}

	kvs := map[string]string{
		"dns_upstream":          upstreams,
		"dns_upstream_strategy": strategy,
		"rpz_default_action":    rpzDefaultAction,
		"dns_cache_size":        dnsCacheSizeStr,
		"dns_audit_log":         auditLog,
		"rrl_rate":              rrlRateStr,
		"rrl_burst":             rrlBurstStr,
	}
	if err := saveSettingsMap(ctx, s, kvs); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	// Signal the DNS process to reload its upstream pool from the DB.
	if s.dnsSignal != nil {
		if err := s.dnsSignal(); err != nil {
			s.logger.Warn("failed to signal dns process for upstream reload", "err", err)
		} else {
			s.logger.Info("dns process signaled for upstream reload")
		}
	}

	s.logger.Info("dns upstream settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?tab=dns&saved=dns")
}

// handleSettingsSaveWeb saves Web Server settings (port).
func (s *Server) handleSettingsSaveWeb(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":          currentUser(c),
			"CSRFToken":     csrfToken(c),
			"ActivePage":    "settings",
			"ActiveSubPage": "general",
			"Tab":           "general",
			"Settings":      settings,
			"ErrorWeb":      msg,
		})
	}

	webPort := strings.TrimSpace(c.PostForm("web_port"))
	if p, err := strconv.Atoi(webPort); err != nil || p < 1 || p > 65535 {
		renderErr("Web port must be a number between 1 and 65535.")
		return
	}

	if err := s.db.SetSetting(ctx, "web_port", webPort); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	s.logger.Info("web server settings updated", "user", currentUser(c).Username, "port", webPort)

	// Restart the web service in background so the redirect response is sent first.
	if s.restartWeb != nil {
		go func() {
			time.Sleep(800 * time.Millisecond)
			if err := s.restartWeb(); err != nil {
				s.logger.Warn("failed to restart web service", "err", err)
			}
		}()
	}

	c.Redirect(http.StatusFound, "/settings?tab=general&saved=web")
}

// handleSettingsSaveSystem saves System settings (timezone).
func (s *Server) handleSettingsSaveSystem(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":          currentUser(c),
			"CSRFToken":     csrfToken(c),
			"ActivePage":    "settings",
			"ActiveSubPage": "general",
			"Tab":           "general",
			"Settings":      settings,
			"ErrorSystem":   msg,
		})
	}

	timezone := strings.TrimSpace(c.PostForm("timezone"))
	if _, err := time.LoadLocation(timezone); err != nil {
		renderErr(fmt.Sprintf("Invalid timezone %q. Use IANA format, e.g. Asia/Jakarta, UTC, America/New_York.", timezone))
		return
	}

	if err := s.db.SetSetting(ctx, "timezone", timezone); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	if err := ApplyTimezone(timezone); err != nil {
		s.logger.Warn("timezone apply failed (requires root/sudo)", "timezone", timezone, "err", err)
	}

	s.logger.Info("system settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?tab=general&saved=system")
}

// saveSettingsMap persists a key-value map to the settings store.
func saveSettingsMap(ctx context.Context, s *Server, kvs map[string]string) error {
	for k, v := range kvs {
		if err := s.db.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

// ApplyTimezone sets the system timezone via timedatectl.
// Requires the process to have sufficient privileges (root or CAP_SYS_TIME).
func ApplyTimezone(tz string) error {
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	out, err := exec.Command("timedatectl", "set-timezone", tz).CombinedOutput()
	if err != nil {
		return fmt.Errorf("timedatectl set-timezone %s: %s: %w", tz, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// handleSettingsSaveLogging saves Logging settings to DB, writes logrotate config if enabled,
// then signals both DNS and dashboard processes to reload.
func (s *Server) handleSettingsSaveLogging(c *gin.Context) {
	ctx := c.Request.Context()

	renderErr := func(msg string) {
		settings, _ := s.db.LoadAppSettings(ctx)
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":          currentUser(c),
			"CSRFToken":     csrfToken(c),
			"ActivePage":    "settings",
			"ActiveSubPage": "general",
			"Tab":           "general",
			"Settings":      settings,
			"ErrorLogging":  msg,
		})
	}

	logLevel := c.PostForm("log_level")
	switch logLevel {
	case "debug", "info", "warn", "error":
	default:
		renderErr("Log level must be one of: debug, info, warn, error.")
		return
	}

	logFormat := c.PostForm("log_format")
	if logFormat != "text" && logFormat != "json" {
		renderErr("Log format must be text or json.")
		return
	}

	logFile := "false"
	if c.PostForm("log_file") == "true" {
		logFile = "true"
	}

	logFilePath := strings.TrimSpace(c.PostForm("log_file_path"))
	if logFilePath == "" {
		logFilePath = "/var/log/rpzd/rpzd.log"
	}

	logRotate := "false"
	if c.PostForm("log_rotate") == "true" {
		logRotate = "true"
	}

	logRotateSize := strings.TrimSpace(c.PostForm("log_rotate_size"))
	if logRotateSize == "" {
		logRotateSize = "100M"
	}

	logRotateKeep := strings.TrimSpace(c.PostForm("log_rotate_keep"))
	if k, err := strconv.Atoi(logRotateKeep); err != nil || k < 1 {
		renderErr("Log rotate keep must be a positive integer.")
		return
	}

	kvs := map[string]string{
		"log_level":       logLevel,
		"log_format":      logFormat,
		"log_file":        logFile,
		"log_file_path":   logFilePath,
		"log_rotate":      logRotate,
		"log_rotate_size": logRotateSize,
		"log_rotate_keep": logRotateKeep,
	}
	if err := saveSettingsMap(ctx, s, kvs); err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to save settings", err)
		return
	}

	// Write or remove /etc/logrotate.d/rpzd
	if logRotate == "true" && logFile == "true" {
		if err := writeLogrotateConfig(logFilePath, logRotateSize, logRotateKeep); err != nil {
			s.logger.Warn("failed to write logrotate config (requires root)", "err", err)
		} else {
			s.logger.Info("logrotate config written", "path", "/etc/logrotate.d/rpzd")
		}
	} else {
		if err := os.Remove("/etc/logrotate.d/rpzd"); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("failed to remove logrotate config", "err", err)
		}
	}

	// Ensure log directory exists if log_file is enabled
	if logFile == "true" {
		dir := filepath.Dir(logFilePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			s.logger.Warn("failed to create log directory", "dir", dir, "err", err)
		}
	}

	// Signal DNS process and self to reload log settings
	if s.dnsSignal != nil {
		if err := s.dnsSignal(); err != nil {
			s.logger.Warn("failed to signal dns process for logging reload", "err", err)
		}
	}
	if s.selfReload != nil {
		if err := s.selfReload(); err != nil {
			s.logger.Warn("failed to signal self for logging reload", "err", err)
		}
	}

	s.logger.Info("logging settings updated", "user", currentUser(c).Username)
	c.Redirect(http.StatusFound, "/settings?tab=general&saved=logging")
}

// handleSettingsClearLog truncates the active log file configured in DB settings.
func (s *Server) handleSettingsClearLog(c *gin.Context) {
	ctx := c.Request.Context()

	settings, err := s.db.LoadAppSettings(ctx)
	if err != nil {
		s.renderError(c, http.StatusInternalServerError, "Failed to load settings", err)
		return
	}

	if !settings.LogFile {
		c.HTML(http.StatusBadRequest, "settings.html", gin.H{
			"User":          currentUser(c),
			"CSRFToken":     csrfToken(c),
			"ActivePage":    "settings",
			"ActiveSubPage": "general",
			"Tab":           "general",
			"Settings":      settings,
			"ErrorLogging":  "Log file is not enabled. Enable log file output first.",
		})
		return
	}

	logFilePath := settings.LogFilePath
	if logFilePath == "" {
		logFilePath = "/var/log/rpzd/rpzd.log"
	}

	if err := os.Truncate(logFilePath, 0); err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet — nothing to clear
			c.Redirect(http.StatusFound, "/settings?tab=general&saved=log_cleared")
			return
		}
		s.renderError(c, http.StatusInternalServerError, "Failed to clear log file", err)
		return
	}

	s.logger.Info("log file cleared", "user", currentUser(c).Username, "path", logFilePath)
	c.Redirect(http.StatusFound, "/settings?tab=general&saved=log_cleared")
}

// writeLogrotateConfig writes a logrotate config file for rpzd to /etc/logrotate.d/rpzd.
func writeLogrotateConfig(logFilePath, size, keepStr string) error {
	keep := 7
	fmt.Sscanf(keepStr, "%d", &keep)
	content := fmt.Sprintf(`%s {
    daily
    size %s
    rotate %d
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root adm
}
`, logFilePath, size, keep)
	return os.WriteFile("/etc/logrotate.d/rpzd", []byte(content), 0644)
}
