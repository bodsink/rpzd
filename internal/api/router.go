package api

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"

	"github.com/bodsink/dns-rpz/internal/store"
	"github.com/bodsink/dns-rpz/internal/syncer"
)

// fmtNumPositive formats a non-negative int64 with dot thousands separators.
// e.g. 5123456 → "5.123.456"
func fmtNumPositive(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	result := make([]byte, 0, len(s)+(len(s)-1)/3)
	mod := len(s) % 3
	if mod == 0 {
		mod = 3
	}
	result = append(result, s[:mod]...)
	for i := mod; i < len(s); i += 3 {
		result = append(result, '.')
		result = append(result, s[i:i+3]...)
	}
	return string(result)
}

// Server holds all dependencies for the HTTP API server.
type Server struct {
	db         *store.DB
	syncer     *syncer.ZoneSyncer
	logger     *slog.Logger
	router     *gin.Engine
	dnsSignal  func() error // send SIGHUP to dns-rpz-dns — reloads upstream pool from DB
	selfReload func() error // send SIGHUP to self — reloads sync interval into scheduler
	restartWeb func() error // restart dns-rpz-http service — applies new web port
	dnsAddr    string       // DNS listen address for health-check (e.g. "0.0.0.0:53")
	sysCache   sysStatsCache
}

// NewServer creates and configures the HTTP server with all routes and middleware.
func NewServer(db *store.DB, zoneSyncer *syncer.ZoneSyncer, logger *slog.Logger, templatesDir, staticDir string) *Server {
	gin.SetMode(gin.ReleaseMode)

	s := &Server{
		db:     db,
		syncer: zoneSyncer,
		logger: logger,
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	r.Use(s.middlewareSecurityHeaders())
	r.Use(s.middlewareLogger())

	// Build per-page template renderer: parses base.html + page template together
	// so each page has its own isolated {{define "content"}} — fixes LoadHTMLGlob
	// limitation where all pages share one template set and "content" gets overwritten.
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"slice": func(s string, i, j int) string {
			if i >= len(s) {
				return ""
			}
			if j > len(s) {
				j = len(s)
			}
			return s[i:j]
		},
		"sub": func(a, b int) int { return a - b },
		"add": func(a, b int) int { return a + b },
		"mul": func(a, b int) int { return a * b },
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},
		"int": func(v int64) int { return int(v) },
		// pct returns what percentage `part` is of `total`, as float64.
		// Returns 0 if total is 0.
		"pct": func(part, total int64) float64 {
			if total == 0 {
				return 0
			}
			return float64(part) / float64(total) * 100
		},
		// fmtNum formats an integer with dot thousands separators (e.g. 5123456 → "5.123.456")
		"fmtNum": func(v interface{}) string {
			var n int64
			switch val := v.(type) {
			case int:
				n = int64(val)
			case int64:
				n = val
			default:
				return fmt.Sprintf("%v", v)
			}
			if n < 0 {
				return "-" + fmtNumPositive(-n)
			}
			return fmtNumPositive(n)
		},
		// fmtTime formats a time value (time.Time, *time.Time, or interface{}) as
		// "2006-01-02 15:04:05". Returns "—" for nil/zero values.
		"fmtTime": func(v interface{}) string {
			if v == nil {
				return "\u2014"
			}
			type formatter interface {
				Format(string) string
			}
			switch t := v.(type) {
			case formatter:
				if t == nil {
					return "\u2014"
				}
				return t.Format("2006-01-02 15:04:05")
			default:
				return fmt.Sprintf("%v", v)
			}
		},
		// upstreamsDisplay converts stored "8.8.8.8:53,1.1.1.1:53" to newline-separated IPs
		// stripping the default port 53, for display in the upstream textarea.
		"upstreamsDisplay": func(s string) string {
			parts := strings.Split(s, ",")
			var lines []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				// Strip trailing :53 (default port)
				ip := strings.TrimSuffix(p, ":53")
				lines = append(lines, ip)
			}
			return strings.Join(lines, "\n")
		},
	}
	r.HTMLRender = newRenderer(templatesDir, funcMap)

	// Static assets caching: app.css and app.js are no-cache (frequently updated),
	// library files get long-term cache (1 year, immutable).
	r.Use(func(c *gin.Context) {
		p := c.Request.URL.Path
		if p == "/static/app.css" || p == "/static/app.js" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		} else if strings.HasPrefix(p, "/static/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		}
		c.Next()
	})
	r.Static("/static", staticDir)

	// --- Public routes ---
	r.GET("/login", s.handleLoginPage)
	r.POST("/login", s.middlewareRateLimit(), s.handleLoginSubmit)
	r.POST("/logout", s.handleLogout)

	// --- Protected routes (require valid session) ---
	auth := r.Group("/")
	auth.Use(s.middlewareRequireSession())
	{
		auth.GET("/", s.handleDashboard)
		auth.GET("/api/system-stats", s.handleSystemStats)

		// Zones
		auth.GET("/zones", s.handleZoneList)
		auth.GET("/zones/new", s.middlewareRequireAdmin(), s.handleZoneNew)
		auth.POST("/zones", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneCreate)
		auth.GET("/zones/:id", s.handleZoneDetail)
		auth.GET("/zones/:id/edit", s.middlewareRequireAdmin(), s.handleZoneEdit)
		auth.POST("/zones/:id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneUpdate)
		auth.POST("/zones/:id/delete", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneDelete)
		auth.POST("/zones/:id/toggle", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneToggle)
		auth.POST("/zones/:id/sync", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleZoneTriggerSync)
		auth.GET("/zones/:id/records", s.handleRecordList)
		auth.GET("/zones/:id/history", s.handleZoneSyncHistory)

		// Settings
		auth.GET("/settings", s.middlewareRequireAdmin(), s.handleSettingsPage)
		auth.POST("/settings/sync", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsSaveSync)
		auth.POST("/settings/dns", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsSaveDNS)
		auth.POST("/settings/web", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsSaveWeb)
		auth.POST("/settings/system", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsSaveSystem)
		auth.POST("/settings/logging", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsSaveLogging)
		auth.POST("/settings/logging/clear", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleSettingsClearLog)

		// IP Filters (ACL)
		auth.GET("/ip-filters", s.middlewareRequireAdmin(), s.handleIPFilterList)
		auth.POST("/ip-filters", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleIPFilterCreate)
		auth.POST("/ip-filters/:id/delete", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleIPFilterDelete)
		auth.POST("/ip-filters/:id/toggle", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleIPFilterToggle)

		// Users
		auth.GET("/users", s.middlewareRequireAdmin(), s.handleUserList)
		auth.GET("/users/new", s.middlewareRequireAdmin(), s.handleUserNew)
		auth.POST("/users", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserCreate)
		auth.GET("/users/:id/edit", s.middlewareRequireAdmin(), s.handleUserEdit)
		auth.POST("/users/:id", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserUpdate)
		auth.POST("/users/:id/delete", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserDelete)
		auth.POST("/users/:id/toggle", s.middlewareRequireAdmin(), s.middlewareCSRF(), s.handleUserToggle)

		// Sync history (global)
		auth.GET("/sync-history", s.handleSyncHistoryList)

		// Statistics
		auth.GET("/statistics", s.handleStatisticsPage)

		// Profile (change password — available to all authenticated users)
		auth.GET("/profile", s.handleProfilePage)
		auth.POST("/profile", s.middlewareCSRF(), s.handleProfileSave)
	}

	s.router = r
	return s
}

// SetDNSSignal sets a callback invoked after DNS upstream settings are saved.
// Typically used to send SIGHUP to the DNS process so it reloads from DB.
func (s *Server) SetDNSSignal(fn func() error) { s.dnsSignal = fn }

// SetSelfReload sets a callback invoked after sync settings are saved.
// Typically sends SIGHUP to self so the scheduler reloads the new interval from DB.
func (s *Server) SetSelfReload(fn func() error) { s.selfReload = fn }

// SetRestartWeb sets a callback invoked after web port is saved.
// Typically runs "systemctl restart dns-rpz-http" to apply the new port.
func (s *Server) SetRestartWeb(fn func() error) { s.restartWeb = fn }

// SetDNSAddress sets the DNS service listen address used for health checks on the dashboard.
func (s *Server) SetDNSAddress(addr string) { s.dnsAddr = addr }

// Start runs the HTTPS server on the given address using the provided TLS cert/key.
// Blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Start(ctx context.Context, addr string, tls *TLSConfig) error {
	go s.runSysStatsWorker(ctx)

	srv := &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("dashboard listening (HTTPS)", "addr", addr)
		if err := srv.ListenAndServeTLS(tls.CertFile, tls.KeyFile); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return srv.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}
