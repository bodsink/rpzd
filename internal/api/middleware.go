package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/bodsink/rpzd/internal/store"
	"golang.org/x/time/rate"
)

const (
	sessionCookieName = "rpz_session"
	csrfTokenName     = "csrf_token"
	sessionDuration   = 24 * time.Hour
)

// contextKey is the type for gin context keys set by middleware.
type contextKey string

const (
	ctxKeyUser      contextKey = "user"
	ctxKeyCSRFToken contextKey = "csrf_token"
)

// middlewareSecurityHeaders sets strict HTTP security headers on every response.
func (s *Server) middlewareSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Header("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
		c.Next()
	}
}

// middlewareLogger logs each request using slog at DEBUG level.
func (s *Server) middlewareLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		s.logger.Debug("http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency", time.Since(start).String(),
			"ip", c.ClientIP(),
		)
	}
}

// --- Rate limiter (per-IP, for login endpoint) ---

type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

var loginLimiter = &ipLimiter{limiters: make(map[string]*rate.Limiter)}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[ip]; ok {
		return lim
	}
	// 5 requests per minute, burst of 5
	lim := rate.NewLimiter(rate.Every(time.Minute/5), 5)
	l.limiters[ip] = lim
	return lim
}

// middlewareRateLimit limits login attempts: 5 per minute per IP.
func (s *Server) middlewareRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		if !loginLimiter.get(ip).Allow() {
			c.HTML(http.StatusTooManyRequests, "login.html", gin.H{
				"Error": "Too many login attempts. Please wait a moment.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// --- Session middleware ---

// middlewareRequireSession validates the session cookie.
// On success, sets the authenticated User into the gin context.
// On failure, redirects to /login.
func (s *Server) middlewareRequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie(sessionCookieName)
		if err != nil || sessionID == "" {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		session, err := s.db.GetSession(c.Request.Context(), sessionID)
		if err != nil || session == nil {
			// Clear invalid cookie
			clearSessionCookie(c)
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		user, err := s.db.GetUserByID(c.Request.Context(), session.UserID)
		if err != nil || user == nil || !user.Enabled {
			clearSessionCookie(c)
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Attach user and a fresh CSRF token to context
		c.Set(string(ctxKeyUser), user)
		csrfToken := generateCSRFToken(sessionID)
		c.Set(string(ctxKeyCSRFToken), csrfToken)
		c.Next()
	}
}

// middlewareRequireAdmin aborts with 403 if the logged-in user is not an admin.
func (s *Server) middlewareRequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := currentUser(c)
		if user == nil || user.Role != "admin" {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Title":   "403 Forbidden",
				"Message": "You do not have permission to access this page.",
				"User":    user,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// middlewareCSRF validates the CSRF token on state-mutating requests (POST).
func (s *Server) middlewareCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, _ := c.Cookie(sessionCookieName)
		expected := generateCSRFToken(sessionID)

		submitted := c.PostForm(csrfTokenName)
		if submitted == "" {
			submitted = c.GetHeader("X-CSRF-Token")
		}

		if submitted != expected {
			slog.Warn("CSRF token mismatch",
				"ip", c.ClientIP(),
				"path", c.Request.URL.Path,
			)
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Title":   "403 Forbidden",
				"Message": "Invalid or missing CSRF token. Please reload the page and try again.",
				"User":    currentUser(c),
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// --- Helpers ---

// generateSessionID creates a cryptographically secure random 32-byte session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- CSRF token (HMAC-SHA256 of session ID using process-scoped secret) ---

// csrfSecret is a random 32-byte key generated once at process startup.
// Used as the HMAC key for CSRF tokens — changes on every restart
// which automatically invalidates any open forms. This is intentional.
var csrfSecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
				panic("rpzd: failed to generate CSRF secret: " + err.Error())
	}
	return b
}()

// generateCSRFToken derives a CSRF token bound to a session ID using HMAC-SHA256.
// Tokens are per-process (invalidated on restart) and per-session.
func generateCSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, csrfSecret)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// setSessionCookie sets the session cookie with secure flags.
func setSessionCookie(c *gin.Context, sessionID string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   false, // set true when TLS is terminated at the app
	})
}

// clearSessionCookie removes the session cookie.
func clearSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// middlewareLocalhostOnly rejects requests that do not originate from 127.0.0.1 or ::1.
// Used to restrict internal endpoints (e.g. /internal/notify) to the local machine only.
func (s *Server) middlewareLocalhostOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}
		if host != "127.0.0.1" && host != "::1" {
			c.Status(http.StatusForbidden)
			c.Abort()
			return
		}
		c.Next()
	}
}

// currentUser retrieves the authenticated user from gin context.
// Returns nil if not authenticated.
func currentUser(c *gin.Context) *store.User {
	val, exists := c.Get(string(ctxKeyUser))
	if !exists {
		return nil
	}
	u, _ := val.(*store.User)
	return u
}

// csrfToken retrieves the CSRF token from gin context.
func csrfToken(c *gin.Context) string {
	val, _ := c.Get(string(ctxKeyCSRFToken))
	s, _ := val.(string)
	return s
}
