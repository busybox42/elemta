package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/auth"
	"golang.org/x/time/rate"
)

// AuthContext represents authentication context
type AuthContext struct {
	Username    string
	IsAPIKey    bool
	Permissions []auth.Permission
}

// contextKey is used for context keys to avoid collisions
type contextKey string

const (
	authContextKey contextKey = "auth_context"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	rbac           *auth.RBAC
	apiKeyManager  *auth.APIKeyManager
	sessionManager *auth.SessionManager
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(rbac *auth.RBAC, apiKeyManager *auth.APIKeyManager, sessionManager *auth.SessionManager) *AuthMiddleware {
	return &AuthMiddleware{
		rbac:           rbac,
		apiKeyManager:  apiKeyManager,
		sessionManager: sessionManager,
	}
}

// RequireAuth middleware that requires authentication
func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, err := am.authenticate(r)
		if err != nil {
			// Check if this is a browser request (accepts HTML) vs API request (accepts JSON)
			acceptHeader := r.Header.Get("Accept")
			isBrowserRequest := strings.Contains(acceptHeader, "text/html") ||
				strings.Contains(acceptHeader, "*/*") ||
				r.Header.Get("X-Requested-With") == ""

			if isBrowserRequest && r.Method == http.MethodGet {
				// Redirect browser requests to login page
				http.Redirect(w, r, "/login", http.StatusFound)
			} else {
				// Return 401 JSON for API requests
				am.writeError(w, http.StatusUnauthorized, "Authentication required", err.Error())
			}
			return
		}

		// Add auth context to request
		ctx := context.WithValue(r.Context(), authContextKey, authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission middleware that requires a specific permission
func (am *AuthMiddleware) RequirePermission(permission auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, err := am.authenticate(r)
			if err != nil {
				am.writeError(w, http.StatusUnauthorized, "Authentication required", err.Error())
				return
			}

			// Check if user has the required permission
			hasPermission := false
			for _, perm := range authCtx.Permissions {
				if perm == permission {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				am.writeError(w, http.StatusForbidden, "Insufficient permissions",
					"Required permission: "+string(permission))
				return
			}

			// Add auth context to request
			ctx := context.WithValue(r.Context(), authContextKey, authCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin middleware that requires admin privileges
func (am *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	return am.RequirePermission(auth.PermissionSystemAdmin)(next)
}

// OptionalAuth middleware that provides optional authentication
func (am *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, _ := am.authenticate(r) // Ignore errors for optional auth

		// Add auth context to request (may be nil)
		ctx := context.WithValue(r.Context(), authContextKey, authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate performs authentication using API key, HTTP Basic Auth, or session
func (am *AuthMiddleware) authenticate(r *http.Request) (*AuthContext, error) {
	// Try API key authentication first
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if apiKey, err := auth.ExtractKeyFromHeader(authHeader); err == nil {
			return am.authenticateAPIKey(apiKey)
		}

		// Try HTTP Basic Authentication
		if username, password, ok := r.BasicAuth(); ok {
			return am.authenticateBasicAuth(username, password)
		}
	}

	// Try session authentication
	if am.sessionManager != nil {
		if sessionID := am.sessionManager.GetSessionFromRequest(r); sessionID != "" {
			return am.authenticateSession(sessionID)
		}
	}

	return nil, auth.ErrInvalidCredentials
}

// authenticateAPIKey authenticates using API key
func (am *AuthMiddleware) authenticateAPIKey(keyString string) (*AuthContext, error) {
	if am.apiKeyManager == nil {
		return nil, auth.ErrInvalidAPIKey
	}

	apiKey, err := am.apiKeyManager.ValidateAPIKey(keyString)
	if err != nil {
		return nil, err
	}

	return &AuthContext{
		Username:    apiKey.Username,
		IsAPIKey:    true,
		Permissions: apiKey.Permissions,
	}, nil
}

// authenticateBasicAuth authenticates using HTTP Basic Auth
func (am *AuthMiddleware) authenticateBasicAuth(username, password string) (*AuthContext, error) {
	if am.rbac == nil {
		return nil, auth.ErrInvalidCredentials
	}

	// Authenticate user with the auth system
	ctx := context.Background()
	authenticated, err := am.rbac.Authenticate(ctx, username, password)
	if err != nil || !authenticated {
		return nil, auth.ErrInvalidCredentials
	}

	// Get user permissions from RBAC
	permissions, _ := am.rbac.GetUserPermissions(ctx, username)

	return &AuthContext{
		Username:    username,
		IsAPIKey:    false,
		Permissions: permissions,
	}, nil
}

// authenticateSession authenticates using session
func (am *AuthMiddleware) authenticateSession(sessionID string) (*AuthContext, error) {
	if am.sessionManager == nil {
		return nil, auth.ErrInvalidSession
	}

	session, err := am.sessionManager.ValidateSession(sessionID)
	if err != nil {
		return nil, err
	}

	// Get user permissions from RBAC
	var permissions []auth.Permission
	if am.rbac != nil {
		ctx := context.Background()
		permissions, _ = am.rbac.GetUserPermissions(ctx, session.Username)
	}

	return &AuthContext{
		Username:    session.Username,
		IsAPIKey:    false,
		Permissions: permissions,
	}, nil
}

// GetAuthContext extracts authentication context from request
func GetAuthContext(r *http.Request) *AuthContext {
	if authCtx, ok := r.Context().Value(authContextKey).(*AuthContext); ok {
		return authCtx
	}
	return nil
}

// writeError writes an error response
func (am *AuthMiddleware) writeError(w http.ResponseWriter, statusCode int, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":   message,
		"details": details,
		"status":  statusCode,
	}

	// Only try to encode if we haven't already written the body
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// If JSON encoding fails, we can't recover since headers are already sent
		// Log the error instead of trying to write again
		fmt.Printf("Error encoding JSON response: %v\n", err)
	}
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	Enabled          bool     `toml:"enabled" json:"enabled"`
	AllowedOrigins   []string `toml:"allowed_origins" json:"allowed_origins"`
	AllowedMethods   []string `toml:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders   []string `toml:"allowed_headers" json:"allowed_headers"`
	AllowCredentials bool     `toml:"allow_credentials" json:"allow_credentials"`
	MaxAge           int      `toml:"max_age" json:"max_age"`
}

// CORSMiddleware provides configurable CORS support
type CORSMiddleware struct {
	config CORSConfig
}

// NewCORSMiddleware creates a new CORS middleware
func NewCORSMiddleware(config CORSConfig) *CORSMiddleware {
	// Set defaults if not specified
	if len(config.AllowedMethods) == 0 {
		config.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(config.AllowedHeaders) == 0 {
		config.AllowedHeaders = []string{"Content-Type", "Authorization"}
	}
	if config.MaxAge == 0 {
		config.MaxAge = 86400 // 24 hours
	}

	return &CORSMiddleware{config: config}
}

// Handler returns the CORS middleware handler
func (cm *CORSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cm.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")

		// Validate origin against whitelist
		allowed := false
		allowedOrigin := ""
		for _, allowedOrg := range cm.config.AllowedOrigins {
			if allowedOrg == "*" || allowedOrg == origin {
				allowed = true
				allowedOrigin = origin
				if allowedOrg == "*" {
					allowedOrigin = "*"
				}
				break
			}
		}

		if !allowed && origin != "" {
			// Origin not allowed, reject preflight requests
			if r.Method == "OPTIONS" {
				http.Error(w, "Origin not allowed", http.StatusForbidden)
				return
			}
			// For non-preflight requests, continue without CORS headers
			next.ServeHTTP(w, r)
			return
		}

		// Set CORS headers only for allowed origins
		if allowed && allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)

			if cm.config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			w.Header().Set("Access-Control-Allow-Methods", strings.Join(cm.config.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(cm.config.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cm.config.MaxAge))
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CORS middleware for handling Cross-Origin Resource Sharing (deprecated, use NewCORSMiddleware)
func (am *AuthMiddleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware provides basic rate limiting (simplified implementation)
// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool     `toml:"enabled" json:"enabled"`
	RequestsPerSecond float64  `toml:"requests_per_second" json:"requests_per_second"`
	Burst             int      `toml:"burst" json:"burst"`
	TrustedProxies    []string `toml:"trusted_proxies" json:"trusted_proxies"`
}

// RateLimitMiddleware provides per-IP rate limiting
type RateLimitMiddleware struct {
	limiters        map[string]*rate.Limiter
	mu              sync.RWMutex
	rate            rate.Limit
	burst           int
	cleanupInterval time.Duration
	enabled         bool
	stopCleanup     chan struct{}
	trustedProxies  []*net.IPNet
}

// NewRateLimitMiddleware creates a new rate limit middleware
func NewRateLimitMiddleware(config RateLimitConfig) *RateLimitMiddleware {
	if !config.Enabled {
		return &RateLimitMiddleware{enabled: false}
	}

	requestsPerSecond := config.RequestsPerSecond
	if requestsPerSecond <= 0 {
		requestsPerSecond = 10.0
	}

	burst := config.Burst
	if burst <= 0 {
		burst = 20
	}

	// Parse trusted proxy CIDRs
	var trustedProxies []*net.IPNet
	for _, proxy := range config.TrustedProxies {
		if strings.Contains(proxy, "/") {
			_, cidr, err := net.ParseCIDR(proxy)
			if err == nil {
				trustedProxies = append(trustedProxies, cidr)
			}
		} else {
			ip := net.ParseIP(proxy)
			if ip != nil {
				mask := net.CIDRMask(128, 128)
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				}
				trustedProxies = append(trustedProxies, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}

	rl := &RateLimitMiddleware{
		limiters:        make(map[string]*rate.Limiter),
		rate:            rate.Limit(requestsPerSecond),
		burst:           burst,
		cleanupInterval: 5 * time.Minute,
		enabled:         true,
		stopCleanup:     make(chan struct{}),
		trustedProxies:  trustedProxies,
	}

	go rl.cleanupLoop()
	return rl
}

// Stop stops the rate limiter cleanup goroutine
func (rl *RateLimitMiddleware) Stop() {
	if rl.enabled && rl.stopCleanup != nil {
		close(rl.stopCleanup)
	}
}

// cleanupLoop periodically removes idle limiters to prevent memory leaks
func (rl *RateLimitMiddleware) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			// Remove limiters that haven't been used recently
			// This is a simple implementation; production might track last access time
			if len(rl.limiters) > 1000 {
				rl.limiters = make(map[string]*rate.Limiter)
			}
			rl.mu.Unlock()
		case <-rl.stopCleanup:
			return
		}
	}
}

// getLimiter returns the rate limiter for a given IP
func (rl *RateLimitMiddleware) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	limiter, exists = rl.limiters[ip]
	if exists {
		return limiter
	}

	limiter = rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters[ip] = limiter
	return limiter
}

// extractIP extracts the client IP from the request.
// It only trusts X-Forwarded-For and X-Real-IP headers when the direct
// connection comes from a trusted proxy. When trusted, it returns the
// rightmost untrusted IP from the X-Forwarded-For chain.
func extractIP(r *http.Request, trustedProxies []*net.IPNet) string {
	// Parse RemoteAddr to get the direct connection IP
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Only check forwarded headers if RemoteAddr is a trusted proxy
	if len(trustedProxies) > 0 && isTrustedProxy(remoteIP, trustedProxies) {
		// Check X-Forwarded-For: use the rightmost untrusted IP
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			// Walk from the right to find the first IP not in trusted proxies
			for i := len(ips) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(ips[i])
				if candidate != "" && !isTrustedProxy(candidate, trustedProxies) {
					return candidate
				}
			}
		}

		// Check X-Real-IP as fallback
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
	}

	return remoteIP
}

// isTrustedProxy checks if an IP is within any of the trusted proxy CIDRs
func isTrustedProxy(ipStr string, trustedProxies []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Limit applies rate limiting
func (rl *RateLimitMiddleware) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r, rl.trustedProxies)
		limiter := rl.getLimiter(ip)

		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Log request
		// In a production system, you'd use a proper logger
		// log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)

		next.ServeHTTP(wrapper, r)

		// Log response
		// log.Printf("%s %s %s - %d", r.Method, r.URL.Path, r.RemoteAddr, wrapper.statusCode)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
