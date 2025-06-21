package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/busybox42/elemta/internal/auth"
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
			am.writeError(w, http.StatusUnauthorized, "Authentication required", err.Error())
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

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// If JSON encoding fails, fall back to plain text
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Error: %s", message)
	}
}

// CORS middleware for handling Cross-Origin Resource Sharing
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
type RateLimitMiddleware struct {
	// In a production system, you'd use a more sophisticated rate limiter
	// like golang.org/x/time/rate or a Redis-based solution
}

// NewRateLimitMiddleware creates a new rate limit middleware
func NewRateLimitMiddleware() *RateLimitMiddleware {
	return &RateLimitMiddleware{}
}

// Limit applies rate limiting (placeholder implementation)
func (rl *RateLimitMiddleware) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement actual rate limiting
		// For now, just pass through
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
