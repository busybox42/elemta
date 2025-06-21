package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/auth"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/gorilla/mux"
)

// Server represents an API server for Elemta
type Server struct {
	httpServer     *http.Server
	queueMgr       *queue.Manager
	listenAddr     string
	webRoot        string
	authSystem     *auth.Auth
	rbac           *auth.RBAC
	apiKeyManager  *auth.APIKeyManager
	sessionManager *auth.SessionManager
	authMiddleware *AuthMiddleware
}

// Config represents API server configuration
type Config struct {
	Enabled     bool   `toml:"enabled" json:"enabled"`
	ListenAddr  string `toml:"listen_addr" json:"listen_addr"`
	WebRoot     string `toml:"web_root" json:"web_root"`
	AuthEnabled bool   `toml:"auth_enabled" json:"auth_enabled"`
}

// NewServer creates a new API server
func NewServer(config *Config, queueDir string) (*Server, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("API server disabled in configuration")
	}

	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8025"
	}

	webRoot := config.WebRoot
	if webRoot == "" {
		webRoot = "./web/static"
	}

	queueMgr := queue.NewManager(queueDir)

	server := &Server{
		queueMgr:   queueMgr,
		listenAddr: listenAddr,
		webRoot:    webRoot,
	}

	// Initialize authentication if enabled
	if config.AuthEnabled {
		if err := server.initializeAuth(); err != nil {
			return nil, fmt.Errorf("failed to initialize authentication: %w", err)
		}
	}

	return server, nil
}

// initializeAuth initializes the authentication system
func (s *Server) initializeAuth() error {
	// Use production datasource from environment variables or default to file-based auth
	authSystem, err := auth.NewFromEnv()
	if err != nil {
		// Fallback to file-based authentication with users.txt
		log.Printf("Warning: Failed to initialize auth from environment (%v), falling back to file-based auth", err)
		authSystem, err = auth.NewWithFile("/app/config/users.txt")
		if err != nil {
			return fmt.Errorf("failed to initialize file-based authentication: %w", err)
		}
		log.Printf("Authentication initialized using file-based datasource: /app/config/users.txt")
	} else {
		log.Printf("Authentication initialized from environment configuration")
	}

	// Initialize RBAC
	rbac := auth.NewRBAC(authSystem)

	// Initialize API key manager
	apiKeyManager := auth.NewAPIKeyManager(rbac)

	// Initialize session manager
	sessionConfig := auth.SessionConfig{
		MaxAge:       24 * time.Hour,
		CookieName:   "elemta_session",
		SecureCookie: false, // Set to true in production with HTTPS
		HTTPOnly:     true,
		SameSite:     "lax",
	}
	sessionManager := auth.NewSessionManager(sessionConfig)

	// Create authentication middleware
	authMiddleware := NewAuthMiddleware(rbac, apiKeyManager, sessionManager)

	s.authSystem = authSystem
	s.rbac = rbac
	s.apiKeyManager = apiKeyManager
	s.sessionManager = sessionManager
	s.authMiddleware = authMiddleware

	return nil
}

// Start starts the API server
func (s *Server) Start() error {
	r := mux.NewRouter()

	// Apply global middleware
	if s.authMiddleware != nil {
		r.Use(s.authMiddleware.CORS)
		r.Use(LoggingMiddleware)
	}

	// Serve static files for the web interface
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(s.webRoot))))

	// Serve the main dashboard at root (no auth required for now)
	r.HandleFunc("/", s.handleDashboard).Methods("GET")
	r.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")
	
	// Debug routes (no auth required for debugging)
	r.HandleFunc("/debug/auth", s.handleDebugAuth).Methods("GET")

	// Authentication routes (if auth is enabled)
	if s.authMiddleware != nil {
		auth := r.PathPrefix("/auth").Subrouter()
		auth.HandleFunc("/login", s.handleLogin).Methods("POST")
		auth.HandleFunc("/logout", s.handleLogout).Methods("POST")
		auth.HandleFunc("/me", s.handleMe).Methods("GET")

		// API key management routes (require authentication)
		apiKeys := r.PathPrefix("/auth/apikeys").Subrouter()
		apiKeys.Use(s.authMiddleware.RequireAuth)
		apiKeys.HandleFunc("", s.handleListAPIKeys).Methods("GET")
		apiKeys.HandleFunc("", s.handleCreateAPIKey).Methods("POST")
		apiKeys.HandleFunc("/{id}", s.handleGetAPIKey).Methods("GET")
		apiKeys.HandleFunc("/{id}", s.handleUpdateAPIKey).Methods("PUT")
		apiKeys.HandleFunc("/{id}", s.handleDeleteAPIKey).Methods("DELETE")
		apiKeys.HandleFunc("/{id}/revoke", s.handleRevokeAPIKey).Methods("POST")
	}

	// API routes
	api := r.PathPrefix("/api").Subrouter()

	// Read-only queue operations (no authentication required for web interface)
	api.HandleFunc("/queue/stats", s.handleGetQueueStats).Methods("GET")
	api.HandleFunc("/queue/message/{id}", s.handleGetMessage).Methods("GET")
	api.HandleFunc("/queue/{type}", s.handleGetQueue).Methods("GET")
	api.HandleFunc("/queue", s.handleGetAllQueues).Methods("GET")

	// Destructive operations require authentication (only if auth is enabled)
	if s.authMiddleware != nil {
		// Message deletion requires queue:delete permission
		deleteHandler := s.authMiddleware.RequirePermission(auth.PermissionQueueDelete)(http.HandlerFunc(s.handleDeleteMessage))
		api.Handle("/queue/message/{id}", deleteHandler).Methods("DELETE")
		// Queue flushing requires queue:flush permission
		flushHandler := s.authMiddleware.RequirePermission(auth.PermissionQueueFlush)(http.HandlerFunc(s.handleFlushQueue))
		api.Handle("/queue/{type}/flush", flushHandler).Methods("POST")
	} else {
		// If auth is disabled, allow destructive operations without authentication
		api.HandleFunc("/queue/message/{id}", s.handleDeleteMessage).Methods("DELETE")
		api.HandleFunc("/queue/{type}/flush", s.handleFlushQueue).Methods("POST")
	}

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         s.listenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting API server on %s", s.listenAddr)
		if s.authMiddleware != nil {
			log.Printf("Authentication enabled - default admin:password")
		}
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// API handlers

// handleGetAllQueues returns all messages in all queues
func (s *Server) handleGetAllQueues(w http.ResponseWriter, r *http.Request) {
	messages, err := s.queueMgr.GetAllMessages()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, messages)
}

// handleGetQueue returns messages in a specific queue
func (s *Server) handleGetQueue(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	qType := vars["type"]

	queueType, err := parseQueueType(qType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	messages, err := s.queueMgr.ListMessages(queueType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, messages)
}

// handleFlushQueue flushes a specific queue
func (s *Server) handleFlushQueue(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	qType := vars["type"]

	var err error
	if qType == "all" {
		err = s.queueMgr.FlushAllQueues()
	} else {
		queueType, qErr := parseQueueType(qType)
		if qErr != nil {
			http.Error(w, fmt.Sprintf("Error: %v", qErr), http.StatusBadRequest)
			return
		}

		err = s.queueMgr.FlushQueue(queueType)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": fmt.Sprintf("Queue %s flushed", qType)})
}

// handleGetMessage returns a specific message
func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// Get message metadata first
	msg, err := s.queueMgr.GetMessage(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Message not found: %v", err), http.StatusNotFound)
		return
	}

	content, err := s.queueMgr.GetMessageContent(id)
	if err != nil {
		// Log the error and return a more specific message to the user
		log.Printf("Error getting content for message %s: %v", id, err)
		http.Error(w, fmt.Sprintf("Message metadata loaded, but content is missing or corrupt: %v", err), http.StatusNotFound)
		return
	}

	// If format=raw is specified, return raw message
	if r.URL.Query().Get("format") == "raw" {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write(content); err != nil {
			log.Printf("Error writing raw response for message %s: %v", id, err)
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
		return
	}

	// Include the content with the message
	type MessageWithContent struct {
		queue.Message
		Content string `json:"content"`
	}

	msgWithContent := MessageWithContent{
		Message: msg,
		Content: string(content),
	}

	writeJSON(w, msgWithContent)
}

// handleDeleteMessage deletes a specific message
func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := s.queueMgr.DeleteMessage(id); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": fmt.Sprintf("Message %s deleted", id)})
}

// handleGetQueueStats returns queue statistics
func (s *Server) handleGetQueueStats(w http.ResponseWriter, r *http.Request) {
	stats := s.queueMgr.GetStats()
	writeJSON(w, stats)
}

// handleDashboard serves the main dashboard page
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, s.webRoot+"/index.html")
}

// Authentication handlers

// handleLogin handles user login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.authSystem == nil {
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Authenticate user
	ctx := context.Background()
	authenticated, err := s.authSystem.Authenticate(ctx, loginReq.Username, loginReq.Password)
	if err != nil || !authenticated {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	session, err := s.sessionManager.CreateSession(loginReq.Username, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	s.sessionManager.SetCookie(w, session.ID)

	// Get user permissions
	permissions, _ := s.rbac.GetUserPermissions(ctx, loginReq.Username)

	writeJSON(w, map[string]interface{}{
		"status":      "success",
		"username":    loginReq.Username,
		"session_id":  session.ID,
		"permissions": permissions,
	})
}

// handleLogout handles user logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.sessionManager == nil {
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	sessionID := s.sessionManager.GetSessionFromRequest(r)
	if sessionID != "" {
		s.sessionManager.RevokeSession(sessionID)
	}

	// Clear session cookie
	s.sessionManager.ClearCookie(w)

	writeJSON(w, map[string]string{"status": "success", "message": "Logged out"})
}

// handleMe returns current user information
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if s.authMiddleware == nil {
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Get user details
	ctx := context.Background()
	user, err := s.authSystem.GetUser(ctx, authCtx.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Don't return password
	user.Password = ""

	writeJSON(w, map[string]interface{}{
		"user":        user,
		"permissions": authCtx.Permissions,
		"is_api_key":  authCtx.IsAPIKey,
	})
}

// API Key management handlers

// handleListAPIKeys lists API keys for the current user
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	keys := s.apiKeyManager.ListAPIKeys(authCtx.Username)
	writeJSON(w, keys)
}

// handleCreateAPIKey creates a new API key
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Permissions []auth.Permission `json:"permissions"`
		ExpiryDays  *int              `json:"expiry_days,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var expiryDuration *time.Duration
	if req.ExpiryDays != nil && *req.ExpiryDays > 0 {
		duration := time.Duration(*req.ExpiryDays) * 24 * time.Hour
		expiryDuration = &duration
	}

	apiKey, keyString, err := s.apiKeyManager.CreateAPIKey(
		authCtx.Username,
		req.Name,
		req.Description,
		req.Permissions,
		expiryDuration,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create API key: %v", err), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]interface{}{
		"api_key": apiKey,
		"key":     keyString, // Only returned once
	})
}

// handleGetAPIKey gets a specific API key
func (s *Server) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	// Users can only see their own keys (unless admin)
	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	writeJSON(w, apiKey)
}

// handleUpdateAPIKey updates an API key
func (s *Server) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Permissions []auth.Permission `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check ownership
	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := s.apiKeyManager.UpdateAPIKey(keyID, req.Name, req.Description, req.Permissions); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update API key: %v", err), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": "API key updated"})
}

// handleDeleteAPIKey deletes an API key
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	// Check ownership
	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := s.apiKeyManager.DeleteAPIKey(keyID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete API key: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": "API key deleted"})
}

// handleRevokeAPIKey revokes an API key
func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	authCtx := GetAuthContext(r)
	if authCtx == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]

	// Check ownership
	apiKey, err := s.apiKeyManager.GetAPIKey(keyID)
	if err != nil {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	if apiKey.Username != authCtx.Username && !s.isAdmin(authCtx) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if err := s.apiKeyManager.RevokeAPIKey(keyID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to revoke API key: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": "API key revoked"})
}

// Debug handlers

// handleDebugAuth provides authentication debugging information
func (s *Server) handleDebugAuth(w http.ResponseWriter, r *http.Request) {
	debug := map[string]interface{}{
		"auth_enabled": s.authSystem != nil,
		"rbac_enabled": s.rbac != nil,
		"middleware_enabled": s.authMiddleware != nil,
	}

	if s.authSystem != nil {
		debug["auth_type"] = "available"
		
		// Test authentication with query parameters if provided
		username := r.URL.Query().Get("user")
		password := r.URL.Query().Get("pass")
		
		if username != "" && password != "" {
			ctx := context.Background()
			authenticated, err := s.authSystem.Authenticate(ctx, username, password)
			debug["test_auth"] = map[string]interface{}{
				"username": username,
				"authenticated": authenticated,
				"error": err,
			}
			
			if authenticated && s.rbac != nil {
				permissions, _ := s.rbac.GetUserPermissions(ctx, username)
				debug["test_permissions"] = permissions
			}
		}
	}

	writeJSON(w, debug)
}

// Helper functions

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
	}
}

// parseQueueType converts a string to a QueueType
func parseQueueType(qType string) (queue.QueueType, error) {
	qType = strings.ToLower(qType)

	switch qType {
	case "active":
		return queue.Active, nil
	case "deferred":
		return queue.Deferred, nil
	case "hold":
		return queue.Hold, nil
	case "failed":
		return queue.Failed, nil
	default:
		return "", fmt.Errorf("invalid queue type: %s", qType)
	}
}

// isAdmin checks if the user has admin permissions
func (s *Server) isAdmin(authCtx *AuthContext) bool {
	for _, perm := range authCtx.Permissions {
		if perm == auth.PermissionSystemAdmin {
			return true
		}
	}
	return false
}
