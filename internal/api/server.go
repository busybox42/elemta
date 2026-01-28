package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/auth"
	"github.com/busybox42/elemta/internal/metrics"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/gorilla/mux"
)

// Server represents an API server for Elemta
type Server struct {
	config         *Config
	httpServer     *http.Server
	queueMgr       *queue.Manager
	listenAddr     string
	webRoot        string
	authSystem     *auth.Auth
	rbac           *auth.RBAC
	apiKeyManager  *auth.APIKeyManager
	sessionManager *auth.SessionManager
	authMiddleware *AuthMiddleware
	metricsStore   MetricsStore
}

// MetricsStore interface for delivery metrics
type MetricsStore interface {
	GetMetrics(ctx context.Context) (*DeliveryMetricsData, error)
	GetHourlyStats(ctx context.Context) ([]HourlyStatsData, error)
	GetRecentErrors(ctx context.Context, limit int64) ([]map[string]string, error)
}

// DeliveryMetricsData holds delivery statistics
type DeliveryMetricsData struct {
	TotalDelivered int64     `json:"total_delivered"`
	TotalFailed    int64     `json:"total_failed"`
	TotalDeferred  int64     `json:"total_deferred"`
	TotalReceived  int64     `json:"total_received"`
	LastUpdated    time.Time `json:"last_updated"`
}

// HourlyStatsData holds hourly delivery counts
type HourlyStatsData struct {
	Hour      string `json:"hour"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// Config represents API server configuration
type Config struct {
	Enabled     bool   `toml:"enabled" json:"enabled"`
	ListenAddr  string `toml:"listen_addr" json:"listen_addr"`
	WebRoot     string `toml:"web_root" json:"web_root"`
	AuthEnabled bool   `toml:"auth_enabled" json:"auth_enabled"`
	AuthFile    string `toml:"auth_file" json:"auth_file"`
	ValkeyAddr  string `toml:"valkey_addr" json:"valkey_addr"`
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
		config:     config,
		queueMgr:   queueMgr,
		listenAddr: listenAddr,
		webRoot:    webRoot,
	}

	// Initialize metrics store (Valkey)
	valkeyAddr := config.ValkeyAddr
	if valkeyAddr == "" {
		// Try environment variable or default
		valkeyAddr = os.Getenv("VALKEY_ADDR")
		if valkeyAddr == "" {
			valkeyAddr = "elemta-valkey:6379"
		}
	}
	metricsStore, err := metrics.NewValkeyStore(valkeyAddr)
	if err != nil {
		log.Printf("Warning: Failed to connect to Valkey for metrics: %v", err)
		// Continue without metrics - not fatal
	} else {
		server.metricsStore = &valkeyMetricsAdapter{store: metricsStore}
		log.Printf("Connected to Valkey for metrics at %s", valkeyAddr)
	}

	// Initialize authentication if enabled
	if config.AuthEnabled {
		if err := server.initializeAuth(); err != nil {
			return nil, fmt.Errorf("failed to initialize authentication: %w", err)
		}
	}

	return server, nil
}

// valkeyMetricsAdapter adapts ValkeyStore to MetricsStore interface
type valkeyMetricsAdapter struct {
	store *metrics.ValkeyStore
}

func (a *valkeyMetricsAdapter) GetMetrics(ctx context.Context) (*DeliveryMetricsData, error) {
	m, err := a.store.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	return &DeliveryMetricsData{
		TotalDelivered: m.TotalDelivered,
		TotalFailed:    m.TotalFailed,
		TotalDeferred:  m.TotalDeferred,
		TotalReceived:  m.TotalReceived,
		LastUpdated:    m.LastUpdated,
	}, nil
}

func (a *valkeyMetricsAdapter) GetHourlyStats(ctx context.Context) ([]HourlyStatsData, error) {
	stats, err := a.store.GetHourlyStats(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]HourlyStatsData, len(stats))
	for i, s := range stats {
		result[i] = HourlyStatsData{
			Hour:      s.Hour,
			Delivered: s.Delivered,
			Failed:    s.Failed,
			Deferred:  s.Deferred,
		}
	}
	return result, nil
}

func (a *valkeyMetricsAdapter) GetRecentErrors(ctx context.Context, limit int64) ([]map[string]string, error) {
	return a.store.GetRecentErrors(ctx, limit)
}

// initializeAuth initializes the authentication system
func (s *Server) initializeAuth() error {
	// Create logger for auth initialization
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "api-auth",
	)

	// Use config auth file if specified, otherwise try environment, then fallback to default
	var authSystem *auth.Auth
	var err error

	authFile := s.config.AuthFile
	if authFile == "" {
		authFile = "/app/config/users.txt"
	}

	// Try environment first
	authSystem, err = auth.NewFromEnv()
	if err != nil {
		// Fallback to file-based authentication
		logger.Warn("Failed to initialize auth from environment, falling back to file-based auth",
			"error", err,
		)
		authSystem, err = auth.NewWithFile(authFile)
		if err != nil {
			return fmt.Errorf("failed to initialize file-based authentication from %s: %w", authFile, err)
		}
		logger.Info("Authentication initialized using file-based datasource",
			"datasource", authFile,
		)
	} else {
		logger.Info("Authentication initialized from environment configuration")
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

	// Apply CORS middleware first - before any other middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers for all requests
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
	})

	// Apply other middleware
	r.Use(LoggingMiddleware)
	if s.authMiddleware != nil {
		// Note: Don't use s.authMiddleware.CORS since we handle CORS above
		// Only apply auth-related middleware for protected routes
		log.Printf("API Server: Auth middleware available")
	}

	// Serve static files for the web interface (protected)
	if s.authMiddleware != nil {
		// Public login page
		r.HandleFunc("/login", s.handleLoginPage).Methods("GET")

		// Public logo for login page
		r.HandleFunc("/static/images/elemta.png", s.handleLogo).Methods("GET")

		// Protected routes
		r.PathPrefix("/static/").Handler(s.authMiddleware.RequireAuth(http.StripPrefix("/static/", http.FileServer(http.Dir(s.webRoot)))))
		// Serve the main dashboard at root (requires authentication)
		r.Handle("/", s.authMiddleware.RequireAuth(http.HandlerFunc(s.handleDashboard))).Methods("GET")
		r.Handle("/dashboard", s.authMiddleware.RequireAuth(http.HandlerFunc(s.handleDashboard))).Methods("GET")
	} else {
		// Fallback to no auth if auth system is not configured
		r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(s.webRoot))))
		r.HandleFunc("/", s.handleDashboard).Methods("GET")
		r.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")
	}

	// Debug routes (no auth required for debugging)
	r.HandleFunc("/debug/auth", s.handleDebugAuth).Methods("GET")

	// Authentication routes (if auth is enabled)
	if s.authMiddleware != nil {
		auth := r.PathPrefix("/auth").Subrouter()
		auth.HandleFunc("/login", s.handleLogin).Methods("POST")
		auth.HandleFunc("/logout", s.handleLogout).Methods("POST", "GET")
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

	// Logging management endpoints (no auth required for GET, auth required for SET)
	api.HandleFunc("/logging/level", s.HandleGetLogLevel).Methods("GET")

	// Protected logging endpoints (require auth)
	if s.authMiddleware != nil {
		loggingProtected := api.PathPrefix("/logging").Subrouter()
		loggingProtected.Use(s.authMiddleware.RequireAuth)
		loggingProtected.HandleFunc("/level", s.HandleSetLogLevel).Methods("POST", "PUT")
	} else {
		// If no auth middleware, still allow setting log level (development mode)
		api.HandleFunc("/logging/level", s.HandleSetLogLevel).Methods("POST", "PUT")
	}

	// Read-only queue operations (no authentication required for web interface)
	api.HandleFunc("/queue/stats", s.handleGetQueueStats).Methods("GET")
	api.HandleFunc("/queue/message/{id}", s.handleGetMessage).Methods("GET")
	api.HandleFunc("/queue/{type}", s.handleGetQueue).Methods("GET")
	api.HandleFunc("/queue", s.handleGetAllQueues).Methods("GET")

	// Logs endpoint (no authentication required for web interface)
	api.HandleFunc("/logs", s.handleGetLogs).Methods("GET")
	api.HandleFunc("/logs/messages", s.handleGetMessageLogs).Methods("GET")

	// Health and monitoring endpoints (no auth required for dashboard)
	api.HandleFunc("/health", s.handleHealthStats).Methods("GET")
	api.HandleFunc("/stats/delivery", s.handleDeliveryStats).Methods("GET")

	// Test email endpoint (requires auth if enabled, otherwise open)
	if s.authMiddleware != nil {
		sendHandler := s.authMiddleware.RequireAuth(http.HandlerFunc(s.handleSendTestEmail))
		api.Handle("/send-test", sendHandler).Methods("POST")
	} else {
		api.HandleFunc("/send-test", s.handleSendTestEmail).Methods("POST")
	}

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
	if s.httpServer == nil {
		return nil
	}

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

// handleLoginPage serves the public login page
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/login.html")
}

// handleLogo serves the Elemta logo for the login page (public)
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "images/elemta.png")
}

// handleDashboard serves the main dashboard page
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, s.webRoot+"/index.html")
}

// Authentication handlers

// handleLogin handles user login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("Login attempt received")

	if s.authSystem == nil {
		log.Printf("Auth system is nil - authentication not enabled")
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	if s.sessionManager == nil {
		log.Printf("Session manager is nil")
		http.Error(w, "Session management not available", http.StatusServiceUnavailable)
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
	log.Printf("Creating session for user: %s", loginReq.Username)
	session, err := s.sessionManager.CreateSession(loginReq.Username, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	log.Printf("Session created successfully, ID: %s", session.ID)

	// Set session cookie
	log.Printf("Setting session cookie")
	s.sessionManager.SetCookie(w, session.ID)
	log.Printf("Session cookie set")

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
	log.Printf("Logout request received")

	if s.sessionManager == nil {
		log.Printf("Session manager is nil during logout")
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	sessionID := s.sessionManager.GetSessionFromRequest(r)
	log.Printf("Found session ID for logout: %s", sessionID)

	if sessionID != "" {
		err := s.sessionManager.RevokeSession(sessionID)
		if err != nil {
			log.Printf("Error revoking session: %v", err)
		} else {
			log.Printf("Session revoked successfully")
		}
	}

	// Clear session cookie
	log.Printf("Clearing session cookie")
	s.sessionManager.ClearCookie(w)
	log.Printf("Session cookie cleared")

	// Redirect to login page instead of returning JSON
	log.Printf("Redirecting to login page")
	http.Redirect(w, r, "/login?logout=1", http.StatusFound)
}

// handleMe returns current user information
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if s.authMiddleware == nil {
		http.Error(w, "Authentication not enabled", http.StatusServiceUnavailable)
		return
	}

	// Authenticate using the same method as RequireAuth middleware
	authCtx, err := s.authMiddleware.authenticate(r)
	if err != nil {
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

// handleGetLogs fetches recent logs from log files
func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "100" // Default to last 100 lines
	}

	// Try to read from various log file locations
	logFiles := []string{
		"/app/logs/elemta.log",
		"/app/logs/smtp.log",
		"/app/logs/queue.log",
		"/app/logs/application.log",
	}

	var allLogs []string
	var source string

	// Read from available log files
	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); err == nil {
			data, err := os.ReadFile(logFile)
			if err == nil {
				lines := strings.Split(string(data), "\n")
				// Filter out empty lines
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						allLogs = append(allLogs, line)
					}
				}
				source = filepath.Base(logFile)
				break // Use the first available log file
			}
		}
	}

	// If no log files found, provide a helpful message
	if len(allLogs) == 0 {
		response := map[string]interface{}{
			"logs":    []string{"No log files found. Logs may be written to stdout/stderr."},
			"count":   1,
			"tail":    tail,
			"source":  "none",
			"time":    time.Now().Format(time.RFC3339),
			"message": "Configure Elemta to write logs to /app/logs/ directory",
		}
		writeJSON(w, response)
		return
	}

	// If we have more logs than requested, return only the tail
	tailInt, err := strconv.Atoi(tail)
	if err != nil {
		tailInt = 100
	}

	if len(allLogs) > tailInt {
		allLogs = allLogs[len(allLogs)-tailInt:]
	}

	// Create response
	response := map[string]interface{}{
		"logs":   allLogs,
		"count":  len(allLogs),
		"tail":   tail,
		"source": source,
		"time":   time.Now().Format(time.RFC3339),
	}

	writeJSON(w, response)
}

// MessageLog represents a structured message lifecycle log entry
type MessageLog struct {
	Time      string                 `json:"time"`
	Level     string                 `json:"level"`
	Message   string                 `json:"msg"`
	EventType string                 `json:"event_type,omitempty"`
	Component string                 `json:"component,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// handleGetMessageLogs fetches structured message lifecycle logs
func (s *Server) handleGetMessageLogs(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		limitStr = "100"
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000 // Cap at 1000 entries
	}

	eventTypeFilter := r.URL.Query().Get("event_type")
	levelFilter := r.URL.Query().Get("level")

	// Read log file
	logFile := "/app/logs/elemta.log"
	data, err := os.ReadFile(logFile)
	if err != nil {
		// Try alternate location
		logFile = "./logs/elemta.log"
		data, err = os.ReadFile(logFile)
		if err != nil {
			writeJSON(w, map[string]interface{}{
				"logs":    []MessageLog{},
				"count":   0,
				"message": "No log file found",
			})
			return
		}
	}

	// Parse log lines
	lines := strings.Split(string(data), "\n")
	var messageLogs []MessageLog

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var logEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
			// Skip non-JSON lines
			continue
		}

		// Extract common fields
		timeStr, _ := logEntry["time"].(string)
		level, _ := logEntry["level"].(string)
		msg, _ := logEntry["msg"].(string)
		eventType, _ := logEntry["event_type"].(string)
		component, _ := logEntry["component"].(string)

		// Enforce strict categorization for 4xx/5xx errors if event_type is missing or system
		if eventType == "" || eventType == "system" {
			eventType = categorizeLogEntry(logEntry, msg)
		}

		// Apply filters
		if eventTypeFilter != "" {
			if eventTypeFilter == "system" {
				// System filter matches explicit "system" events or events with no type
				// It excludes known lifecycle events
				isKnownCategory := false
				knownCategories := []string{"reception", "delivery", "rejection", "deferral", "bounce", "tempfail", "authentication"}
				for _, t := range knownCategories {
					if eventType == t {
						isKnownCategory = true
						break
					}
				}
				if isKnownCategory {
					continue
				}
			} else if eventType != eventTypeFilter {
				continue
			}
		}
		if levelFilter != "" && !strings.EqualFold(level, levelFilter) {
			continue
		}

		// Only include message lifecycle events or interesting logs
		includeLog := false
		messageLifecycleTypes := []string{
			"reception", "delivery", "rejection", "deferral", "bounce", "tempfail", "authentication",
		}

		// Include if it's a message lifecycle event
		for _, t := range messageLifecycleTypes {
			if eventType == t {
				includeLog = true
				break
			}
		}

		// Also include queue-related logs
		if component == "queue" || component == "smtp-session" || component == "message-lifecycle" {
			includeLog = true
		}

		// Include if no event_type filter is specified (show all)
		if eventTypeFilter == "" && eventType == "" && (component != "" || msg != "") {
			includeLog = true
		}

		// Always include if explicitly filtered
		if eventTypeFilter != "" {
			includeLog = true
		}

		if !includeLog {
			continue
		}

		// Extract remaining fields
		fields := make(map[string]interface{})
		standardFields := map[string]bool{
			"time": true, "level": true, "msg": true, "event_type": true, "component": true,
		}
		for k, v := range logEntry {
			if !standardFields[k] {
				fields[k] = v
			}
		}

		messageLog := MessageLog{
			Time:      timeStr,
			Level:     level,
			Message:   msg,
			EventType: eventType,
			Component: component,
			Fields:    fields,
		}

		messageLogs = append(messageLogs, messageLog)
	}

	// Sort by time (newest first) and limit
	if len(messageLogs) > limit {
		messageLogs = messageLogs[len(messageLogs)-limit:]
	}

	// Reverse to show newest first
	for i, j := 0, len(messageLogs)-1; i < j; i, j = i+1, j-1 {
		messageLogs[i], messageLogs[j] = messageLogs[j], messageLogs[i]
	}

	writeJSON(w, map[string]interface{}{
		"logs":     messageLogs,
		"count":    len(messageLogs),
		"has_more": false,
	})
}

// handleDebugAuth provides authentication debugging information
func (s *Server) handleDebugAuth(w http.ResponseWriter, r *http.Request) {
	debug := map[string]interface{}{
		"auth_enabled":       s.authSystem != nil,
		"rbac_enabled":       s.rbac != nil,
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
				"username":      username,
				"authenticated": authenticated,
				"error":         err,
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

// Regex patterns for SMTP code detection
var (
	smtp5xxPattern = regexp.MustCompile(`\b5[0-9]{2}\b`)
	smtp4xxPattern = regexp.MustCompile(`\b4[0-9]{2}\b`)
)

// categorizeLogEntry determines the event_type for a log entry based on its content
// This ensures 5xx errors are categorized as rejection and 4xx as tempfail/deferral
func categorizeLogEntry(logEntry map[string]interface{}, msg string) string {
	msgLower := strings.ToLower(msg)

	// 1. Check for rejection keywords in message
	rejectionKeywords := []string{
		"rejected", "virus", "spam", "blocked", "denied", "refused",
		"malware", "threat", "infected", "banned", "blacklist",
	}
	for _, keyword := range rejectionKeywords {
		if strings.Contains(msgLower, keyword) {
			return "rejection"
		}
	}

	// 2. Check for tempfail/deferral keywords in message
	tempfailKeywords := []string{
		"deferred", "retry", "temporary", "tempfail", "greylisted",
		"try again", "later", "busy", "throttled", "rate limit",
	}
	for _, keyword := range tempfailKeywords {
		if strings.Contains(msgLower, keyword) {
			return "tempfail"
		}
	}

	// 3. Check for spam_score field (content-based rejection)
	if spamScore, ok := logEntry["spam_score"].(float64); ok && spamScore > 0 {
		return "rejection"
	}

	// 4. Check for threats field (virus/content rejection)
	if _, ok := logEntry["threats"]; ok {
		return "rejection"
	}

	// 5. Check for virus_found field
	if virusFound, ok := logEntry["virus_found"].(bool); ok && virusFound {
		return "rejection"
	}

	// 6. Scan ALL string fields for SMTP 5xx codes (permanent failures)
	for _, v := range logEntry {
		if str, ok := v.(string); ok {
			if smtp5xxPattern.MatchString(str) {
				return "rejection"
			}
		}
	}

	// 7. Scan ALL string fields for SMTP 4xx codes (temporary failures)
	for _, v := range logEntry {
		if str, ok := v.(string); ok {
			if smtp4xxPattern.MatchString(str) {
				return "tempfail"
			}
		}
	}

	// 8. Check for delivery/bounce status fields
	if status, ok := logEntry["status"].(string); ok {
		statusLower := strings.ToLower(status)
		if statusLower == "rejected" || statusLower == "bounced" {
			return "rejection"
		}
		if statusLower == "deferred" || statusLower == "temporary_failure" {
			return "tempfail"
		}
	}

	// Default: remain as system/empty (will be filtered appropriately)
	return ""
}
