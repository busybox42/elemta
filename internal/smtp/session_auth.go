// internal/smtp/session_auth.go
package smtp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/auth"
)

// Note: AuthMethod and constants are defined in auth.go

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Success   bool
	Username  string
	Method    AuthMethod
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

// AuthSecurityConfig defines security configuration for authentication
type AuthSecurityConfig struct {
	MaxAuthAttempts        int           // Maximum auth attempts per session
	MaxAuthAttemptsPerIP   int           // Maximum auth attempts per IP
	AuthRateInterval       time.Duration // Rate limiting interval
	AccountLockoutDuration time.Duration // How long to lock accounts
	RequireTLSForPlain     bool          // Require TLS for PLAIN auth
	EnabledMethods         []AuthMethod  // Enabled authentication methods
}

// AuthFailureInfo tracks authentication failure information
type AuthFailureInfo struct {
	Count     int
	LastTime  time.Time
	IPAddress string
}

// AccountLockInfo tracks account lockout information
type AccountLockInfo struct {
	LockedUntil time.Time
	Reason      string
}

// AuthenticationSecurityManager handles authentication security
type AuthenticationSecurityManager struct {
	mu              sync.RWMutex
	config          *AuthSecurityConfig
	ipFailures      map[string]*AuthFailureInfo
	accountLockouts map[string]*AccountLockInfo
	logger          *slog.Logger
}

// NewAuthenticationSecurityManager creates a new authentication security manager
func NewAuthenticationSecurityManager(config *AuthSecurityConfig, logger *slog.Logger) *AuthenticationSecurityManager {
	if config == nil {
		config = &AuthSecurityConfig{
			MaxAuthAttempts:        5,
			MaxAuthAttemptsPerIP:   10,
			AuthRateInterval:       15 * time.Minute,
			AccountLockoutDuration: 30 * time.Minute,
			RequireTLSForPlain:     true,
			EnabledMethods:         []AuthMethod{AuthMethodPlain, AuthMethodLogin},
		}
	}

	return &AuthenticationSecurityManager{
		config:          config,
		ipFailures:      make(map[string]*AuthFailureInfo),
		accountLockouts: make(map[string]*AccountLockInfo),
		logger:          logger.With("component", "auth-security"),
	}
}

// AuthHandler manages SMTP authentication for a session
type AuthHandler struct {
	session             *Session
	state               *SessionState
	authenticator       Authenticator
	securityManager     *AuthenticationSecurityManager
	sessionStateMachine *auth.SessionStateMachine
	logger              *slog.Logger
	conn                net.Conn
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(session *Session, state *SessionState, authenticator Authenticator, conn net.Conn, logger *slog.Logger) *AuthHandler {
	securityConfig := &AuthSecurityConfig{
		MaxAuthAttempts:        5,
		MaxAuthAttemptsPerIP:   10,
		AuthRateInterval:       15 * time.Minute,
		AccountLockoutDuration: 30 * time.Minute,
		RequireTLSForPlain:     false, // Allow PLAIN auth without TLS for testing/internal use
		EnabledMethods:         []AuthMethod{AuthMethodPlain, AuthMethodLogin},
	}

	securityManager := NewAuthenticationSecurityManager(securityConfig, logger)

	// Create secure session state machine
	ipAddress := conn.RemoteAddr().String()
	userAgent := "SMTP-Client" // SMTP doesn't have user agents, use generic identifier
	sessionStateMachine, err := auth.NewSessionStateMachine(nil, ipAddress, userAgent, logger)
	if err != nil {
		logger.Error("Failed to create session state machine", "error", err)
		// Continue without state machine for backward compatibility
	}

	return &AuthHandler{
		session:             session,
		state:               state,
		authenticator:       authenticator,
		securityManager:     securityManager,
		sessionStateMachine: sessionStateMachine,
		logger:              logger.With("component", "session-auth"),
		conn:                conn,
	}
}

// HandleAuth processes the AUTH command
func (ah *AuthHandler) HandleAuth(ctx context.Context, cmd string) error {
	ah.logger.DebugContext(ctx, "Processing AUTH command", "command", cmd)

	// Use session state machine if available
	if ah.sessionStateMachine != nil {
		// Check if already authenticated using state machine
		if ah.sessionStateMachine.IsAuthenticated() {
			return fmt.Errorf("503 5.5.1 Already authenticated")
		}

		// Transition to authenticating state
		if err := ah.sessionStateMachine.TransitionTo(auth.SessionStateAuthenticating, "auth_command_received"); err != nil {
			ah.logger.Error("Failed to transition to authenticating state", "error", err)
			return fmt.Errorf("421 4.7.0 Authentication system error")
		}
	} else {
		// Fallback to legacy state check
		if ah.state.IsAuthenticated() {
			return fmt.Errorf("503 5.5.1 Already authenticated")
		}
	}

	// Parse AUTH command
	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		ah.logger.WarnContext(ctx, "Invalid AUTH command format", "command", cmd)
		return fmt.Errorf("501 5.5.4 Syntax: AUTH mechanism")
	}

	method := AuthMethod(strings.ToUpper(parts[1]))

	// Validate authentication method
	if !ah.isMethodEnabled(method) {
		ah.logger.WarnContext(ctx, "Authentication method not supported",
			"method", string(method),
			"enabled_methods", ah.securityManager.config.EnabledMethods,
		)
		return fmt.Errorf("504 5.7.4 Authentication mechanism not supported")
	}

	// Check security constraints
	if err := ah.checkSecurityConstraints(ctx, method); err != nil {
		return err
	}

	// Increment auth attempts
	attempts := ah.state.IncrementAuthAttempts(ctx)
	if attempts > ah.securityManager.config.MaxAuthAttempts {
		ah.logger.WarnContext(ctx, "Too many authentication attempts",
			"attempts", attempts,
			"max_attempts", ah.securityManager.config.MaxAuthAttempts,
		)
		return fmt.Errorf("421 4.7.0 Too many authentication attempts")
	}

	// Handle specific authentication method
	switch method {
	case AuthMethodPlain:
		return ah.handleAuthPlain(ctx, cmd)
	case AuthMethodLogin:
		return ah.handleAuthLogin(ctx)
	case AuthMethodCramMD5:
		return ah.handleAuthCramMD5(ctx)
	default:
		ah.logger.WarnContext(ctx, "Unsupported authentication method", "method", string(method))
		return fmt.Errorf("504 5.7.4 Authentication mechanism not supported")
	}
}

// handleAuthPlain processes PLAIN authentication
func (ah *AuthHandler) handleAuthPlain(ctx context.Context, cmd string) error {
	ah.logger.DebugContext(ctx, "Processing PLAIN authentication")

	// Check TLS requirement for PLAIN auth
	if ah.securityManager.config.RequireTLSForPlain && !ah.state.IsTLSActive() {
		ah.logger.WarnContext(ctx, "PLAIN authentication requires TLS")
		return fmt.Errorf("538 5.7.11 Encryption required for requested authentication mechanism")
	}

	parts := strings.Fields(cmd)

	var authData string
	if len(parts) == 3 {
		// AUTH PLAIN <base64-data>
		authData = parts[2]
	} else if len(parts) == 2 {
		// AUTH PLAIN (followed by base64 data on next line)
		if err := ah.session.write("334 "); err != nil {
			return fmt.Errorf("failed to write auth prompt: %w", err)
		}

		line, _, err := ah.session.reader.ReadLine()
		if err != nil {
			ah.logger.ErrorContext(ctx, "Failed to read auth data", "error", err)
			return fmt.Errorf("failed to read authentication data: %w", err)
		}
		authData = string(line)
	} else {
		return fmt.Errorf("501 5.5.4 Syntax: AUTH PLAIN [<base64-data>]")
	}

	// Validate and decode base64 data
	if err := ah.validateBase64Input(authData); err != nil {
		ah.logger.WarnContext(ctx, "Invalid base64 authentication data", "error", err)
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	decoded, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		ah.logger.WarnContext(ctx, "Failed to decode base64 authentication data", "error", err)
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	// Parse PLAIN authentication data: \0username\0password
	parts = strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		ah.logger.WarnContext(ctx, "Invalid PLAIN authentication format")
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	// Extract username and password (skip authorization identity)
	username := parts[1]
	password := parts[2]

	return ah.performAuthentication(ctx, username, password, AuthMethodPlain)
}

// handleAuthLogin processes LOGIN authentication
func (ah *AuthHandler) handleAuthLogin(ctx context.Context) error {
	ah.logger.DebugContext(ctx, "Processing LOGIN authentication")

	// Send username prompt
	if err := ah.session.write("334 " + base64.StdEncoding.EncodeToString([]byte("Username:"))); err != nil {
		return fmt.Errorf("failed to write username prompt: %w", err)
	}

	// Read username
	userLine, _, err := ah.session.reader.ReadLine()
	if err != nil {
		ah.logger.ErrorContext(ctx, "Failed to read username", "error", err)
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Validate and decode username
	if err := ah.validateBase64Input(string(userLine)); err != nil {
		ah.logger.WarnContext(ctx, "Invalid base64 username", "error", err)
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	usernameBytes, err := base64.StdEncoding.DecodeString(string(userLine))
	if err != nil {
		ah.logger.WarnContext(ctx, "Failed to decode username", "error", err)
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}
	username := string(usernameBytes)

	// Send password prompt
	if err := ah.session.write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:"))); err != nil {
		return fmt.Errorf("failed to write password prompt: %w", err)
	}

	// Read password
	passLine, _, err := ah.session.reader.ReadLine()
	if err != nil {
		ah.logger.ErrorContext(ctx, "Failed to read password", "error", err)
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Validate and decode password
	if err := ah.validateBase64Input(string(passLine)); err != nil {
		ah.logger.WarnContext(ctx, "Invalid base64 password", "error", err)
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	passwordBytes, err := base64.StdEncoding.DecodeString(string(passLine))
	if err != nil {
		ah.logger.WarnContext(ctx, "Failed to decode password", "error", err)
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}
	password := string(passwordBytes)

	return ah.performAuthentication(ctx, username, password, AuthMethodLogin)
}

// handleAuthCramMD5 processes CRAM-MD5 authentication (disabled for security)
func (ah *AuthHandler) handleAuthCramMD5(ctx context.Context) error {
	ah.logger.WarnContext(ctx, "CRAM-MD5 authentication disabled for security reasons")
	return fmt.Errorf("504 5.7.4 CRAM-MD5 authentication disabled for security reasons")
}

// performAuthentication performs the actual authentication
func (ah *AuthHandler) performAuthentication(ctx context.Context, username, password string, method AuthMethod) error {
	startTime := time.Now()

	// Validate authentication data
	if err := ah.validateAuthenticationData(ctx, username, password); err != nil {
		ah.recordAuthFailure(ctx, username, method, err, time.Since(startTime))
		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	// Check account lockout
	if ah.isAccountLocked(username) {
		ah.logger.WarnContext(ctx, "Account is locked",
			"username", username,
			"method", string(method),
		)
		ah.recordAuthFailure(ctx, username, method, fmt.Errorf("account locked"), time.Since(startTime))
		return fmt.Errorf("535 5.7.8 Account temporarily locked")
	}

	// Perform authentication
	authenticated, err := ah.authenticator.Authenticate(ctx, username, password)
	duration := time.Since(startTime)

	if err != nil || !authenticated {
		ah.logger.WarnContext(ctx, "Authentication failed",
			"username", username,
			"method", string(method),
			"error", err,
			"duration", duration,
		)
		ah.recordAuthFailure(ctx, username, method, err, duration)

		// Update session state machine if available
		if ah.sessionStateMachine != nil {
			// Transition to failed state
			if err := ah.sessionStateMachine.TransitionTo(auth.SessionStateFailed, "authentication_failed"); err != nil {
				ah.logger.Error("Failed to transition to failed state", "error", err)
			}
		}

		return fmt.Errorf("535 5.7.8 Authentication credentials invalid")
	}

	// Authentication successful
	ah.state.SetAuthenticated(ctx, true, username)
	ah.recordAuthSuccess(ctx, username, method, duration)

	// Update session state machine if available
	if ah.sessionStateMachine != nil {
		// Set username in state machine
		if err := ah.sessionStateMachine.SetUsername(username); err != nil {
			ah.logger.Error("Failed to set username in state machine", "error", err)
		}

		// Transition to authenticated state
		if err := ah.sessionStateMachine.TransitionTo(auth.SessionStateAuthenticated, "authentication_successful"); err != nil {
			ah.logger.Error("Failed to transition to authenticated state", "error", err)
			// Continue anyway, but log the error
		}

		// Regenerate session ID to prevent session fixation attacks
		if err := ah.sessionStateMachine.RegenerateSessionID(); err != nil {
			ah.logger.Error("Failed to regenerate session ID", "error", err)
			// Continue anyway, but log the error
		}

		// Set up RBAC context for the authenticated user
		if err := ah.setupRBACContext(ctx, username); err != nil {
			ah.logger.Error("Failed to setup RBAC context", "error", err)
			// Continue anyway, but log the error
		}
	}

	ah.logger.InfoContext(ctx, "Authentication successful",
		"username", username,
		"method", string(method),
		"duration", duration,
	)

	// Send success response to client
	if err := ah.session.write("235 2.7.0 Authentication successful"); err != nil {
		ah.logger.ErrorContext(ctx, "Failed to send authentication success response", "error", err)
		return fmt.Errorf("451 4.3.0 Internal server error")
	}

	return nil
}

// setupRBACContext sets up RBAC context for the authenticated user
func (ah *AuthHandler) setupRBACContext(ctx context.Context, username string) error {
	if ah.sessionStateMachine == nil {
		return nil // No state machine available
	}

	// Create basic RBAC context (in a real implementation, this would query the user's roles)
	rbacContext := &auth.RBACContext{
		Username:    username,
		Roles:       []string{"user"}, // Default role
		Permissions: []auth.Permission{auth.PermissionSMTPAuth, auth.PermissionSMTPSend},
		LastCheck:   time.Now(),
	}

	// Set RBAC context in session state machine
	if err := ah.sessionStateMachine.SetRBACContext(rbacContext); err != nil {
		return fmt.Errorf("failed to set RBAC context: %w", err)
	}

	ah.logger.Info("RBAC context setup for user",
		"username", username,
		"roles", rbacContext.Roles,
		"permissions", rbacContext.Permissions,
	)

	return nil
}

// CheckPermission checks if the current session has a specific permission
func (ah *AuthHandler) CheckPermission(permission auth.Permission) bool {
	if ah.sessionStateMachine == nil {
		return false // No state machine available
	}

	return ah.sessionStateMachine.HasPermission(permission)
}

// validateBase64Input validates base64 input data
func (ah *AuthHandler) validateBase64Input(input string) error {
	if input == "" {
		return fmt.Errorf("empty input")
	}

	// Check for reasonable length limits
	if len(input) > 1000 {
		return fmt.Errorf("input too long")
	}

	// Check for valid base64 characters
	for _, char := range input {
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '+' || char == '/' || char == '=') {
			return fmt.Errorf("invalid base64 character")
		}
	}

	return nil
}

// validateAuthenticationData validates username and password
func (ah *AuthHandler) validateAuthenticationData(ctx context.Context, username, password string) error {
	// Username validation
	if username == "" {
		ah.logger.WarnContext(ctx, "Empty username provided")
		return fmt.Errorf("empty username")
	}

	if len(username) > 255 {
		ah.logger.WarnContext(ctx, "Username too long", "length", len(username))
		return fmt.Errorf("username too long")
	}

	// Check for suspicious patterns in username
	suspiciousPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"UNION", "SELECT", "INSERT", "DELETE", "UPDATE", "DROP",
		"\x00", "\r", "\n",
	}

	usernameUpper := strings.ToUpper(username)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(usernameUpper, strings.ToUpper(pattern)) {
			ah.logger.WarnContext(ctx, "Suspicious pattern in username",
				"username", username,
				"pattern", pattern,
			)
			return fmt.Errorf("invalid username format")
		}
	}

	// Password validation
	if password == "" {
		ah.logger.WarnContext(ctx, "Empty password provided")
		return fmt.Errorf("empty password")
	}

	if len(password) > 1000 {
		ah.logger.WarnContext(ctx, "Password too long", "length", len(password))
		return fmt.Errorf("password too long")
	}

	return nil
}

// checkSecurityConstraints checks various security constraints
func (ah *AuthHandler) checkSecurityConstraints(ctx context.Context, method AuthMethod) error {
	// Check if method is enabled
	if !ah.isMethodEnabled(method) {
		return fmt.Errorf("504 5.7.4 Authentication mechanism not supported")
	}

	// Check TLS requirement for PLAIN
	if method == AuthMethodPlain && ah.securityManager.config.RequireTLSForPlain && !ah.state.IsTLSActive() {
		ah.logger.WarnContext(ctx, "PLAIN authentication requires TLS")
		return fmt.Errorf("538 5.7.11 Encryption required for requested authentication mechanism")
	}

	// Check IP-based rate limiting
	remoteAddr := ah.conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		if ah.isIPRateLimited(host) {
			ah.logger.WarnContext(ctx, "IP rate limited for authentication", "ip", host)
			return fmt.Errorf("421 4.7.0 Too many authentication attempts from this IP")
		}
	}

	return nil
}

// isMethodEnabled checks if an authentication method is enabled
func (ah *AuthHandler) isMethodEnabled(method AuthMethod) bool {
	for _, enabled := range ah.securityManager.config.EnabledMethods {
		if enabled == method {
			return true
		}
	}
	return false
}

// isIPRateLimited checks if an IP is rate limited
func (ah *AuthHandler) isIPRateLimited(ip string) bool {
	ah.securityManager.mu.RLock()
	defer ah.securityManager.mu.RUnlock()

	failure, exists := ah.securityManager.ipFailures[ip]
	if !exists {
		return false
	}

	// Check if rate limit window has passed
	if time.Since(failure.LastTime) > ah.securityManager.config.AuthRateInterval {
		return false
	}

	return failure.Count >= ah.securityManager.config.MaxAuthAttemptsPerIP
}

// isAccountLocked checks if an account is locked
func (ah *AuthHandler) isAccountLocked(username string) bool {
	ah.securityManager.mu.RLock()
	defer ah.securityManager.mu.RUnlock()

	lockInfo, exists := ah.securityManager.accountLockouts[username]
	if !exists {
		return false
	}

	return time.Now().Before(lockInfo.LockedUntil)
}

// recordAuthFailure records an authentication failure
func (ah *AuthHandler) recordAuthFailure(ctx context.Context, username string, method AuthMethod, err error, duration time.Duration) {
	ah.securityManager.mu.Lock()
	defer ah.securityManager.mu.Unlock()

	// Record IP failure
	remoteAddr := ah.conn.RemoteAddr().String()
	if host, _, splitErr := net.SplitHostPort(remoteAddr); splitErr == nil {
		if failure, exists := ah.securityManager.ipFailures[host]; exists {
			failure.Count++
			failure.LastTime = time.Now()
		} else {
			ah.securityManager.ipFailures[host] = &AuthFailureInfo{
				Count:     1,
				LastTime:  time.Now(),
				IPAddress: host,
			}
		}
	}

	// Check if account should be locked
	attempts := ah.state.GetAuthAttempts()
	if attempts >= ah.securityManager.config.MaxAuthAttempts {
		ah.securityManager.accountLockouts[username] = &AccountLockInfo{
			LockedUntil: time.Now().Add(ah.securityManager.config.AccountLockoutDuration),
			Reason:      "Too many failed authentication attempts",
		}

		ah.logger.WarnContext(ctx, "Account locked due to failed authentication attempts",
			"username", username,
			"attempts", attempts,
			"locked_until", ah.securityManager.accountLockouts[username].LockedUntil,
		)
	}

	// Log security event
	ah.logger.WarnContext(ctx, "Authentication failure recorded",
		"username", username,
		"method", string(method),
		"error", err,
		"duration", duration,
		"attempts", attempts,
		"ip", remoteAddr,
	)
}

// recordAuthSuccess records a successful authentication
func (ah *AuthHandler) recordAuthSuccess(ctx context.Context, username string, method AuthMethod, duration time.Duration) {
	ah.securityManager.mu.Lock()
	defer ah.securityManager.mu.Unlock()

	// Clear IP failures on successful auth
	remoteAddr := ah.conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		delete(ah.securityManager.ipFailures, host)
	}

	// Clear account lockout
	delete(ah.securityManager.accountLockouts, username)

	// Log security event
	ah.logger.InfoContext(ctx, "Authentication success recorded",
		"username", username,
		"method", string(method),
		"duration", duration,
		"ip", remoteAddr,
	)
}

// GetEnabledMethods returns the list of enabled authentication methods
func (ah *AuthHandler) GetEnabledMethods() []AuthMethod {
	return ah.securityManager.config.EnabledMethods
}

// GetAuthMethodsString returns enabled methods as EHLO response string
func (ah *AuthHandler) GetAuthMethodsString() string {
	methods := make([]string, len(ah.securityManager.config.EnabledMethods))
	for i, method := range ah.securityManager.config.EnabledMethods {
		methods[i] = string(method)
	}
	return strings.Join(methods, " ")
}

// Cleanup performs cleanup of expired entries
func (ah *AuthHandler) Cleanup(ctx context.Context) {
	ah.securityManager.mu.Lock()
	defer ah.securityManager.mu.Unlock()

	now := time.Now()

	// Clean up expired IP failures
	for ip, failure := range ah.securityManager.ipFailures {
		if now.Sub(failure.LastTime) > ah.securityManager.config.AuthRateInterval {
			delete(ah.securityManager.ipFailures, ip)
		}
	}

	// Clean up expired account lockouts
	for username, lockInfo := range ah.securityManager.accountLockouts {
		if now.After(lockInfo.LockedUntil) {
			delete(ah.securityManager.accountLockouts, username)
		}
	}

	ah.logger.DebugContext(ctx, "Authentication security cleanup completed",
		"remaining_ip_failures", len(ah.securityManager.ipFailures),
		"remaining_lockouts", len(ah.securityManager.accountLockouts),
	)
}
