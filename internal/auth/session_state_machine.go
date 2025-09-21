package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// SessionState represents the current state of an authentication session
type SessionState int

const (
	// SessionStateInitial - Session just created, no authentication attempted
	SessionStateInitial SessionState = iota
	// SessionStateAuthenticating - Authentication in progress
	SessionStateAuthenticating
	// SessionStateAuthenticated - Successfully authenticated
	SessionStateAuthenticated
	// SessionStateFailed - Authentication failed
	SessionStateFailed
	// SessionStateLocked - Account locked due to failures
	SessionStateLocked
	// SessionStateExpired - Session expired
	SessionStateExpired
	// SessionStateInvalidated - Session invalidated (e.g., due to security concerns)
	SessionStateInvalidated
)

// String returns a string representation of the session state
func (s SessionState) String() string {
	switch s {
	case SessionStateInitial:
		return "initial"
	case SessionStateAuthenticating:
		return "authenticating"
	case SessionStateAuthenticated:
		return "authenticated"
	case SessionStateFailed:
		return "failed"
	case SessionStateLocked:
		return "locked"
	case SessionStateExpired:
		return "expired"
	case SessionStateInvalidated:
		return "invalidated"
	default:
		return "unknown"
	}
}

// IsValidTransition checks if a state transition is valid
func (s SessionState) IsValidTransition(newState SessionState) bool {
	switch s {
	case SessionStateInitial:
		return newState == SessionStateAuthenticating || newState == SessionStateExpired || newState == SessionStateInvalidated
	case SessionStateAuthenticating:
		return newState == SessionStateAuthenticated || newState == SessionStateFailed || newState == SessionStateLocked || newState == SessionStateExpired || newState == SessionStateInvalidated
	case SessionStateAuthenticated:
		return newState == SessionStateExpired || newState == SessionStateInvalidated
	case SessionStateFailed:
		return newState == SessionStateAuthenticating || newState == SessionStateLocked || newState == SessionStateExpired || newState == SessionStateInvalidated
	case SessionStateLocked:
		return newState == SessionStateExpired || newState == SessionStateInvalidated
	case SessionStateExpired, SessionStateInvalidated:
		return false // Terminal states
	default:
		return false
	}
}

// SessionStateMachine manages secure session state transitions
type SessionStateMachine struct {
	mu                sync.RWMutex
	currentState      SessionState
	previousState     SessionState
	stateHistory      []SessionStateTransition
	createdAt         time.Time
	lastTransition    time.Time
	expiresAt         time.Time
	maxAge            time.Duration
	failureCount      int
	maxFailures       int
	lockoutDuration   time.Duration
	lockoutUntil      *time.Time
	sessionID         string
	username          string
	ipAddress         string
	userAgent         string
	rbacContext       *RBACContext
	logger            *slog.Logger
}

// SessionStateTransition records a state transition
type SessionStateTransition struct {
	FromState   SessionState `json:"from_state"`
	ToState     SessionState `json:"to_state"`
	Timestamp   time.Time    `json:"timestamp"`
	Reason      string       `json:"reason"`
	IPAddress   string       `json:"ip_address"`
	UserAgent   string       `json:"user_agent"`
}

// RBACContext holds role-based access control information
type RBACContext struct {
	Username   string     `json:"username"`
	Roles      []string   `json:"roles"`
	Permissions []Permission `json:"permissions"`
	LastCheck  time.Time  `json:"last_check"`
}

// SessionStateMachineConfig configures the session state machine
type SessionStateMachineConfig struct {
	MaxAge            time.Duration `json:"max_age"`
	MaxFailures       int           `json:"max_failures"`
	LockoutDuration   time.Duration `json:"lockout_duration"`
	MaxStateHistory   int           `json:"max_state_history"`
}

// DefaultSessionStateMachineConfig returns sensible defaults
func DefaultSessionStateMachineConfig() *SessionStateMachineConfig {
	return &SessionStateMachineConfig{
		MaxAge:            30 * time.Minute,
		MaxFailures:       5,
		LockoutDuration:   30 * time.Minute,
		MaxStateHistory:   10,
	}
}

// NewSessionStateMachine creates a new secure session state machine
func NewSessionStateMachine(config *SessionStateMachineConfig, ipAddress, userAgent string, logger *slog.Logger) (*SessionStateMachine, error) {
	if config == nil {
		config = DefaultSessionStateMachineConfig()
	}

	// Generate secure session ID
	sessionID, err := generateSecureSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	ssm := &SessionStateMachine{
		currentState:   SessionStateInitial,
		previousState:  SessionStateInitial,
		stateHistory:   make([]SessionStateTransition, 0, config.MaxStateHistory),
		createdAt:      now,
		lastTransition: now,
		expiresAt:      now.Add(config.MaxAge),
		maxAge:         config.MaxAge,
		maxFailures:    config.MaxFailures,
		lockoutDuration: config.LockoutDuration,
		sessionID:      sessionID,
		ipAddress:      ipAddress,
		userAgent:      userAgent,
		logger:         logger.With("component", "session-state-machine", "session_id", sessionID),
	}

	// Record initial state
	ssm.recordTransition(SessionStateInitial, "session_created")

	ssm.logger.Info("Session state machine created",
		"session_id", sessionID,
		"ip_address", ipAddress,
		"max_age", config.MaxAge,
		"max_failures", config.MaxFailures,
	)

	return ssm, nil
}

// TransitionTo attempts to transition to a new state with validation
func (ssm *SessionStateMachine) TransitionTo(newState SessionState, reason string) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	// Check if session is expired
	if ssm.isExpired() {
		return fmt.Errorf("session expired: %w", ErrSessionExpired)
	}

	// Check if session is in terminal state
	if ssm.currentState == SessionStateExpired || ssm.currentState == SessionStateInvalidated {
		return fmt.Errorf("session in terminal state: %s", ssm.currentState.String())
	}

	// Validate transition
	if !ssm.currentState.IsValidTransition(newState) {
		return fmt.Errorf("invalid state transition from %s to %s", ssm.currentState.String(), newState.String())
	}

	// Check lockout status
	if ssm.isLockedOut() {
		if newState != SessionStateExpired && newState != SessionStateInvalidated {
			return fmt.Errorf("session locked until %v", ssm.lockoutUntil)
		}
	}

	// Perform state-specific validations
	if err := ssm.validateStateTransition(newState); err != nil {
		return fmt.Errorf("state transition validation failed: %w", err)
	}

	// Record the transition
	ssm.recordTransition(newState, reason)

	// Update state
	ssm.previousState = ssm.currentState
	ssm.currentState = newState
	ssm.lastTransition = time.Now()

	// Handle state-specific actions
	ssm.handleStateTransition(newState)

	ssm.logger.Info("Session state transitioned",
		"from_state", ssm.previousState.String(),
		"to_state", ssm.currentState.String(),
		"reason", reason,
		"failure_count", ssm.failureCount,
	)

	return nil
}

// GetCurrentState returns the current session state
func (ssm *SessionStateMachine) GetCurrentState() SessionState {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.currentState
}

// IsAuthenticated checks if the session is in authenticated state
func (ssm *SessionStateMachine) IsAuthenticated() bool {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.currentState == SessionStateAuthenticated && !ssm.isExpired() && !ssm.isLockedOut()
}

// IsExpired checks if the session has expired
func (ssm *SessionStateMachine) IsExpired() bool {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.isExpired()
}

// IsLockedOut checks if the session is locked out
func (ssm *SessionStateMachine) IsLockedOut() bool {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.isLockedOut()
}

// GetSessionID returns the session ID
func (ssm *SessionStateMachine) GetSessionID() string {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.sessionID
}

// GetUsername returns the authenticated username
func (ssm *SessionStateMachine) GetUsername() string {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.username
}

// SetUsername sets the authenticated username (in authenticating or authenticated state)
func (ssm *SessionStateMachine) SetUsername(username string) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	if ssm.currentState != SessionStateAuthenticating && ssm.currentState != SessionStateAuthenticated {
		return fmt.Errorf("cannot set username in state: %s", ssm.currentState.String())
	}

	ssm.username = username
	ssm.logger.Info("Username set for session", "username", username)
	return nil
}

// SetRBACContext sets the RBAC context for the session
func (ssm *SessionStateMachine) SetRBACContext(ctx *RBACContext) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	if ssm.currentState != SessionStateAuthenticated {
		return fmt.Errorf("cannot set RBAC context in state: %s", ssm.currentState.String())
	}

	ssm.rbacContext = ctx
	ssm.logger.Info("RBAC context set for session", "username", ctx.Username, "roles", ctx.Roles)
	return nil
}

// GetRBACContext returns the RBAC context
func (ssm *SessionStateMachine) GetRBACContext() *RBACContext {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.rbacContext
}

// HasPermission checks if the session has a specific permission
func (ssm *SessionStateMachine) HasPermission(permission Permission) bool {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()

	if ssm.rbacContext == nil {
		return false
	}

	for _, p := range ssm.rbacContext.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// Invalidate invalidates the session (security concern)
func (ssm *SessionStateMachine) Invalidate(reason string) error {
	return ssm.TransitionTo(SessionStateInvalidated, reason)
}

// RegenerateSessionID regenerates the session ID to prevent session fixation attacks
func (ssm *SessionStateMachine) RegenerateSessionID() error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	// Generate new secure session ID
	newSessionID, err := generateSecureSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate new session ID: %w", err)
	}

	oldSessionID := ssm.sessionID
	ssm.sessionID = newSessionID

	ssm.logger.Info("Session ID regenerated for security",
		"old_session_id", oldSessionID,
		"new_session_id", newSessionID,
	)

	return nil
}

// ExtendExpiration extends the session expiration time
func (ssm *SessionStateMachine) ExtendExpiration(duration time.Duration) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	if ssm.currentState == SessionStateExpired || ssm.currentState == SessionStateInvalidated {
		return fmt.Errorf("cannot extend expired or invalidated session")
	}

	ssm.expiresAt = time.Now().Add(duration)
	ssm.logger.Info("Session expiration extended", "new_expires_at", ssm.expiresAt)
	return nil
}

// GetStateHistory returns the state transition history
func (ssm *SessionStateMachine) GetStateHistory() []SessionStateTransition {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()

	// Return a copy to prevent external modification
	history := make([]SessionStateTransition, len(ssm.stateHistory))
	copy(history, ssm.stateHistory)
	return history
}

// Private helper methods

func (ssm *SessionStateMachine) isExpired() bool {
	return time.Now().After(ssm.expiresAt)
}

func (ssm *SessionStateMachine) isLockedOut() bool {
	return ssm.lockoutUntil != nil && time.Now().Before(*ssm.lockoutUntil)
}

func (ssm *SessionStateMachine) recordTransition(newState SessionState, reason string) {
	transition := SessionStateTransition{
		FromState: ssm.currentState,
		ToState:   newState,
		Timestamp: time.Now(),
		Reason:    reason,
		IPAddress: ssm.ipAddress,
		UserAgent: ssm.userAgent,
	}

	ssm.stateHistory = append(ssm.stateHistory, transition)

	// Trim history if it exceeds max size
	if len(ssm.stateHistory) > ssm.maxFailures*2 { // Allow some extra history
		ssm.stateHistory = ssm.stateHistory[1:]
	}
}

func (ssm *SessionStateMachine) validateStateTransition(newState SessionState) error {
	switch newState {
	case SessionStateAuthenticated:
		// Ensure we have a username
		if ssm.username == "" {
			return fmt.Errorf("username required for authenticated state")
		}
	case SessionStateLocked:
		// Ensure we have exceeded failure threshold
		if ssm.failureCount < ssm.maxFailures {
			return fmt.Errorf("insufficient failures for lockout")
		}
	}
	return nil
}

func (ssm *SessionStateMachine) handleStateTransition(newState SessionState) {
	switch newState {
	case SessionStateFailed:
		ssm.failureCount++
		ssm.logger.Warn("Authentication failure recorded",
			"failure_count", ssm.failureCount,
			"max_failures", ssm.maxFailures,
		)

		// Check if we should lock the session
		if ssm.failureCount >= ssm.maxFailures {
			lockoutUntil := time.Now().Add(ssm.lockoutDuration)
			ssm.lockoutUntil = &lockoutUntil
			ssm.logger.Warn("Session locked due to excessive failures",
				"lockout_until", lockoutUntil,
			)
		}

	case SessionStateAuthenticated:
		// Reset failure count on successful authentication
		ssm.failureCount = 0
		ssm.lockoutUntil = nil
		ssm.logger.Info("Authentication successful, failure count reset")

	case SessionStateExpired:
		ssm.logger.Info("Session expired")

	case SessionStateInvalidated:
		ssm.logger.Warn("Session invalidated for security reasons")
	}
}

// generateSecureSessionID generates a cryptographically secure session ID
func generateSecureSessionID() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode as base64 URL-safe string
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ConstantTimeStringCompare performs constant-time string comparison
func ConstantTimeStringCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
