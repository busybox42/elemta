package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Session errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidSession  = errors.New("invalid session")
)

// Session represents a web session
type Session struct {
	ID        string            `json:"id"`
	Username  string            `json:"username"`
	UserAgent string            `json:"user_agent"`
	IPAddress string            `json:"ip_address"`
	Data      map[string]string `json:"data"`
	CreatedAt time.Time         `json:"created_at"`
	LastSeen  time.Time         `json:"last_seen"`
	ExpiresAt time.Time         `json:"expires_at"`
	IsActive  bool              `json:"is_active"`
}

// SessionManager manages web sessions
type SessionManager struct {
	sessions     map[string]*Session // key: session ID
	mu           sync.RWMutex
	maxAge       time.Duration
	cookieName   string
	secureCookie bool
	httpOnly     bool
	sameSite     http.SameSite
}

// SessionConfig represents session configuration
type SessionConfig struct {
	MaxAge          time.Duration `json:"max_age"`
	CookieName      string        `json:"cookie_name"`
	SecureCookie    bool          `json:"secure_cookie"`
	HTTPOnly        bool          `json:"http_only"`
	SameSite        string        `json:"same_site"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// NewSessionManager creates a new session manager
func NewSessionManager(config SessionConfig) *SessionManager {
	if config.MaxAge == 0 {
		config.MaxAge = 24 * time.Hour // Default 24 hours
	}
	if config.CookieName == "" {
		config.CookieName = "elemta_session"
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour // Default 1 hour cleanup interval
	}

	var sameSite http.SameSite
	switch config.SameSite {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	default:
		sameSite = http.SameSiteLaxMode
	}

	sm := &SessionManager{
		sessions:     make(map[string]*Session),
		maxAge:       config.MaxAge,
		cookieName:   config.CookieName,
		secureCookie: config.SecureCookie,
		httpOnly:     config.HTTPOnly,
		sameSite:     sameSite,
	}

	// Start cleanup goroutine
	go sm.cleanupLoop(config.CleanupInterval)

	return sm
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(username, userAgent, ipAddress string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		Username:  username,
		UserAgent: userAgent,
		IPAddress: ipAddress,
		Data:      make(map[string]string),
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(sm.maxAge),
		IsActive:  true,
	}

	sm.sessions[sessionID] = session

	// Return a copy to prevent external modification
	sessionCopy := *session
	sessionCopy.Data = make(map[string]string)
	for k, v := range session.Data {
		sessionCopy.Data[k] = v
	}

	return &sessionCopy, nil
}

// ValidateSession validates a session and updates last seen time
func (sm *SessionManager) ValidateSession(sessionID string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Remove expired session
		delete(sm.sessions, sessionID)
		return nil, ErrSessionExpired
	}

	// Check if session is active
	if !session.IsActive {
		return nil, ErrInvalidSession
	}

	// Update last seen time
	session.LastSeen = time.Now()

	// Return a copy to prevent external modification
	sessionCopy := *session
	sessionCopy.Data = make(map[string]string)
	for k, v := range session.Data {
		sessionCopy.Data[k] = v
	}

	return &sessionCopy, nil
}

// SetCookie sets a session cookie in the HTTP response
func (sm *SessionManager) SetCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     sm.cookieName,
		Value:    sessionID,
		MaxAge:   int(sm.maxAge.Seconds()),
		HttpOnly: sm.httpOnly,
		Secure:   sm.secureCookie,
		SameSite: sm.sameSite,
		Path:     "/",
	}

	http.SetCookie(w, cookie)
}

// GetSessionFromRequest extracts session ID from HTTP request
func (sm *SessionManager) GetSessionFromRequest(r *http.Request) string {
	// Try to get session ID from cookie first
	if cookie, err := r.Cookie(sm.cookieName); err == nil {
		return cookie.Value
	}

	return ""
}

// CleanupExpiredSessions removes expired and inactive sessions
func (sm *SessionManager) CleanupExpiredSessions() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for sessionID, session := range sm.sessions {
		if now.After(session.ExpiresAt) || !session.IsActive {
			delete(sm.sessions, sessionID)
			cleaned++
		}
	}

	return cleaned
}

// cleanupLoop runs periodic cleanup of expired sessions
func (sm *SessionManager) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		<-ticker.C
		sm.CleanupExpiredSessions()
	}
}

// generateSessionID generates a secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// RevokeSession revokes a session by ID
func (sm *SessionManager) RevokeSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	session.IsActive = false
	return nil
}

// ClearCookie clears the session cookie
func (sm *SessionManager) ClearCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: sm.httpOnly,
		Secure:   sm.secureCookie,
		SameSite: sm.sameSite,
		Path:     "/",
	}

	http.SetCookie(w, cookie)
}
