package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// API key errors
var (
	ErrAPIKeyNotFound = errors.New("API key not found")
	ErrAPIKeyExpired  = errors.New("API key expired")
	ErrAPIKeyRevoked  = errors.New("API key revoked")
	ErrInvalidAPIKey  = errors.New("invalid API key format")
)

// APIKey represents an API key
type APIKey struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	KeyHash     string            `json:"key_hash"` // SHA256 hash of the key
	Username    string            `json:"username"` // Associated user
	Permissions []Permission      `json:"permissions"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	IsActive    bool              `json:"is_active"`
	IsRevoked   bool              `json:"is_revoked"`
}

// APIKeyManager manages API keys
type APIKeyManager struct {
	keys map[string]*APIKey // key: key hash
	mu   sync.RWMutex
	rbac *RBAC
}

// NewAPIKeyManager creates a new API key manager
func NewAPIKeyManager(rbac *RBAC) *APIKeyManager {
	return &APIKeyManager{
		keys: make(map[string]*APIKey),
		rbac: rbac,
	}
}

// CreateAPIKey creates a new API key
func (m *APIKeyManager) CreateAPIKey(username, name, description string, permissions []Permission, expiryDuration *time.Duration) (*APIKey, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a secure random key
	keyBytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Encode key as base64
	keyString := base64.URLEncoding.EncodeToString(keyBytes)
	keyString = "elemta_" + keyString // Add prefix for identification

	// Hash the key for storage
	hash := sha256.Sum256([]byte(keyString))
	keyHash := fmt.Sprintf("%x", hash)

	// Generate unique ID
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate API key ID: %w", err)
	}
	keyID := fmt.Sprintf("api_%x", idBytes)

	// Calculate expiry time
	var expiresAt *time.Time
	if expiryDuration != nil {
		expiry := time.Now().Add(*expiryDuration)
		expiresAt = &expiry
	}

	// Validate permissions
	for _, perm := range permissions {
		if m.rbac != nil && !m.rbac.isValidPermission(perm) {
			return nil, "", fmt.Errorf("%w: %s", ErrInvalidPermission, perm)
		}
	}

	// Create API key
	apiKey := &APIKey{
		ID:          keyID,
		Name:        name,
		Description: description,
		KeyHash:     keyHash,
		Username:    username,
		Permissions: permissions,
		Metadata:    make(map[string]string),
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		IsActive:    true,
		IsRevoked:   false,
	}

	// Store the key
	m.keys[keyHash] = apiKey

	return apiKey, keyString, nil
}

// ValidateAPIKey validates an API key and returns the associated key info
func (m *APIKeyManager) ValidateAPIKey(keyString string) (*APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check key format
	if !strings.HasPrefix(keyString, "elemta_") {
		return nil, ErrInvalidAPIKey
	}

	// Hash the provided key
	hash := sha256.Sum256([]byte(keyString))
	keyHash := fmt.Sprintf("%x", hash)

	// Find the key
	apiKey, exists := m.keys[keyHash]
	if !exists {
		return nil, ErrAPIKeyNotFound
	}

	// Check if key is active
	if !apiKey.IsActive {
		return nil, ErrAPIKeyRevoked
	}

	// Check if key is revoked
	if apiKey.IsRevoked {
		return nil, ErrAPIKeyRevoked
	}

	// Check if key is expired
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, ErrAPIKeyExpired
	}

	// Update last used time (in a real implementation, you might want to do this asynchronously)
	now := time.Now()
	apiKey.LastUsedAt = &now

	// Return a copy to prevent external modification
	keyCopy := *apiKey
	keyCopy.Permissions = make([]Permission, len(apiKey.Permissions))
	copy(keyCopy.Permissions, apiKey.Permissions)

	return &keyCopy, nil
}

// HasPermission checks if an API key has a specific permission
func (m *APIKeyManager) HasPermission(keyString string, permission Permission) (bool, error) {
	apiKey, err := m.ValidateAPIKey(keyString)
	if err != nil {
		return false, err
	}

	// Check if the key has the specific permission
	for _, perm := range apiKey.Permissions {
		if perm == permission {
			return true, nil
		}
	}

	return false, nil
}

// CheckPermission returns an error if the API key doesn't have the permission
func (m *APIKeyManager) CheckPermission(keyString string, permission Permission) error {
	hasPermission, err := m.HasPermission(keyString, permission)
	if err != nil {
		return err
	}

	if !hasPermission {
		return fmt.Errorf("%w: API key lacks permission %s", ErrPermissionDenied, permission)
	}

	return nil
}

// RevokeAPIKey revokes an API key
func (m *APIKeyManager) RevokeAPIKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the key by ID
	for _, apiKey := range m.keys {
		if apiKey.ID == keyID {
			apiKey.IsRevoked = true
			apiKey.IsActive = false
			return nil
		}
	}

	return ErrAPIKeyNotFound
}

// DeleteAPIKey permanently deletes an API key
func (m *APIKeyManager) DeleteAPIKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find and delete the key by ID
	for keyHash, apiKey := range m.keys {
		if apiKey.ID == keyID {
			delete(m.keys, keyHash)
			return nil
		}
	}

	return ErrAPIKeyNotFound
}

// UpdateAPIKey updates an API key's metadata
func (m *APIKeyManager) UpdateAPIKey(keyID, name, description string, permissions []Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the key by ID
	for _, apiKey := range m.keys {
		if apiKey.ID == keyID {
			// Validate permissions
			if m.rbac != nil {
				for _, perm := range permissions {
					if !m.rbac.isValidPermission(perm) {
						return fmt.Errorf("%w: %s", ErrInvalidPermission, perm)
					}
				}
			}

			apiKey.Name = name
			apiKey.Description = description
			apiKey.Permissions = permissions
			return nil
		}
	}

	return ErrAPIKeyNotFound
}

// ListAPIKeys returns all API keys for a user
func (m *APIKeyManager) ListAPIKeys(username string) []*APIKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var userKeys []*APIKey
	for _, apiKey := range m.keys {
		if apiKey.Username == username {
			// Return a copy to prevent external modification
			keyCopy := *apiKey
			keyCopy.Permissions = make([]Permission, len(apiKey.Permissions))
			copy(keyCopy.Permissions, apiKey.Permissions)
			// Don't include the key hash in the response
			keyCopy.KeyHash = "[REDACTED]"
			userKeys = append(userKeys, &keyCopy)
		}
	}

	return userKeys
}

// ListAllAPIKeys returns all API keys (admin only)
func (m *APIKeyManager) ListAllAPIKeys() []*APIKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var allKeys []*APIKey
	for _, apiKey := range m.keys {
		// Return a copy to prevent external modification
		keyCopy := *apiKey
		keyCopy.Permissions = make([]Permission, len(apiKey.Permissions))
		copy(keyCopy.Permissions, apiKey.Permissions)
		// Don't include the key hash in the response
		keyCopy.KeyHash = "[REDACTED]"
		allKeys = append(allKeys, &keyCopy)
	}

	return allKeys
}

// GetAPIKey returns an API key by ID
func (m *APIKeyManager) GetAPIKey(keyID string) (*APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, apiKey := range m.keys {
		if apiKey.ID == keyID {
			// Return a copy to prevent external modification
			keyCopy := *apiKey
			keyCopy.Permissions = make([]Permission, len(apiKey.Permissions))
			copy(keyCopy.Permissions, apiKey.Permissions)
			// Don't include the key hash in the response
			keyCopy.KeyHash = "[REDACTED]"
			return &keyCopy, nil
		}
	}

	return nil, ErrAPIKeyNotFound
}

// CleanupExpiredKeys removes expired API keys
func (m *APIKeyManager) CleanupExpiredKeys() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for keyHash, apiKey := range m.keys {
		if apiKey.ExpiresAt != nil && now.After(*apiKey.ExpiresAt) {
			delete(m.keys, keyHash)
			cleaned++
		}
	}

	return cleaned
}

// ExtractKeyFromHeader extracts API key from Authorization header
func ExtractKeyFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrInvalidAPIKey
	}

	// Support both "Bearer" and "ApiKey" schemes
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), nil
	}

	if strings.HasPrefix(authHeader, "ApiKey ") {
		return strings.TrimPrefix(authHeader, "ApiKey "), nil
	}

	// Also support direct key (no scheme)
	if strings.HasPrefix(authHeader, "elemta_") {
		return authHeader, nil
	}

	return "", ErrInvalidAPIKey
}

// GenerateAPIKeyStats returns statistics about API keys
func (m *APIKeyManager) GenerateAPIKeyStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalKeys := len(m.keys)
	activeKeys := 0
	expiredKeys := 0
	revokedKeys := 0
	now := time.Now()

	for _, apiKey := range m.keys {
		if apiKey.IsRevoked {
			revokedKeys++
		} else if apiKey.ExpiresAt != nil && now.After(*apiKey.ExpiresAt) {
			expiredKeys++
		} else if apiKey.IsActive {
			activeKeys++
		}
	}

	return map[string]interface{}{
		"total_keys":   totalKeys,
		"active_keys":  activeKeys,
		"expired_keys": expiredKeys,
		"revoked_keys": revokedKeys,
	}
}
