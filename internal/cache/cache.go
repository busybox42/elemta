package cache

import (
	"context"
	"errors"
	"time"
)

// Common errors
var (
	ErrNotFound      = errors.New("key not found in cache")
	ErrAlreadyExists = errors.New("key already exists in cache")
	ErrNotConnected  = errors.New("not connected to cache")
)

// Cache defines the interface that all cache implementations must satisfy
type Cache interface {
	// Connect establishes a connection to the cache
	Connect() error

	// Close closes the connection to the cache
	Close() error

	// IsConnected returns true if the cache is connected
	IsConnected() bool

	// Name returns the name of the cache
	Name() string

	// Type returns the type of the cache (e.g., "redis", "memcached", etc.)
	Type() string

	// Get retrieves a value from the cache
	Get(ctx context.Context, key string) (interface{}, error)

	// Set stores a value in the cache with an optional expiration
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error

	// SetNX sets a value in the cache only if the key does not exist
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error)

	// Delete removes a value from the cache
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in the cache
	Exists(ctx context.Context, key string) (bool, error)

	// Increment increments a numeric value by the given amount
	Increment(ctx context.Context, key string, amount int64) (int64, error)

	// Decrement decrements a numeric value by the given amount
	Decrement(ctx context.Context, key string, amount int64) (int64, error)

	// Expire sets an expiration time on a key
	Expire(ctx context.Context, key string, expiration time.Duration) error

	// FlushAll removes all keys from the cache
	FlushAll(ctx context.Context) error
}

// Config represents the configuration for a cache
type Config struct {
	Type     string                 // Type of cache (redis, memcached, etc.)
	Name     string                 // Name of this cache instance
	Host     string                 // Hostname or IP address
	Port     int                    // Port number
	Password string                 // Password for authentication
	Database int                    // Database number (for Redis)
	Options  map[string]interface{} // Additional options specific to the cache type
}

// Factory creates cache instances based on configuration
func Factory(config Config) (Cache, error) {
	switch config.Type {
	case "redis":
		return NewRedis(config), nil
	case "memory":
		return NewMemory(config), nil
	default:
		return nil, errors.New("unsupported cache type: " + config.Type)
	}
}

// Manager manages multiple cache instances
type Manager struct {
	caches map[string]Cache
}

// NewManager creates a new cache manager
func NewManager() *Manager {
	return &Manager{
		caches: make(map[string]Cache),
	}
}

// Register adds a cache to the manager
func (m *Manager) Register(cache Cache) error {
	name := cache.Name()
	if _, exists := m.caches[name]; exists {
		return errors.New("cache with name '" + name + "' already registered")
	}

	m.caches[name] = cache
	return nil
}

// Get retrieves a cache by name
func (m *Manager) Get(name string) (Cache, bool) {
	cache, exists := m.caches[name]
	return cache, exists
}

// List returns all registered caches
func (m *Manager) List() map[string]Cache {
	return m.caches
}

// Remove removes a cache from the manager
func (m *Manager) Remove(name string) error {
	cache, exists := m.caches[name]
	if !exists {
		return errors.New("cache '" + name + "' not found")
	}

	if cache.IsConnected() {
		if err := cache.Close(); err != nil {
			return err
		}
	}

	delete(m.caches, name)
	return nil
}

// CloseAll closes all caches
func (m *Manager) CloseAll() error {
	var errs []error
	for name, cache := range m.caches {
		if cache.IsConnected() {
			if err := cache.Close(); err != nil {
				errs = append(errs, errors.New("failed to close cache '"+name+"': "+err.Error()))
			}
		}
	}

	if len(errs) > 0 {
		return errors.New("errors closing caches")
	}

	return nil
}
