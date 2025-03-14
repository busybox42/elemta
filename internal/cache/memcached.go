package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
)

// Memcached implements the Cache interface for Memcached
type Memcached struct {
	client      *memcache.Client
	config      Config
	isConnected bool
}

// NewMemcached creates a new Memcached cache
func NewMemcached(config Config) *Memcached {
	return &Memcached{
		config: config,
	}
}

// Connect establishes a connection to the Memcached server
func (m *Memcached) Connect() error {
	if m.isConnected {
		return nil
	}

	// Build server list
	servers := []string{}

	// If host and port are specified, use them
	if m.config.Host != "" {
		port := m.config.Port
		if port == 0 {
			port = 11211 // Default Memcached port
		}
		servers = append(servers, fmt.Sprintf("%s:%d", m.config.Host, port))
	}

	// Check for additional servers in options
	if additionalServers, ok := m.config.Options["servers"].([]string); ok && len(additionalServers) > 0 {
		servers = append(servers, additionalServers...)
	}

	// If no servers are specified, use localhost
	if len(servers) == 0 {
		servers = append(servers, "localhost:11211")
	}

	// Create client
	m.client = memcache.New(servers...)

	// Configure client
	if maxIdleConns, ok := m.config.Options["max_idle_conns"].(int); ok {
		m.client.MaxIdleConns = maxIdleConns
	}

	if timeout, ok := m.config.Options["timeout"].(time.Duration); ok {
		m.client.Timeout = timeout
	}

	// Test connection
	if err := m.client.Ping(); err != nil {
		return fmt.Errorf("failed to connect to Memcached: %w", err)
	}

	m.isConnected = true
	return nil
}

// Close closes the connection to the Memcached server
func (m *Memcached) Close() error {
	if !m.isConnected {
		return nil
	}
	m.isConnected = false
	return nil
}

// IsConnected returns true if the cache is connected
func (m *Memcached) IsConnected() bool {
	return m.isConnected
}

// Name returns the name of the cache
func (m *Memcached) Name() string {
	if m.config.Name != "" {
		return m.config.Name
	}
	return "memcached"
}

// Type returns the type of the cache
func (m *Memcached) Type() string {
	return "memcached"
}

// Get retrieves a value from the cache
func (m *Memcached) Get(ctx context.Context, key string) (interface{}, error) {
	if !m.isConnected {
		return nil, ErrNotConnected
	}

	item, err := m.client.Get(key)
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal(item.Value, &value); err != nil {
		return nil, err
	}

	return value, nil
}

// Set stores a value in the cache with an optional expiration
func (m *Memcached) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if !m.isConnected {
		return ErrNotConnected
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	// Convert expiration to seconds
	expirationSeconds := int32(0)
	if expiration > 0 {
		expirationSeconds = int32(expiration.Seconds())
	}

	item := &memcache.Item{
		Key:        key,
		Value:      data,
		Expiration: expirationSeconds,
	}

	return m.client.Set(item)
}

// SetNX sets a value in the cache only if the key does not exist
func (m *Memcached) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	if !m.isConnected {
		return false, ErrNotConnected
	}

	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}

	// Convert expiration to seconds
	expirationSeconds := int32(0)
	if expiration > 0 {
		expirationSeconds = int32(expiration.Seconds())
	}

	item := &memcache.Item{
		Key:        key,
		Value:      data,
		Expiration: expirationSeconds,
	}

	err = m.client.Add(item)
	if err != nil {
		if errors.Is(err, memcache.ErrNotStored) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// Delete removes a value from the cache
func (m *Memcached) Delete(ctx context.Context, key string) error {
	if !m.isConnected {
		return ErrNotConnected
	}

	err := m.client.Delete(key)
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return nil // Key doesn't exist, which is fine
		}
		return err
	}

	return nil
}

// Exists checks if a key exists in the cache
func (m *Memcached) Exists(ctx context.Context, key string) (bool, error) {
	if !m.isConnected {
		return false, ErrNotConnected
	}

	_, err := m.client.Get(key)
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// Increment increments a numeric value by the given amount
func (m *Memcached) Increment(ctx context.Context, key string, amount int64) (int64, error) {
	if !m.isConnected {
		return 0, ErrNotConnected
	}

	// Check if key exists
	exists, err := m.Exists(ctx, key)
	if err != nil {
		return 0, err
	}

	if !exists {
		// Initialize with amount
		if err := m.Set(ctx, key, strconv.FormatInt(amount, 10), 0); err != nil {
			return 0, err
		}
		return amount, nil
	}

	// Increment existing value
	newValue, err := m.client.Increment(key, uint64(amount))
	if err != nil {
		return 0, err
	}

	return int64(newValue), nil
}

// Decrement decrements a numeric value by the given amount
func (m *Memcached) Decrement(ctx context.Context, key string, amount int64) (int64, error) {
	if !m.isConnected {
		return 0, ErrNotConnected
	}

	// Check if key exists
	exists, err := m.Exists(ctx, key)
	if err != nil {
		return 0, err
	}

	if !exists {
		// Initialize with 0
		if err := m.Set(ctx, key, "0", 0); err != nil {
			return 0, err
		}
		return 0, nil
	}

	// Decrement existing value
	newValue, err := m.client.Decrement(key, uint64(amount))
	if err != nil {
		return 0, err
	}

	return int64(newValue), nil
}

// Expire sets an expiration time on a key
func (m *Memcached) Expire(ctx context.Context, key string, expiration time.Duration) error {
	if !m.isConnected {
		return ErrNotConnected
	}

	// Get current value
	item, err := m.client.Get(key)
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return ErrNotFound
		}
		return err
	}

	// Convert expiration to seconds
	expirationSeconds := int32(0)
	if expiration > 0 {
		expirationSeconds = int32(expiration.Seconds())
	}

	// Update expiration
	item.Expiration = expirationSeconds
	return m.client.Set(item)
}

// FlushAll removes all keys from the cache
func (m *Memcached) FlushAll(ctx context.Context) error {
	if !m.isConnected {
		return ErrNotConnected
	}

	return m.client.FlushAll()
}
