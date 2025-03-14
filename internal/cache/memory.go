package cache

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Item represents a cached item with expiration
type Item struct {
	Value      interface{}
	Expiration int64 // Unix timestamp in nanoseconds
}

// Memory implements the Cache interface for in-memory caching
type Memory struct {
	config    Config
	items     map[string]Item
	mu        sync.RWMutex
	connected bool
	janitor   *time.Ticker
	stopChan  chan bool
}

// NewMemory creates a new in-memory cache
func NewMemory(config Config) *Memory {
	m := &Memory{
		config:    config,
		items:     make(map[string]Item),
		connected: false,
	}
	return m
}

// Connect initializes the memory cache and starts the janitor
func (m *Memory) Connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connected {
		return nil
	}

	// Start the janitor to clean expired items
	m.janitor = time.NewTicker(time.Minute)
	m.stopChan = make(chan bool)

	go func() {
		for {
			select {
			case <-m.janitor.C:
				m.deleteExpired()
			case <-m.stopChan:
				m.janitor.Stop()
				return
			}
		}
	}()

	m.connected = true
	return nil
}

// Close stops the janitor and clears the cache
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return nil
	}

	// Stop the janitor
	m.stopChan <- true
	close(m.stopChan)

	// Clear the cache
	m.items = make(map[string]Item)
	m.connected = false
	return nil
}

// IsConnected returns true if the cache is connected
func (m *Memory) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// Name returns the name of this cache instance
func (m *Memory) Name() string {
	return m.config.Name
}

// Type returns the type of this cache
func (m *Memory) Type() string {
	return "memory"
}

// Get retrieves a value from the cache
func (m *Memory) Get(_ context.Context, key string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.connected {
		return nil, ErrNotConnected
	}

	item, found := m.items[key]
	if !found {
		return nil, ErrNotFound
	}

	// Check if the item has expired
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		return nil, ErrNotFound
	}

	return item.Value, nil
}

// Set stores a value in the cache
func (m *Memory) Set(_ context.Context, key string, value interface{}, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return ErrNotConnected
	}

	var exp int64
	if expiration > 0 {
		exp = time.Now().Add(expiration).UnixNano()
	}

	m.items[key] = Item{
		Value:      value,
		Expiration: exp,
	}

	return nil
}

// SetNX sets a value in the cache only if the key does not exist
func (m *Memory) SetNX(_ context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return false, ErrNotConnected
	}

	// Check if the key exists and is not expired
	if item, found := m.items[key]; found {
		if item.Expiration == 0 || time.Now().UnixNano() < item.Expiration {
			return false, nil
		}
	}

	var exp int64
	if expiration > 0 {
		exp = time.Now().Add(expiration).UnixNano()
	}

	m.items[key] = Item{
		Value:      value,
		Expiration: exp,
	}

	return true, nil
}

// Delete removes a value from the cache
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return ErrNotConnected
	}

	if _, found := m.items[key]; !found {
		return ErrNotFound
	}

	delete(m.items, key)
	return nil
}

// Exists checks if a key exists in the cache
func (m *Memory) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.connected {
		return false, ErrNotConnected
	}

	item, found := m.items[key]
	if !found {
		return false, nil
	}

	// Check if the item has expired
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		return false, nil
	}

	return true, nil
}

// Increment increments a numeric value
func (m *Memory) Increment(_ context.Context, key string, amount int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return 0, ErrNotConnected
	}

	item, found := m.items[key]
	if !found {
		// If the key doesn't exist, create it with the amount
		m.items[key] = Item{
			Value:      amount,
			Expiration: 0,
		}
		return amount, nil
	}

	// Check if the item has expired
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		m.items[key] = Item{
			Value:      amount,
			Expiration: 0,
		}
		return amount, nil
	}

	// Try to convert the value to int64
	var currentValue int64
	switch v := item.Value.(type) {
	case int:
		currentValue = int64(v)
	case int64:
		currentValue = v
	case float64:
		currentValue = int64(v)
	case string:
		// Try to parse the string as an integer
		var err error
		currentValue, err = parseInt(v)
		if err != nil {
			return 0, err
		}
	default:
		return 0, errors.New("value is not a number")
	}

	newValue := currentValue + amount
	m.items[key] = Item{
		Value:      newValue,
		Expiration: item.Expiration,
	}

	return newValue, nil
}

// Decrement decrements a numeric value
func (m *Memory) Decrement(ctx context.Context, key string, amount int64) (int64, error) {
	return m.Increment(ctx, key, -amount)
}

// Expire sets an expiration time on a key
func (m *Memory) Expire(_ context.Context, key string, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return ErrNotConnected
	}

	item, found := m.items[key]
	if !found {
		return ErrNotFound
	}

	// Check if the item has already expired
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		return ErrNotFound
	}

	// Set the new expiration
	var exp int64
	if expiration > 0 {
		exp = time.Now().Add(expiration).UnixNano()
	}

	m.items[key] = Item{
		Value:      item.Value,
		Expiration: exp,
	}

	return nil
}

// FlushAll removes all keys from the cache
func (m *Memory) FlushAll(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return ErrNotConnected
	}

	m.items = make(map[string]Item)
	return nil
}

// deleteExpired removes expired items from the cache
func (m *Memory) deleteExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UnixNano()
	for k, v := range m.items {
		if v.Expiration > 0 && now > v.Expiration {
			delete(m.items, k)
		}
	}
}

// parseInt tries to parse a string as an int64
func parseInt(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
