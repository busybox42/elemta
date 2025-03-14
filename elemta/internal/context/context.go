package context

import (
	"fmt"
	"sync"
	"time"
)

// ContextValue represents a value stored in the context
type ContextValue struct {
	Value      interface{}
	Timestamp  time.Time
	Expiration *time.Time
}

// Context represents a key-value store for SMTP sessions
type Context struct {
	values map[string]ContextValue
	mu     sync.RWMutex
}

// NewContext creates a new context
func NewContext() *Context {
	return &Context{
		values: make(map[string]ContextValue),
	}
}

// Set sets a value in the context
func (c *Context) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values[key] = ContextValue{
		Value:     value,
		Timestamp: time.Now(),
	}
}

// SetWithExpiration sets a value in the context with an expiration time
func (c *Context) SetWithExpiration(key string, value interface{}, expiration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expirationTime := time.Now().Add(expiration)
	c.values[key] = ContextValue{
		Value:      value,
		Timestamp:  time.Now(),
		Expiration: &expirationTime,
	}
}

// Get gets a value from the context
func (c *Context) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	value, ok := c.values[key]
	if !ok {
		return nil, false
	}

	// Check if the value has expired
	if value.Expiration != nil && time.Now().After(*value.Expiration) {
		delete(c.values, key)
		return nil, false
	}

	return value.Value, true
}

// GetString gets a string value from the context
func (c *Context) GetString(key string) (string, bool) {
	value, ok := c.Get(key)
	if !ok {
		return "", false
	}

	str, ok := value.(string)
	if !ok {
		return "", false
	}

	return str, true
}

// GetInt gets an int value from the context
func (c *Context) GetInt(key string) (int, bool) {
	value, ok := c.Get(key)
	if !ok {
		return 0, false
	}

	i, ok := value.(int)
	if !ok {
		return 0, false
	}

	return i, true
}

// GetFloat gets a float64 value from the context
func (c *Context) GetFloat(key string) (float64, bool) {
	value, ok := c.Get(key)
	if !ok {
		return 0, false
	}

	f, ok := value.(float64)
	if !ok {
		return 0, false
	}

	return f, true
}

// GetBool gets a bool value from the context
func (c *Context) GetBool(key string) (bool, bool) {
	value, ok := c.Get(key)
	if !ok {
		return false, false
	}

	b, ok := value.(bool)
	if !ok {
		return false, false
	}

	return b, true
}

// Delete deletes a value from the context
func (c *Context) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.values, key)
}

// Clear clears all values from the context
func (c *Context) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values = make(map[string]ContextValue)
}

// Keys returns all keys in the context
func (c *Context) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.values))
	for k := range c.values {
		keys = append(keys, k)
	}

	return keys
}

// Dump returns a string representation of the context
func (c *Context) Dump() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := "Context dump:\n"
	for k, v := range c.values {
		expiration := "never"
		if v.Expiration != nil {
			expiration = v.Expiration.Format(time.RFC3339)
		}
		result += fmt.Sprintf("  %s = %v (set at %s, expires %s)\n",
			k, v.Value, v.Timestamp.Format(time.RFC3339), expiration)
	}

	return result
}

// Count returns the number of values in the context
func (c *Context) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.values)
}

// Cleanup removes expired values from the context
func (c *Context) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	now := time.Now()

	for k, v := range c.values {
		if v.Expiration != nil && now.After(*v.Expiration) {
			delete(c.values, k)
			count++
		}
	}

	return count
}
