package smtp

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

// Dump returns a string representation of the context
func (c *Context) Dump() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := ""
	for k, v := range c.values {
		expiration := "never"
		if v.Expiration != nil {
			expiration = v.Expiration.Format(time.RFC3339)
		}
		result += fmt.Sprintf("%s = %v (set at %s, expires %s)\n",
			k, v.Value, v.Timestamp.Format(time.RFC3339), expiration)
	}

	return result
}
