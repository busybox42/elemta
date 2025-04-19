// Package context provides context management for SMTP transactions
package context

import (
	"fmt"
	"sync"
	"time"
)

// Context represents a context for storing key-value pairs
type Context struct {
	mu   sync.RWMutex
	data map[string]interface{}
	exp  map[string]time.Time
}

// NewContext creates a new context
func NewContext() *Context {
	ctx := &Context{
		data: make(map[string]interface{}),
		exp:  make(map[string]time.Time),
	}
	return ctx
}

// Set stores a value in the context
func (c *Context) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
	delete(c.exp, key) // Remove any expiration
}

// SetWithExpiration stores a value with an expiration time
func (c *Context) SetWithExpiration(key string, value interface{}, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
	c.exp[key] = time.Now().Add(duration)
}

// Get retrieves a value from the context
func (c *Context) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if key exists
	value, ok := c.data[key]
	if !ok {
		return nil, false
	}

	// Check if key has expired
	if expTime, ok := c.exp[key]; ok {
		if time.Now().After(expTime) {
			// Key has expired, but we can't delete it here with a read lock
			return nil, false
		}
	}

	return value, true
}

// GetString retrieves a string value from the context
func (c *Context) GetString(key string) (string, bool) {
	value, ok := c.Get(key)
	if !ok {
		return "", false
	}

	strValue, ok := value.(string)
	return strValue, ok
}

// GetInt retrieves an int value from the context
func (c *Context) GetInt(key string) (int, bool) {
	value, ok := c.Get(key)
	if !ok {
		return 0, false
	}

	intValue, ok := value.(int)
	return intValue, ok
}

// GetFloat retrieves a float64 value from the context
func (c *Context) GetFloat(key string) (float64, bool) {
	value, ok := c.Get(key)
	if !ok {
		return 0, false
	}

	floatValue, ok := value.(float64)
	return floatValue, ok
}

// GetBool retrieves a bool value from the context
func (c *Context) GetBool(key string) (bool, bool) {
	value, ok := c.Get(key)
	if !ok {
		return false, false
	}

	boolValue, ok := value.(bool)
	return boolValue, ok
}

// Delete removes a value from the context
func (c *Context) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
	delete(c.exp, key)
}

// Clear removes all values from the context
func (c *Context) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]interface{})
	c.exp = make(map[string]time.Time)
}

// Keys returns a slice of all keys in the context
func (c *Context) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.data))
	for k := range c.data {
		keys = append(keys, k)
	}

	return keys
}

// Count returns the number of items in the context
func (c *Context) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

// Cleanup removes expired values from the context and returns the number of items cleaned up
func (c *Context) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0
	for k, expTime := range c.exp {
		if now.After(expTime) {
			delete(c.data, k)
			delete(c.exp, k)
			count++
		}
	}

	return count
}

// Dump returns a string representation of the context
func (c *Context) Dump() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := "Context dump:\n"
	for k, v := range c.data {
		expiration := "never"
		if exp, ok := c.exp[k]; ok {
			expiration = exp.String()
		}
		result += fmt.Sprintf("%s = %v (expires %s)\n", k, v, expiration)
	}

	return result
}

// MessageContext represents the context of an email message being processed
type MessageContext struct {
	// Message metadata
	ID            string
	From          string
	To            []string
	Subject       string
	ReceivedAt    time.Time
	Size          int64
	ClientIP      string
	ClientHost    string
	AuthUser      string
	Authenticated bool

	// Processing state
	PluginResults map[string]interface{}
	Headers       map[string][]string
	Attachments   []Attachment
	Queue         string
	Status        string
	NextRetry     time.Time
	RetryCount    int

	// Internal state
	mu   sync.RWMutex
	data map[string]interface{}
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Size        int64
	Data        []byte
}

// NewMessageContext creates a new message context
func NewMessageContext() *MessageContext {
	return &MessageContext{
		ReceivedAt:    time.Now(),
		PluginResults: make(map[string]interface{}),
		Headers:       make(map[string][]string),
		Attachments:   []Attachment{},
		data:          make(map[string]interface{}),
	}
}

// Set stores a value in the context
func (m *MessageContext) Set(key string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
}

// Get retrieves a value from the context
func (m *MessageContext) Get(key string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.data[key]
	return value, ok
}

// Delete removes a value from the context
func (m *MessageContext) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

// AddHeader adds a header to the message
func (m *MessageContext) AddHeader(name, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Headers[name] = append(m.Headers[name], value)
}

// GetHeaders returns all headers with the given name
func (m *MessageContext) GetHeaders(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Headers[name]
}

// SetPluginResult stores a plugin result
func (m *MessageContext) SetPluginResult(pluginName string, result interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PluginResults[pluginName] = result
}

// GetPluginResult retrieves a plugin result
func (m *MessageContext) GetPluginResult(pluginName string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result, ok := m.PluginResults[pluginName]
	return result, ok
}

// AddAttachment adds an attachment to the message
func (m *MessageContext) AddAttachment(attachment Attachment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Attachments = append(m.Attachments, attachment)
}

// GetAttachments returns all attachments
func (m *MessageContext) GetAttachments() []Attachment {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Attachments
}
