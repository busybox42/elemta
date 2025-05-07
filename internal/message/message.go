// Package message provides message handling functionality for Elemta
package message

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// Status represents the delivery status of a message
type Status string

const (
	StatusReceived   Status = "received"
	StatusQueued     Status = "queued"
	StatusDelivering Status = "delivering"
	StatusDelivered  Status = "delivered"
	StatusFailed     Status = "failed"
	StatusDeferred   Status = "deferred"
	StatusHeld       Status = "held"
)

// Message represents an email message in the system
type Message struct {
	ID        string            // Unique identifier
	From      string            // Sender address
	To        []string          // Recipient addresses
	Data      []byte            // Raw message data
	Status    Status            // Current status
	CreatedAt time.Time         // Creation timestamp
	Headers   map[string]string // Message headers
}

// NewMessage creates a new message instance
func NewMessage() *Message {
	return &Message{
		ID:        uuid.New().String(),
		To:        make([]string, 0),
		Status:    StatusReceived,
		CreatedAt: time.Now(),
		Headers:   make(map[string]string),
	}
}

// AddHeader adds a header to the message
func (m *Message) AddHeader(name, value string) {
	m.Headers[name] = value
}

// GetHeader retrieves a header from the message
func (m *Message) GetHeader(name string) string {
	return m.Headers[name]
}

// Save persists the message to the specified queue directory
func (m *Message) Save(queueDir string) error {
	// Save message data
	msgPath := filepath.Join(queueDir, m.ID)
	if err := os.WriteFile(msgPath, m.Data, 0644); err != nil {
		return err
	}

	// Prepare metadata
	info := struct {
		ID        string            `json:"id"`
		From      string            `json:"from"`
		To        []string          `json:"to"`
		Status    Status            `json:"status"`
		CreatedAt time.Time         `json:"created_at"`
		UpdatedAt time.Time         `json:"updated_at"`
		Headers   map[string]string `json:"headers,omitempty"`
	}{
		ID:        m.ID,
		From:      m.From,
		To:        m.To,
		Status:    m.Status,
		CreatedAt: m.CreatedAt,
		UpdatedAt: time.Now(),
		Headers:   m.Headers,
	}

	// Save metadata
	metaData, err := json.Marshal(info)
	if err != nil {
		return err
	}

	metaPath := filepath.Join(queueDir, m.ID+".json")
	return os.WriteFile(metaPath, metaData, 0644)
}
