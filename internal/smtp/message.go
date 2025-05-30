// internal/smtp/message.go
package smtp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

type MessageStatus string

const (
	StatusReceived   MessageStatus = "received"
	StatusQueued     MessageStatus = "queued"
	StatusDelivering MessageStatus = "delivering"
	StatusDelivered  MessageStatus = "delivered"
	StatusFailed     MessageStatus = "failed"
)

type Message struct {
	id           string
	from         string
	to           []string
	data         []byte
	status       MessageStatus
	created      time.Time
	receivedTime time.Time // Time when the message was received
}

func NewMessage() *Message {
	now := time.Now()
	return &Message{
		id:           uuid.New().String(),
		to:           make([]string, 0),
		status:       StatusReceived,
		created:      now,
		receivedTime: now,
	}
}

func (m *Message) Save(config *Config) error {
	// Save message data
	msgPath := filepath.Join(config.QueueDir, m.id)
	if err := os.WriteFile(msgPath, m.data, 0644); err != nil {
		return err
	}

	// Save metadata
	info := &MessageInfo{
		ID:         m.id,
		From:       m.from,
		To:         m.to,
		Status:     m.status,
		CreatedAt:  m.created,
		UpdatedAt:  time.Now(),
		ReceivedAt: m.receivedTime,
		Size:       len(m.data),
		Retry: RetryInfo{
			Attempts:    0,
			LastAttempt: time.Time{},
			NextAttempt: time.Now().Add(5 * time.Minute), // Default initial retry
			LastError:   "",
		},
	}

	metaData, err := json.Marshal(info)
	if err != nil {
		return err
	}

	metaPath := filepath.Join(config.QueueDir, m.id+".json")
	return os.WriteFile(metaPath, metaData, 0644)
}
