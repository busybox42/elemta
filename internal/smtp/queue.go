package smtp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Priority levels for messages
type Priority int

const (
	PriorityLow      Priority = 0
	PriorityNormal   Priority = 1
	PriorityHigh     Priority = 2
	PriorityCritical Priority = 3
)

// QueuedMessage extends MessageInfo with additional queue-specific fields
type QueuedMessage struct {
	MessageInfo
	Priority   Priority    `json:"priority"`
	RetryCount int         `json:"retry_count"`
	NextRetry  time.Time   `json:"next_retry"`
	LastError  string      `json:"last_error"`
	Attempts   []time.Time `json:"attempts"`
}

// QueueManager handles message queuing, prioritization, and retry logic
type QueueManager struct {
	config     *Config
	logger     *slog.Logger
	running    bool
	activeMu   sync.Mutex
	activeJobs map[string]bool
	workerPool chan struct{}
}

// NewQueueManager creates a new queue manager
func NewQueueManager(config *Config) *QueueManager {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	return &QueueManager{
		config:     config,
		logger:     logger,
		activeJobs: make(map[string]bool),
		workerPool: make(chan struct{}, config.MaxWorkers),
	}
}

// Start begins queue processing
func (qm *QueueManager) Start() {
	qm.running = true
	go qm.processQueue()
	go qm.cleanupQueue()
}

// Stop halts queue processing
func (qm *QueueManager) Stop() {
	qm.running = false
}

// EnqueueMessage adds a message to the queue with specified priority
func (qm *QueueManager) EnqueueMessage(msg *Message, priority Priority) error {
	// Create queue directory if it doesn't exist
	if err := os.MkdirAll(qm.config.QueueDir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Save message data
	msgPath := filepath.Join(qm.config.QueueDir, msg.id)
	if err := os.WriteFile(msgPath, msg.data, 0644); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	// Create queued message metadata
	queuedMsg := &QueuedMessage{
		MessageInfo: MessageInfo{
			ID:        msg.id,
			From:      msg.from,
			To:        msg.to,
			Status:    StatusQueued,
			CreatedAt: msg.created,
			UpdatedAt: time.Now(),
		},
		Priority:   priority,
		RetryCount: 0,
		NextRetry:  time.Now(),
		Attempts:   []time.Time{},
	}

	// Save metadata
	if err := qm.saveQueuedMessage(queuedMsg); err != nil {
		// Try to clean up message file if metadata save fails
		os.Remove(msgPath)
		return fmt.Errorf("failed to save message metadata: %w", err)
	}

	qm.logger.Info("message enqueued",
		"id", msg.id,
		"from", msg.from,
		"to", msg.to,
		"priority", priority)

	return nil
}

// processQueue continuously processes queued messages
func (qm *QueueManager) processQueue() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for qm.running {
		<-ticker.C

		messages, err := qm.getQueuedMessages()
		if err != nil {
			qm.logger.Error("failed to get queued messages", "error", err)
			continue
		}

		// Sort messages by priority (highest first) and then by next retry time
		sort.Slice(messages, func(i, j int) bool {
			if messages[i].Priority != messages[j].Priority {
				return messages[i].Priority > messages[j].Priority
			}
			return messages[i].NextRetry.Before(messages[j].NextRetry)
		})

		// Process messages that are ready for delivery
		now := time.Now()
		for _, msg := range messages {
			if msg.NextRetry.After(now) {
				continue // Skip messages not yet ready for retry
			}

			// Check if we have available workers
			select {
			case qm.workerPool <- struct{}{}:
				// Worker slot acquired, process the message
				go func(message *QueuedMessage) {
					defer func() { <-qm.workerPool }() // Release worker slot when done
					qm.processMessage(message)
				}(msg)
			default:
				// No worker slots available, try again later
				qm.logger.Debug("worker pool full, waiting for next cycle")
				break
			}
		}
	}
}

// cleanupQueue periodically removes old messages that have exceeded max queue time
func (qm *QueueManager) cleanupQueue() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for qm.running {
		<-ticker.C

		messages, err := qm.getQueuedMessages()
		if err != nil {
			qm.logger.Error("failed to get queued messages for cleanup", "error", err)
			continue
		}

		now := time.Now()
		maxAge := time.Duration(qm.config.MaxQueueTime) * time.Second

		for _, msg := range messages {
			age := now.Sub(msg.CreatedAt)
			if age > maxAge {
				qm.logger.Info("removing expired message from queue",
					"id", msg.ID,
					"age_hours", age.Hours(),
					"max_age_hours", maxAge.Hours())

				// Remove message and metadata files
				msgPath := filepath.Join(qm.config.QueueDir, msg.ID)
				metaPath := msgPath + ".json"

				os.Remove(msgPath)
				os.Remove(metaPath)
			}
		}
	}
}

// processMessage handles delivery of a single message with retry logic
func (qm *QueueManager) processMessage(msg *QueuedMessage) {
	messageID := msg.ID

	// Atomic job tracking to prevent duplicate processing
	qm.activeMu.Lock()
	if qm.activeJobs[messageID] {
		qm.activeMu.Unlock()
		return // Already being processed
	}
	qm.activeJobs[messageID] = true
	qm.activeMu.Unlock()

	defer func() {
		qm.activeMu.Lock()
		delete(qm.activeJobs, messageID)
		qm.activeMu.Unlock()
	}()

	// Read message data
	msgPath := filepath.Join(qm.config.QueueDir, messageID)
	data, err := os.ReadFile(msgPath)
	if err != nil {
		qm.logger.Error("failed to read message data", "id", messageID, "error", err)
		return
	}

	// Update status to delivering
	msg.Status = StatusDelivering
	msg.UpdatedAt = time.Now()
	msg.Attempts = append(msg.Attempts, time.Now())
	if err := qm.saveQueuedMessage(msg); err != nil {
		qm.logger.Error("failed to update message status", "id", messageID, "error", err)
		return
	}

	// Attempt delivery
	deliveryErr := qm.attemptDelivery(msg, data)

	if deliveryErr == nil {
		// Successful delivery
		msg.Status = StatusDelivered
		msg.UpdatedAt = time.Now()
		if err := qm.saveQueuedMessage(msg); err != nil {
			qm.logger.Error("failed to update message status after delivery", "id", messageID, "error", err)
		}

		// Cleanup message file after successful delivery
		if err := os.Remove(msgPath); err != nil {
			qm.logger.Error("failed to remove delivered message file", "id", messageID, "error", err)
		}

		// Cleanup metadata file after successful delivery
		metaPath := msgPath + ".json"
		if err := os.Remove(metaPath); err != nil {
			qm.logger.Error("failed to remove metadata file", "id", messageID, "error", err)
		}

		qm.logger.Info("message delivered successfully", "id", messageID)
	} else {
		// Failed delivery, schedule retry
		msg.Status = StatusFailed
		msg.RetryCount++
		msg.LastError = deliveryErr.Error()
		msg.UpdatedAt = time.Now()

		// Calculate next retry time based on retry schedule
		retryDelay := qm.getRetryDelay(msg.RetryCount)
		msg.NextRetry = time.Now().Add(time.Duration(retryDelay) * time.Second)

		if msg.RetryCount >= qm.config.MaxRetries {
			qm.logger.Warn("message exceeded maximum retry attempts",
				"id", messageID,
				"retry_count", msg.RetryCount,
				"max_retries", qm.config.MaxRetries)

			// Could implement bounce message generation here
		}

		if err := qm.saveQueuedMessage(msg); err != nil {
			qm.logger.Error("failed to update message status after failed delivery", "id", messageID, "error", err)
		}

		qm.logger.Info("message delivery failed, scheduled for retry",
			"id", messageID,
			"retry_count", msg.RetryCount,
			"next_retry", msg.NextRetry,
			"error", deliveryErr)
	}
}

// getRetryDelay returns the delay in seconds for the given retry attempt
func (qm *QueueManager) getRetryDelay(retryCount int) int {
	if retryCount <= 0 {
		return 0
	}

	if retryCount > len(qm.config.RetrySchedule) {
		// Use the last value in the retry schedule for any retries beyond the schedule
		return qm.config.RetrySchedule[len(qm.config.RetrySchedule)-1]
	}

	return qm.config.RetrySchedule[retryCount-1]
}

// attemptDelivery tries to deliver a message to all recipients
func (qm *QueueManager) attemptDelivery(msg *QueuedMessage, data []byte) error {
	if qm.config.DevMode {
		qm.logger.Info("dev mode: simulating delivery",
			"id", msg.ID,
			"from", msg.From,
			"to", msg.To)
		return nil
	}

	var lastError error
	for _, recipient := range msg.To {
		if err := qm.deliverToRecipient(recipient, msg.From, data); err != nil {
			lastError = err
			qm.logger.Error("recipient delivery failed",
				"id", msg.ID,
				"recipient", recipient,
				"error", err)
			continue
		}
		qm.logger.Info("recipient delivery successful",
			"id", msg.ID,
			"recipient", recipient)
	}
	return lastError
}

// deliverToRecipient delivers a message to a single recipient
func (qm *QueueManager) deliverToRecipient(recipient, from string, data []byte) error {
	// This would use the same logic as in the DeliveryManager
	// For now, we'll just call the existing delivery manager's method
	dm := NewDeliveryManager(qm.config)
	return dm.deliverToRecipient(recipient, from, data)
}

// getQueuedMessages returns all queued messages sorted by priority
func (qm *QueueManager) getQueuedMessages() ([]*QueuedMessage, error) {
	files, err := os.ReadDir(qm.config.QueueDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %w", err)
	}

	var messages []*QueuedMessage

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		metaPath := filepath.Join(qm.config.QueueDir, file.Name())
		msg, err := qm.loadQueuedMessage(metaPath)
		if err != nil {
			qm.logger.Error("failed to load message metadata", "file", file.Name(), "error", err)
			continue
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

// loadQueuedMessage loads a QueuedMessage from a metadata file
func (qm *QueueManager) loadQueuedMessage(path string) (*QueuedMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var msg QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &msg, nil
}

// saveQueuedMessage saves a QueuedMessage to a metadata file
func (qm *QueueManager) saveQueuedMessage(msg *QueuedMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metaPath := filepath.Join(qm.config.QueueDir, msg.ID+".json")
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}
