package queue

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager handles queue operations
type Manager struct {
	QueueDir   string
	mutex      sync.RWMutex
	logger     *slog.Logger
	queueStats QueueStats
	statsLock  sync.RWMutex
	stopCh     chan struct{}
}

// QueueType represents the type of queue
type QueueType string

const (
	// Active queue for messages ready to be delivered
	Active QueueType = "active"
	// Deferred queue for messages that will be retried later
	Deferred QueueType = "deferred"
	// Hold queue for messages that are manually held
	Hold QueueType = "hold"
	// Failed queue for messages that failed delivery
	Failed QueueType = "failed"
)

// Priority represents message priority
type Priority int

const (
	// PriorityLow is for low priority messages
	PriorityLow Priority = 1
	// PriorityNormal is for normal priority messages
	PriorityNormal Priority = 2
	// PriorityHigh is for high priority messages
	PriorityHigh Priority = 3
	// PriorityCritical is for critical messages
	PriorityCritical Priority = 4
)

// QueueStats represents statistics about the queue
type QueueStats struct {
	ActiveCount   int       `json:"active_count"`
	DeferredCount int       `json:"deferred_count"`
	HoldCount     int       `json:"hold_count"`
	FailedCount   int       `json:"failed_count"`
	TotalSize     int64     `json:"total_size"`
	LastUpdated   time.Time `json:"last_updated"`
}

// Message represents an email message in the queue
type Message struct {
	ID          string            `json:"id"`
	QueueType   QueueType         `json:"queue_type"`
	FilePath    string            `json:"file_path"`
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Subject     string            `json:"subject"`
	Size        int64             `json:"size"`
	Priority    Priority          `json:"priority"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	NextRetry   time.Time         `json:"next_retry,omitempty"`
	RetryCount  int               `json:"retry_count"`
	LastError   string            `json:"last_error,omitempty"`
	HoldReason  string            `json:"hold_reason,omitempty"`
	Attempts    []Attempt         `json:"attempts,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Attempt represents a delivery attempt
type Attempt struct {
	Time   time.Time `json:"time"`
	Result string    `json:"result"`
	Error  string    `json:"error,omitempty"`
}

// NewManager creates a new queue manager
func NewManager(queueDir string) *Manager {
	m := &Manager{
		QueueDir:   queueDir,
		logger:     slog.Default().With("component", "queue"),
		queueStats: QueueStats{LastUpdated: time.Now()},
		stopCh:     make(chan struct{}),
	}

	// Ensure queue directories exist
	m.ensureQueueDirectories()

	// Start background stats updater
	go m.updateStatsLoop()

	return m
}

// ensureQueueDirectories creates necessary queue directories if they don't exist
func (m *Manager) ensureQueueDirectories() {
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}

	for _, qType := range queueTypes {
		qDir := filepath.Join(m.QueueDir, string(qType))
		if err := os.MkdirAll(qDir, 0755); err != nil {
			m.logger.Error("Failed to create queue directory", "path", qDir, "error", err)
		}
	}

	// Create data directory for message contents
	dataDir := filepath.Join(m.QueueDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		m.logger.Error("Failed to create data directory", "path", dataDir, "error", err)
	}
}

// updateStatsLoop periodically updates queue statistics
func (m *Manager) updateStatsLoop() {
	// Use a shorter interval for tests to make them more responsive
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.UpdateStats(); err != nil {
				m.logger.Error("Failed to update queue stats", "error", err)
			}
		case <-m.stopCh:
			m.logger.Debug("Stats updater stopped")
			return
		}
	}
}

// UpdateStats updates the queue statistics
func (m *Manager) UpdateStats() error {
	stats := QueueStats{
		LastUpdated: time.Now(),
	}

	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	var totalSize int64

	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			return fmt.Errorf("failed to list %s queue: %v", qType, err)
		}

		// Update count based on queue type
		switch qType {
		case Active:
			stats.ActiveCount = len(messages)
		case Deferred:
			stats.DeferredCount = len(messages)
		case Hold:
			stats.HoldCount = len(messages)
		case Failed:
			stats.FailedCount = len(messages)
		}

		// Sum message sizes
		for _, msg := range messages {
			totalSize += msg.Size
		}
	}

	stats.TotalSize = totalSize

	// Update stats atomically
	m.statsLock.Lock()
	m.queueStats = stats
	m.statsLock.Unlock()

	return nil
}

// GetStats returns the current queue statistics
func (m *Manager) GetStats() QueueStats {
	m.statsLock.RLock()
	defer m.statsLock.RUnlock()
	return m.queueStats
}

// ListMessages lists all messages in the specified queue
func (m *Manager) ListMessages(queueType QueueType) ([]Message, error) {
	queuePath := filepath.Join(m.QueueDir, string(queueType))

	// Check if the directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("queue directory %s does not exist", queuePath)
	}

	// Get all files in the queue directory
	files, err := os.ReadDir(queuePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %v", err)
	}

	var messages []Message
	for _, file := range files {
		// Skip directories and non-.json files
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		// Get the message ID from the filename
		msgID := strings.TrimSuffix(file.Name(), ".json")

		// Read the message file
		filePath := filepath.Join(queuePath, file.Name())
		msg, err := m.readMessageMetadata(filePath, msgID, queueType)
		if err != nil {
			m.logger.Warn("Failed to read message", "path", filePath, "error", err)
			continue
		}

		messages = append(messages, msg)
	}

	// Sort messages by priority (higher priority first) and then by creation time
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].Priority != messages[j].Priority {
			return messages[i].Priority > messages[j].Priority
		}
		return messages[i].CreatedAt.Before(messages[j].CreatedAt)
	})

	return messages, nil
}

// readMessageMetadata reads a message metadata from disk
func (m *Manager) readMessageMetadata(filePath, msgID string, queueType QueueType) (Message, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return Message{}, fmt.Errorf("failed to read message file: %v", err)
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("failed to unmarshal message data: %v", err)
	}

	return msg, nil
}

// GetAllMessages lists all messages across all queue types
func (m *Manager) GetAllMessages() ([]Message, error) {
	var allMessages []Message

	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			m.logger.Warn("Failed to list queue", "type", qType, "error", err)
			continue
		}

		allMessages = append(allMessages, messages...)
	}

	return allMessages, nil
}

// GetMessage gets a single message by ID
func (m *Manager) GetMessage(id string) (Message, error) {
	// Check all queue types
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		queuePath := filepath.Join(m.QueueDir, string(qType))
		filePath := filepath.Join(queuePath, fmt.Sprintf("%s.json", id))

		if _, err := os.Stat(filePath); err == nil {
			// File exists, read it
			return m.readMessageMetadata(filePath, id, qType)
		}
	}

	return Message{}, fmt.Errorf("message %s not found in any queue", id)
}

// EnqueueMessage adds a new message to the queue
func (m *Manager) EnqueueMessage(from string, to []string, subject string, data []byte, priority Priority) (string, error) {
	// Generate a unique ID for the message
	id := generateUniqueID()

	// Create message metadata
	msg := Message{
		ID:          id,
		QueueType:   Active,
		From:        from,
		To:          to,
		Subject:     subject,
		Size:        int64(len(data)),
		Priority:    priority,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		RetryCount:  0,
		Annotations: make(map[string]string),
		Attempts:    make([]Attempt, 0),
	}

	// Save message data to disk
	dataPath := filepath.Join(m.QueueDir, "data", id)
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write message data: %v", err)
	}

	// Set file path in message metadata
	msg.FilePath = dataPath

	// Save message metadata
	metadataPath := filepath.Join(m.QueueDir, string(Active), fmt.Sprintf("%s.json", id))
	if err := m.saveMessageMetadata(msg, metadataPath); err != nil {
		// Try to clean up data file on error
		os.Remove(dataPath)
		return "", fmt.Errorf("failed to save message metadata: %v", err)
	}

	// Update stats atomically
	m.statsLock.Lock()
	m.queueStats.ActiveCount++
	m.queueStats.LastUpdated = time.Now()
	m.queueStats.TotalSize += msg.Size
	m.statsLock.Unlock()

	return id, nil
}

// saveMessageMetadata saves message metadata to disk
func (m *Manager) saveMessageMetadata(msg Message, path string) error {
	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message metadata: %v", err)
	}

	// Ensure parent directory exists before locking
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Write to disk with a lock to ensure thread safety, but keep the lock scope small
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Write atomically using a temporary file
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary file: %v", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath) // Clean up temp file on error
		return fmt.Errorf("failed to rename temporary file: %v", err)
	}

	return nil
}

// GetMessageContent returns the full content of a message
func (m *Manager) GetMessageContent(id string) ([]byte, error) {
	// Find the message in any queue
	msg, err := m.GetMessage(id)
	if err != nil {
		return nil, err
	}

	// Read the full message content from the file path stored in metadata
	if msg.FilePath != "" {
		data, err := os.ReadFile(msg.FilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read message data from FilePath: %v", err)
		}
		return data, nil
	}

	// Fallback to the default data location
	dataPath := filepath.Join(m.QueueDir, "data", id)
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read message data: %v", err)
	}

	return data, nil
}

// DeleteMessage removes a message from the queue
func (m *Manager) DeleteMessage(id string) error {
	// Find the message in any queue
	msg, err := m.GetMessage(id)
	if err != nil {
		return err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Delete the metadata file
	metadataPath := filepath.Join(m.QueueDir, string(msg.QueueType), fmt.Sprintf("%s.json", id))
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete message metadata: %v", err)
	}

	// Delete the message data
	dataPath := filepath.Join(m.QueueDir, "data", id)
	if err := os.Remove(dataPath); err != nil && !os.IsNotExist(err) {
		m.logger.Warn("Failed to delete message data", "path", dataPath, "error", err)
	}

	// Update stats
	m.statsLock.Lock()
	switch msg.QueueType {
	case Active:
		m.queueStats.ActiveCount--
	case Deferred:
		m.queueStats.DeferredCount--
	case Hold:
		m.queueStats.HoldCount--
	case Failed:
		m.queueStats.FailedCount--
	}
	m.queueStats.TotalSize -= msg.Size
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()

	return nil
}

// MoveMessage moves a message between queues
func (m *Manager) MoveMessage(id string, targetQueue QueueType, reason string) error {
	// Find the message
	msg, err := m.GetMessage(id)
	if err != nil {
		return err
	}

	// Skip if already in the target queue
	if msg.QueueType == targetQueue {
		return nil
	}

	// Record the old queue type for stats update
	oldQueue := msg.QueueType

	// Update message metadata
	msg.QueueType = targetQueue
	msg.UpdatedAt = time.Now()

	// Set reason based on target queue
	switch targetQueue {
	case Hold:
		msg.HoldReason = reason
	case Deferred:
		msg.NextRetry = calculateNextRetry(msg.RetryCount)
		msg.RetryCount++
		if reason != "" {
			msg.LastError = reason
		}
	case Failed:
		if reason != "" {
			msg.LastError = reason
		}
	}

	// Get the paths before locking
	oldPath := filepath.Join(m.QueueDir, string(oldQueue), fmt.Sprintf("%s.json", id))
	newPath := filepath.Join(m.QueueDir, string(targetQueue), fmt.Sprintf("%s.json", id))

	// The saveMessageMetadata method already has its own locking, so we don't need to lock here
	// First save to the new path
	if err := m.saveMessageMetadata(msg, newPath); err != nil {
		return fmt.Errorf("failed to save to new queue: %v", err)
	}

	// Then delete from the old path
	if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
		// Don't fail if remove fails, just log the error
		m.logger.Warn("Failed to remove old message metadata", "path", oldPath, "error", err)
	}

	// Update stats - this is done outside the lock to prevent deadlocks
	m.statsLock.Lock()
	switch oldQueue {
	case Active:
		m.queueStats.ActiveCount--
	case Deferred:
		m.queueStats.DeferredCount--
	case Hold:
		m.queueStats.HoldCount--
	case Failed:
		m.queueStats.FailedCount--
	}

	switch targetQueue {
	case Active:
		m.queueStats.ActiveCount++
	case Deferred:
		m.queueStats.DeferredCount++
	case Hold:
		m.queueStats.HoldCount++
	case Failed:
		m.queueStats.FailedCount++
	}
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()

	return nil
}

// AddAttempt adds a delivery attempt record to a message
func (m *Manager) AddAttempt(id string, result string, errorMsg string) error {
	// Find the message
	msg, err := m.GetMessage(id)
	if err != nil {
		return err
	}

	// Add the attempt
	attempt := Attempt{
		Time:   time.Now(),
		Result: result,
		Error:  errorMsg,
	}

	msg.Attempts = append(msg.Attempts, attempt)
	msg.UpdatedAt = time.Now()

	if errorMsg != "" {
		msg.LastError = errorMsg
	}

	// Save the updated message
	path := filepath.Join(m.QueueDir, string(msg.QueueType), fmt.Sprintf("%s.json", id))
	return m.saveMessageMetadata(msg, path)
}

// FlushQueue removes all messages from the specified queue
func (m *Manager) FlushQueue(queueType QueueType) error {
	queuePath := filepath.Join(m.QueueDir, string(queueType))

	// Check if the directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return fmt.Errorf("queue directory %s does not exist", queuePath)
	}

	// Get messages to capture IDs before deletion
	messages, err := m.ListMessages(queueType)
	if err != nil {
		return fmt.Errorf("failed to list messages: %v", err)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get all files in the queue directory
	files, err := os.ReadDir(queuePath)
	if err != nil {
		return fmt.Errorf("failed to read queue directory: %v", err)
	}

	// Delete all message metadata files
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			filePath := filepath.Join(queuePath, file.Name())
			if err := os.Remove(filePath); err != nil {
				m.logger.Warn("Failed to delete file", "path", filePath, "error", err)
			}
		}
	}

	// Attempt to delete message data files
	for _, msg := range messages {
		dataPath := filepath.Join(m.QueueDir, "data", msg.ID)
		if err := os.Remove(dataPath); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("Failed to delete message data", "path", dataPath, "error", err)
		}
	}

	// Update stats
	m.statsLock.Lock()
	switch queueType {
	case Active:
		m.queueStats.ActiveCount = 0
	case Deferred:
		m.queueStats.DeferredCount = 0
	case Hold:
		m.queueStats.HoldCount = 0
	case Failed:
		m.queueStats.FailedCount = 0
	}
	m.queueStats.LastUpdated = time.Now()
	m.statsLock.Unlock()

	return nil
}

// FlushAllQueues removes all messages from all queues
func (m *Manager) FlushAllQueues() error {
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		if err := m.FlushQueue(qType); err != nil {
			m.logger.Warn("Failed to flush queue", "type", qType, "error", err)
		}
	}

	// Reset all stats
	m.statsLock.Lock()
	m.queueStats = QueueStats{
		LastUpdated: time.Now(),
	}
	m.statsLock.Unlock()

	return nil
}

// CleanupExpiredMessages removes messages that are older than the retention period
func (m *Manager) CleanupExpiredMessages(retentionHours int) (int, error) {
	if retentionHours <= 0 {
		return 0, fmt.Errorf("retention period must be positive")
	}

	m.logger.Info("Starting queue cleanup", "retention_hours", retentionHours)

	cutoffTime := time.Now().Add(-time.Duration(retentionHours) * time.Hour)
	var deletedCount int

	// Check all queue types
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			m.logger.Error("Failed to list messages for cleanup", "queue", qType, "error", err)
			continue
		}

		for _, msg := range messages {
			// For active and deferred messages, check creation time
			// For hold and failed, check update time (we keep these longer)
			var checkTime time.Time
			switch qType {
			case Active, Deferred:
				checkTime = msg.CreatedAt
			case Hold, Failed:
				checkTime = msg.UpdatedAt
			}

			if checkTime.Before(cutoffTime) {
				if err := m.DeleteMessage(msg.ID); err != nil {
					m.logger.Error("Failed to delete expired message", "id", msg.ID, "error", err)
					continue
				}
				deletedCount++
			}
		}
	}

	m.logger.Info("Queue cleanup completed", "deleted", deletedCount)
	return deletedCount, nil
}

// SetAnnotation adds or updates an annotation for a message
func (m *Manager) SetAnnotation(id string, key, value string) error {
	msg, err := m.GetMessage(id)
	if err != nil {
		return err
	}

	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}

	msg.Annotations[key] = value
	msg.UpdatedAt = time.Now()

	// Save the updated message
	path := filepath.Join(m.QueueDir, string(msg.QueueType), fmt.Sprintf("%s.json", id))
	return m.saveMessageMetadata(msg, path)
}

// Helper functions

// generateUniqueID creates a unique message ID
func generateUniqueID() string {
	// Format: timestamp-random
	return fmt.Sprintf("%d-%07d", time.Now().UnixNano(), time.Now().Nanosecond())
}

// calculateNextRetry determines when to retry a message based on retry count
// Uses exponential backoff with some randomness
func calculateNextRetry(retryCount int) time.Time {
	if retryCount <= 0 {
		retryCount = 1
	}

	// Base delay in seconds - exponential with retry count
	// 1: 60s, 2: 5m, 3: 15m, 4: 1h, 5: 3h, 6+: 6h
	var delaySeconds int

	switch {
	case retryCount == 1:
		delaySeconds = 60
	case retryCount == 2:
		delaySeconds = 300
	case retryCount == 3:
		delaySeconds = 900
	case retryCount == 4:
		delaySeconds = 3600
	case retryCount == 5:
		delaySeconds = 10800
	default:
		delaySeconds = 21600
	}

	// Add some randomness (±10%)
	jitter := float64(delaySeconds) * 0.1
	delaySeconds = delaySeconds + int(jitter*(2.0*rand.Float64()-1.0))

	return time.Now().Add(time.Duration(delaySeconds) * time.Second)
}

// Stop stops the queue manager and cleans up resources
func (m *Manager) Stop() {
	// Only close the channel if it hasn't been closed already
	m.mutex.Lock()
	select {
	case <-m.stopCh:
		// Channel is already closed
	default:
		close(m.stopCh)
	}
	m.mutex.Unlock()
}
