package queue

import (
	"fmt"
	"log/slog"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager handles queue operations and implements the QueueManager interface
type Manager struct {
	queueDir       string
	mutex          sync.RWMutex
	logger         *slog.Logger
	queueStats     QueueStats
	statsLock      sync.RWMutex
	stopCh         chan struct{}
	storageBackend StorageBackend
}

// Ensure Manager implements QueueManager interface
var _ QueueManager = (*Manager)(nil)

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
	Domain      string            `json:"domain,omitempty"`
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

// NewManager creates a new queue manager using file storage
func NewManager(queueDir string) *Manager {
	storage := NewFileStorageBackend(queueDir)
	return NewManagerWithStorage(storage)
}

// NewManagerWithStorage creates a new queue manager with a custom storage backend
func NewManagerWithStorage(storage StorageBackend) *Manager {
	m := &Manager{
		queueDir:       extractQueueDir(storage),
		logger:         slog.Default().With("component", "queue"),
		queueStats:     QueueStats{LastUpdated: time.Now()},
		stopCh:         make(chan struct{}),
		storageBackend: storage,
	}

	// Ensure directories exist if using file storage
	if fileStorage, ok := storage.(*FileStorageBackend); ok {
		_ = fileStorage.EnsureDirectories() // Best effort, will fail on first operation if needed
	}

	// Start background stats updater
	go m.updateStatsLoop()

	return m
}

// extractQueueDir tries to extract queue directory from storage backend
func extractQueueDir(storage StorageBackend) string {
	if fileStorage, ok := storage.(*FileStorageBackend); ok {
		return fileStorage.queueDir
	}
	return "" // Unknown storage type
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
			return fmt.Errorf("failed to list %s queue: %w", qType, err)
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
	messages, err := m.storageBackend.List(queueType)
	if err != nil {
		return nil, fmt.Errorf("failed to list messages: %w", err)
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
	return m.storageBackend.Retrieve(id)
}

// EnqueueMessage adds a new message to the queue
func (m *Manager) EnqueueMessage(from string, to []string, subject string, data []byte, priority Priority) (string, error) {
	// Generate a unique ID for the message
	id := generateUniqueID()

	m.logger.Info("message_accepted",
		"event_type", "message_accepted",
		"message_id", id,
		"from_envelope", from,
		"to_envelope", to,
		"to_count", len(to),
		"message_size", len(data),
		"priority", priority,
		"queue_type", "active",
		"enqueue_time", time.Now().Format(time.RFC3339),
	)

	// Derive primary routing domain from first recipient
	var domain string
	if len(to) > 0 {
		domain = extractDomain(to[0])
	}

	// Create message metadata
	msg := Message{
		ID:          id,
		QueueType:   Active,
		From:        from,
		To:          to,
		Domain:      domain,
		Subject:     subject,
		Size:        int64(len(data)),
		Priority:    priority,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		RetryCount:  0,
		Annotations: make(map[string]string),
		Attempts:    make([]Attempt, 0),
	}

	// Store message content
	if err := m.storageBackend.StoreContent(id, data); err != nil {
		return "", fmt.Errorf("failed to store message content: %w", err)
	}

	// Set file path in message metadata
	msg.FilePath = filepath.Join(m.queueDir, "data", id)

	// Store message metadata
	if err := m.storageBackend.Store(msg); err != nil {
		// Try to clean up content on error (best effort)
		_ = m.storageBackend.DeleteContent(id)
		return "", fmt.Errorf("failed to store message metadata: %w", err)
	}

	// Update stats atomically
	m.statsLock.Lock()
	m.queueStats.ActiveCount++
	m.queueStats.LastUpdated = time.Now()
	m.queueStats.TotalSize += msg.Size
	m.statsLock.Unlock()

	m.logger.Debug("message enqueued successfully",
		"message_id", id,
		"queue_type", Active,
		"active_count", m.queueStats.ActiveCount)

	return id, nil
}

// GetMessageContent retrieves the content data for a message
func (m *Manager) GetMessageContent(id string) ([]byte, error) {
	return m.storageBackend.RetrieveContent(id)
}

// DeleteMessage removes a message from the queue
func (m *Manager) DeleteMessage(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get message first to determine queue type for stats
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return fmt.Errorf("message not found: %w", err)
	}

	// Delete message metadata
	if err := m.storageBackend.Delete(id); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	// Delete message content
	if err := m.storageBackend.DeleteContent(id); err != nil {
		m.logger.Warn("Failed to delete message content", "id", id, "error", err)
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

// MoveMessage moves a message to a different queue
func (m *Manager) MoveMessage(id string, targetQueue QueueType, reason string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get current message
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return fmt.Errorf("message not found: %w", err)
	}

	sourceQueue := msg.QueueType

	// Update message properties
	msg.QueueType = targetQueue
	msg.UpdatedAt = time.Now()

	if reason != "" {
		if targetQueue == Failed {
			msg.LastError = reason
		} else if targetQueue == Hold {
			msg.HoldReason = reason
		} else if targetQueue == Deferred {
			msg.LastError = reason
			msg.RetryCount++ // Increment retry count when moving to deferred queue
			msg.NextRetry = calculateNextRetry(msg.RetryCount)
		}
	}

	// Move in storage
	if err := m.storageBackend.Move(id, sourceQueue, targetQueue); err != nil {
		return fmt.Errorf("failed to move message: %w", err)
	}

	// Update message metadata
	if err := m.storageBackend.Update(msg); err != nil {
		return fmt.Errorf("failed to update message metadata: %w", err)
	}

	// Update stats
	m.statsLock.Lock()
	switch sourceQueue {
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
	// Get the message
	msg, err := m.storageBackend.Retrieve(id)
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

	// Update the message
	return m.storageBackend.Update(msg)
}

// FlushQueue removes all messages from the specified queue
func (m *Manager) FlushQueue(queueType QueueType) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get messages to capture count before deletion
	messages, err := m.storageBackend.List(queueType)
	if err != nil {
		return fmt.Errorf("failed to list messages: %w", err)
	}

	// Delete all messages and their content
	for _, msg := range messages {
		if err := m.storageBackend.Delete(msg.ID); err != nil {
			m.logger.Warn("Failed to delete message", "id", msg.ID, "error", err)
		}
		if err := m.storageBackend.DeleteContent(msg.ID); err != nil {
			m.logger.Warn("Failed to delete message content", "id", msg.ID, "error", err)
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

	deletedCount, err := m.storageBackend.Cleanup(retentionHours)
	if err != nil {
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	m.logger.Info("Queue cleanup completed", "deleted", deletedCount)
	return deletedCount, nil
}

// SetAnnotation adds or updates an annotation for a message
func (m *Manager) SetAnnotation(id string, key, value string) error {
	msg, err := m.storageBackend.Retrieve(id)
	if err != nil {
		return err
	}

	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}

	msg.Annotations[key] = value
	msg.UpdatedAt = time.Now()

	return m.storageBackend.Update(msg)
}

// Helper functions

// generateUniqueID creates a unique message ID
func generateUniqueID() string {
	// Format: timestamp-random
	return fmt.Sprintf("%d-%07d", time.Now().UnixNano(), time.Now().Nanosecond())
}

// extractDomain returns the domain portion of an email address, or empty string if invalid
func extractDomain(addr string) string {
	if addr == "" {
		return ""
	}
	at := strings.LastIndex(addr, "@")
	if at == -1 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
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
