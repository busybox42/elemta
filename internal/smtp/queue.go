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

// QueueType represents different queue types for message processing
type QueueType string

const (
	QueueTypeActive   QueueType = "active"   // Messages actively being processed
	QueueTypeDeferred QueueType = "deferred" // Messages waiting for retry
	QueueTypeHeld     QueueType = "held"     // Messages held for manual review
	QueueTypeFailed   QueueType = "failed"   // Messages that have permanently failed
)

// Priority levels for messages
type Priority int

const (
	PriorityLow      Priority = 0
	PriorityNormal   Priority = 1
	PriorityHigh     Priority = 2
	PriorityCritical Priority = 3
)

// Additional message status constants
const (
	StatusDeferred MessageStatus = "deferred"
	StatusHeld     MessageStatus = "held"
)

// Message status constants
// const (
// 	StatusQueued     = "queued"
// 	StatusDelivering = "delivering"
// 	StatusDelivered  = "delivered"
// 	StatusFailed     = "failed"
// 	StatusDeferred   = "deferred"
// 	StatusHeld       = "held"
// )

// QueuedMessage extends MessageInfo with additional queue-specific fields
type QueuedMessage struct {
	MessageInfo
	Priority    Priority          `json:"priority"`
	QueueType   QueueType         `json:"queue_type"`
	RetryCount  int               `json:"retry_count"`
	NextRetry   time.Time         `json:"next_retry"`
	LastError   string            `json:"last_error"`
	Attempts    []time.Time       `json:"attempts"`
	HoldReason  string            `json:"hold_reason,omitempty"`
	FailReason  string            `json:"fail_reason,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"` // For storing metadata like SPF/DKIM results
}

// QueueManager handles message queuing, prioritization, and retry logic
type QueueManager struct {
	config     *Config
	logger     *slog.Logger
	running    bool
	activeMu   sync.Mutex
	activeJobs map[string]bool
	workerPool chan struct{}

	// Queue statistics
	stats   QueueStats
	statsMu sync.RWMutex
}

// QueueStats tracks statistics about the queue
type QueueStats struct {
	ActiveCount    int       `json:"active_count"`
	DeferredCount  int       `json:"deferred_count"`
	HeldCount      int       `json:"held_count"`
	FailedCount    int       `json:"failed_count"`
	TotalProcessed int       `json:"total_processed"`
	TotalDelivered int       `json:"total_delivered"`
	TotalFailed    int       `json:"total_failed"`
	LastUpdated    time.Time `json:"last_updated"`
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
		stats: QueueStats{
			LastUpdated: time.Now(),
		},
	}
}

// Start begins queue processing
func (qm *QueueManager) Start() {
	qm.running = true

	// Create queue directories if they don't exist
	qm.ensureQueueDirectories()

	// Start queue processors for different queue types
	go qm.processActiveQueue()
	go qm.processDeferredQueue()
	go qm.cleanupQueue()
	go qm.updateQueueStats()
}

// Stop halts queue processing
func (qm *QueueManager) Stop() {
	qm.running = false
}

// ensureQueueDirectories creates the necessary queue directories
func (qm *QueueManager) ensureQueueDirectories() {
	baseDir := qm.config.QueueDir

	// Create base queue directory
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		qm.logger.Error("Failed to create base queue directory", "error", err)
		return
	}

	// Create subdirectories for each queue type
	for _, qType := range []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed} {
		qDir := filepath.Join(baseDir, string(qType))
		if err := os.MkdirAll(qDir, 0755); err != nil {
			qm.logger.Error("Failed to create queue directory", "type", qType, "error", err)
		}
	}

	// Create data directory for message content
	dataDir := filepath.Join(baseDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		qm.logger.Error("Failed to create message data directory", "error", err)
	}
}

// EnqueueMessage adds a message to the queue with specified priority
func (qm *QueueManager) EnqueueMessage(msg *Message, priority Priority) error {
	// Create queue directory if it doesn't exist
	if err := os.MkdirAll(qm.config.QueueDir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Save message data to the data directory
	dataDir := filepath.Join(qm.config.QueueDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	msgDataPath := filepath.Join(dataDir, msg.id)
	if err := os.WriteFile(msgDataPath, msg.data, 0644); err != nil {
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
		Priority:    priority,
		QueueType:   QueueTypeActive, // Start in active queue
		RetryCount:  0,
		NextRetry:   time.Now(),
		Attempts:    []time.Time{},
		Annotations: make(map[string]string),
	}

	// Save metadata to the active queue
	if err := qm.saveQueuedMessage(queuedMsg); err != nil {
		// Try to clean up message file if metadata save fails
		os.Remove(msgDataPath)
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

		messages, err := qm.getQueuedMessagesFromDir(qm.config.QueueDir)
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

// cleanupQueue periodically removes old messages from the queue
func (qm *QueueManager) cleanupQueue() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		if !qm.running {
			return
		}

		select {
		case <-ticker.C:
			qm.logger.Info("starting queue cleanup")

			// Get all messages from all queues
			var allMessages []*QueuedMessage

			for _, qType := range []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed} {
				qDir := filepath.Join(qm.config.QueueDir, string(qType))
				messages, err := qm.getQueuedMessagesFromDir(qDir)
				if err != nil {
					qm.logger.Error("failed to get messages for cleanup", "queue", qType, "error", err)
					continue
				}
				allMessages = append(allMessages, messages...)
			}

			// Check for messages that have been in the queue too long
			maxAge := time.Duration(qm.config.MaxQueueTime) * time.Second
			now := time.Now()

			for _, msg := range allMessages {
				// Skip messages in the failed queue
				if msg.QueueType == QueueTypeFailed {
					continue
				}

				age := now.Sub(msg.CreatedAt)
				if age > maxAge {
					qm.logger.Info("removing expired message from queue",
						"id", msg.ID,
						"age", age.String(),
						"max_age", maxAge.String())

					// Move to failed queue
					msg.QueueType = QueueTypeFailed
					msg.Status = StatusFailed
					msg.FailReason = fmt.Sprintf("Message expired after %s", age.String())
					msg.UpdatedAt = now

					if err := qm.moveMessage(msg, msg.QueueType, QueueTypeFailed); err != nil {
						qm.logger.Error("failed to move expired message to failed queue",
							"id", msg.ID,
							"error", err)
					}

					// Update stats
					qm.statsMu.Lock()
					qm.stats.TotalFailed++
					qm.statsMu.Unlock()
				}
			}

			qm.logger.Info("queue cleanup completed")
		}
	}
}

// processMessage processes a single message from the queue
func (qm *QueueManager) processMessage(msg *QueuedMessage) {
	qm.logger.Info("processing message",
		"id", msg.ID,
		"from", msg.From,
		"to", msg.To,
		"retry_count", msg.RetryCount)

	// Update stats
	qm.statsMu.Lock()
	qm.stats.TotalProcessed++
	qm.statsMu.Unlock()

	// Load message data
	dataPath := filepath.Join(qm.config.QueueDir, "data", msg.ID)
	data, err := os.ReadFile(dataPath)
	if err != nil {
		qm.logger.Error("failed to read message data", "id", msg.ID, "error", err)

		// Move to failed queue if data can't be read
		msg.QueueType = QueueTypeFailed
		msg.FailReason = fmt.Sprintf("Failed to read message data: %v", err)
		msg.Status = StatusFailed
		msg.UpdatedAt = time.Now()

		if err := qm.saveQueuedMessage(msg); err != nil {
			qm.logger.Error("failed to save failed message", "id", msg.ID, "error", err)
		}

		return
	}

	// Record attempt
	msg.Attempts = append(msg.Attempts, time.Now())

	// Attempt delivery
	err = qm.attemptDelivery(msg, data)

	if err == nil {
		// Delivery successful
		qm.logger.Info("message delivered successfully", "id", msg.ID)

		// Update stats
		qm.statsMu.Lock()
		qm.stats.TotalDelivered++
		qm.statsMu.Unlock()

		// Update message status
		msg.Status = StatusDelivered
		msg.UpdatedAt = time.Now()

		// Save to completed directory or delete
		if qm.config.KeepDeliveredMessages {
			// Move to a "delivered" directory for archiving
			deliveredDir := filepath.Join(qm.config.QueueDir, "delivered")
			if err := os.MkdirAll(deliveredDir, 0755); err == nil {
				deliveredPath := filepath.Join(deliveredDir, msg.ID+".json")
				data, err := json.Marshal(msg)
				if err == nil {
					os.WriteFile(deliveredPath, data, 0644)
				}
			}
		}

		// Remove from queue
		queuePath := filepath.Join(qm.config.QueueDir, string(msg.QueueType), msg.ID+".json")
		os.Remove(queuePath)

		// Remove message data if configured
		if !qm.config.KeepMessageData {
			os.Remove(dataPath)
		}

		return
	}

	// Delivery failed
	qm.logger.Error("message delivery failed",
		"id", msg.ID,
		"retry_count", msg.RetryCount,
		"error", err)

	// Update message
	msg.LastError = err.Error()
	msg.RetryCount++
	msg.UpdatedAt = time.Now()

	// Check if we've exceeded max retries
	if msg.RetryCount >= qm.config.MaxRetries {
		// Move to failed queue
		qm.logger.Info("max retries exceeded, moving to failed queue",
			"id", msg.ID,
			"retry_count", msg.RetryCount)

		msg.QueueType = QueueTypeFailed
		msg.Status = StatusFailed
		msg.FailReason = fmt.Sprintf("Max retries (%d) exceeded. Last error: %s",
			qm.config.MaxRetries, msg.LastError)

		// Update stats
		qm.statsMu.Lock()
		qm.stats.TotalFailed++
		qm.statsMu.Unlock()
	} else {
		// Calculate next retry time with exponential backoff
		backoffDelay := qm.getBackoffDelay(msg.RetryCount)
		msg.NextRetry = time.Now().Add(time.Duration(backoffDelay) * time.Second)

		// Move to deferred queue
		msg.QueueType = QueueTypeDeferred
		msg.Status = StatusDeferred

		qm.logger.Info("message deferred",
			"id", msg.ID,
			"retry_count", msg.RetryCount,
			"next_retry", msg.NextRetry.Format(time.RFC3339))
	}

	// Save updated message
	if err := qm.moveMessage(msg, QueueTypeActive, msg.QueueType); err != nil {
		qm.logger.Error("failed to move message", "id", msg.ID, "error", err)
	}
}

// getBackoffDelay calculates the delay for the next retry using exponential backoff
func (qm *QueueManager) getBackoffDelay(retryCount int) int {
	// If a custom retry schedule is defined, use it
	if len(qm.config.RetrySchedule) > 0 {
		if retryCount <= len(qm.config.RetrySchedule) {
			return qm.config.RetrySchedule[retryCount-1]
		}
		// If we've gone beyond the defined schedule, use the last value
		return qm.config.RetrySchedule[len(qm.config.RetrySchedule)-1]
	}

	// Default exponential backoff: 1min, 5min, 15min, 30min, 1hr, 2hr, 4hr, 8hr
	baseDelay := 60 // 1 minute in seconds

	// Calculate exponential backoff with a maximum of 8 hours
	delay := baseDelay * (1 << uint(retryCount-1)) // 2^(retryCount-1) * baseDelay
	maxDelay := 8 * 60 * 60                        // 8 hours in seconds

	if delay > maxDelay {
		return maxDelay
	}

	return delay
}

// HoldMessage moves a message to the held queue for manual review
func (qm *QueueManager) HoldMessage(msgID, reason string) error {
	// Find the message in any queue
	var msg *QueuedMessage
	var sourceQueue QueueType

	for _, qType := range []QueueType{QueueTypeActive, QueueTypeDeferred} {
		qDir := filepath.Join(qm.config.QueueDir, string(qType))
		path := filepath.Join(qDir, msgID+".json")

		if _, err := os.Stat(path); err == nil {
			// Found the message
			loadedMsg, err := qm.loadQueuedMessage(path)
			if err != nil {
				return fmt.Errorf("failed to load message: %w", err)
			}

			msg = loadedMsg
			sourceQueue = qType
			break
		}
	}

	if msg == nil {
		return fmt.Errorf("message %s not found in active or deferred queues", msgID)
	}

	// Update message
	msg.QueueType = QueueTypeHeld
	msg.Status = StatusHeld
	msg.HoldReason = reason
	msg.UpdatedAt = time.Now()

	// Move to held queue
	return qm.moveMessage(msg, sourceQueue, QueueTypeHeld)
}

// ReleaseMessage moves a message from the held queue back to the active queue
func (qm *QueueManager) ReleaseMessage(msgID string) error {
	// Find the message in the held queue
	heldDir := filepath.Join(qm.config.QueueDir, string(QueueTypeHeld))
	path := filepath.Join(heldDir, msgID+".json")

	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("message %s not found in held queue: %w", msgID, err)
	}

	msg, err := qm.loadQueuedMessage(path)
	if err != nil {
		return fmt.Errorf("failed to load message: %w", err)
	}

	// Update message
	msg.QueueType = QueueTypeActive
	msg.Status = StatusQueued
	msg.HoldReason = ""
	msg.UpdatedAt = time.Now()

	// Move to active queue
	return qm.moveMessage(msg, QueueTypeHeld, QueueTypeActive)
}

// GetQueueStats returns the current queue statistics
func (qm *QueueManager) GetQueueStats() QueueStats {
	qm.statsMu.RLock()
	defer qm.statsMu.RUnlock()

	// Return a copy to avoid race conditions
	return QueueStats{
		ActiveCount:    qm.stats.ActiveCount,
		DeferredCount:  qm.stats.DeferredCount,
		HeldCount:      qm.stats.HeldCount,
		FailedCount:    qm.stats.FailedCount,
		TotalProcessed: qm.stats.TotalProcessed,
		TotalDelivered: qm.stats.TotalDelivered,
		TotalFailed:    qm.stats.TotalFailed,
		LastUpdated:    qm.stats.LastUpdated,
	}
}

// processActiveQueue processes messages in the active queue
func (qm *QueueManager) processActiveQueue() {
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	for {
		if !qm.running {
			return
		}

		select {
		case <-ticker.C:
			// Get messages from active queue
			activeQueue := filepath.Join(qm.config.QueueDir, string(QueueTypeActive))
			messages, err := qm.getQueuedMessagesFromDir(activeQueue)
			if err != nil {
				qm.logger.Error("failed to get active queue messages", "error", err)
				continue
			}

			// Sort messages by priority (highest first) and then by creation time (oldest first)
			sort.Slice(messages, func(i, j int) bool {
				if messages[i].Priority != messages[j].Priority {
					return messages[i].Priority > messages[j].Priority
				}
				return messages[i].CreatedAt.Before(messages[j].CreatedAt)
			})

			// Process each message
			for _, msg := range messages {
				// Skip if we're already processing this message
				qm.activeMu.Lock()
				if qm.activeJobs[msg.ID] {
					qm.activeMu.Unlock()
					continue
				}
				qm.activeMu.Unlock()

				// Acquire worker from pool (blocks if pool is full)
				select {
				case qm.workerPool <- struct{}{}:
					// Process message in a goroutine
					go func(msg *QueuedMessage) {
						defer func() {
							// Release worker back to pool
							<-qm.workerPool

							// Remove from active jobs
							qm.activeMu.Lock()
							delete(qm.activeJobs, msg.ID)
							qm.activeMu.Unlock()
						}()

						// Mark as active job
						qm.activeMu.Lock()
						qm.activeJobs[msg.ID] = true
						qm.activeMu.Unlock()

						qm.processMessage(msg)
					}(msg)
				default:
					// Worker pool is full, try again next tick
					break
				}
			}
		}
	}
}

// processDeferredQueue checks deferred messages and moves them to active queue when ready
func (qm *QueueManager) processDeferredQueue() {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		if !qm.running {
			return
		}

		select {
		case <-ticker.C:
			// Get messages from deferred queue
			deferredQueue := filepath.Join(qm.config.QueueDir, string(QueueTypeDeferred))
			messages, err := qm.getQueuedMessagesFromDir(deferredQueue)
			if err != nil {
				qm.logger.Error("failed to get deferred queue messages", "error", err)
				continue
			}

			now := time.Now()
			for _, msg := range messages {
				// If it's time to retry, move to active queue
				if now.After(msg.NextRetry) {
					msg.QueueType = QueueTypeActive
					if err := qm.moveMessage(msg, QueueTypeDeferred, QueueTypeActive); err != nil {
						qm.logger.Error("failed to move message to active queue",
							"id", msg.ID,
							"error", err)
					} else {
						qm.logger.Info("moved message from deferred to active queue",
							"id", msg.ID,
							"retry_count", msg.RetryCount)
					}
				}
			}
		}
	}
}

// moveMessage moves a message from one queue to another
func (qm *QueueManager) moveMessage(msg *QueuedMessage, fromQueue, toQueue QueueType) error {
	// Update message metadata
	msg.QueueType = toQueue
	msg.UpdatedAt = time.Now()

	// Delete from source queue
	sourceFile := filepath.Join(qm.config.QueueDir, string(fromQueue), msg.ID+".json")
	if err := os.Remove(sourceFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove message from source queue: %w", err)
	}

	// Save to destination queue
	return qm.saveQueuedMessage(msg)
}

// updateQueueStats periodically updates queue statistics
func (qm *QueueManager) updateQueueStats() {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		if !qm.running {
			return
		}

		select {
		case <-ticker.C:
			stats := QueueStats{
				LastUpdated: time.Now(),
			}

			// Count messages in each queue
			for _, qType := range []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed} {
				qDir := filepath.Join(qm.config.QueueDir, string(qType))
				files, err := os.ReadDir(qDir)
				if err != nil {
					qm.logger.Error("failed to read queue directory", "type", qType, "error", err)
					continue
				}

				count := 0
				for _, file := range files {
					if !file.IsDir() && filepath.Ext(file.Name()) == ".json" {
						count++
					}
				}

				switch qType {
				case QueueTypeActive:
					stats.ActiveCount = count
				case QueueTypeDeferred:
					stats.DeferredCount = count
				case QueueTypeHeld:
					stats.HeldCount = count
				case QueueTypeFailed:
					stats.FailedCount = count
				}
			}

			// Update stats
			qm.statsMu.Lock()
			// Preserve counters that are incremented elsewhere
			stats.TotalProcessed = qm.stats.TotalProcessed
			stats.TotalDelivered = qm.stats.TotalDelivered
			stats.TotalFailed = qm.stats.TotalFailed
			qm.stats = stats
			qm.statsMu.Unlock()

			qm.logger.Info("queue stats updated",
				"active", stats.ActiveCount,
				"deferred", stats.DeferredCount,
				"held", stats.HeldCount,
				"failed", stats.FailedCount,
				"total_processed", stats.TotalProcessed,
				"total_delivered", stats.TotalDelivered,
				"total_failed", stats.TotalFailed)
		}
	}
}

// getQueuedMessagesFromDir gets all queued messages from a specific directory
func (qm *QueueManager) getQueuedMessagesFromDir(dir string) ([]*QueuedMessage, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*QueuedMessage{}, nil
		}
		return nil, fmt.Errorf("failed to read queue directory: %w", err)
	}

	var messages []*QueuedMessage
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		path := filepath.Join(dir, file.Name())
		msg, err := qm.loadQueuedMessage(path)
		if err != nil {
			qm.logger.Error("failed to load queued message", "path", path, "error", err)
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
	// Determine queue directory based on message queue type
	queueDir := filepath.Join(qm.config.QueueDir, string(msg.QueueType))
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Save to queue directory
	path := filepath.Join(queueDir, msg.ID+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write message metadata: %w", err)
	}

	return nil
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
