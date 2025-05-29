package smtp

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"net/smtp"
)

// QueueType represents different queue types for message processing
type QueueType string

const (
	QueueTypeActive    QueueType = "active"    // Messages actively being processed
	QueueTypeDeferred  QueueType = "deferred"  // Messages waiting for retry
	QueueTypeHeld      QueueType = "held"      // Messages held for manual review
	QueueTypeFailed    QueueType = "failed"    // Messages that have permanently failed
	QueueTypeDelivered QueueType = "delivered" // Messages that have been successfully delivered
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
	Priority            Priority                   `json:"priority"`
	QueueType           QueueType                  `json:"queue_type"`
	RetryCount          int                        `json:"retry_count"`
	NextRetry           time.Time                  `json:"next_retry"`
	LastError           string                     `json:"last_error"`
	Attempts            []DeliveryAttempt          `json:"attempts"`
	HoldReason          string                     `json:"hold_reason,omitempty"`
	FailReason          string                     `json:"fail_reason,omitempty"`
	Annotations         map[string]string          `json:"annotations,omitempty"`      // For storing metadata like SPF/DKIM results
	DeliveryStatus      map[string]RecipientStatus `json:"delivery_status,omitempty"`  // Status per recipient
	LastDeliveryAttempt time.Time                  `json:"last_delivery_attempt"`      // Time of last delivery attempt
	FirstAttemptTime    time.Time                  `json:"first_attempt_time"`         // Time of first delivery attempt
	ExpiryTime          time.Time                  `json:"expiry_time"`                // Time when message expires
	DeliveryTags        []string                   `json:"delivery_tags,omitempty"`    // Tags for categorizing messages
	DSN                 bool                       `json:"dsn"`                        // Whether to send DSN
	ORCPT               map[string]string          `json:"orcpt,omitempty"`            // Original recipient per recipient
	EnvelopeOptions     map[string]string          `json:"envelope_options,omitempty"` // SMTP envelope options
}

// DeliveryAttempt represents a single delivery attempt
type DeliveryAttempt struct {
	Timestamp  time.Time              `json:"timestamp"`
	Error      string                 `json:"error,omitempty"`
	Server     string                 `json:"server,omitempty"`
	Recipients []string               `json:"recipients,omitempty"`
	Response   string                 `json:"response,omitempty"`
	Duration   time.Duration          `json:"duration"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// RecipientStatus represents the delivery status for a single recipient
type RecipientStatus struct {
	Status      MessageStatus `json:"status"`
	LastAttempt time.Time     `json:"last_attempt"`
	LastError   string        `json:"last_error,omitempty"`
	RetryCount  int           `json:"retry_count"`
	NextRetry   time.Time     `json:"next_retry,omitempty"`
	Server      string        `json:"server,omitempty"`
	Response    string        `json:"response,omitempty"`
	DSNSent     bool          `json:"dsn_sent"`
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

	// Enhanced fields
	deliveryCache   *sync.Map               // Cache for MX records, etc.
	rateLimiters    map[string]*RateLimiter // Rate limiters per domain/IP
	rateLimitersMu  sync.RWMutex
	deliveryHooks   []DeliveryHook // Hooks for delivery events
	deliveryHooksMu sync.RWMutex
	queueStorage    QueueStorage // Storage backend for queue
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

// QueueProcessorConfig represents the queue processor configuration section
type QueueProcessorConfig struct {
	Enabled       bool `toml:"enabled" json:"enabled"`
	Interval      int  `toml:"interval" json:"interval"`
	MaxConcurrent int  `toml:"max_concurrent" json:"max_concurrent"`
	MaxRetries    int  `toml:"max_retries" json:"max_retries"`
}

// StartQueueProcessor starts the queue processor if enabled
func (s *Server) StartQueueProcessor() {
	if s.queueManager == nil {
		log.Printf("Error: No queue manager initialized")
		return
	}

	// Check both possible configuration locations
	var enabled bool
	var interval int

	// Check if we have a queue_processor section
	if s.config.QueueProcessorEnabled {
		enabled = true
		interval = s.config.QueueProcessInterval
		log.Printf("Queue processor enabled via top-level config: %v, interval: %d seconds",
			enabled, interval)
	} else {
		enabled = false
		interval = 0
		log.Printf("Queue processor disabled via config")
	}

	if enabled {
		log.Printf("Starting queue processor with interval %d seconds", interval)

		// Set queue processing parameters
		s.queueManager.config.QueueProcessorEnabled = true
		s.queueManager.config.QueueProcessInterval = interval

		// Start the queue processor
		s.queueManager.Start()
	} else {
		log.Printf("Queue processor disabled, not starting")
	}
}

// RateLimiter represents a rate limiter for a domain or IP
type RateLimiter struct {
	Limit     int           // Maximum number of concurrent connections
	Tokens    int           // Current number of available tokens
	TokensMu  sync.Mutex    // Mutex for tokens
	LastReset time.Time     // Time of last token reset
	Interval  time.Duration // Interval between token resets
}

// DeliveryHook is a function that is called on delivery events
type DeliveryHook func(event string, msg *QueuedMessage, details map[string]interface{})

// QueueStorage defines the interface for queue storage backends
type QueueStorage interface {
	// Store a message in the queue
	Store(msg *QueuedMessage) error

	// Retrieve a message from the queue
	Retrieve(id string) (*QueuedMessage, error)

	// Update a message in the queue
	Update(msg *QueuedMessage) error

	// Delete a message from the queue
	Delete(id string) error

	// List messages in a queue
	List(queueType QueueType) ([]*QueuedMessage, error)

	// Count messages in a queue
	Count(queueType QueueType) (int, error)

	// Move a message between queues
	Move(id string, fromQueue, toQueue QueueType) error
}

// FileQueueStorage implements QueueStorage using the file system
type FileQueueStorage struct {
	queueDir string
}

// NewFileQueueStorage creates a new FileQueueStorage
func NewFileQueueStorage(queueDir string) *FileQueueStorage {
	return &FileQueueStorage{
		queueDir: queueDir,
	}
}

// Store stores a message in the queue
func (s *FileQueueStorage) Store(msg *QueuedMessage) error {
	// Create queue directory if it doesn't exist
	queueDir := filepath.Join(s.queueDir, string(msg.QueueType))
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write to file
	filePath := filepath.Join(queueDir, msg.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	return nil
}

// Retrieve retrieves a message from the queue
func (s *FileQueueStorage) Retrieve(id string) (*QueuedMessage, error) {
	// Try to find the message in any queue
	queueTypes := []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed}

	for _, queueType := range queueTypes {
		filePath := filepath.Join(s.queueDir, string(queueType), id+".json")
		if _, err := os.Stat(filePath); err == nil {
			// File exists, read it
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read message file: %w", err)
			}

			// Unmarshal JSON
			var msg QueuedMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				return nil, fmt.Errorf("failed to unmarshal message: %w", err)
			}

			return &msg, nil
		}
	}

	return nil, fmt.Errorf("message not found: %s", id)
}

// Update updates a message in the queue
func (s *FileQueueStorage) Update(msg *QueuedMessage) error {
	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write to file
	filePath := filepath.Join(s.queueDir, string(msg.QueueType), msg.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	return nil
}

// Delete deletes a message from the queue
func (s *FileQueueStorage) Delete(id string) error {
	// Try to find the message in any queue
	queueTypes := []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed}

	for _, queueType := range queueTypes {
		filePath := filepath.Join(s.queueDir, string(queueType), id+".json")
		if _, err := os.Stat(filePath); err == nil {
			// File exists, delete it
			if err := os.Remove(filePath); err != nil {
				return fmt.Errorf("failed to delete message file: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("message not found: %s", id)
}

// List lists messages in a queue
func (s *FileQueueStorage) List(queueType QueueType) ([]*QueuedMessage, error) {
	queueDir := filepath.Join(s.queueDir, string(queueType))

	// Check if directory exists
	if _, err := os.Stat(queueDir); os.IsNotExist(err) {
		return []*QueuedMessage{}, nil
	}

	// Read directory
	files, err := os.ReadDir(queueDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %w", err)
	}

	// Load each message
	messages := make([]*QueuedMessage, 0, len(files))
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(queueDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		var msg QueuedMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // Skip files that can't be unmarshaled
		}

		messages = append(messages, &msg)
	}

	return messages, nil
}

// Count counts messages in a queue
func (s *FileQueueStorage) Count(queueType QueueType) (int, error) {
	queueDir := filepath.Join(s.queueDir, string(queueType))

	// Check if directory exists
	if _, err := os.Stat(queueDir); os.IsNotExist(err) {
		return 0, nil
	}

	// Read directory
	files, err := os.ReadDir(queueDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read queue directory: %w", err)
	}

	// Count JSON files
	count := 0
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			count++
		}
	}

	return count, nil
}

// Move moves a message between queues
func (s *FileQueueStorage) Move(id string, fromQueue, toQueue QueueType) error {
	// Construct file paths
	fromPath := filepath.Join(s.queueDir, string(fromQueue), id+".json")
	toPath := filepath.Join(s.queueDir, string(toQueue), id+".json")

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(toPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Read message
	data, err := os.ReadFile(fromPath)
	if err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}

	// Unmarshal to update queue type
	var msg QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Update queue type
	msg.QueueType = toQueue

	// Marshal updated message
	data, err = json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(toPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	// Remove from source
	if err := os.Remove(fromPath); err != nil {
		return fmt.Errorf("failed to remove source file: %w", err)
	}

	return nil
}

// NewQueueManager creates a new queue manager
func NewQueueManager(config *Config) *QueueManager {
	qm := &QueueManager{
		config:     config,
		logger:     slog.Default().With("component", "queue"),
		activeJobs: make(map[string]bool),
		workerPool: make(chan struct{}, config.QueueWorkers),
		stats: QueueStats{
			LastUpdated: time.Now(),
		},
		deliveryCache: &sync.Map{},
		rateLimiters:  make(map[string]*RateLimiter),
		deliveryHooks: make([]DeliveryHook, 0),
		queueStorage:  NewFileQueueStorage(config.QueueDir),
	}

	return qm
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

	// Give goroutines a moment to notice the running flag change
	time.Sleep(200 * time.Millisecond)
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

// EnqueueMessage adds a message to the queue
func (qm *QueueManager) EnqueueMessage(msg *Message, priority Priority) error {
	// Create a new queued message
	qMsg := &QueuedMessage{
		MessageInfo: MessageInfo{
			ID:         msg.id,
			From:       msg.from,
			To:         msg.to,
			Size:       len(msg.data),
			ReceivedAt: time.Now(),
			Status:     StatusQueued,
		},
		Priority:         priority,
		QueueType:        QueueTypeActive,
		RetryCount:       0,
		NextRetry:        time.Time{},
		LastError:        "",
		Attempts:         make([]DeliveryAttempt, 0),
		Annotations:      make(map[string]string),
		DeliveryStatus:   make(map[string]RecipientStatus),
		FirstAttemptTime: time.Time{},
		ExpiryTime:       time.Now().Add(time.Duration(qm.config.MessageRetentionHours) * time.Hour),
		DeliveryTags:     make([]string, 0),
		DSN:              false,
		ORCPT:            make(map[string]string),
		EnvelopeOptions:  make(map[string]string),
	}

	// Initialize delivery status for each recipient
	for _, rcpt := range msg.to {
		qMsg.DeliveryStatus[rcpt] = RecipientStatus{
			Status:      StatusQueued,
			LastAttempt: time.Time{},
			RetryCount:  0,
		}
	}

	// Save message data to disk
	dataPath := filepath.Join(qm.config.QueueDir, "data", qMsg.ID)
	if err := os.MkdirAll(filepath.Dir(dataPath), 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	if err := os.WriteFile(dataPath, msg.data, 0644); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	// Save queued message to active queue
	if err := qm.queueStorage.Store(qMsg); err != nil {
		return fmt.Errorf("failed to save queued message: %w", err)
	}

	// Update statistics
	qm.statsMu.Lock()
	qm.stats.ActiveCount++
	qm.stats.LastUpdated = time.Now()
	qm.statsMu.Unlock()

	// Trigger hooks
	qm.triggerHooks("enqueue", qMsg, nil)

	return nil
}

// cleanupQueue periodically removes old messages from the queue
func (qm *QueueManager) cleanupQueue() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for qm.running {
		select {
		case <-ticker.C:
			// Check if we should stop
			if !qm.running {
				return
			}

			qm.logger.Info("starting queue cleanup")

			// Get all messages from all queues
			var allMessages []*QueuedMessage

			for _, qType := range []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed} {
				// Check if we should stop
				if !qm.running {
					return
				}

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
				// Check if we should stop
				if !qm.running {
					return
				}

				// Skip messages in the failed queue
				if msg.QueueType == QueueTypeFailed {
					continue
				}

				// Check if message is too old based on queue time
				age := now.Sub(msg.CreatedAt)
				expired := false
				expiredReason := ""

				if age > maxAge && maxAge > 0 {
					expired = true
					expiredReason = fmt.Sprintf("Message expired after %s", age.String())
				}

				// Also check the ExpiryTime field if it's set
				if !msg.ExpiryTime.IsZero() && now.After(msg.ExpiryTime) {
					expired = true
					expiredReason = fmt.Sprintf("Message reached expiry time %s", msg.ExpiryTime.Format(time.RFC3339))
				}

				if expired {
					qm.logger.Info("removing expired message from queue",
						"id", msg.ID,
						"reason", expiredReason)

					// Move to failed queue
					msg.QueueType = QueueTypeFailed
					msg.Status = StatusFailed
					msg.FailReason = expiredReason
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
		default:
			// Add a small sleep to prevent CPU spinning and allow for quick exit
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// processMessage processes a single message from the queue
func (qm *QueueManager) processMessage(msg *QueuedMessage) {
	// Mark message as being processed
	qm.activeMu.Lock()
	qm.activeJobs[msg.ID] = true
	qm.activeMu.Unlock()

	// Ensure we mark the job as done when we're finished
	defer func() {
		qm.activeMu.Lock()
		delete(qm.activeJobs, msg.ID)
		qm.activeMu.Unlock()

		// Release worker token
		<-qm.workerPool
	}()

	// Update message status
	msg.Status = StatusDelivering
	if err := qm.queueStorage.Update(msg); err != nil {
		qm.logger.Error("Failed to update message status", "error", err, "id", msg.ID)
	}

	// If this is the first attempt, set the first attempt time
	if msg.FirstAttemptTime.IsZero() {
		msg.FirstAttemptTime = time.Now()
	}

	// Update last delivery attempt time
	msg.LastDeliveryAttempt = time.Now()

	// Load message data
	dataPath := filepath.Join(qm.config.QueueDir, "data", msg.ID)
	data, err := os.ReadFile(dataPath)
	if err != nil {
		qm.logger.Error("Failed to read message data", "error", err, "id", msg.ID)

		// Move to failed queue if we can't read the data
		msg.Status = StatusFailed
		msg.FailReason = fmt.Sprintf("Failed to read message data: %v", err)
		if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeFailed); err != nil {
			qm.logger.Error("Failed to move message to failed queue", "error", err, "id", msg.ID)
		}
		return
	}

	// Create a new delivery attempt
	attempt := DeliveryAttempt{
		Timestamp:  time.Now(),
		Recipients: make([]string, 0, len(msg.To)),
		Details:    make(map[string]interface{}),
	}

	// Group recipients by domain for more efficient delivery
	recipientsByDomain := make(map[string][]string)
	for _, rcpt := range msg.To {
		// Skip recipients that have already been delivered or permanently failed
		status, ok := msg.DeliveryStatus[rcpt]
		if ok && (status.Status == StatusDelivered || status.Status == StatusFailed) {
			continue
		}

		// Extract domain from recipient
		parts := strings.Split(rcpt, "@")
		if len(parts) != 2 {
			qm.logger.Warn("Invalid recipient address", "recipient", rcpt, "id", msg.ID)

			// Mark as failed
			msg.DeliveryStatus[rcpt] = RecipientStatus{
				Status:      StatusFailed,
				LastAttempt: time.Now(),
				LastError:   "Invalid recipient address",
				RetryCount:  msg.DeliveryStatus[rcpt].RetryCount,
			}
			continue
		}

		domain := parts[1]
		recipientsByDomain[domain] = append(recipientsByDomain[domain], rcpt)
		attempt.Recipients = append(attempt.Recipients, rcpt)
	}

	// If no recipients to deliver to, mark as delivered
	if len(attempt.Recipients) == 0 {
		qm.logger.Info("No recipients to deliver to", "id", msg.ID)

		// Check if all recipients have been delivered or failed
		allDone := true
		for _, status := range msg.DeliveryStatus {
			if status.Status != StatusDelivered && status.Status != StatusFailed {
				allDone = false
				break
			}
		}

		if allDone {
			// Move to delivered or failed queue based on whether any recipients were delivered
			anyDelivered := false
			for _, status := range msg.DeliveryStatus {
				if status.Status == StatusDelivered {
					anyDelivered = true
					break
				}
			}

			if anyDelivered {
				msg.Status = StatusDelivered
				if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeDelivered); err != nil {
					qm.logger.Error("Failed to move message to delivered queue", "error", err, "id", msg.ID)
				}
			} else {
				msg.Status = StatusFailed
				msg.FailReason = "All recipients failed"
				if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeFailed); err != nil {
					qm.logger.Error("Failed to move message to failed queue", "error", err, "id", msg.ID)
				}
			}
		} else {
			// Some recipients are deferred, move to deferred queue
			msg.Status = StatusDeferred
			if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeDeferred); err != nil {
				qm.logger.Error("Failed to move message to deferred queue", "error", err, "id", msg.ID)
			}
		}

		return
	}

	// Attempt delivery for each domain
	startTime := time.Now()
	deliveryErrors := make(map[string]string)

	for domain, recipients := range recipientsByDomain {
		// Apply rate limiting for this domain
		if !qm.acquireRateLimit(domain) {
			// If rate limited, defer all recipients for this domain
			for _, rcpt := range recipients {
				msg.DeliveryStatus[rcpt] = RecipientStatus{
					Status:      StatusDeferred,
					LastAttempt: time.Now(),
					LastError:   "Rate limited",
					RetryCount:  msg.DeliveryStatus[rcpt].RetryCount,
					NextRetry:   time.Now().Add(time.Minute * 5), // Retry in 5 minutes
				}
			}
			continue
		}

		// Release rate limit when done
		defer qm.releaseRateLimit(domain)

		// Attempt delivery to this domain
		err := qm.deliverToDomain(msg, domain, recipients, data)

		if err != nil {
			qm.logger.Error("Failed to deliver to domain", "error", err, "domain", domain, "id", msg.ID)
			deliveryErrors[domain] = err.Error()

			// Determine if this is a permanent or temporary failure
			isPermanent := false
			if strings.Contains(err.Error(), "550") ||
				strings.Contains(err.Error(), "553") ||
				strings.Contains(err.Error(), "554") {
				isPermanent = true
			}

			// Update status for all recipients in this domain
			for _, rcpt := range recipients {
				status := msg.DeliveryStatus[rcpt]
				status.LastAttempt = time.Now()
				status.LastError = err.Error()
				status.RetryCount++

				if isPermanent {
					status.Status = StatusFailed
				} else {
					status.Status = StatusDeferred
					status.NextRetry = time.Now().Add(time.Duration(qm.getBackoffDelay(status.RetryCount)) * time.Second)
				}

				msg.DeliveryStatus[rcpt] = status
			}
		} else {
			// Delivery successful for this domain
			for _, rcpt := range recipients {
				msg.DeliveryStatus[rcpt] = RecipientStatus{
					Status:      StatusDelivered,
					LastAttempt: time.Now(),
					Server:      domain,
					Response:    "250 OK",
					DSNSent:     false,
				}
			}
		}
	}

	// Record the delivery attempt
	attempt.Duration = time.Since(startTime)
	if len(deliveryErrors) > 0 {
		// Combine errors
		errStr := ""
		for domain, err := range deliveryErrors {
			if errStr != "" {
				errStr += "; "
			}
			errStr += domain + ": " + err
		}
		attempt.Error = errStr
	}
	msg.Attempts = append(msg.Attempts, attempt)

	// Check if all recipients have been delivered or failed
	allDelivered := true
	allFailed := true
	anyDeferred := false

	for _, status := range msg.DeliveryStatus {
		if status.Status != StatusDelivered {
			allDelivered = false
		}
		if status.Status != StatusFailed {
			allFailed = false
		}
		if status.Status == StatusDeferred {
			anyDeferred = true
		}
	}

	// Determine next steps based on delivery status
	if allDelivered {
		// All recipients delivered successfully
		msg.Status = StatusDelivered
		if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeDelivered); err != nil {
			qm.logger.Error("Failed to move message to delivered queue", "error", err, "id", msg.ID)
		}

		// Trigger hooks
		qm.triggerHooks("delivered", msg, map[string]interface{}{
			"attempt": attempt,
		})

		// Update statistics
		qm.statsMu.Lock()
		qm.stats.TotalDelivered++
		qm.statsMu.Unlock()
	} else if allFailed {
		// All recipients failed permanently
		msg.Status = StatusFailed
		msg.FailReason = "All recipients failed"
		if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeFailed); err != nil {
			qm.logger.Error("Failed to move message to failed queue", "error", err, "id", msg.ID)
		}

		// Trigger hooks
		qm.triggerHooks("failed", msg, map[string]interface{}{
			"attempt": attempt,
		})

		// Update statistics
		qm.statsMu.Lock()
		qm.stats.TotalFailed++
		qm.statsMu.Unlock()
	} else if anyDeferred {
		// Some recipients need to be retried
		msg.Status = StatusDeferred
		msg.RetryCount++

		// Calculate next retry time based on the earliest recipient retry
		nextRetry := time.Now().Add(time.Hour * 24) // Default to 24 hours
		for _, status := range msg.DeliveryStatus {
			if status.Status == StatusDeferred && !status.NextRetry.IsZero() && status.NextRetry.Before(nextRetry) {
				nextRetry = status.NextRetry
			}
		}
		msg.NextRetry = nextRetry

		if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeDeferred); err != nil {
			qm.logger.Error("Failed to move message to deferred queue", "error", err, "id", msg.ID)
		}

		// Trigger hooks
		qm.triggerHooks("deferred", msg, map[string]interface{}{
			"attempt":   attempt,
			"nextRetry": nextRetry,
		})
	} else {
		// Mixed results - some delivered, some failed, none deferred
		// This is an unusual case, but we'll move to delivered if at least one recipient was delivered
		anyDelivered := false
		for _, status := range msg.DeliveryStatus {
			if status.Status == StatusDelivered {
				anyDelivered = true
				break
			}
		}

		if anyDelivered {
			msg.Status = StatusDelivered
			if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeDelivered); err != nil {
				qm.logger.Error("Failed to move message to delivered queue", "error", err, "id", msg.ID)
			}

			// Trigger hooks
			qm.triggerHooks("partial_delivered", msg, map[string]interface{}{
				"attempt": attempt,
			})

			// Update statistics
			qm.statsMu.Lock()
			qm.stats.TotalDelivered++
			qm.statsMu.Unlock()
		} else {
			msg.Status = StatusFailed
			msg.FailReason = "All recipients failed"
			if err := qm.moveMessage(msg, QueueTypeActive, QueueTypeFailed); err != nil {
				qm.logger.Error("Failed to move message to failed queue", "error", err, "id", msg.ID)
			}

			// Trigger hooks
			qm.triggerHooks("failed", msg, map[string]interface{}{
				"attempt": attempt,
			})

			// Update statistics
			qm.statsMu.Lock()
			qm.stats.TotalFailed++
			qm.statsMu.Unlock()
		}
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

	for qm.running {
		select {
		case <-ticker.C:
			// Check if we should stop
			if !qm.running {
				return
			}

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
				// Skip if we're not running anymore
				if !qm.running {
					return
				}

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
		default:
			// Add a small sleep to prevent CPU spinning and allow for quick exit
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// processDeferredQueue checks deferred messages and moves them to active queue when ready
func (qm *QueueManager) processDeferredQueue() {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for qm.running {
		select {
		case <-ticker.C:
			// Check if we should stop
			if !qm.running {
				return
			}

			// Get messages from deferred queue
			deferredQueue := filepath.Join(qm.config.QueueDir, string(QueueTypeDeferred))
			messages, err := qm.getQueuedMessagesFromDir(deferredQueue)
			if err != nil {
				qm.logger.Error("failed to get deferred queue messages", "error", err)
				continue
			}

			now := time.Now()
			for _, msg := range messages {
				// Check if we should stop
				if !qm.running {
					return
				}

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
		default:
			// Add a small sleep to prevent CPU spinning and allow for quick exit
			time.Sleep(100 * time.Millisecond)
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

	for qm.running {
		select {
		case <-ticker.C:
			// Check if we should stop
			if !qm.running {
				return
			}

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
		default:
			// Add a small sleep to prevent CPU spinning and allow for quick exit
			time.Sleep(100 * time.Millisecond)
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

	// Initialize maps if they're nil
	if msg.Annotations == nil {
		msg.Annotations = make(map[string]string)
	}
	if msg.DeliveryStatus == nil {
		msg.DeliveryStatus = make(map[string]RecipientStatus)
	}
	if msg.ORCPT == nil {
		msg.ORCPT = make(map[string]string)
	}
	if msg.EnvelopeOptions == nil {
		msg.EnvelopeOptions = make(map[string]string)
	}

	// Set expiry time if not set or invalid (far in the past or future)
	if msg.ExpiryTime.IsZero() || msg.ExpiryTime.Year() < 2000 || msg.ExpiryTime.Year() > 2100 {
		// Set a reasonable default expiry time (7 days from now)
		msg.ExpiryTime = time.Now().Add(time.Duration(qm.config.MessageRetentionHours) * time.Hour)
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

// deliverToDomain attempts to deliver a message to all recipients at a specific domain
func (qm *QueueManager) deliverToDomain(msg *QueuedMessage, domain string, recipients []string, data []byte) error {
	// Look up MX records for the domain
	mxRecords, err := qm.lookupMX(domain)
	if err != nil {
		return fmt.Errorf("MX lookup failed: %w", err)
	}

	// Try each MX record in order of preference
	var lastErr error
	for _, mx := range mxRecords {
		// Attempt delivery to this MX
		err := qm.deliverToMX(msg, mx.Host, recipients, data)
		if err == nil {
			// Delivery successful
			return nil
		}

		// Store the error and try the next MX
		lastErr = err
		qm.logger.Warn("Delivery to MX failed, trying next", "mx", mx.Host, "error", err, "id", msg.ID)
	}

	// If we get here, all MX records failed
	if lastErr != nil {
		return fmt.Errorf("all MX servers failed: %w", lastErr)
	}

	return fmt.Errorf("no MX records found for domain %s", domain)
}

// lookupMX looks up MX records for a domain with caching
func (qm *QueueManager) lookupMX(domain string) ([]*net.MX, error) {
	// Check cache first
	if cached, ok := qm.deliveryCache.Load(domain + ":mx"); ok {
		if mxRecords, ok := cached.([]*net.MX); ok {
			return mxRecords, nil
		}
	}

	// Lookup MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	// Cache the result (for 1 hour)
	qm.deliveryCache.Store(domain+":mx", mxRecords)
	time.AfterFunc(time.Hour, func() {
		qm.deliveryCache.Delete(domain + ":mx")
	})

	return mxRecords, nil
}

// deliverToMX attempts to deliver a message to a specific MX server
func (qm *QueueManager) deliverToMX(msg *QueuedMessage, mxHost string, recipients []string, data []byte) error {
	// Connect to the MX server
	conn, err := net.DialTimeout("tcp", mxHost+":25", time.Duration(qm.config.ConnectTimeout)*time.Second)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set deadlines
	if err := conn.SetDeadline(time.Now().Add(time.Duration(qm.config.SMTPTimeout) * time.Second)); err != nil {
		qm.logger.Warn("Failed to set connection deadline", "error", err)
	}

	// Create SMTP client
	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	// Say HELO
	if err := client.Hello(qm.config.Hostname); err != nil {
		return fmt.Errorf("HELO failed: %w", err)
	}

	// Start TLS if available
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: mxHost,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			qm.logger.Warn("STARTTLS failed, continuing without TLS", "error", err, "host", mxHost)
		}
	}

	// Set the sender
	if err := client.Mail(msg.From); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set the recipients
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			// Update status for this recipient
			msg.DeliveryStatus[rcpt] = RecipientStatus{
				Status:      StatusFailed,
				LastAttempt: time.Now(),
				LastError:   err.Error(),
				RetryCount:  msg.DeliveryStatus[rcpt].RetryCount + 1,
				Server:      mxHost,
				Response:    err.Error(),
			}

			// Continue with other recipients
			continue
		}
	}

	// Check if any recipients were accepted
	anyAccepted := false
	for _, rcpt := range recipients {
		if status, ok := msg.DeliveryStatus[rcpt]; !ok || status.Status != StatusFailed {
			anyAccepted = true
			break
		}
	}

	if !anyAccepted {
		return fmt.Errorf("all recipients rejected")
	}

	// Send the message data
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("sending message data failed: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing message data failed: %w", err)
	}

	// Quit the session
	if err := client.Quit(); err != nil {
		qm.logger.Warn("Failed to quit SMTP session", "error", err, "host", mxHost)
	}

	// Mark all non-failed recipients as delivered
	for _, rcpt := range recipients {
		if status, ok := msg.DeliveryStatus[rcpt]; !ok || status.Status != StatusFailed {
			msg.DeliveryStatus[rcpt] = RecipientStatus{
				Status:      StatusDelivered,
				LastAttempt: time.Now(),
				Server:      mxHost,
				Response:    "250 OK",
				DSNSent:     false,
			}
		}
	}

	return nil
}

// acquireRateLimit attempts to acquire a rate limit token for a domain
func (qm *QueueManager) acquireRateLimit(domain string) bool {
	qm.rateLimitersMu.RLock()
	limiter, ok := qm.rateLimiters[domain]
	qm.rateLimitersMu.RUnlock()

	if !ok {
		// Create a new rate limiter for this domain
		qm.rateLimitersMu.Lock()
		limiter = &RateLimiter{
			Limit:     qm.config.MaxConnectionsPerDomain,
			Tokens:    qm.config.MaxConnectionsPerDomain,
			LastReset: time.Now(),
			Interval:  time.Second,
		}
		qm.rateLimiters[domain] = limiter
		qm.rateLimitersMu.Unlock()
	}

	// Try to acquire a token
	limiter.TokensMu.Lock()
	defer limiter.TokensMu.Unlock()

	// Reset tokens if interval has passed
	if time.Since(limiter.LastReset) > limiter.Interval {
		limiter.Tokens = limiter.Limit
		limiter.LastReset = time.Now()
	}

	if limiter.Tokens > 0 {
		limiter.Tokens--
		return true
	}

	return false
}

// releaseRateLimit releases a rate limit token for a domain
func (qm *QueueManager) releaseRateLimit(domain string) {
	qm.rateLimitersMu.RLock()
	limiter, ok := qm.rateLimiters[domain]
	qm.rateLimitersMu.RUnlock()

	if ok {
		limiter.TokensMu.Lock()
		if limiter.Tokens < limiter.Limit {
			limiter.Tokens++
		}
		limiter.TokensMu.Unlock()
	}
}

// AddDeliveryHook adds a hook function to be called on delivery events
func (qm *QueueManager) AddDeliveryHook(hook DeliveryHook) {
	qm.deliveryHooksMu.Lock()
	defer qm.deliveryHooksMu.Unlock()

	qm.deliveryHooks = append(qm.deliveryHooks, hook)
}

// triggerHooks calls all registered hooks for an event
func (qm *QueueManager) triggerHooks(event string, msg *QueuedMessage, details map[string]interface{}) {
	qm.deliveryHooksMu.RLock()
	hooks := make([]DeliveryHook, len(qm.deliveryHooks))
	copy(hooks, qm.deliveryHooks)
	qm.deliveryHooksMu.RUnlock()

	for _, hook := range hooks {
		go hook(event, msg, details)
	}
}
