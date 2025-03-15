package smtp

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestQueueManager(t *testing.T) {
	// Create a temporary directory for the queue
	tempDir, err := os.MkdirTemp("", "elemta-queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test config
	config := &Config{
		QueueDir:              tempDir,
		MaxWorkers:            2,
		MaxRetries:            3,
		MaxQueueTime:          3600,
		RetrySchedule:         []int{1, 5, 10},
		DevMode:               true, // Use dev mode to avoid actual delivery
		KeepDeliveredMessages: true,
		KeepMessageData:       true,
	}

	// Create a queue manager
	qm := NewQueueManager(config)
	qm.Start()
	defer qm.Stop()

	// Create a test message
	msg := NewMessage()
	msg.from = "sender@example.com"
	msg.to = []string{"recipient@example.com"}
	msg.data = []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.")

	// Test enqueuing a message
	t.Run("EnqueueMessage", func(t *testing.T) {
		err := qm.EnqueueMessage(msg, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Check if message data file exists
		msgPath := filepath.Join(tempDir, "data", msg.id)
		if _, err := os.Stat(msgPath); os.IsNotExist(err) {
			t.Errorf("Message data file not created: %s", msgPath)
		}

		// Check if metadata file exists in active queue
		metaPath := filepath.Join(tempDir, "active", msg.id+".json")
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			t.Errorf("Metadata file not created in active queue: %s", metaPath)
		}
	})

	// Test getting queued messages from active queue
	t.Run("GetQueuedMessagesFromActiveQueue", func(t *testing.T) {
		activeQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Errorf("Expected 1 queued message, got %d", len(messages))
		}

		if len(messages) > 0 && messages[0].ID != msg.id {
			t.Errorf("Expected message ID %s, got %s", msg.id, messages[0].ID)
		}

		if len(messages) > 0 && messages[0].QueueType != QueueTypeActive {
			t.Errorf("Expected queue type %s, got %s", QueueTypeActive, messages[0].QueueType)
		}
	})

	// Test moving a message to the deferred queue
	t.Run("MoveMessageToDeferred", func(t *testing.T) {
		// Get the message from active queue
		activeQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Fatalf("Expected 1 queued message, got %d", len(messages))
		}

		// Move to deferred queue
		message := messages[0]
		message.QueueType = QueueTypeDeferred
		message.Status = StatusDeferred
		message.NextRetry = time.Now().Add(time.Minute)
		message.RetryCount = 1
		message.LastError = "Test error"

		err = qm.moveMessage(message, QueueTypeActive, QueueTypeDeferred)
		if err != nil {
			t.Fatalf("Failed to move message to deferred queue: %v", err)
		}

		// Check if message is in deferred queue
		deferredQueue := filepath.Join(tempDir, "deferred")
		messages, err = qm.getQueuedMessagesFromDir(deferredQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Errorf("Expected 1 queued message in deferred queue, got %d", len(messages))
		}

		if len(messages) > 0 && messages[0].QueueType != QueueTypeDeferred {
			t.Errorf("Expected queue type %s, got %s", QueueTypeDeferred, messages[0].QueueType)
		}

		// Check if message is no longer in active queue
		activeQueue = filepath.Join(tempDir, "active")
		messages, err = qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 0 {
			t.Errorf("Expected 0 queued messages in active queue, got %d", len(messages))
		}
	})

	// Test holding a message
	t.Run("HoldMessage", func(t *testing.T) {
		// Get the message from deferred queue
		deferredQueue := filepath.Join(tempDir, "deferred")
		messages, err := qm.getQueuedMessagesFromDir(deferredQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Fatalf("Expected 1 queued message, got %d", len(messages))
		}

		// Hold the message
		err = qm.HoldMessage(messages[0].ID, "Test hold reason")
		if err != nil {
			t.Fatalf("Failed to hold message: %v", err)
		}

		// Check if message is in held queue
		heldQueue := filepath.Join(tempDir, "held")
		messages, err = qm.getQueuedMessagesFromDir(heldQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Errorf("Expected 1 queued message in held queue, got %d", len(messages))
		}

		if len(messages) > 0 && messages[0].QueueType != QueueTypeHeld {
			t.Errorf("Expected queue type %s, got %s", QueueTypeHeld, messages[0].QueueType)
		}

		if len(messages) > 0 && messages[0].Status != StatusHeld {
			t.Errorf("Expected status %s, got %s", StatusHeld, messages[0].Status)
		}

		if len(messages) > 0 && messages[0].HoldReason != "Test hold reason" {
			t.Errorf("Expected hold reason 'Test hold reason', got '%s'", messages[0].HoldReason)
		}

		// Check if message is no longer in deferred queue
		deferredQueue = filepath.Join(tempDir, "deferred")
		messages, err = qm.getQueuedMessagesFromDir(deferredQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 0 {
			t.Errorf("Expected 0 queued messages in deferred queue, got %d", len(messages))
		}
	})

	// Test releasing a message
	t.Run("ReleaseMessage", func(t *testing.T) {
		// Get the message from held queue
		heldQueue := filepath.Join(tempDir, "held")
		messages, err := qm.getQueuedMessagesFromDir(heldQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Fatalf("Expected 1 queued message, got %d", len(messages))
		}

		// Release the message
		err = qm.ReleaseMessage(messages[0].ID)
		if err != nil {
			t.Fatalf("Failed to release message: %v", err)
		}

		// Check if message is in active queue
		activeQueue := filepath.Join(tempDir, "active")
		messages, err = qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Errorf("Expected 1 queued message in active queue, got %d", len(messages))
		}

		if len(messages) > 0 && messages[0].QueueType != QueueTypeActive {
			t.Errorf("Expected queue type %s, got %s", QueueTypeActive, messages[0].QueueType)
		}

		if len(messages) > 0 && messages[0].Status != StatusQueued {
			t.Errorf("Expected status %s, got %s", StatusQueued, messages[0].Status)
		}

		if len(messages) > 0 && messages[0].HoldReason != "" {
			t.Errorf("Expected empty hold reason, got '%s'", messages[0].HoldReason)
		}

		// Check if message is no longer in held queue
		heldQueue = filepath.Join(tempDir, "held")
		messages, err = qm.getQueuedMessagesFromDir(heldQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 0 {
			t.Errorf("Expected 0 queued messages in held queue, got %d", len(messages))
		}
	})

	// Test failing a message
	t.Run("FailMessage", func(t *testing.T) {
		// Get the message from active queue
		activeQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Fatalf("Expected 1 queued message, got %d", len(messages))
		}

		// Move to failed queue
		message := messages[0]
		message.QueueType = QueueTypeFailed
		message.Status = StatusFailed
		message.FailReason = "Test failure reason"

		err = qm.moveMessage(message, QueueTypeActive, QueueTypeFailed)
		if err != nil {
			t.Fatalf("Failed to move message to failed queue: %v", err)
		}

		// Check if message is in failed queue
		failedQueue := filepath.Join(tempDir, "failed")
		messages, err = qm.getQueuedMessagesFromDir(failedQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Errorf("Expected 1 queued message in failed queue, got %d", len(messages))
		}

		if len(messages) > 0 && messages[0].QueueType != QueueTypeFailed {
			t.Errorf("Expected queue type %s, got %s", QueueTypeFailed, messages[0].QueueType)
		}

		if len(messages) > 0 && messages[0].Status != StatusFailed {
			t.Errorf("Expected status %s, got %s", StatusFailed, messages[0].Status)
		}

		if len(messages) > 0 && messages[0].FailReason != "Test failure reason" {
			t.Errorf("Expected fail reason 'Test failure reason', got '%s'", messages[0].FailReason)
		}

		// Check if message is no longer in active queue
		activeQueue = filepath.Join(tempDir, "active")
		messages, err = qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 0 {
			t.Errorf("Expected 0 queued messages in active queue, got %d", len(messages))
		}
	})

	// Test queue statistics
	t.Run("QueueStats", func(t *testing.T) {
		// Force update stats
		qm.updateQueueStats()

		// Get stats
		stats := qm.GetQueueStats()

		// Verify stats
		if stats.ActiveCount != 0 {
			t.Errorf("Expected 0 active messages, got %d", stats.ActiveCount)
		}

		if stats.DeferredCount != 0 {
			t.Errorf("Expected 0 deferred messages, got %d", stats.DeferredCount)
		}

		if stats.HeldCount != 0 {
			t.Errorf("Expected 0 held messages, got %d", stats.HeldCount)
		}

		if stats.FailedCount != 1 {
			t.Errorf("Expected 1 failed message, got %d", stats.FailedCount)
		}
	})

	// Test backoff delay calculation
	t.Run("BackoffDelay", func(t *testing.T) {
		// Test with custom retry schedule
		delay := qm.getBackoffDelay(1)
		if delay != 1 {
			t.Errorf("Expected delay of 1 second for retry 1, got %d", delay)
		}

		delay = qm.getBackoffDelay(2)
		if delay != 5 {
			t.Errorf("Expected delay of 5 seconds for retry 2, got %d", delay)
		}

		delay = qm.getBackoffDelay(3)
		if delay != 10 {
			t.Errorf("Expected delay of 10 seconds for retry 3, got %d", delay)
		}

		// Test beyond defined schedule
		delay = qm.getBackoffDelay(4)
		if delay != 10 {
			t.Errorf("Expected delay of 10 seconds for retry 4 (last value in schedule), got %d", delay)
		}

		// Test with empty schedule (should use exponential backoff)
		config.RetrySchedule = []int{}
		delay = qm.getBackoffDelay(1)
		if delay != 60 {
			t.Errorf("Expected delay of 60 seconds for retry 1 with exponential backoff, got %d", delay)
		}

		delay = qm.getBackoffDelay(2)
		if delay != 120 {
			t.Errorf("Expected delay of 120 seconds for retry 2 with exponential backoff, got %d", delay)
		}

		delay = qm.getBackoffDelay(3)
		if delay != 240 {
			t.Errorf("Expected delay of 240 seconds for retry 3 with exponential backoff, got %d", delay)
		}

		// Test max delay
		delay = qm.getBackoffDelay(10)
		maxDelay := 8 * 60 * 60 // 8 hours in seconds
		if delay != maxDelay {
			t.Errorf("Expected max delay of %d seconds, got %d", maxDelay, delay)
		}
	})
}

// Helper function to create a test message in a specific queue
func createTestMessageInQueue(t *testing.T, qm *QueueManager, queueType QueueType, status MessageStatus) *QueuedMessage {
	msg := NewMessage()
	msg.from = "sender@example.com"
	msg.to = []string{"recipient@example.com"}
	msg.data = []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.")

	// Save message data
	dataDir := filepath.Join(qm.config.QueueDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("Failed to create data directory: %v", err)
	}

	msgDataPath := filepath.Join(dataDir, msg.id)
	if err := os.WriteFile(msgDataPath, msg.data, 0644); err != nil {
		t.Fatalf("Failed to write message data: %v", err)
	}

	// Create queued message
	queuedMsg := &QueuedMessage{
		MessageInfo: MessageInfo{
			ID:        msg.id,
			From:      msg.from,
			To:        msg.to,
			Status:    status,
			CreatedAt: msg.created,
			UpdatedAt: time.Now(),
		},
		Priority:    PriorityNormal,
		QueueType:   queueType,
		RetryCount:  0,
		NextRetry:   time.Now(),
		Attempts:    []time.Time{},
		Annotations: make(map[string]string),
	}

	// Save to queue
	if err := qm.saveQueuedMessage(queuedMsg); err != nil {
		t.Fatalf("Failed to save queued message: %v", err)
	}

	return queuedMsg
}

func TestQueueManagerMultipleMessages(t *testing.T) {
	// Create a temporary directory for the queue
	tempDir, err := os.MkdirTemp("", "elemta-queue-test-multi")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test config
	config := &Config{
		QueueDir:              tempDir,
		MaxWorkers:            2,
		MaxRetries:            3,
		MaxQueueTime:          3600,
		RetrySchedule:         []int{1, 5, 10},
		DevMode:               true,
		KeepDeliveredMessages: true,
		KeepMessageData:       true,
	}

	// Create a queue manager
	qm := NewQueueManager(config)
	qm.Start()
	defer qm.Stop()

	// Create test messages in different queues
	msg1 := createTestMessageInQueue(t, qm, QueueTypeActive, StatusQueued)
	msg2 := createTestMessageInQueue(t, qm, QueueTypeDeferred, StatusDeferred)
	msg3 := createTestMessageInQueue(t, qm, QueueTypeHeld, StatusHeld)
	msg4 := createTestMessageInQueue(t, qm, QueueTypeFailed, StatusFailed)

	// Test queue statistics
	t.Run("QueueStatsMultiple", func(t *testing.T) {
		// Force update stats
		qm.updateQueueStats()

		// Get stats
		stats := qm.GetQueueStats()

		// Verify stats
		if stats.ActiveCount != 1 {
			t.Errorf("Expected 1 active message, got %d", stats.ActiveCount)
		}

		if stats.DeferredCount != 1 {
			t.Errorf("Expected 1 deferred message, got %d", stats.DeferredCount)
		}

		if stats.HeldCount != 1 {
			t.Errorf("Expected 1 held message, got %d", stats.HeldCount)
		}

		if stats.FailedCount != 1 {
			t.Errorf("Expected 1 failed message, got %d", stats.FailedCount)
		}
	})

	// Test priority sorting
	t.Run("PrioritySorting", func(t *testing.T) {
		// Update priorities
		msg1.Priority = PriorityNormal
		msg2.Priority = PriorityHigh
		msg3.Priority = PriorityLow
		msg4.Priority = PriorityCritical

		// Save updated messages
		if err := qm.saveQueuedMessage(msg1); err != nil {
			t.Fatalf("Failed to save message 1: %v", err)
		}
		if err := qm.saveQueuedMessage(msg2); err != nil {
			t.Fatalf("Failed to save message 2: %v", err)
		}
		if err := qm.saveQueuedMessage(msg3); err != nil {
			t.Fatalf("Failed to save message 3: %v", err)
		}
		if err := qm.saveQueuedMessage(msg4); err != nil {
			t.Fatalf("Failed to save message 4: %v", err)
		}

		// Get all messages
		var allMessages []*QueuedMessage
		for _, qType := range []QueueType{QueueTypeActive, QueueTypeDeferred, QueueTypeHeld, QueueTypeFailed} {
			qDir := filepath.Join(tempDir, string(qType))
			messages, err := qm.getQueuedMessagesFromDir(qDir)
			if err != nil {
				t.Fatalf("Failed to get messages from %s queue: %v", qType, err)
			}
			allMessages = append(allMessages, messages...)
		}

		// Sort by priority
		qm.sortMessagesByPriority(allMessages)

		// Verify sort order
		if len(allMessages) != 4 {
			t.Fatalf("Expected 4 messages, got %d", len(allMessages))
		}

		if allMessages[0].Priority != PriorityCritical {
			t.Errorf("Expected first message to have priority Critical, got %v", allMessages[0].Priority)
		}

		if allMessages[1].Priority != PriorityHigh {
			t.Errorf("Expected second message to have priority High, got %v", allMessages[1].Priority)
		}

		if allMessages[2].Priority != PriorityNormal {
			t.Errorf("Expected third message to have priority Normal, got %v", allMessages[2].Priority)
		}

		if allMessages[3].Priority != PriorityLow {
			t.Errorf("Expected fourth message to have priority Low, got %v", allMessages[3].Priority)
		}
	})
}

// Helper function to sort messages by priority
func (qm *QueueManager) sortMessagesByPriority(messages []*QueuedMessage) {
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Priority > messages[j].Priority
	})
}
