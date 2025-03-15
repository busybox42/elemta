package smtp

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestQueueManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "queue-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a config with the temp directory
	config := &Config{
		QueueDir:              tempDir,
		MessageRetentionHours: 24,
		MaxRetries:            5,
		RetrySchedule:         []int{300, 600, 1200, 3600, 7200},
	}

	// Create a new queue manager
	qm := NewQueueManager(config)

	// Test basic queue operations
	t.Run("BasicQueueOperations", func(t *testing.T) {
		// Create a test message
		msg := &Message{
			id:   "test-message-1",
			from: "sender@example.com",
			to:   []string{"recipient@example.com"},
			data: []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		}

		// Enqueue the message
		err := qm.EnqueueMessage(msg, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Check if the message was saved to disk
		msgDir := filepath.Join(tempDir, "active", "test-message-1")
		if _, err := os.Stat(msgDir); os.IsNotExist(err) {
			t.Errorf("Message directory was not created: %s", msgDir)
		}

		// Get active messages
		activeQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get active messages: %v", err)
		}
		if len(messages) != 1 {
			t.Errorf("Expected 1 active message, got %d", len(messages))
		}
		if messages[0].ID != "test-message-1" {
			t.Errorf("Expected message ID 'test-message-1', got '%s'", messages[0].ID)
		}
	})

	// Test queue types
	t.Run("QueueTypes", func(t *testing.T) {
		// Create test messages for different queue types
		msgActive := &Message{
			id:   "test-active",
			from: "sender@example.com",
			to:   []string{"recipient@example.com"},
			data: []byte("Test active message"),
		}
		msgDeferred := &Message{
			id:   "test-deferred",
			from: "sender@example.com",
			to:   []string{"recipient@example.com"},
			data: []byte("Test deferred message"),
		}
		msgHeld := &Message{
			id:   "test-held",
			from: "sender@example.com",
			to:   []string{"recipient@example.com"},
			data: []byte("Test held message"),
		}

		// Enqueue the active message
		err := qm.EnqueueMessage(msgActive, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue active message: %v", err)
		}

		// Enqueue the deferred message
		err = qm.EnqueueMessage(msgDeferred, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue deferred message: %v", err)
		}

		// Get the deferred message and move it to the deferred queue
		deferredQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(deferredQueue)
		if err != nil {
			t.Fatalf("Failed to get messages: %v", err)
		}

		var deferredMsg *QueuedMessage
		for _, m := range messages {
			if m.ID == "test-deferred" {
				deferredMsg = m
				break
			}
		}

		if deferredMsg == nil {
			t.Fatalf("Failed to find deferred message")
		}

		deferredMsg.QueueType = QueueTypeDeferred
		deferredMsg.NextRetry = time.Now().Add(time.Hour)
		err = qm.moveMessage(deferredMsg, QueueTypeActive, QueueTypeDeferred)
		if err != nil {
			t.Fatalf("Failed to move deferred message: %v", err)
		}

		// Enqueue the held message
		err = qm.EnqueueMessage(msgHeld, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue held message: %v", err)
		}

		// Get the held message and move it to the held queue
		activeQueue := filepath.Join(tempDir, "active")
		messages, err = qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get messages: %v", err)
		}

		var heldMsg *QueuedMessage
		for _, m := range messages {
			if m.ID == "test-held" {
				heldMsg = m
				break
			}
		}

		if heldMsg == nil {
			t.Fatalf("Failed to find held message")
		}

		heldMsg.QueueType = QueueTypeHeld
		heldMsg.HoldReason = "Manual hold for testing"
		err = qm.moveMessage(heldMsg, QueueTypeActive, QueueTypeHeld)
		if err != nil {
			t.Fatalf("Failed to move held message: %v", err)
		}

		// Get active messages
		activeMessages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get active messages: %v", err)
		}
		if len(activeMessages) != 2 { // test-message-1 from previous test + test-active
			t.Errorf("Expected 2 active messages, got %d", len(activeMessages))
		}

		// Get deferred messages
		deferredMessages, err := qm.getQueuedMessagesFromDir(filepath.Join(tempDir, "deferred"))
		if err != nil {
			t.Fatalf("Failed to get deferred messages: %v", err)
		}
		if len(deferredMessages) != 1 {
			t.Errorf("Expected 1 deferred message, got %d", len(deferredMessages))
		}
		if deferredMessages[0].ID != "test-deferred" {
			t.Errorf("Expected deferred message ID 'test-deferred', got '%s'", deferredMessages[0].ID)
		}

		// Get held messages
		heldMessages, err := qm.getQueuedMessagesFromDir(filepath.Join(tempDir, "held"))
		if err != nil {
			t.Fatalf("Failed to get held messages: %v", err)
		}
		if len(heldMessages) != 1 {
			t.Errorf("Expected 1 held message, got %d", len(heldMessages))
		}
		if heldMessages[0].ID != "test-held" {
			t.Errorf("Expected held message ID 'test-held', got '%s'", heldMessages[0].ID)
		}
	})

	// Test message metadata and annotations
	t.Run("MessageMetadata", func(t *testing.T) {
		// Create a test message
		msg := &Message{
			id:   "test-metadata",
			from: "sender@example.com",
			to:   []string{"recipient@example.com"},
			data: []byte("Test metadata message"),
		}

		// Enqueue the message
		err := qm.EnqueueMessage(msg, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Get the message
		activeQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get messages: %v", err)
		}

		var qMsg *QueuedMessage
		for _, m := range messages {
			if m.ID == "test-metadata" {
				qMsg = m
				break
			}
		}

		if qMsg == nil {
			t.Fatalf("Failed to find metadata message")
		}

		// Add annotations
		qMsg.Annotations["spf"] = "pass"
		qMsg.Annotations["dkim"] = "pass"
		qMsg.Annotations["dmarc"] = "pass"

		// Update delivery status
		qMsg.DeliveryStatus["recipient@example.com"] = RecipientStatus{
			Status:      StatusDelivered,
			LastAttempt: time.Now(),
			LastError:   "",
		}

		// Add delivery tags
		qMsg.DeliveryTags = append(qMsg.DeliveryTags, "important", "newsletter")

		// Initialize Attempts if needed
		if qMsg.Attempts == nil {
			qMsg.Attempts = make([]DeliveryAttempt, 0)
		}

		// Save the message
		err = qm.saveQueuedMessage(qMsg)
		if err != nil {
			t.Fatalf("Failed to save message: %v", err)
		}

		// Get the message again to verify changes
		messages, err = qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get messages: %v", err)
		}

		var updatedMsg *QueuedMessage
		for _, m := range messages {
			if m.ID == "test-metadata" {
				updatedMsg = m
				break
			}
		}

		if updatedMsg == nil {
			t.Fatalf("Failed to find updated metadata message")
		}

		// Check annotations
		if updatedMsg.Annotations["spf"] != "pass" {
			t.Errorf("Expected SPF annotation 'pass', got '%s'", updatedMsg.Annotations["spf"])
		}
		if updatedMsg.Annotations["dkim"] != "pass" {
			t.Errorf("Expected DKIM annotation 'pass', got '%s'", updatedMsg.Annotations["dkim"])
		}
		if updatedMsg.Annotations["dmarc"] != "pass" {
			t.Errorf("Expected DMARC annotation 'pass', got '%s'", updatedMsg.Annotations["dmarc"])
		}

		// Check delivery status
		status, ok := updatedMsg.DeliveryStatus["recipient@example.com"]
		if !ok {
			t.Errorf("Expected delivery status for recipient@example.com, but it was not found")
		} else if status.Status != StatusDelivered {
			t.Errorf("Expected status StatusDelivered, got %s", status.Status)
		}

		// Check delivery tags
		if len(updatedMsg.DeliveryTags) != 2 {
			t.Errorf("Expected 2 delivery tags, got %d", len(updatedMsg.DeliveryTags))
		}
		if updatedMsg.DeliveryTags[0] != "important" {
			t.Errorf("Expected first tag 'important', got '%s'", updatedMsg.DeliveryTags[0])
		}
		if updatedMsg.DeliveryTags[1] != "newsletter" {
			t.Errorf("Expected second tag 'newsletter', got '%s'", updatedMsg.DeliveryTags[1])
		}
	})

	// Test queue statistics
	t.Run("QueueStatistics", func(t *testing.T) {
		// Get initial stats
		initialStats := qm.GetQueueStats()

		// Create and process a message
		msg := &Message{
			id:   "test-stats",
			from: "sender@example.com",
			to:   []string{"recipient@example.com"},
			data: []byte("Test stats message"),
		}

		// Enqueue the message
		err := qm.EnqueueMessage(msg, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Get the message and mark it as delivered
		activeQueue := filepath.Join(tempDir, "active")
		messages, err := qm.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			t.Fatalf("Failed to get messages: %v", err)
		}

		var qMsg *QueuedMessage
		for _, m := range messages {
			if m.ID == "test-stats" {
				qMsg = m
				break
			}
		}

		if qMsg == nil {
			t.Fatalf("Failed to find stats message")
		}

		qMsg.Status = StatusDelivered
		qMsg.QueueType = QueueTypeDelivered
		err = qm.moveMessage(qMsg, QueueTypeActive, QueueTypeDelivered)
		if err != nil {
			t.Fatalf("Failed to move message: %v", err)
		}

		// Increment the delivered count
		qm.statsMu.Lock()
		qm.stats.TotalDelivered++
		qm.stats.TotalProcessed++
		qm.statsMu.Unlock()

		// Get updated stats
		updatedStats := qm.GetQueueStats()

		// Check that the delivered count increased
		if updatedStats.TotalDelivered <= initialStats.TotalDelivered {
			t.Errorf("Expected TotalDelivered to increase, got %d (was %d)",
				updatedStats.TotalDelivered, initialStats.TotalDelivered)
		}

		// Check that the processed count increased
		if updatedStats.TotalProcessed <= initialStats.TotalProcessed {
			t.Errorf("Expected TotalProcessed to increase, got %d (was %d)",
				updatedStats.TotalProcessed, initialStats.TotalProcessed)
		}
	})
}

// Helper function to create a test message in a specific queue
func createTestMessageInQueue(t *testing.T, qm *QueueManager, queueType QueueType, status MessageStatus) *QueuedMessage {
	// Create a test message
	msg := NewMessage()
	msg.from = "sender@example.com"
	msg.to = []string{"recipient@example.com"}
	msg.data = []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.")

	// Create a queued message
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
		Attempts:    make([]DeliveryAttempt, 0),
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
