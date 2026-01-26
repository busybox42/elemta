package queue

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestUnifiedQueueSystem(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "unified_queue_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create configuration
	config := QueueConfiguration{
		QueueDir:           tempDir,
		StorageType:        "file",
		Enabled:            true,
		MaxWorkers:         2,
		ProcessInterval:    1, // 1 second for testing
		MaxConcurrent:      3,
		RetrySchedule:      []int{60, 300, 900},
		MaxRetries:         3,
		DeliveryTimeout:    30,
		RetentionHours:     24,
		CleanupInterval:    1,
		RateLimitEnabled:   true,
		RateLimitPerDomain: 5,
		RateLimitWindow:    60,
		MonitoringEnabled:  true,
		Debug:              true,
		VerboseLogging:     true,
	}

	// Create unified queue system
	uqs := NewUnifiedQueueSystem(config)
	if uqs == nil {
		t.Fatal("Failed to create unified queue system")
	}

	// Start the system
	if err := uqs.Start(); err != nil {
		t.Fatalf("Failed to start unified queue system: %v", err)
	}
	defer uqs.Stop()

	// Test enqueuing messages
	t.Run("EnqueueMessage", func(t *testing.T) {
		messageID, err := uqs.QueueManager.EnqueueMessage(
			"sender@example.com",
			[]string{"recipient@example.com"},
			"Test Message",
			[]byte("This is a test message"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		if messageID == "" {
			t.Fatal("Message ID should not be empty")
		}

		// Verify message exists
		msg, err := uqs.QueueManager.GetMessage(messageID)
		if err != nil {
			t.Fatalf("Failed to get message: %v", err)
		}

		if msg.ID != messageID {
			t.Errorf("Expected message ID %s, got %s", messageID, msg.ID)
		}

		if msg.From != "sender@example.com" {
			t.Errorf("Expected from 'sender@example.com', got '%s'", msg.From)
		}

		if len(msg.To) != 1 || msg.To[0] != "recipient@example.com" {
			t.Errorf("Expected to ['recipient@example.com'], got %v", msg.To)
		}
	})

	// Test queue statistics
	t.Run("QueueStats", func(t *testing.T) {
		stats := uqs.QueueManager.GetStats()

		// Should have at least one message from previous test
		if stats.ActiveCount < 1 {
			t.Errorf("Expected at least 1 active message, got %d", stats.ActiveCount)
		}

		if stats.LastUpdated.IsZero() {
			t.Error("LastUpdated should not be zero")
		}
	})

	// Test message operations
	t.Run("MessageOperations", func(t *testing.T) {
		// Enqueue a test message
		messageID, err := uqs.QueueManager.EnqueueMessage(
			"test@example.com",
			[]string{"dest@example.com"},
			"Operation Test",
			[]byte("Test content for operations"),
			PriorityHigh,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Test moving message to deferred queue
		err = uqs.QueueManager.MoveMessage(messageID, Deferred, "Testing deferred queue")
		if err != nil {
			t.Fatalf("Failed to move message to deferred queue: %v", err)
		}

		// Verify message is in deferred queue
		msg, err := uqs.QueueManager.GetMessage(messageID)
		if err != nil {
			t.Fatalf("Failed to get message: %v", err)
		}

		if msg.QueueType != Deferred {
			t.Errorf("Expected queue type %s, got %s", Deferred, msg.QueueType)
		}

		// Test adding attempt
		err = uqs.QueueManager.AddAttempt(messageID, "failed", "Connection timeout")
		if err != nil {
			t.Fatalf("Failed to add attempt: %v", err)
		}

		// Verify attempt was added
		msg, err = uqs.QueueManager.GetMessage(messageID)
		if err != nil {
			t.Fatalf("Failed to get message: %v", err)
		}

		if len(msg.Attempts) != 1 {
			t.Errorf("Expected 1 attempt, got %d", len(msg.Attempts))
		}

		if msg.Attempts[0].Result != "failed" {
			t.Errorf("Expected attempt result 'failed', got '%s'", msg.Attempts[0].Result)
		}

		// Test annotations
		err = uqs.QueueManager.SetAnnotation(messageID, "test_key", "test_value")
		if err != nil {
			t.Fatalf("Failed to set annotation: %v", err)
		}

		msg, err = uqs.QueueManager.GetMessage(messageID)
		if err != nil {
			t.Fatalf("Failed to get message: %v", err)
		}

		if msg.Annotations["test_key"] != "test_value" {
			t.Errorf("Expected annotation 'test_value', got '%s'", msg.Annotations["test_key"])
		}

		// Test message content
		content, err := uqs.QueueManager.GetMessageContent(messageID)
		if err != nil {
			t.Fatalf("Failed to get message content: %v", err)
		}

		expectedContent := "Test content for operations"
		if string(content) != expectedContent {
			t.Errorf("Expected content '%s', got '%s'", expectedContent, string(content))
		}

		// Clean up
		err = uqs.QueueManager.DeleteMessage(messageID)
		if err != nil {
			t.Fatalf("Failed to delete message: %v", err)
		}
	})

	// Test list operations
	t.Run("ListOperations", func(t *testing.T) {
		// Enqueue multiple messages
		messageIDs := make([]string, 3)
		for i := 0; i < 3; i++ {
			messageID, err := uqs.QueueManager.EnqueueMessage(
				"test@example.com",
				[]string{"dest@example.com"},
				"List Test",
				[]byte("Test content"),
				Priority(i+1), // Different priorities
				time.Now(),
			)
			if err != nil {
				t.Fatalf("Failed to enqueue message %d: %v", i, err)
			}
			messageIDs[i] = messageID
		}

		// Test listing active messages
		activeMessages, err := uqs.QueueManager.ListMessages(Active)
		if err != nil {
			t.Fatalf("Failed to list active messages: %v", err)
		}

		if len(activeMessages) < 3 {
			t.Errorf("Expected at least 3 active messages, got %d", len(activeMessages))
		}

		// Verify messages are sorted by priority (highest first)
		for i := 0; i < len(activeMessages)-1; i++ {
			if activeMessages[i].Priority < activeMessages[i+1].Priority {
				t.Errorf("Messages not sorted by priority correctly")
				break
			}
		}

		// Test listing all messages
		allMessages, err := uqs.QueueManager.GetAllMessages()
		if err != nil {
			t.Fatalf("Failed to get all messages: %v", err)
		}

		if len(allMessages) < 3 {
			t.Errorf("Expected at least 3 total messages, got %d", len(allMessages))
		}

		// Clean up
		for _, messageID := range messageIDs {
			uqs.QueueManager.DeleteMessage(messageID)
		}
	})

	// Test system statistics
	t.Run("SystemStats", func(t *testing.T) {
		stats := uqs.GetSystemStats()

		if stats.QueueStats.LastUpdated.IsZero() {
			t.Error("Queue stats LastUpdated should not be zero")
		}

		if stats.LastUpdated.IsZero() {
			t.Error("System stats LastUpdated should not be zero")
		}

		// System health should be true with monitoring enabled
		if !stats.SystemHealth {
			t.Error("System health should be true")
		}
	})

	// Test delivery manager functionality
	t.Run("DeliveryManager", func(t *testing.T) {
		// Test rate limiting
		canAcquire := uqs.DeliveryManager.AcquireRateLimit("example.com")
		if !canAcquire {
			t.Error("Should be able to acquire rate limit for new domain")
		}

		// Test delivery hook
		hook := func(event string, messageID string, details map[string]interface{}) {
			// Hook implementation for testing
		}
		uqs.DeliveryManager.AddDeliveryHook(hook)

		// Test configuration changes
		uqs.DeliveryManager.SetMaxConcurrent(5)
		uqs.DeliveryManager.SetRetrySchedule([]int{30, 60, 120})
	})

	// Test processor manager functionality
	t.Run("ProcessorManager", func(t *testing.T) {
		// Test configuration changes
		uqs.ProcessorManager.SetEnabled(true)
		uqs.ProcessorManager.SetInterval(2 * time.Second)
		uqs.ProcessorManager.SetMaxWorkers(3)

		// Test cleanup
		err := uqs.ProcessorManager.RunCleanup()
		if err != nil {
			t.Fatalf("Failed to run cleanup: %v", err)
		}

		// Test queue processing
		ctx := context.Background()
		err = uqs.ProcessorManager.ProcessAllQueues(ctx)
		if err != nil {
			t.Fatalf("Failed to process all queues: %v", err)
		}
	})
}

func TestQueueSystemIntegration(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "integration_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Test with minimal configuration
	config := QueueConfiguration{
		QueueDir:        tempDir,
		StorageType:     "file",
		Enabled:         true,
		MaxWorkers:      1,
		ProcessInterval: 1,
		RetentionHours:  1,
	}

	uqs := NewUnifiedQueueSystem(config)
	if err := uqs.Start(); err != nil {
		t.Fatalf("Failed to start system: %v", err)
	}
	defer uqs.Stop()

	// Test complete message lifecycle
	messageID, err := uqs.QueueManager.EnqueueMessage(
		"sender@test.com",
		[]string{"recipient@test.com"},
		"Integration Test",
		[]byte("Full lifecycle test"),
		PriorityNormal,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("Failed to enqueue message: %v", err)
	}

	// Move through different queues
	err = uqs.QueueManager.MoveMessage(messageID, Deferred, "Testing deferred")
	if err != nil {
		t.Fatalf("Failed to move to deferred: %v", err)
	}

	err = uqs.QueueManager.MoveMessage(messageID, Hold, "Testing hold")
	if err != nil {
		t.Fatalf("Failed to move to hold: %v", err)
	}

	err = uqs.QueueManager.MoveMessage(messageID, Failed, "Testing failed")
	if err != nil {
		t.Fatalf("Failed to move to failed: %v", err)
	}

	// Verify final state
	msg, err := uqs.QueueManager.GetMessage(messageID)
	if err != nil {
		t.Fatalf("Failed to get final message: %v", err)
	}

	if msg.QueueType != Failed {
		t.Errorf("Expected final queue type %s, got %s", Failed, msg.QueueType)
	}

	if msg.LastError != "Testing failed" {
		t.Errorf("Expected last error 'Testing failed', got '%s'", msg.LastError)
	}
}

func TestStorageBackendDirect(t *testing.T) {
	// Test the storage backend directly
	tempDir, err := os.MkdirTemp("", "storage_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	storage := NewFileStorageBackend(tempDir)
	if err := storage.EnsureDirectories(); err != nil {
		t.Fatalf("Failed to ensure directories: %v", err)
	}

	// Test basic storage operations
	// Make the message older than 1 hour for cleanup testing
	oldTime := time.Now().Add(-2 * time.Hour)
	msg := Message{
		ID:        "test-storage-001",
		QueueType: Active,
		From:      "test@example.com",
		To:        []string{"dest@example.com"},
		Subject:   "Storage Test",
		Size:      100,
		Priority:  PriorityNormal,
		CreatedAt: oldTime,
		UpdatedAt: oldTime,
	}

	// Store message
	if err := storage.Store(msg); err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	// Store content
	content := []byte("Test message content")
	if err := storage.StoreContent(msg.ID, content); err != nil {
		t.Fatalf("Failed to store content: %v", err)
	}

	// Retrieve message
	retrieved, err := storage.Retrieve(msg.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve message: %v", err)
	}

	if retrieved.ID != msg.ID {
		t.Errorf("Expected ID %s, got %s", msg.ID, retrieved.ID)
	}

	// Retrieve content
	retrievedContent, err := storage.RetrieveContent(msg.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve content: %v", err)
	}

	if string(retrievedContent) != string(content) {
		t.Errorf("Expected content '%s', got '%s'", string(content), string(retrievedContent))
	}

	// Test list operation
	messages, err := storage.List(Active)
	if err != nil {
		t.Fatalf("Failed to list messages: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(messages))
	}

	// Test move operation
	if err := storage.Move(msg.ID, Active, Deferred); err != nil {
		t.Fatalf("Failed to move message: %v", err)
	}

	// Verify move
	moved, err := storage.Retrieve(msg.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve moved message: %v", err)
	}

	if moved.QueueType != Deferred {
		t.Errorf("Expected queue type %s, got %s", Deferred, moved.QueueType)
	}

	// Test cleanup (use 1 hour retention to force cleanup)
	deleted, err := storage.Cleanup(1)
	if err != nil {
		t.Fatalf("Failed to cleanup: %v", err)
	}

	if deleted != 1 {
		t.Errorf("Expected to delete 1 message, deleted %d", deleted)
	}
}
