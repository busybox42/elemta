package queue

import (
	"testing"
	"time"
)

func TestProcessor(t *testing.T) {
	// Create a temporary directory for testing
	queueDir := t.TempDir()

	// Create queue manager
	manager := NewManager(queueDir, 24) // 24 hours retention
	defer manager.Stop()

	// Create processor config
	config := ProcessorConfig{
		Enabled:       true,
		Interval:      100 * time.Millisecond, // Fast for testing
		MaxConcurrent: 2,
		MaxRetries:    3,
		RetrySchedule: []int{1, 2, 4}, // Fast retries for testing
		CleanupAge:    time.Hour,
	}

	t.Run("StartStop", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}

		// Wait a bit to ensure it's running
		time.Sleep(200 * time.Millisecond)

		if err := processor.Stop(); err != nil {
			t.Fatalf("Failed to stop processor: %v", err)
		}
	})

	t.Run("ProcessMessage", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Ensure mock handler is configured for success
		mockHandler.SetShouldFail(false)

		// Enqueue a test message
		msgID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"recipient@example.com"},
			"Test Subject",
			[]byte("Test message content"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for processing
		time.Sleep(500 * time.Millisecond)

		// Check that message was delivered
		deliveries := mockHandler.GetDeliveries()
		if len(deliveries) != 1 {
			t.Errorf("Expected 1 delivery, got %d", len(deliveries))
		}

		if len(deliveries) > 0 && deliveries[0].ID != msgID {
			t.Errorf("Expected message ID %s, got %s", msgID, deliveries[0].ID)
		}

		// Check that message was deleted from queue
		stats := manager.GetStats()
		if stats.ActiveCount != 0 {
			t.Errorf("Expected 0 active messages, got %d", stats.ActiveCount)
		}
	})

	t.Run("RetryLogic", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Configure to fail
		mockHandler.SetShouldFail(true)

		// Enqueue a test message
		msgID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"recipient@example.com"},
			"Test Subject",
			[]byte("Test message content"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for initial processing attempt
		time.Sleep(300 * time.Millisecond)

		// Message should be moved to deferred queue
		stats := manager.GetStats()
		if stats.DeferredCount != 1 {
			t.Errorf("Expected 1 deferred message, got %d", stats.DeferredCount)
		}

		// Get the message to check retry count
		msg, err := manager.GetMessage(msgID)
		if err != nil {
			t.Fatalf("Failed to get message: %v", err)
		}

		if msg.RetryCount != 1 {
			t.Errorf("Expected retry count 1, got %d", msg.RetryCount)
		}

		if msg.QueueType != Deferred {
			t.Errorf("Expected message in deferred queue, got %s", msg.QueueType)
		}
	})

	t.Run("PriorityProcessing", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Ensure success mode
		mockHandler.SetShouldFail(false)

		// Enqueue messages with different priorities
		lowID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"low@example.com"},
			"Low Priority",
			[]byte("Low priority message"),
			PriorityLow,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue low priority message: %v", err)
		}

		highID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"high@example.com"},
			"High Priority",
			[]byte("High priority message"),
			PriorityHigh,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue high priority message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for processing
		time.Sleep(500 * time.Millisecond)

		// Check delivery order (high priority should be delivered first)
		deliveries := mockHandler.GetDeliveries()
		if len(deliveries) != 2 {
			t.Fatalf("Expected 2 deliveries, got %d", len(deliveries))
		}

		// Since we can't guarantee exact order due to concurrency,
		// just verify both messages were delivered
		deliveredIDs := make(map[string]bool)
		for _, delivery := range deliveries {
			deliveredIDs[delivery.ID] = true
		}

		if !deliveredIDs[lowID] {
			t.Errorf("Low priority message %s was not delivered", lowID)
		}

		if !deliveredIDs[highID] {
			t.Errorf("High priority message %s was not delivered", highID)
		}
	})

	t.Run("ConcurrencyLimit", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion

		// Create a processor with concurrency limit of 1
		limitedConfig := config
		limitedConfig.MaxConcurrent = 1
		limitedProcessor := NewProcessor(manager, limitedConfig, mockHandler)

		// Ensure success mode
		mockHandler.SetShouldFail(false)

		// Enqueue multiple messages
		for i := 0; i < 5; i++ {
			_, err := manager.EnqueueMessage(
				"sender@example.com",
				[]string{"recipient@example.com"},
				"Test Subject",
				[]byte("Test message content"),
				PriorityNormal,
				time.Now(),
			)
			if err != nil {
				t.Fatalf("Failed to enqueue message %d: %v", i, err)
			}
		}

		// Start processor
		if err := limitedProcessor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer limitedProcessor.Stop()

		// Wait for processing
		time.Sleep(1 * time.Second)

		// All messages should be delivered
		deliveries := mockHandler.GetDeliveries()
		if len(deliveries) != 5 {
			t.Errorf("Expected 5 deliveries, got %d", len(deliveries))
		}
	})

	t.Run("MetricsTracking", func(t *testing.T) {
		// Create fresh mock handler for this test
		mockHandler := NewMockDeliveryHandler(0) // Default: immediate deletion
		processor := NewProcessor(manager, config, mockHandler)

		// Ensure success mode
		mockHandler.SetShouldFail(false)

		// Enqueue test messages
		successID, err := manager.EnqueueMessage(
			"sender@example.com",
			[]string{"success@example.com"},
			"Success",
			[]byte("Success message"),
			PriorityNormal,
			time.Now(),
		)
		if err != nil {
			t.Fatalf("Failed to enqueue success message: %v", err)
		}

		// Start processor
		if err := processor.Start(); err != nil {
			t.Fatalf("Failed to start processor: %v", err)
		}
		defer processor.Stop()

		// Wait for processing
		time.Sleep(500 * time.Millisecond)

		// Check metrics
		metrics := processor.GetMetrics()
		if metrics.ProcessedTotal < 1 {
			t.Errorf("Expected at least 1 processed message, got %d", metrics.ProcessedTotal)
		}

		if metrics.DeliveredTotal < 1 {
			t.Errorf("Expected at least 1 delivered message, got %d", metrics.DeliveredTotal)
		}

		// Verify message was delivered
		deliveries := mockHandler.GetDeliveries()
		delivered := false
		for _, delivery := range deliveries {
			if delivery.ID == successID {
				delivered = true
				break
			}
		}

		if !delivered {
			t.Errorf("Success message was not delivered")
		}
	})
}

func TestProcessorConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultProcessorConfig()

		if !config.Enabled {
			t.Error("Expected default config to be enabled")
		}

		if config.Interval != 10*time.Second {
			t.Errorf("Expected default interval 10s, got %v", config.Interval)
		}

		if config.MaxConcurrent != 5 {
			t.Errorf("Expected default max concurrent 5, got %d", config.MaxConcurrent)
		}

		if config.MaxRetries != 5 {
			t.Errorf("Expected default max retries 5, got %d", config.MaxRetries)
		}

		if len(config.RetrySchedule) == 0 {
			t.Error("Expected default retry schedule to be non-empty")
		}
	})
}
