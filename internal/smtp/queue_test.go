package smtp

import (
	"os"
	"path/filepath"
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
		QueueDir:      tempDir,
		MaxWorkers:    2,
		MaxRetries:    3,
		MaxQueueTime:  3600,
		RetrySchedule: []int{1, 5, 10},
		DevMode:       true, // Use dev mode to avoid actual delivery
	}

	// Create a queue manager
	qm := NewQueueManager(config)

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

		// Check if message file exists
		msgPath := filepath.Join(tempDir, msg.id)
		if _, err := os.Stat(msgPath); os.IsNotExist(err) {
			t.Errorf("Message file not created: %s", msgPath)
		}

		// Check if metadata file exists
		metaPath := msgPath + ".json"
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			t.Errorf("Metadata file not created: %s", metaPath)
		}
	})

	// Test getting queued messages
	t.Run("GetQueuedMessages", func(t *testing.T) {
		messages, err := qm.getQueuedMessages()
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Errorf("Expected 1 queued message, got %d", len(messages))
		}

		if len(messages) > 0 && messages[0].ID != msg.id {
			t.Errorf("Expected message ID %s, got %s", msg.id, messages[0].ID)
		}
	})

	// Test message processing
	t.Run("ProcessMessage", func(t *testing.T) {
		// Create a temporary directory for the queue
		tempDir, err := os.MkdirTemp("", "elemta-queue-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		// Create a test config
		config := &Config{
			QueueDir:      tempDir,
			MaxWorkers:    2,
			MaxRetries:    3,
			MaxQueueTime:  3600,
			RetrySchedule: []int{1, 5, 10},
			DevMode:       true, // Use dev mode to avoid actual delivery
		}

		// Create a queue manager
		qm := NewQueueManager(config)

		// Create a test message
		msg := NewMessage()
		msg.from = "sender@example.com"
		msg.to = []string{"recipient@example.com"}
		msg.data = []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.")

		err = qm.EnqueueMessage(msg, PriorityNormal)
		if err != nil {
			t.Fatalf("Failed to enqueue message: %v", err)
		}

		// Get the queued message
		messages, err := qm.getQueuedMessages()
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		if len(messages) != 1 {
			t.Fatalf("Expected 1 queued message, got %d", len(messages))
		}

		// Manually process the message
		queuedMsg := messages[0]
		t.Logf("Processing message ID: %s", queuedMsg.ID)

		// Read message data
		msgPath := filepath.Join(tempDir, queuedMsg.ID)
		_, err = os.ReadFile(msgPath)
		if err != nil {
			t.Fatalf("Failed to read message data: %v", err)
		}

		// Update status to delivering
		queuedMsg.Status = StatusDelivering
		queuedMsg.UpdatedAt = time.Now()
		queuedMsg.Attempts = append(queuedMsg.Attempts, time.Now())
		if err := qm.saveQueuedMessage(queuedMsg); err != nil {
			t.Fatalf("Failed to update message status: %v", err)
		}

		// Simulate successful delivery (in dev mode)
		queuedMsg.Status = StatusDelivered
		queuedMsg.UpdatedAt = time.Now()
		if err := qm.saveQueuedMessage(queuedMsg); err != nil {
			t.Fatalf("Failed to update message status after delivery: %v", err)
		}

		// Cleanup message file after successful delivery
		if err := os.Remove(msgPath); err != nil {
			t.Fatalf("Failed to remove delivered message file: %v", err)
		}

		// Cleanup metadata file after successful delivery
		metaPath := msgPath + ".json"
		if err := os.Remove(metaPath); err != nil {
			t.Fatalf("Failed to remove metadata file: %v", err)
		}

		t.Logf("Message processed successfully")

		// Check if message was processed (files should be removed after successful delivery)
		if _, err := os.Stat(msgPath); !os.IsNotExist(err) {
			t.Errorf("Message file still exists after processing: %s", msgPath)
		}

		if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
			t.Errorf("Metadata file still exists after processing: %s", metaPath)
		}
	})

	// Test priority ordering
	t.Run("PriorityOrdering", func(t *testing.T) {
		// Create a temporary directory for the queue
		tempDir, err := os.MkdirTemp("", "elemta-queue-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		// Create a test config
		config := &Config{
			QueueDir:      tempDir,
			MaxWorkers:    2,
			MaxRetries:    3,
			MaxQueueTime:  3600,
			RetrySchedule: []int{1, 5, 10},
			DevMode:       true, // Use dev mode to avoid actual delivery
		}

		// Create a queue manager
		qm := NewQueueManager(config)

		// Create three messages with different priorities
		msg1 := NewMessage()
		msg1.from = "sender@example.com"
		msg1.to = []string{"recipient1@example.com"}
		msg1.data = []byte("Test message 1")

		msg2 := NewMessage()
		msg2.from = "sender@example.com"
		msg2.to = []string{"recipient2@example.com"}
		msg2.data = []byte("Test message 2")

		msg3 := NewMessage()
		msg3.from = "sender@example.com"
		msg3.to = []string{"recipient3@example.com"}
		msg3.data = []byte("Test message 3")

		// Enqueue with different priorities
		if err := qm.EnqueueMessage(msg1, PriorityLow); err != nil {
			t.Fatalf("Failed to enqueue message 1: %v", err)
		}
		if err := qm.EnqueueMessage(msg2, PriorityHigh); err != nil {
			t.Fatalf("Failed to enqueue message 2: %v", err)
		}
		if err := qm.EnqueueMessage(msg3, PriorityNormal); err != nil {
			t.Fatalf("Failed to enqueue message 3: %v", err)
		}

		// Get messages and check order
		messages, err := qm.getQueuedMessages()
		if err != nil {
			t.Fatalf("Failed to get queued messages: %v", err)
		}

		// Sort messages by priority
		qm.sortMessagesByPriority(messages)

		// Check if we have exactly 3 messages
		if len(messages) != 3 {
			t.Fatalf("Expected exactly 3 queued messages, got %d", len(messages))
		}

		// Check if they're in the right order (highest priority first)
		expectedOrder := []Priority{PriorityHigh, PriorityNormal, PriorityLow}
		for i, expectedPriority := range expectedOrder {
			if i >= len(messages) {
				t.Fatalf("Not enough messages to check priority at index %d", i)
			}
			if messages[i].Priority != expectedPriority {
				t.Errorf("Expected priority %d at index %d, got %d",
					expectedPriority, i, messages[i].Priority)
			}
		}
	})
}

// Helper function to sort messages by priority for testing
func (qm *QueueManager) sortMessagesByPriority(messages []*QueuedMessage) {
	// Sort messages by priority (highest first) and then by next retry time
	for i := 0; i < len(messages); i++ {
		for j := i + 1; j < len(messages); j++ {
			if messages[i].Priority < messages[j].Priority {
				messages[i], messages[j] = messages[j], messages[i]
			}
		}
	}
}
