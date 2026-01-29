package queue

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Helper function to create a new queue manager for testing
func setupQueueManager(t *testing.T) (*Manager, string) {
	// Create a temporary test directory
	queueDir := t.TempDir()

	// Create queue manager
	qm := NewManager(queueDir, 24) // 24 hours retention

	return qm, queueDir
}

func TestEnqueueMessage(t *testing.T) {
	qm, _ := setupQueueManager(t)
	defer qm.Stop()

	id1, err := qm.EnqueueMessage(
		"sender@example.com",
		[]string{"recipient@example.com"},
		"Test message",
		[]byte("From: sender@example.com\nTo: recipient@example.com\nSubject: Test message\n\nTest content"),
		PriorityNormal,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("Error enqueuing message: %v", err)
	}
	if id1 == "" {
		t.Fatal("Expected non-empty message ID")
	}

	// Test statistics
	stats := qm.GetStats()
	if stats.ActiveCount != 1 {
		t.Errorf("Expected active count of 1, got %d", stats.ActiveCount)
	}

	// Test message retrieval
	msg, err := qm.GetMessage(id1)
	if err != nil {
		t.Fatalf("Error retrieving message: %v", err)
	}
	if msg.ID != id1 {
		t.Errorf("Expected message ID %s, got %s", id1, msg.ID)
	}
	if msg.From != "sender@example.com" {
		t.Errorf("Expected From=sender@example.com, got %s", msg.From)
	}

	// Test content retrieval
	content, err := qm.GetMessageContent(id1)
	if err != nil {
		t.Fatalf("Error retrieving content: %v", err)
	}
	expectedContent := "From: sender@example.com\nTo: recipient@example.com\nSubject: Test message\n\nTest content"
	if string(content) != expectedContent {
		t.Errorf("Expected content %q, got %q", expectedContent, string(content))
	}

	// Test annotations
	err = qm.SetAnnotation(id1, "test-key", "test-value")
	if err != nil {
		t.Fatalf("Error setting annotation: %v", err)
	}
	msg, _ = qm.GetMessage(id1)
	if msg.Annotations["test-key"] != "test-value" {
		t.Errorf("Expected annotation test-key=test-value, got %s", msg.Annotations["test-key"])
	}

	// Test message deletion
	err = qm.DeleteMessage(id1)
	if err != nil {
		t.Fatalf("Error deleting message: %v", err)
	}
	_, err = qm.GetMessage(id1)
	if err == nil {
		t.Error("Expected error after message deletion, but message still exists")
	}
}

func TestCleanupExpiredMessages(t *testing.T) {
	qm, queueDir := setupQueueManager(t)
	defer qm.Stop()

	// Create a message with old timestamps
	id2, err := qm.EnqueueMessage(
		"old@example.com",
		[]string{"recipient@example.com"},
		"Old message",
		[]byte("This is an old test message"),
		PriorityLow,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("Error creating old message: %v", err)
	}

	// Update the timestamps directly in the file
	activeDir := filepath.Join(queueDir, string(Active))
	msgPath := filepath.Join(activeDir, id2+".json")

	// Get the message
	msg, err := qm.GetMessage(id2)
	if err != nil {
		t.Fatalf("Error getting message: %v", err)
	}

	// Set timestamps to 48 hours ago
	oldTime := time.Now().Add(-48 * time.Hour)
	msg.CreatedAt = oldTime
	msg.UpdatedAt = oldTime

	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Error marshaling message: %v", err)
	}

	// Write the updated message
	if err := os.WriteFile(msgPath, data, 0644); err != nil {
		t.Fatalf("Error writing message file: %v", err)
	}

	// Run cleanup with 24h retention
	deleted, err := qm.CleanupExpiredMessages(24)
	if err != nil {
		t.Fatalf("Error during cleanup: %v", err)
	}
	if deleted != 1 {
		t.Errorf("Expected to delete 1 message, deleted %d", deleted)
	}

	// Verify deletion
	_, err = qm.GetMessage(id2)
	if err == nil {
		t.Error("Expected old message to be deleted, but it still exists")
	}
}

func TestQueueOperations(t *testing.T) {
	qm, _ := setupQueueManager(t)
	defer qm.Stop()

	// Create a message
	id, err := qm.EnqueueMessage(
		"sender@example.com",
		[]string{"recipient@example.com"},
		"Queue operations test",
		[]byte("Queue operations test content"),
		PriorityNormal,
		time.Now(),
	)
	if err != nil {
		t.Fatalf("Error enqueuing message: %v", err)
	}

	// Move to deferred queue
	err = qm.MoveMessage(id, Deferred, "Testing deferred queue")
	if err != nil {
		t.Fatalf("Error moving message to deferred queue: %v", err)
	}

	// Check that it's in the deferred queue
	msg, err := qm.GetMessage(id)
	if err != nil {
		t.Fatalf("Error getting message: %v", err)
	}
	if msg.QueueType != Deferred {
		t.Errorf("Expected queue type %s, got %s", Deferred, msg.QueueType)
	}
	if msg.LastError != "Testing deferred queue" {
		t.Errorf("Expected LastError='Testing deferred queue', got %s", msg.LastError)
	}

	// Add delivery attempts
	err = qm.AddAttempt(id, "failed", "Connection timeout")
	if err != nil {
		t.Fatalf("Error adding attempt: %v", err)
	}

	// Check attempts
	msg, err = qm.GetMessage(id)
	if err != nil {
		t.Fatalf("Error getting message: %v", err)
	}
	if len(msg.Attempts) != 1 {
		t.Errorf("Expected 1 attempt, got %d", len(msg.Attempts))
	}
	if msg.Attempts[0].Result != "failed" {
		t.Errorf("Expected attempt result 'failed', got %s", msg.Attempts[0].Result)
	}
	if msg.Attempts[0].Error != "Connection timeout" {
		t.Errorf("Expected attempt error 'Connection timeout', got %s", msg.Attempts[0].Error)
	}

	// Clean up
	err = qm.DeleteMessage(id)
	if err != nil {
		t.Fatalf("Error deleting message: %v", err)
	}
}
