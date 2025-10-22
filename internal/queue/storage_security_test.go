package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStorageBackendSecurity(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "elemta_queue_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create storage backend
	backend := NewFileStorageBackend(tmpDir)

	// Test 1: Ensure directories are created with secure permissions (0700)
	t.Run("SecureDirectoryPermissions", func(t *testing.T) {
		if err := backend.EnsureDirectories(); err != nil {
			t.Fatalf("Failed to ensure directories: %v", err)
		}

		// Check main queue directory permissions
		info, err := os.Stat(tmpDir)
		if err != nil {
			t.Fatalf("Failed to stat main queue directory: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Main queue directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
		}

		// Check subdirectory permissions
		queueTypes := []QueueType{Active, Deferred, Hold, Failed}
		for _, qType := range queueTypes {
			qDir := filepath.Join(tmpDir, string(qType))
			info, err := os.Stat(qDir)
			if err != nil {
				t.Fatalf("Failed to stat queue directory %s: %v", qType, err)
			}
			if info.Mode().Perm() != 0700 {
				t.Errorf("Queue directory %s has incorrect permissions: got %o, want 0700", qType, info.Mode().Perm())
			}
		}

		// Check data directory permissions
		dataDir := filepath.Join(tmpDir, "data")
		info, err = os.Stat(dataDir)
		if err != nil {
			t.Fatalf("Failed to stat data directory: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Data directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
		}

		// Check tmp directory permissions
		tmpDirPath := filepath.Join(tmpDir, "tmp")
		info, err = os.Stat(tmpDirPath)
		if err != nil {
			t.Fatalf("Failed to stat tmp directory: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Tmp directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
		}
	})

	// Test 2: File operations use secure permissions (0600)
	t.Run("SecureFilePermissions", func(t *testing.T) {
		// Create a test message
		msg := Message{
			ID:        "test-message-1",
			QueueType: Active,
			From:      "test@example.com",
			To:        []string{"recipient@example.com"},
			Subject:   "Test Message",
			CreatedAt: time.Now(),
		}

		// Store message
		if err := backend.Store(msg); err != nil {
			t.Fatalf("Failed to store message: %v", err)
		}

		// Check file permissions
		filePath := filepath.Join(tmpDir, string(Active), "test-message-1.json")
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("Failed to stat message file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("Message file has incorrect permissions: got %o, want 0600", info.Mode().Perm())
		}

		// Test content file permissions
		contentData := []byte("This is test message content")
		if err := backend.StoreContent("test-message-1", contentData); err != nil {
			t.Fatalf("Failed to store content: %v", err)
		}

		contentPath := filepath.Join(tmpDir, "data", "test-message-1")
		info, err = os.Stat(contentPath)
		if err != nil {
			t.Fatalf("Failed to stat content file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("Content file has incorrect permissions: got %o, want 0600", info.Mode().Perm())
		}
	})

	// Test 3: Atomic file operations
	t.Run("AtomicFileOperations", func(t *testing.T) {
		// Create a test message
		msg := Message{
			ID:        "test-atomic-1",
			QueueType: Active,
			From:      "test@example.com",
			To:        []string{"recipient@example.com"},
			Subject:   "Atomic Test Message",
			CreatedAt: time.Now(),
		}

		// Store message (should use atomic write)
		if err := backend.Store(msg); err != nil {
			t.Fatalf("Failed to store message atomically: %v", err)
		}

		// Verify message was stored correctly
		retrieved, err := backend.Retrieve("test-atomic-1")
		if err != nil {
			t.Fatalf("Failed to retrieve message: %v", err)
		}
		if retrieved.ID != msg.ID {
			t.Errorf("Retrieved message ID mismatch: got %s, want %s", retrieved.ID, msg.ID)
		}
	})

	// Test 4: Symlink attack prevention
	t.Run("SymlinkAttackPrevention", func(t *testing.T) {
		// Create a symlink to a sensitive file
		sensitiveFile := filepath.Join(tmpDir, "sensitive.txt")
		if err := os.WriteFile(sensitiveFile, []byte("sensitive data"), 0600); err != nil {
			t.Fatalf("Failed to create sensitive file: %v", err)
		}

		// Create a symlink in the queue directory
		symlinkPath := filepath.Join(tmpDir, string(Active), "malicious.json")
		if err := os.Symlink(sensitiveFile, symlinkPath); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		// Try to store a message with the same name (should detect symlink attack)
		msg := Message{
			ID:        "malicious",
			QueueType: Active,
			From:      "attacker@example.com",
			To:        []string{"victim@example.com"},
			Subject:   "Malicious Message",
			CreatedAt: time.Now(),
		}

		err := backend.Store(msg)
		if err == nil {
			t.Error("Expected symlink attack to be detected, but operation succeeded")
		}
		if err != nil && !contains(err.Error(), "symlink attack detected") {
			t.Errorf("Expected symlink attack error, got: %v", err)
		}
	})

	// Test 5: Race condition prevention with concurrent operations
	t.Run("RaceConditionPrevention", func(t *testing.T) {
		// Create multiple messages concurrently
		const numMessages = 10
		done := make(chan error, numMessages)

		for i := 0; i < numMessages; i++ {
			go func(id int) {
				msg := Message{
					ID:        fmt.Sprintf("concurrent-%d", id),
					QueueType: Active,
					From:      "test@example.com",
					To:        []string{"recipient@example.com"},
					Subject:   "Concurrent Test Message",
					CreatedAt: time.Now(),
				}
				done <- backend.Store(msg)
			}(i)
		}

		// Wait for all operations to complete
		for i := 0; i < numMessages; i++ {
			if err := <-done; err != nil {
				t.Errorf("Concurrent store operation failed: %v", err)
			}
		}

		// Verify all messages were stored correctly
		for i := 0; i < numMessages; i++ {
			id := fmt.Sprintf("concurrent-%d", i)
			msg, err := backend.Retrieve(id)
			if err != nil {
				t.Errorf("Failed to retrieve concurrent message %s: %v", id, err)
			}
			if msg.ID != id {
				t.Errorf("Retrieved message ID mismatch: got %s, want %s", msg.ID, id)
			}
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			contains(s[1:], substr))))
}
