package message

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMessage(t *testing.T) {
	msg := NewMessage()

	assert.NotEmpty(t, msg.ID, "Message ID should be generated")
	assert.Equal(t, StatusReceived, msg.Status, "Initial status should be 'received'")
	assert.NotNil(t, msg.To, "To field should be initialized")
	assert.NotNil(t, msg.Headers, "Headers field should be initialized")
	assert.WithinDuration(t, time.Now(), msg.CreatedAt, time.Second, "CreatedAt should be recent")
}

func TestMessageHeaders(t *testing.T) {
	msg := NewMessage()

	t.Run("AddHeader", func(t *testing.T) {
		msg.AddHeader("Subject", "Test Email")
		msg.AddHeader("From", "sender@test.com")
		msg.AddHeader("To", "recipient@test.com")

		assert.Len(t, msg.Headers, 3, "Should have 3 headers")
	})

	t.Run("GetHeader", func(t *testing.T) {
		subject := msg.GetHeader("Subject")
		assert.Equal(t, "Test Email", subject)

		from := msg.GetHeader("From")
		assert.Equal(t, "sender@test.com", from)
	})

	t.Run("GetHeader non-existent", func(t *testing.T) {
		missing := msg.GetHeader("NonExistent")
		assert.Empty(t, missing, "Non-existent header should return empty string")
	})

	t.Run("OverwriteHeader", func(t *testing.T) {
		msg.AddHeader("Subject", "Updated Subject")
		subject := msg.GetHeader("Subject")
		assert.Equal(t, "Updated Subject", subject, "Header should be overwritten")
	})
}

func TestMessageSave(t *testing.T) {
	t.Run("Save message successfully", func(t *testing.T) {
		// Create temp directory
		queueDir := t.TempDir()

		// Create message
		msg := NewMessage()
		msg.From = "sender@example.com"
		msg.To = []string{"recipient@example.com", "another@example.com"}
		msg.Data = []byte("Subject: Test\r\n\r\nThis is a test message")
		msg.Status = StatusQueued
		msg.AddHeader("Subject", "Test Message")
		msg.AddHeader("Message-ID", "<12345@example.com>")

		// Save message
		err := msg.Save(queueDir)
		require.NoError(t, err, "Save should succeed")

		// Verify data file exists
		dataPath := filepath.Join(queueDir, msg.ID)
		data, err := os.ReadFile(dataPath)
		require.NoError(t, err, "Data file should exist")
		assert.Equal(t, msg.Data, data, "Data should match")

		// Verify metadata file exists
		metaPath := filepath.Join(queueDir, msg.ID+".json")
		metaData, err := os.ReadFile(metaPath)
		require.NoError(t, err, "Metadata file should exist")

		// Parse metadata
		var metadata struct {
			ID        string            `json:"id"`
			From      string            `json:"from"`
			To        []string          `json:"to"`
			Status    Status            `json:"status"`
			CreatedAt time.Time         `json:"created_at"`
			UpdatedAt time.Time         `json:"updated_at"`
			Headers   map[string]string `json:"headers"`
		}
		err = json.Unmarshal(metaData, &metadata)
		require.NoError(t, err, "Metadata should be valid JSON")

		// Verify metadata
		assert.Equal(t, msg.ID, metadata.ID)
		assert.Equal(t, msg.From, metadata.From)
		assert.Equal(t, msg.To, metadata.To)
		assert.Equal(t, msg.Status, metadata.Status)
		assert.Equal(t, msg.CreatedAt.Unix(), metadata.CreatedAt.Unix())
		assert.WithinDuration(t, time.Now(), metadata.UpdatedAt, 2*time.Second)
		assert.Equal(t, msg.Headers, metadata.Headers)
	})

	t.Run("Save to non-existent directory fails", func(t *testing.T) {
		msg := NewMessage()
		msg.Data = []byte("test")

		err := msg.Save("/non/existent/directory")
		assert.Error(t, err, "Should fail when directory doesn't exist")
	})

	t.Run("Save with empty data", func(t *testing.T) {
		queueDir := t.TempDir()
		msg := NewMessage()
		msg.From = "test@example.com"
		msg.To = []string{"recipient@example.com"}
		msg.Data = []byte{} // Empty data

		err := msg.Save(queueDir)
		require.NoError(t, err, "Should save even with empty data")

		// Verify files exist
		dataPath := filepath.Join(queueDir, msg.ID)
		_, err = os.Stat(dataPath)
		assert.NoError(t, err, "Data file should exist")
	})

	t.Run("Save with large data", func(t *testing.T) {
		queueDir := t.TempDir()
		msg := NewMessage()
		msg.From = "sender@example.com"
		msg.To = []string{"recipient@example.com"}

		// Create 1MB of data
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		msg.Data = largeData

		err := msg.Save(queueDir)
		require.NoError(t, err, "Should save large data")

		// Verify data is correct
		dataPath := filepath.Join(queueDir, msg.ID)
		savedData, err := os.ReadFile(dataPath)
		require.NoError(t, err)
		assert.Equal(t, largeData, savedData, "Large data should match")
	})

	t.Run("Save with multiple recipients", func(t *testing.T) {
		queueDir := t.TempDir()
		msg := NewMessage()
		msg.From = "sender@example.com"
		msg.To = []string{
			"user1@example.com",
			"user2@example.com",
			"user3@example.com",
			"user4@example.com",
			"user5@example.com",
		}
		msg.Data = []byte("Test message")

		err := msg.Save(queueDir)
		require.NoError(t, err)

		// Verify metadata contains all recipients
		metaPath := filepath.Join(queueDir, msg.ID+".json")
		metaData, err := os.ReadFile(metaPath)
		require.NoError(t, err)

		var metadata struct {
			To []string `json:"to"`
		}
		err = json.Unmarshal(metaData, &metadata)
		require.NoError(t, err)
		assert.Equal(t, msg.To, metadata.To, "All recipients should be saved")
	})
}

func TestMessageStatuses(t *testing.T) {
	statuses := []Status{
		StatusReceived,
		StatusQueued,
		StatusDelivering,
		StatusDelivered,
		StatusFailed,
		StatusDeferred,
		StatusHeld,
	}

	expectedStrings := []string{
		"received",
		"queued",
		"delivering",
		"delivered",
		"failed",
		"deferred",
		"held",
	}

	for i, status := range statuses {
		assert.Equal(t, expectedStrings[i], string(status), "Status constant should match expected string")
	}
}

func TestMessageIDUniqueness(t *testing.T) {
	// Create multiple messages and verify IDs are unique
	ids := make(map[string]bool)
	numMessages := 1000

	for i := 0; i < numMessages; i++ {
		msg := NewMessage()
		assert.NotContains(t, ids, msg.ID, "Message IDs should be unique")
		ids[msg.ID] = true
	}

	assert.Len(t, ids, numMessages, "Should have generated unique IDs")
}

func TestMessageConcurrentSave(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	queueDir := t.TempDir()
	numMessages := 10

	done := make(chan bool, numMessages)
	errors := make(chan error, numMessages)

	// Save multiple messages concurrently
	for i := 0; i < numMessages; i++ {
		go func(idx int) {
			msg := NewMessage()
			msg.From = "sender@example.com"
			msg.To = []string{"recipient@example.com"}
			msg.Data = []byte("Concurrent test message")
			msg.AddHeader("X-Test-Index", string(rune(idx)))

			err := msg.Save(queueDir)
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all saves
	for i := 0; i < numMessages; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("Concurrent save failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent save timeout")
		}
	}

	// Verify all files were created
	files, err := filepath.Glob(filepath.Join(queueDir, "*.json"))
	require.NoError(t, err)
	assert.Equal(t, numMessages, len(files), "All metadata files should be created")
}

func TestMessageEdgeCases(t *testing.T) {
	t.Run("Message with special characters in headers", func(t *testing.T) {
		msg := NewMessage()
		msg.AddHeader("X-Custom-Header", "Value with spaces and 特殊文字")
		msg.AddHeader("Subject", "Test: 你好世界")

		header := msg.GetHeader("X-Custom-Header")
		assert.Contains(t, header, "特殊文字")

		subject := msg.GetHeader("Subject")
		assert.Contains(t, subject, "你好世界")
	})

	t.Run("Message with empty From", func(t *testing.T) {
		queueDir := t.TempDir()
		msg := NewMessage()
		msg.From = ""
		msg.To = []string{"recipient@example.com"}
		msg.Data = []byte("Test")

		err := msg.Save(queueDir)
		assert.NoError(t, err, "Should save with empty From")
	})

	t.Run("Message with no recipients", func(t *testing.T) {
		queueDir := t.TempDir()
		msg := NewMessage()
		msg.From = "sender@example.com"
		msg.To = []string{} // Empty recipients
		msg.Data = []byte("Test")

		err := msg.Save(queueDir)
		assert.NoError(t, err, "Should save with no recipients")
	})

	t.Run("Message with binary data", func(t *testing.T) {
		queueDir := t.TempDir()
		msg := NewMessage()
		msg.From = "sender@example.com"
		msg.To = []string{"recipient@example.com"}
		msg.Data = []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}

		err := msg.Save(queueDir)
		require.NoError(t, err)

		// Verify binary data preserved
		dataPath := filepath.Join(queueDir, msg.ID)
		savedData, err := os.ReadFile(dataPath)
		require.NoError(t, err)
		assert.Equal(t, msg.Data, savedData, "Binary data should be preserved")
	})
}
