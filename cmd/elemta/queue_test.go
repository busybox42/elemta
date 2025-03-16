package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func setupTestQueue(t *testing.T) (*queueOperations, string) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "elemta-test-queue-*")
	assert.NoError(t, err)

	// Create queue subdirectories
	queueTypes := []smtp.QueueType{
		smtp.QueueTypeActive,
		smtp.QueueTypeDeferred,
		smtp.QueueTypeHeld,
		smtp.QueueTypeFailed,
	}

	for _, qType := range queueTypes {
		err := os.MkdirAll(filepath.Join(tempDir, string(qType)), 0755)
		assert.NoError(t, err)
	}

	config := &smtp.Config{
		QueueDir: tempDir,
	}

	qo := newQueueOperations(config)
	return qo, tempDir
}

func createTestMessage(t *testing.T, queueDir string, id string, queueType smtp.QueueType) {
	msg := &smtp.QueuedMessage{
		MessageInfo: smtp.MessageInfo{
			ID:        id,
			From:      "sender@example.com",
			To:        []string{"recipient@example.com"},
			Status:    smtp.StatusQueued,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		QueueType:   queueType,
		Priority:    smtp.PriorityNormal,
		RetryCount:  0,
		NextRetry:   time.Now(),
		Attempts:    []smtp.DeliveryAttempt{},
		Annotations: make(map[string]string),
	}

	data, err := json.Marshal(msg)
	assert.NoError(t, err)

	err = os.WriteFile(filepath.Join(queueDir, string(queueType), id+".json"), data, 0644)
	assert.NoError(t, err)
}

func TestQueueOperations(t *testing.T) {
	qo, tempDir := setupTestQueue(t)
	defer os.RemoveAll(tempDir)

	// Create a test message
	createTestMessage(t, tempDir, "test-msg-1", smtp.QueueTypeActive)

	// Create a cobra command for testing
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	t.Run("list command", func(t *testing.T) {
		buf.Reset()
		err := qo.listQueue(cmd, []string{})
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "test-msg-1")
		assert.Contains(t, buf.String(), "sender@example.com")
	})

	t.Run("show command", func(t *testing.T) {
		buf.Reset()
		err := qo.showMessage(cmd, []string{"test-msg-1"})
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "test-msg-1")
		assert.Contains(t, buf.String(), "sender@example.com")
	})

	t.Run("show nonexistent message", func(t *testing.T) {
		buf.Reset()
		err := qo.showMessage(cmd, []string{"nonexistent"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("delete command", func(t *testing.T) {
		buf.Reset()
		err := qo.deleteMessage(cmd, []string{"test-msg-1"})
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "deleted successfully")

		// Verify message is deleted
		_, err = os.Stat(filepath.Join(tempDir, string(smtp.QueueTypeActive), "test-msg-1.json"))
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("delete nonexistent message", func(t *testing.T) {
		buf.Reset()
		err := qo.deleteMessage(cmd, []string{"nonexistent"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("flush command", func(t *testing.T) {
		// Create some test messages
		createTestMessage(t, tempDir, "test-msg-2", smtp.QueueTypeActive)
		createTestMessage(t, tempDir, "test-msg-3", smtp.QueueTypeDeferred)

		buf.Reset()
		err := qo.flushQueue(cmd, []string{})
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "Successfully flushed queue")

		// Verify messages are deleted
		files, err := os.ReadDir(filepath.Join(tempDir, string(smtp.QueueTypeActive)))
		assert.NoError(t, err)
		assert.Empty(t, files)

		files, err = os.ReadDir(filepath.Join(tempDir, string(smtp.QueueTypeDeferred)))
		assert.NoError(t, err)
		assert.Empty(t, files)
	})

	t.Run("stats command", func(t *testing.T) {
		// Create some test messages for stats
		createTestMessage(t, tempDir, "test-msg-4", smtp.QueueTypeActive)
		createTestMessage(t, tempDir, "test-msg-5", smtp.QueueTypeDeferred)
		createTestMessage(t, tempDir, "test-msg-6", smtp.QueueTypeHeld)

		buf.Reset()
		err := qo.showStats(cmd, []string{})
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "Queue Statistics")
		assert.Contains(t, buf.String(), "Active:")
		assert.Contains(t, buf.String(), "Deferred:")
		assert.Contains(t, buf.String(), "Held:")
	})
}
