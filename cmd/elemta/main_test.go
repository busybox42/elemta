package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/stretchr/testify/assert"
)

func setupTestEnv(t *testing.T) (func(), string) {
	// Save current working directory
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "elemta-test-*")
	assert.NoError(t, err)

	// Create queue directories
	queueDir := filepath.Join(tempDir, "queue")
	for _, dir := range []string{"active", "deferred", "held", "failed"} {
		err := os.MkdirAll(filepath.Join(queueDir, dir), 0755)
		assert.NoError(t, err)
	}

	// Create test configuration
	config := smtp.Config{
		ListenAddr:    "localhost:25",
		QueueDir:      queueDir,
		MaxWorkers:    10,
		MaxRetries:    5,
		DevMode:       true,
		Hostname:      "localhost",
		RetrySchedule: []int{300, 600, 1800, 3600},
	}

	configData, err := json.MarshalIndent(config, "", "  ")
	assert.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "elemta.conf"), configData, 0644)
	assert.NoError(t, err)

	// Change to test directory
	err = os.Chdir(tempDir)
	assert.NoError(t, err)

	// Return cleanup function and queue directory path
	return func() {
		os.Chdir(cwd)
		os.RemoveAll(tempDir)
	}, queueDir
}

func TestRootCommand(t *testing.T) {
	cleanup, _ := setupTestEnv(t)
	defer cleanup()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	// Test root command help
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "A command line tool for managing and monitoring the Elemta Mail Transfer Agent")
}

func TestQueueCommands(t *testing.T) {
	cleanup, queueDir := setupTestEnv(t)
	defer cleanup()

	// Create a test message
	testMessage := struct {
		ID        string    `json:"id"`
		From      string    `json:"from"`
		To        []string  `json:"to"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		QueueType string    `json:"queue_type"`
	}{
		ID:        "test-message",
		From:      "sender@example.com",
		To:        []string{"recipient@example.com"},
		Status:    "queued",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		QueueType: "active",
	}

	messageData, err := json.MarshalIndent(testMessage, "", "  ")
	assert.NoError(t, err)

	err = os.WriteFile(filepath.Join(queueDir, "active", "test-message.json"), messageData, 0644)
	assert.NoError(t, err)

	tests := []struct {
		name     string
		args     []string
		expected string
		wantErr  bool
	}{
		{
			name:     "list command",
			args:     []string{"queue", "list"},
			expected: "test-message",
			wantErr:  false,
		},
		{
			name:     "stats command",
			args:     []string{"queue", "stats"},
			expected: "Queue Statistics",
			wantErr:  false,
		},
		{
			name:     "show command",
			args:     []string{"queue", "show", "test-message"},
			expected: "sender@example.com",
			wantErr:  false,
		},
		{
			name:     "delete command",
			args:     []string{"queue", "delete", "test-message"},
			expected: "Successfully deleted message test-message",
			wantErr:  false,
		},
		{
			name:     "flush command",
			args:     []string{"queue", "flush"},
			expected: "Successfully flushed queue",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outBuf := new(bytes.Buffer)
			errBuf := new(bytes.Buffer)
			rootCmd.SetOut(outBuf)
			rootCmd.SetErr(errBuf)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()
			output := outBuf.String() + errBuf.String()
			if err != nil {
				output += err.Error()
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestServerCommand(t *testing.T) {
	cleanup, _ := setupTestEnv(t)
	defer cleanup()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	rootCmd.SetArgs([]string{"server"})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Starting Elemta MTA server...")
}
