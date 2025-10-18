package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/busybox42/elemta/cmd/elemta/commands"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/spf13/cobra"
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
	for _, dir := range []string{"active", "deferred", "hold", "failed", "data"} {
		err := os.MkdirAll(filepath.Join(queueDir, dir), 0755)
		assert.NoError(t, err)
	}

	// Set test mode environment variables
	os.Setenv("ELEMTA_TEST", "1")
	os.Setenv("ELEMTA_TEST_QUEUE_DIR", queueDir)

	// Create test configuration in TOML format
	configContent := `[server]
listen_addr = "localhost:2525"
hostname = "localhost"
dev_mode = true

[queue]
queue_dir = "` + queueDir + `"
max_workers = 10
max_retries = 5
retry_schedule = [300, 600, 1800, 3600]
`

	err = os.WriteFile(filepath.Join(tempDir, "elemta.conf"), []byte(configContent), 0600)
	assert.NoError(t, err)

	// Change to test directory
	err = os.Chdir(tempDir)
	assert.NoError(t, err)

	// Return cleanup function and queue directory path
	return func() {
		os.Chdir(cwd)
		os.RemoveAll(tempDir)
		os.Unsetenv("ELEMTA_TEST")
		os.Unsetenv("ELEMTA_TEST_QUEUE_DIR")
	}, queueDir
}

func TestRootCommand(t *testing.T) {
	cleanup, _ := setupTestEnv(t)
	defer cleanup()

	buf := new(bytes.Buffer)
	commands.GetRootCmd().SetOut(buf)
	commands.GetRootCmd().SetErr(buf)

	// Test root command help
	commands.GetRootCmd().SetArgs([]string{"--help"})
	err := commands.GetRootCmd().Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "A command line tool for managing and monitoring the Elemta Mail Transfer Agent")
}

func TestQueueCommands(t *testing.T) {
	cleanup, queueDir := setupTestEnv(t)
	defer cleanup()

	// Create a test message using the actual queue.Message struct
	testMessage := queue.Message{
		ID:        "test-message",
		From:      "sender@example.com",
		To:        []string{"recipient@example.com"},
		Subject:   "Test Subject",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		QueueType: "active",
		Size:      22, // Size of test content
		Priority:  queue.PriorityNormal,
	}

	messageData, err := json.MarshalIndent(testMessage, "", "  ")
	assert.NoError(t, err)

	// Create data file in the data directory
	dataContent := []byte("Test message content")
	err = os.WriteFile(filepath.Join(queueDir, "data", "test-message"), dataContent, 0644)
	assert.NoError(t, err)

	// Create json metadata in the active queue
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
			expected: "Active",
			wantErr:  false,
		},
		{
			name:     "show command",
			args:     []string{"queue", "show", "test-message"},
			expected: "Test message content",
			wantErr:  false,
		},
		{
			name:     "delete command",
			args:     []string{"queue", "delete", "test-message"},
			expected: "Message test-message deleted",
			wantErr:  false,
		},
		{
			name:     "flush command",
			args:     []string{"queue", "flush"},
			expected: "All queues flushed successfully",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outBuf := new(bytes.Buffer)
			cmd := commands.GetRootCmd()
			cmd.SetOut(outBuf)
			cmd.SetArgs(tt.args)

			// Create a backup of os.Stdout to restore later
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := cmd.Execute()

			// Close the writer and restore os.Stdout
			w.Close()
			os.Stdout = oldStdout

			// Read the output from the pipe
			var stdoutBuf bytes.Buffer
			_, _ = stdoutBuf.ReadFrom(r)

			// Combine both outputs
			output := outBuf.String() + stdoutBuf.String()
			if err != nil {
				output += err.Error()
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Contains(t, output, tt.expected, "Expected output to contain: %s", tt.expected)

			// Recreate test data for next test if it was deleted
			if tt.name == "delete command" || tt.name == "flush command" {
				err = os.WriteFile(filepath.Join(queueDir, "data", "test-message"), dataContent, 0644)
				assert.NoError(t, err)
				err = os.WriteFile(filepath.Join(queueDir, "active", "test-message.json"), messageData, 0644)
				assert.NoError(t, err)
			}
		})
	}
}

func TestServerCommand(t *testing.T) {
	cleanup, _ := setupTestEnv(t)
	defer cleanup()

	// Create a special version of the root command for testing
	testCmd := commands.GetRootCmd()

	// Create a channel to signal when the server "starts"
	serverStarted := make(chan struct{})

	// Mock the server function to avoid actually starting the server
	originalServerFunc := commands.ServerRunFunc
	defer func() {
		commands.ServerRunFunc = originalServerFunc // Restore original function
	}()

	// Replace with a test function that just signals completion
	commands.ServerRunFunc = func(cmd *cobra.Command, args []string) error {
		t.Log("Mock server start function called")
		close(serverStarted)
		return nil
	}

	// Run the command in a goroutine
	go func() {
		buf := new(bytes.Buffer)
		testCmd.SetOut(buf)
		testCmd.SetErr(buf)
		testCmd.SetArgs([]string{"server"})
		err := testCmd.Execute()
		assert.NoError(t, err)
	}()

	// Wait for the server to "start" with a timeout
	select {
	case <-serverStarted:
		// Success, server "started"
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for server command to execute")
	}

	t.Log("Server command test passed")
}
