package smtp

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "elemta-server-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create queue directory
	queueDir := filepath.Join(tempDir, "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatalf("Failed to create queue dir: %v", err)
	}

	// Create SQLite database file for auth testing
	dbPath := filepath.Join(tempDir, "auth.db")
	if err := ioutil.WriteFile(dbPath, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to create test db file: %v", err)
	}

	// Test cases
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name: "Basic server config",
			config: &Config{
				ListenAddr: "127.0.0.1:0", // Use port 0 to get a random available port
				QueueDir:   queueDir,
				Hostname:   "test.example.com",
			},
			wantError: false,
		},
		{
			name: "Server with auth enabled",
			config: &Config{
				ListenAddr: "127.0.0.1:0",
				QueueDir:   queueDir,
				Hostname:   "test.example.com",
				Auth: &AuthConfig{
					Enabled:        true,
					Required:       false,
					DataSourceType: "sqlite",
					DataSourceName: "sqlite",
					DataSourcePath: dbPath,
				},
			},
			wantError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, err := NewServer(tc.config)

			if tc.wantError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			// Verify server was created with correct config
			if server.config != tc.config {
				t.Errorf("Server has incorrect config")
			}

			// Verify authenticator was created
			if server.authenticator == nil {
				t.Errorf("Server authenticator is nil")
			}

			// Clean up
			if err := server.Close(); err != nil {
				t.Errorf("Failed to close server: %v", err)
			}
		})
	}
}

func TestServerStartAndStop(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "elemta-server-start-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create queue directory
	queueDir := filepath.Join(tempDir, "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatalf("Failed to create queue dir: %v", err)
	}

	// Create server with basic config
	config := &Config{
		ListenAddr: "127.0.0.1:0", // Use port 0 to get a random available port
		QueueDir:   queueDir,
		Hostname:   "test.example.com",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Verify server is running
	if !server.running {
		t.Errorf("Server should be running but is not")
	}

	// Get the actual port the server is listening on
	addr := server.listener.Addr().String()
	t.Logf("Server listening on %s", addr)

	// Try to connect to the server
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	conn.Close()

	// Try starting the server again (should fail)
	if err := server.Start(); err == nil {
		t.Errorf("Expected error when starting server twice, but got nil")
	}

	// Stop the server
	if err := server.Close(); err != nil {
		t.Errorf("Failed to close server: %v", err)
	}

	// Verify server is not running
	if server.running {
		t.Errorf("Server should not be running but is")
	}

	// Try to connect to the server again (should fail)
	_, err = net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		t.Errorf("Expected connection to fail after server closed, but it succeeded")
	}
}

func TestServerHandleConnection(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "elemta-server-conn-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create queue directory
	queueDir := filepath.Join(tempDir, "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatalf("Failed to create queue dir: %v", err)
	}

	// Create server with basic config
	config := &Config{
		ListenAddr: "127.0.0.1:0", // Use port 0 to get a random available port
		QueueDir:   queueDir,
		Hostname:   "test.example.com",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Close()

	// Get the actual port the server is listening on
	addr := server.listener.Addr().String()

	// Connect to the server
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}

	// Read the greeting
	buffer := make([]byte, 1024)
	deadline := time.Now().Add(2 * time.Second)
	conn.SetReadDeadline(deadline)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read from server: %v", err)
	}

	// Check that we got a valid SMTP greeting
	greeting := string(buffer[:n])
	t.Logf("Received greeting: %s", greeting)
	if len(greeting) < 4 || greeting[:3] != "220" {
		t.Errorf("Expected greeting to start with 220, got: %s", greeting)
	}

	// Send QUIT command
	if _, err := conn.Write([]byte("QUIT\r\n")); err != nil {
		t.Fatalf("Failed to send QUIT command: %v", err)
	}

	// Read the response
	deadline = time.Now().Add(2 * time.Second)
	conn.SetReadDeadline(deadline)
	n, err = conn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read response to QUIT: %v", err)
	}

	// Check that we got a valid QUIT response
	response := string(buffer[:n])
	t.Logf("Received response: %s", response)
	if len(response) < 4 || response[:3] != "221" {
		t.Errorf("Expected response to start with 221, got: %s", response)
	}

	// Close the connection
	conn.Close()
}
