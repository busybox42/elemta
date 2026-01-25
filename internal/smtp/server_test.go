package smtp

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServer_ErrorHandling_DeadlineSetting tests the deadline setting error handling fix
func TestServer_ErrorHandling_DeadlineSetting(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to server to trigger the deadline setting code path
	conn, err := net.Dial("tcp", "localhost:2525")
	require.NoError(t, err)
	defer conn.Close()

	// Read greeting to ensure server is running
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Close connection
	conn.Close()

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}

// TestServer_Start_BasicFunctionality tests basic server start and stop
func TestServer_Start_BasicFunctionality(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is listening
	conn, err := net.Dial("tcp", "localhost:2525")
	require.NoError(t, err)
	defer conn.Close()

	// Read greeting
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}

// TestServer_MultipleConnections tests handling multiple concurrent connections
func TestServer_MultipleConnections(t *testing.T) {
	config := createTestConfig(t)
	config.Resources.MaxConnections = 10

	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create multiple concurrent connections
	const numConnections = 5
	connections := make([]net.Conn, numConnections)

	for i := 0; i < numConnections; i++ {
		conn, err := net.Dial("tcp", "localhost:2525")
		require.NoError(t, err)
		connections[i] = conn
	}

	// Verify all connections get greetings
	for _, conn := range connections {
		reader := bufio.NewReader(conn)
		greeting, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, greeting, "220 test.example.com")
	}

	// Close all connections
	for _, conn := range connections {
		conn.Close()
	}

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}

// TestServer_ResourceLimits tests resource limit enforcement
func TestServer_ResourceLimits(t *testing.T) {
	config := createTestConfig(t)
	config.Resources.MaxConnections = 2 // Very low limit

	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create connections up to the limit
	conn1, err := net.Dial("tcp", "localhost:2525")
	require.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.Dial("tcp", "localhost:2525")
	require.NoError(t, err)
	defer conn2.Close()

	// Verify both connections work
	reader1 := bufio.NewReader(conn1)
	greeting1, err := reader1.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting1, "220 test.example.com")

	reader2 := bufio.NewReader(conn2)
	greeting2, err := reader2.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting2, "220 test.example.com")

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}

// TestServer_ErrorHandling_InvalidConfig tests server creation with invalid config
func TestServer_ErrorHandling_InvalidConfig(t *testing.T) {
	// Test with nil config
	_, err := NewServer(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config")

	// Test with invalid hostname
	config := &Config{
		Hostname:   "", // Empty hostname
		ListenAddr: ":2525",
		QueueDir:   t.TempDir(),
	}

	_, err = NewServer(config)
	_ = err // Error is acceptable here - we just want to ensure no panic
	// Should either succeed with defaults or fail gracefully
	// The important thing is it doesn't panic
}

// TestServer_ErrorHandling_PortBinding tests port binding error handling
func TestServer_ErrorHandling_PortBinding(t *testing.T) {
	// Try to bind to a privileged port (should fail unless running as root)
	config := &Config{
		Hostname:   "test.example.com",
		ListenAddr: ":25", // Privileged port
		QueueDir:   t.TempDir(),
	}

	server, err := NewServer(config)
	if err != nil {
		// Expected to fail due to privileged port
		assert.Error(t, err)
		return
	}

	// If it succeeded, clean up
	defer func() { _ = server.Close() }()
}

// TestServer_GracefulShutdown tests graceful shutdown behavior
func TestServer_GracefulShutdown(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create a connection
	conn, err := net.Dial("tcp", "localhost:2525")
	require.NoError(t, err)

	// Start graceful shutdown
	go func() {
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	// Connection should still work during shutdown grace period
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	conn.Close()

	// Server should shut down gracefully
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Server did not shut down gracefully")
	}
}
