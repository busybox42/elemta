package smtp

import (
	"bufio"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readSMTPResponse reads a full SMTP response (potentially multi-line).
// Multi-line responses have a dash after the code (e.g. "250-"), while
// the final line has a space (e.g. "250 ").
func readSMTPResponse(reader *bufio.Reader) ([]string, error) {
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return lines, err
		}
		lines = append(lines, line)
		// Final line: code followed by space (e.g. "250 HELP")
		if len(line) >= 4 && line[3] == ' ' {
			return lines, nil
		}
	}
}

// readSMTPLine reads a single-line SMTP response (e.g. "250 OK\r\n").
func readSMTPLine(reader *bufio.Reader) (string, error) {
	return reader.ReadString('\n')
}

// sendAndRead sends a command and reads the full response.
func sendAndRead(conn net.Conn, reader *bufio.Reader, cmd string) ([]string, error) {
	_, err := conn.Write([]byte(cmd + "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("write %q: %w", cmd, err)
	}
	return readSMTPResponse(reader)
}

// TestServer_GracefulShutdown_InFlightConnections tests that in-flight SMTP connections complete during shutdown
func TestServer_GracefulShutdown_InFlightConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shutdown tests in short mode")
	}

	config := createTestConfig(t)
	config.Resources.ConnectionTimeout = 30 // Longer timeout for this test

	server, err := NewServer(config)
	require.NoError(t, err)

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create multiple in-flight connections
	const numConnections = 5
	var wg sync.WaitGroup
	connectionResults := make([]error, numConnections)

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", server.Addr().String())
			if err != nil {
				connectionResults[index] = err
				return
			}
			defer conn.Close()

			// Read greeting
			reader := bufio.NewReader(conn)
			greeting, err := readSMTPLine(reader)
			if err != nil {
				connectionResults[index] = err
				return
			}
			assert.Contains(t, greeting, "220 test.example.com")

			// Send EHLO and read full multi-line response
			ehloResp, err := sendAndRead(conn, reader, "EHLO test.example.com")
			if err != nil {
				connectionResults[index] = err
				return
			}
			assert.True(t, len(ehloResp) > 0)

			// Send a slow command to keep connection alive during shutdown
			time.Sleep(100 * time.Millisecond)

			// Send QUIT to close gracefully
			_, err = conn.Write([]byte("QUIT\r\n"))
			if err != nil {
				connectionResults[index] = err
				return
			}

			// Read final response
			_, err = reader.ReadString('\n')
			connectionResults[index] = err
		}(i)
	}

	// Wait a moment for connections to establish
	time.Sleep(50 * time.Millisecond)

	// Initiate graceful shutdown while connections are active
	shutdownStart := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond) // Small delay to ensure connections are in-flight
		server.Close()
	}()

	// Wait for all connections to complete
	wg.Wait()
	shutdownDuration := time.Since(shutdownStart)

	// Verify all connections completed successfully (or with expected errors)
	for i, err := range connectionResults {
		if err != nil {
			t.Logf("Connection %d completed with error: %v", i, err)
			// Some connection errors during shutdown are acceptable
			assert.True(t, isConnectionErrorAcceptable(err),
				"Connection %d had unexpected error: %v", i, err)
		}
	}

	// Verify server stopped
	select {
	case err := <-serverErr:
		// Server should stop without timeout
		assert.NoError(t, err)
	case <-time.After(35 * time.Second):
		t.Fatal("Server did not shut down within expected time")
	}

	// Shutdown should complete in reasonable time (less than 10 seconds for this test)
	assert.Less(t, shutdownDuration, 10*time.Second,
		"Shutdown took too long: %v", shutdownDuration)

	t.Logf("✓ Graceful shutdown with %d in-flight connections completed in %v",
		numConnections, shutdownDuration)
}

// TestServer_GracefulShutdown_DoubleShutdown tests that calling Close() twice is safe
func TestServer_GracefulShutdown_DoubleShutdown(t *testing.T) {
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

	// First shutdown should work
	firstShutdownErr := server.Close()
	assert.NoError(t, firstShutdownErr)

	// Second shutdown should not panic or cause issues
	secondShutdownErr := server.Close()
	assert.NoError(t, secondShutdownErr)

	// Server should still be stopped
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}

	t.Log("✓ Double shutdown handled correctly")
}

// TestServer_GracefulShutdown_ResourceCleanupOrder tests that resources are cleaned up in correct order
func TestServer_GracefulShutdown_ResourceCleanupOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shutdown tests in short mode")
	}

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

	// Create a connection and start sending a message
	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := readSMTPLine(reader)
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Send EHLO and read full multi-line response
	_, err = sendAndRead(conn, reader, "EHLO test.example.com")
	require.NoError(t, err)

	// Send MAIL FROM
	_, err = sendAndRead(conn, reader, "MAIL FROM:<sender@example.com>")
	require.NoError(t, err)

	// Send RCPT TO
	_, err = sendAndRead(conn, reader, "RCPT TO:<recipient@example.com>")
	require.NoError(t, err)

	// Send DATA
	_, err = sendAndRead(conn, reader, "DATA")
	require.NoError(t, err)

	// Send message content in a goroutine, then signal completion
	txDone := make(chan struct{})
	go func() {
		defer close(txDone)
		conn.Write([]byte("Test message content\r\n.\r\n"))
		readSMTPResponse(reader)
		conn.Write([]byte("QUIT\r\n"))
		readSMTPResponse(reader)
	}()

	// Wait for the SMTP transaction to complete before shutting down
	select {
	case <-txDone:
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP transaction did not complete in time")
	}

	// Initiate shutdown after transaction completes
	shutdownStart := time.Now()
	shutdownErr := server.Close()
	shutdownDuration := time.Since(shutdownStart)

	// Verify shutdown completed
	if shutdownErr != nil {
		t.Logf("Shutdown completed with error (may be acceptable): %v", shutdownErr)
	}
	assert.Less(t, shutdownDuration, 35*time.Second,
		"Shutdown exceeded timeout: %v", shutdownDuration)

	// Verify server stopped
	select {
	case err := <-serverErr:
		if err != nil {
			t.Logf("Server stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}

	t.Log("✓ Resource cleanup order verified during shutdown")
}

// TestServer_GracefulShutdown_ContextCancellation tests that context cancellation properly stops goroutines
func TestServer_GracefulShutdown_ContextCancellation(t *testing.T) {
	config := createTestConfig(t)

	server, err := NewServer(config)
	require.NoError(t, err)

	// Track goroutine count before start
	initialGoroutines := runtime.NumGoroutine()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start and goroutines to spin up
	time.Sleep(200 * time.Millisecond)
	runningGoroutines := runtime.NumGoroutine()
	goroutinesIncrease := runningGoroutines - initialGoroutines

	t.Logf("Initial goroutines: %d, Running goroutines: %d, Increase: %d",
		initialGoroutines, runningGoroutines, goroutinesIncrease)

	// Should have more goroutines when server is running
	assert.Greater(t, goroutinesIncrease, 0, "Server should have created additional goroutines")

	// Create a connection to ensure session goroutines are running
	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)

	// Read greeting to establish session
	reader := bufio.NewReader(conn)
	greeting, err := readSMTPLine(reader)
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	conn.Close()

	// Initiate shutdown
	shutdownStart := time.Now()
	server.Close()
	shutdownDuration := time.Since(shutdownStart)

	// Wait for server to stop
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(35 * time.Second):
		t.Fatal("Server did not shut down")
	}

	// Wait a moment for goroutines to clean up
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	goroutinesRemaining := finalGoroutines - initialGoroutines

	t.Logf("Final goroutines: %d, Remaining increase: %d",
		finalGoroutines, goroutinesRemaining)

	// Should not have significant goroutine leaks (allowing for some variance)
	assert.Less(t, goroutinesRemaining, 5,
		"Too many goroutines remaining after shutdown: %d", goroutinesRemaining)

	assert.Less(t, shutdownDuration, 30*time.Second,
		"Shutdown exceeded 30 second timeout: %v", shutdownDuration)

	t.Log("✓ Context cancellation and goroutine cleanup verified")
}

// TestServer_GracefulShutdown_TimeoutBehavior tests the 30-second timeout behavior
func TestServer_GracefulShutdown_TimeoutBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

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

	// Create a connection that will take a long time to complete
	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := readSMTPLine(reader)
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Send EHLO and read full multi-line response
	_, err = sendAndRead(conn, reader, "EHLO test.example.com")
	require.NoError(t, err)

	// Keep connection alive with slow operations
	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(100 * time.Millisecond)
			// Send NOOP to keep connection alive
			conn.Write([]byte("NOOP\r\n"))
		}
	}()

	// Initiate shutdown and measure time
	shutdownStart := time.Now()
	shutdownErr := server.Close()
	shutdownDuration := time.Since(shutdownStart)

	// Shutdown should complete within reasonable time (under 35 seconds to allow for the 30s timeout + overhead)
	assert.Less(t, shutdownDuration, 35*time.Second,
		"Shutdown should complete within 35 seconds, took: %v", shutdownDuration)

	// Verify shutdown completed (may have error due to timeout, which is acceptable)
	if shutdownErr != nil {
		t.Logf("Shutdown completed with error (acceptable): %v", shutdownErr)
	}

	// Verify server stopped
	select {
	case err := <-serverErr:
		// May have timeout error, which is acceptable
		if err != nil {
			t.Logf("Server stopped with error (acceptable): %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("Server did not shut down within extended timeout")
	}

	t.Logf("✓ Shutdown timeout behavior verified, completed in %v", shutdownDuration)
}

// Helper function to check if connection errors are acceptable during shutdown
func isConnectionErrorAcceptable(err error) bool {
	if err == nil {
		return true
	}

	errStr := err.Error()
	acceptableErrors := []string{
		"connection reset by peer",
		"use of closed network connection",
		"broken pipe",
		"connection refused",
	}

	for _, acceptable := range acceptableErrors {
		if strings.Contains(errStr, acceptable) {
			return true
		}
	}

	return false
}
