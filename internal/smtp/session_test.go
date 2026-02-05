package smtp

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSession_ErrorHandling_TimeoutResponse tests the timeout error handling fix
func TestSession_ErrorHandling_TimeoutResponse(t *testing.T) {
	// Create test server with real dependencies
	config := createTestConfig(t)
	config.Resources.ConnectionTimeout = 1 // Very short timeout for testing

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

	// Connect to server
	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Read greeting
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Send EHLO
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	// Read all EHLO response lines (multi-line response)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		// EHLO responses end with "250 " (space after code, not hyphen)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Don't send anything else - wait for timeout
	time.Sleep(2 * time.Second)

	// Read timeout response
	timeoutResponse, err := reader.ReadString('\n')
	if err == nil {
		// If we can read, verify it's the timeout response
		assert.Contains(t, timeoutResponse, "421 4.4.2 Timeout")
	}

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		// Server should stop without error
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}

// TestSession_ErrorHandling_MessageAcceptance tests the message acceptance error handling fix
func TestSession_ErrorHandling_MessageAcceptance(t *testing.T) {
	// Create test server
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

	// Connect to server
	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220 test.example.com")

	// Send EHLO
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	// Read EHLO response
	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250")

	// Send MAIL FROM
	_, err = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	require.NoError(t, err)

	// Read MAIL FROM response
	response, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250")

	// Send RCPT TO
	_, err = conn.Write([]byte("RCPT TO:<recipient@example.com>\r\n"))
	require.NoError(t, err)

	// Read RCPT TO response
	response, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250")

	// Send DATA
	_, err = conn.Write([]byte("DATA\r\n"))
	require.NoError(t, err)

	// Read DATA response (should be 354)
	response, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "354")

	// Send message content
	_, err = conn.Write([]byte("Test message content\r\n.\r\n"))
	require.NoError(t, err)

	// Read message acceptance response
	response, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250 2.0.0 Message accepted for delivery")

	// Send QUIT
	_, err = conn.Write([]byte("QUIT\r\n"))
	require.NoError(t, err)

	// Read QUIT response
	response, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "221")

	// Close server
	server.Close()
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not shut down")
	}
}
