package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bdatTestSetup creates a server, connects, sends EHLO, MAIL, RCPT and returns the conn+reader
func bdatTestSetup(t *testing.T) (net.Conn, *bufio.Reader, func()) {
	t.Helper()

	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost", "example.com"}
	server, err := NewServer(config)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)

	reader := bufio.NewReader(conn)

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// EHLO
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// MAIL FROM
	_, err = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	require.NoError(t, err)
	resp, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, resp, "250")

	// RCPT TO
	_, err = conn.Write([]byte("RCPT TO:<user@localhost>\r\n"))
	require.NoError(t, err)
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, resp, "250")

	cleanup := func() {
		conn.Close()
		_ = server.Close()
	}
	return conn, reader, cleanup
}

// TestBDATSingleChunkLAST tests sending a single BDAT chunk with LAST
func TestBDATSingleChunkLAST(t *testing.T) {
	conn, reader, cleanup := bdatTestSetup(t)
	defer cleanup()

	msgData := "From: sender@example.com\r\nTo: user@localhost\r\nSubject: BDAT Test\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nHello via BDAT\r\n"
	bdatCmd := fmt.Sprintf("BDAT %d LAST\r\n", len(msgData))

	_, err := conn.Write([]byte(bdatCmd))
	require.NoError(t, err)
	_, err = conn.Write([]byte(msgData))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "Single BDAT LAST should succeed")
	assert.Contains(t, response, "accepted")
}

// TestBDATMultipleChunks tests sending multiple BDAT chunks
func TestBDATMultipleChunks(t *testing.T) {
	conn, reader, cleanup := bdatTestSetup(t)
	defer cleanup()

	headers := "From: sender@example.com\r\nTo: user@localhost\r\nSubject: BDAT Multi\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n"
	body := "Hello via multi-chunk BDAT\r\n"

	// First chunk (headers)
	_, err := conn.Write([]byte(fmt.Sprintf("BDAT %d\r\n", len(headers))))
	require.NoError(t, err)
	_, err = conn.Write([]byte(headers))
	require.NoError(t, err)

	resp1, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp1, "250", "Intermediate chunk should get 250")
	assert.Contains(t, resp1, "bytes received")

	// Second chunk (body + LAST)
	_, err = conn.Write([]byte(fmt.Sprintf("BDAT %d LAST\r\n", len(body))))
	require.NoError(t, err)
	_, err = conn.Write([]byte(body))
	require.NoError(t, err)

	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp2, "250", "Final BDAT LAST should succeed")
	assert.Contains(t, resp2, "accepted")
}

// TestBDATZeroSizeLAST tests BDAT 0 LAST to finalize with zero-byte final chunk
func TestBDATZeroSizeLAST(t *testing.T) {
	conn, reader, cleanup := bdatTestSetup(t)
	defer cleanup()

	msgData := "From: sender@example.com\r\nTo: user@localhost\r\nSubject: BDAT Zero\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody\r\n"

	// Send all data in first chunk
	_, err := conn.Write([]byte(fmt.Sprintf("BDAT %d\r\n", len(msgData))))
	require.NoError(t, err)
	_, err = conn.Write([]byte(msgData))
	require.NoError(t, err)

	resp, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250")

	// Finalize with zero-size LAST
	_, err = conn.Write([]byte("BDAT 0 LAST\r\n"))
	require.NoError(t, err)

	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp2, "250", "BDAT 0 LAST should succeed")
	assert.Contains(t, resp2, "accepted")
}

// TestBDATExceedsMaxSize tests that BDAT rejects when accumulated size exceeds MaxSize
func TestBDATExceedsMaxSize(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost"}
	config.MaxSize = 100 // Very small max size for testing
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // greeting

	_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	_, _ = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	_, _ = reader.ReadString('\n')
	_, _ = conn.Write([]byte("RCPT TO:<user@localhost>\r\n"))
	_, _ = reader.ReadString('\n')

	// Send BDAT with size exceeding MaxSize
	_, err = conn.Write([]byte("BDAT 200 LAST\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "552", "Should reject with 552 when exceeding MaxSize")
}

// TestBDATMissingRecipients tests BDAT without RCPT TO
func TestBDATMissingRecipients(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // greeting

	_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	_, _ = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	_, _ = reader.ReadString('\n')

	// Send BDAT without RCPT TO
	_, err = conn.Write([]byte("BDAT 10 LAST\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "503", "Should reject BDAT without recipients")
}

// TestBDATRSETMidTransfer tests that RSET clears BDAT state mid-transfer
func TestBDATRSETMidTransfer(t *testing.T) {
	conn, reader, cleanup := bdatTestSetup(t)
	defer cleanup()

	// Send first chunk (not LAST)
	chunk := "From: sender@example.com\r\n"
	_, err := conn.Write([]byte(fmt.Sprintf("BDAT %d\r\n", len(chunk))))
	require.NoError(t, err)
	_, err = conn.Write([]byte(chunk))
	require.NoError(t, err)

	resp, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250")

	// RSET mid-transfer
	_, err = conn.Write([]byte("RSET\r\n"))
	require.NoError(t, err)

	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp2, "250", "RSET should succeed")
	assert.Contains(t, resp2, "Reset")

	// After RSET, state goes back to PhaseInit - need EHLO to start new transaction
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	_, err = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	require.NoError(t, err)

	resp3, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp3, "250", "MAIL after RSET+EHLO should succeed")
}

// TestBDATDATAAfterBDATStarted tests that DATA is rejected during BDAT transfer
func TestBDATDATAAfterBDATStarted(t *testing.T) {
	conn, reader, cleanup := bdatTestSetup(t)
	defer cleanup()

	// Send first BDAT chunk (not LAST)
	chunk := "From: sender@example.com\r\n"
	_, err := conn.Write([]byte(fmt.Sprintf("BDAT %d\r\n", len(chunk))))
	require.NoError(t, err)
	_, err = conn.Write([]byte(chunk))
	require.NoError(t, err)

	resp, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250")

	// Try DATA while in BDAT mode - should be rejected
	_, err = conn.Write([]byte("DATA\r\n"))
	require.NoError(t, err)

	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp2, "503", "DATA should be rejected during BDAT transfer")
}

// TestBDATCHUNKINGInEHLO tests that CHUNKING is advertised in EHLO response
func TestBDATCHUNKINGInEHLO(t *testing.T) {
	config := createTestConfig(t)
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // greeting

	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	var responses []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		responses = append(responses, line)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	allResponses := strings.Join(responses, "")
	assert.Contains(t, allResponses, "CHUNKING", "EHLO should advertise CHUNKING")
	assert.Contains(t, allResponses, "ENHANCEDSTATUSCODES", "EHLO should advertise ENHANCEDSTATUSCODES")
}

// TestBDATInvalidSize tests BDAT with invalid size arguments
func TestBDATInvalidSize(t *testing.T) {
	conn, reader, cleanup := bdatTestSetup(t)
	defer cleanup()

	tests := []struct {
		name string
		cmd  string
	}{
		{"negative size", "BDAT -1 LAST\r\n"},
		{"non-numeric", "BDAT abc LAST\r\n"},
		{"empty args", "BDAT\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := conn.Write([]byte(tt.cmd))
			require.NoError(t, err)

			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, response, "501", "Invalid BDAT size should return 501")
		})
	}
}
