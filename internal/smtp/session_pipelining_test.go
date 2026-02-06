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

// TestPipeliningInEHLO verifies that PIPELINING is advertised in the EHLO response
func TestPipeliningInEHLO(t *testing.T) {
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

	// Read greeting
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220")

	// Send EHLO
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	// Read all EHLO responses
	var ehloLines []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		ehloLines = append(ehloLines, strings.TrimRight(line, "\r\n"))
		// Last line starts with "250 " (no dash)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Verify PIPELINING is in the EHLO response
	found := false
	for _, line := range ehloLines {
		if strings.Contains(line, "PIPELINING") {
			found = true
			break
		}
	}
	assert.True(t, found, "PIPELINING should be advertised in EHLO response, got: %v", ehloLines)
}

// TestPipelinedMAILRCPTDATA sends MAIL FROM + RCPT TO + DATA in a single TCP write
// and verifies three correct responses (250, 250, 354)
func TestPipelinedMAILRCPTDATA(t *testing.T) {
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

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Send EHLO and consume response
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send MAIL FROM + RCPT TO + DATA as a single TCP write (pipelined)
	pipelined := "MAIL FROM:<sender@example.com>\r\nRCPT TO:<user@example.com>\r\nDATA\r\n"
	_, err = conn.Write([]byte(pipelined))
	require.NoError(t, err)

	// Read response for MAIL FROM
	resp1, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp1, "250", "MAIL FROM response should be 250, got: %s", resp1)

	// Read response for RCPT TO
	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp2, "250", "RCPT TO response should be 250, got: %s", resp2)

	// Read response for DATA
	resp3, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp3, "354", "DATA response should be 354, got: %s", resp3)

	// Send message body and terminator
	_, err = conn.Write([]byte("Subject: test\r\n\r\nTest body\r\n.\r\n"))
	require.NoError(t, err)

	// Read response for message acceptance
	resp4, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp4, "250", "Message acceptance response should be 250, got: %s", resp4)
}

// TestPipelinedEHLOMAILRCPT sends EHLO + MAIL FROM + RCPT TO in a single TCP write
func TestPipelinedEHLOMAILRCPT(t *testing.T) {
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

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Send EHLO + MAIL FROM + RCPT TO as a single write
	pipelined := "EHLO test.example.com\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<user@example.com>\r\n"
	_, err = conn.Write([]byte(pipelined))
	require.NoError(t, err)

	// Read EHLO responses (multi-line)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
		// Continuation lines start with "250-"
		assert.True(t, strings.HasPrefix(line, "250-"), "EHLO response line should start with 250-, got: %s", line)
	}

	// Read MAIL FROM response
	resp1, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp1, "250", "MAIL FROM response should be 250, got: %s", resp1)

	// Read RCPT TO response
	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp2, "250", "RCPT TO response should be 250, got: %s", resp2)
}

// TestPipelinedErrorMidSequence sends MAIL FROM + invalid RCPT TO + valid RCPT TO
// and verifies 250 + 5xx + 250 responses
func TestPipelinedErrorMidSequence(t *testing.T) {
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

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Send EHLO first
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send MAIL FROM + invalid RCPT (no @) + valid RCPT as a single write
	pipelined := "MAIL FROM:<sender@example.com>\r\nRCPT TO:<invalid-address>\r\nRCPT TO:<user@example.com>\r\n"
	_, err = conn.Write([]byte(pipelined))
	require.NoError(t, err)

	// MAIL FROM should succeed
	resp1, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp1, "250", "MAIL FROM response should be 250, got: %s", resp1)

	// Invalid RCPT should fail with 5xx
	resp2, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(resp2), "5"), "Invalid RCPT should get 5xx, got: %s", resp2)

	// Valid RCPT should succeed
	resp3, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp3, "250", "Valid RCPT response should be 250, got: %s", resp3)
}

// TestPipelinedNOOPs sends multiple NOOP commands in a single TCP write
func TestPipelinedNOOPs(t *testing.T) {
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

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Send EHLO first
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send 5 NOOPs in a single write
	pipelined := "NOOP\r\nNOOP\r\nNOOP\r\nNOOP\r\nNOOP\r\n"
	_, err = conn.Write([]byte(pipelined))
	require.NoError(t, err)

	// Read all 5 responses
	for i := 0; i < 5; i++ {
		resp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, resp, "250", "NOOP #%d response should be 250, got: %s", i+1, resp)
	}
}

// TestPipelinedRSETAndNewTransaction sends MAIL + RCPT + RSET + EHLO + MAIL + RCPT + DATA in one write
// Note: The server resets to INIT phase on RSET, requiring a new EHLO before MAIL FROM.
func TestPipelinedRSETAndNewTransaction(t *testing.T) {
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

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Send EHLO first
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send first transaction + RSET + EHLO + second transaction in one write
	pipelined := "MAIL FROM:<first@example.com>\r\n" +
		"RCPT TO:<user@example.com>\r\n" +
		"RSET\r\n" +
		"EHLO test.example.com\r\n" +
		"MAIL FROM:<second@example.com>\r\n" +
		"RCPT TO:<user@example.com>\r\n" +
		"DATA\r\n"
	_, err = conn.Write([]byte(pipelined))
	require.NoError(t, err)

	// Read MAIL FROM response
	resp, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250", "First MAIL FROM should be 250, got: %s", resp)

	// Read RCPT TO response
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250", "First RCPT TO should be 250, got: %s", resp)

	// Read RSET response
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250", "RSET should be 250, got: %s", resp)

	// Read EHLO response (multi-line)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
		assert.True(t, strings.HasPrefix(line, "250-"), "EHLO response line should start with 250-, got: %s", line)
	}

	// Read second MAIL FROM response
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250", "Second MAIL FROM should be 250, got: %s", resp)

	// Read second RCPT TO response
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250", "Second RCPT TO should be 250, got: %s", resp)

	// Read DATA response (354)
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "354", "DATA should be 354, got: %s", resp)

	// Send message body and terminator
	_, err = conn.Write([]byte("Subject: pipelined test\r\n\r\nBody\r\n.\r\n"))
	require.NoError(t, err)

	// Read acceptance
	resp, err = reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, resp, "250", "Message acceptance should be 250, got: %s", resp)
}

// TestPipelinedResponseBatching verifies that pipelined responses arrive together
// by sending multiple commands and checking we can read all responses without delay
func TestPipelinedResponseBatching(t *testing.T) {
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

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// Send EHLO first
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send 3 NOOPs in one write
	_, err = conn.Write([]byte("NOOP\r\nNOOP\r\nNOOP\r\n"))
	require.NoError(t, err)

	// Set a short read deadline - all responses should arrive quickly together
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var responses []string
	for i := 0; i < 3; i++ {
		resp, err := reader.ReadString('\n')
		require.NoError(t, err, "Should read response #%d without timeout", i+1)
		responses = append(responses, strings.TrimRight(resp, "\r\n"))
	}

	assert.Len(t, responses, 3, "Should have received 3 responses")
	for i, resp := range responses {
		assert.Contains(t, resp, "250", fmt.Sprintf("Response %d should be 250, got: %s", i+1, resp))
	}
}
