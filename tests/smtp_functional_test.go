package tests

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createFunctionalTestConfig creates a test configuration matching the working tests
func createFunctionalTestConfig(t *testing.T) *smtp.Config {
	t.Helper()
	queueDir := t.TempDir() // Create temporary queue directory

	config := &smtp.Config{
		Hostname:          "test.example.com",
		ListenAddr:        ":0", // Use random available port
		QueueDir:          queueDir,
		LocalDomains:      []string{"test.example.com", "example.com"},
		MaxSize:           1024 * 1024, // 1MB
		StrictLineEndings: false,       // Match working tests
	}
	return config
}

// setupFunctionalServer creates and starts a test server like the working tests
func setupFunctionalServer(t *testing.T) (*smtp.Server, net.Conn, *bufio.Reader) {
	config := createFunctionalTestConfig(t)
	config.Auth = nil

	server, err := smtp.NewServer(config)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()

	// Wait for server to start and get address
	var addr net.Addr
	for i := 0; i < 50; i++ { // Wait up to 500ms
		// Check if server failed (non-blocking)
		select {
		case err := <-serverErr:
			if err != nil {
				t.Fatalf("Server failed to start: %v", err)
			}
		default:
			// Server still running, check if address is available
			time.Sleep(10 * time.Millisecond)
			addr = server.Addr()
			if addr != nil {
				goto serverStarted
			}
		}
	}
	require.NotNil(t, addr, "Server address should not be nil after waiting")

serverStarted:

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)

	reader := bufio.NewReader(conn)

	// Read greeting
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	return server, conn, reader
}

// setupSMTPSession establishes a proper SMTP session like the working tests.
// Sends RSET first to reset any prior session state when reusing connections.
func setupSMTPSession(t *testing.T, reader *bufio.Reader, conn net.Conn) {
	// Send RSET to clear any prior session state (ignore response — may fail on first call)
	_, _ = conn.Write([]byte("RSET\r\n"))
	_, _ = reader.ReadString('\n')

	// Send EHLO and read multi-line response
	_, err := conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if len(line) >= 4 && line[3] == ' ' {
			break // Final line of multi-line response
		}
	}
}

// TestSMTP_BasicFunctionality tests core SMTP functionality that actually works
func TestSMTP_BasicFunctionality(t *testing.T) {
	server, conn, reader := setupFunctionalServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("Complete_Email_Flow", func(t *testing.T) {
		// Setup session
		setupSMTPSession(t, reader, conn)

		// MAIL FROM
		_, err := conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
		require.NoError(t, err)
		mailResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, mailResp, "250", "MAIL FROM should succeed")

		// RCPT TO
		_, err = conn.Write([]byte("RCPT TO:<user@example.com>\r\n"))
		require.NoError(t, err)
		rcptResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, rcptResp, "250", "RCPT TO should succeed for local domain")

		// DATA
		_, err = conn.Write([]byte("DATA\r\n"))
		require.NoError(t, err)
		dataResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, dataResp, "354", "DATA should return 354")

		// Send message
		message := "From: sender@example.com\r\n" +
			"To: user@example.com\r\n" +
			"Subject: Functional Test\r\n" +
			"\r\n" +
			"This is a functional test message.\r\n" +
			".\r\n"

		_, err = conn.Write([]byte(message))
		require.NoError(t, err)

		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "250", "Message should be accepted")
	})
}

// TestSMTP_ErrorHandling tests error scenarios
func TestSMTP_ErrorHandling(t *testing.T) {
	server, conn, reader := setupFunctionalServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("Invalid_Command", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		_, err := conn.Write([]byte("INVALID_COMMAND\r\n"))
		require.NoError(t, err)
		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "502", "Invalid command should return 502")
	})

	t.Run("Bad_Command_Sequence", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		// Try RCPT before MAIL
		_, err := conn.Write([]byte("RCPT TO:<user@example.com>\r\n"))
		require.NoError(t, err)
		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "503", "Bad sequence should return 503")
	})

	t.Run("Invalid_Email_Format", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		_, err := conn.Write([]byte("MAIL FROM:<invalid-email>\r\n"))
		require.NoError(t, err)
		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "501", "Invalid email should return 501")
	})
}

// TestSMTP_MultipleMessages tests multiple messages in sequence
func TestSMTP_MultipleMessages(t *testing.T) {
	server, conn, reader := setupFunctionalServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("Multiple_Messages_Same_Connection", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			// Setup session for each message
			setupSMTPSession(t, reader, conn)

			// Send message
			_, err := conn.Write([]byte(fmt.Sprintf("MAIL FROM:<sender%d@example.com>\r\n", i)))
			require.NoError(t, err)
			mailResp, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, mailResp, "250")

			_, err = conn.Write([]byte("RCPT TO:<user@example.com>\r\n"))
			require.NoError(t, err)
			rcptResp, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, rcptResp, "250")

			_, err = conn.Write([]byte("DATA\r\n"))
			require.NoError(t, err)
			dataResp, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, dataResp, "354")

			message := fmt.Sprintf("Subject: Message %d\r\n\r\nThis is message %d.\r\n.\r\n", i, i)
			_, err = conn.Write([]byte(message))
			require.NoError(t, err)

			finalResp, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, finalResp, "250")
		}
	})
}

// TestSMTP_DomainHandling tests domain-specific behavior
func TestSMTP_DomainHandling(t *testing.T) {
	server, conn, reader := setupFunctionalServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("Local_Domain_Accepted", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		_, err := conn.Write([]byte("MAIL FROM:<sender@test.example.com>\r\n"))
		require.NoError(t, err)
		mailResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, mailResp, "250")

		_, err = conn.Write([]byte("RCPT TO:<user@test.example.com>\r\n"))
		require.NoError(t, err)
		rcptResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, rcptResp, "250", "Local domain should be accepted")
	})

	t.Run("External_Domain_Relay_Denied", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		_, err := conn.Write([]byte("MAIL FROM:<sender@test.example.com>\r\n"))
		require.NoError(t, err)
		mailResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, mailResp, "250")

		_, err = conn.Write([]byte("RCPT TO:<user@external.com>\r\n"))
		require.NoError(t, err)
		rcptResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		// External domains should be denied (relay access)
		assert.Contains(t, rcptResp, "554", "External domain relay should be denied")
	})
}

// TestSMTP_MessageSize tests message size handling
func TestSMTP_MessageSize(t *testing.T) {
	server, conn, reader := setupFunctionalServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("Normal_Message_Size", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		_, err := conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
		require.NoError(t, err)
		_, err = reader.ReadString('\n')
		require.NoError(t, err)

		_, err = conn.Write([]byte("RCPT TO:<user@example.com>\r\n"))
		require.NoError(t, err)
		_, err = reader.ReadString('\n')
		require.NoError(t, err)

		_, err = conn.Write([]byte("DATA\r\n"))
		require.NoError(t, err)
		dataResp, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, dataResp, "354")

		// Medium-sized message with proper line breaks (RFC 5321: max 1000 chars per line recommended)
		line := strings.Repeat("This is a line of text. ", 40) + "\r\n" // ~960 chars per line
		body := strings.Repeat(line, 10)                                // 10 lines total
		message := fmt.Sprintf("Subject: Size Test\r\n\r\n%s.\r\n", body)

		_, err = conn.Write([]byte(message))
		require.NoError(t, err)

		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "250", "Normal sized message should be accepted")
	})
}

// TestSMTP_KnownLimitations documents known server limitations
func TestSMTP_KnownLimitations(t *testing.T) {
	server, conn, reader := setupFunctionalServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("NOOP_Implemented", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		_, err := conn.Write([]byte("NOOP\r\n"))
		require.NoError(t, err)
		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		// Server actually implements NOOP
		assert.Contains(t, response, "250", "NOOP should return 250 (server implements it)")
	})

	t.Run("RSET_After_EHLO", func(t *testing.T) {
		setupSMTPSession(t, reader, conn)

		// Send a message first
		_, err := conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
		require.NoError(t, err)
		_, err = reader.ReadString('\n')
		require.NoError(t, err)

		// RSET should work
		_, err = conn.Write([]byte("RSET\r\n"))
		require.NoError(t, err)
		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "250", "RSET should work after EHLO")

		// After RSET, need EHLO again before MAIL FROM
		_, err = conn.Write([]byte("MAIL FROM:<sender2@example.com>\r\n"))
		require.NoError(t, err)
		response, err = reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "503", "MAIL FROM should fail after RSET without EHLO")
	})
}
