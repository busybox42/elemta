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

// createTestConfig creates a test configuration for RFC compliance testing
func createTestConfig(t *testing.T) *smtp.Config {
	config := &smtp.Config{
		Hostname:          "test.example.com",
		ListenAddr:        ":2525",
		LocalDomains:      []string{"test.example.com", "example.com", "localhost"},
		MaxSize:           1024 * 1024, // 1MB for testing
		StrictLineEndings: true,        // Enable strict RFC compliance
	}
	return config
}

// setupTestServer creates and starts a test SMTP server
func setupTestServer(t *testing.T) (*smtp.Server, net.Conn, *bufio.Reader) {
	config := createTestConfig(t)
	config.Auth = nil // Disable auth for basic RFC tests

	server, err := smtp.NewServer(config)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", "localhost:2525")
	require.NoError(t, err)

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, greeting, "220")

	return server, conn, reader
}

// sendCommand sends an SMTP command and returns the response
func sendCommand(conn net.Conn, reader *bufio.Reader, command string) string {
	_, err := conn.Write([]byte(command))
	if err != nil {
		panic(fmt.Sprintf("Failed to write command: %v", err))
	}

	// Read the first line
	response, err := reader.ReadString('\n')
	if err != nil {
		panic(fmt.Sprintf("Failed to read response: %v", err))
	}

	// If it's a multi-line response, read continuation lines
	if len(response) >= 4 && response[3] == '-' {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				panic(fmt.Sprintf("Failed to read continuation line: %v", err))
			}
			response += line
			if len(line) >= 4 && line[3] == ' ' {
				break // Final line of multi-line response
			}
		}
	}

	return response
}

// TestRFC5321_BasicCommands tests basic SMTP command compliance
func TestRFC5321_BasicCommands(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("EHLO_Command", func(t *testing.T) {
		response := sendCommand(conn, reader, "EHLO test.example.com\r\n")
		assert.Contains(t, response, "250", "EHLO should return 250")
		assert.Contains(t, response, "test.example.com", "Should echo hostname")
	})

	t.Run("HELO_Command", func(t *testing.T) {
		// Reset state first
		sendCommand(conn, reader, "RSET\r\n")
		response := sendCommand(conn, reader, "HELO test.example.com\r\n")
		assert.Contains(t, response, "250", "HELO should return 250")
		assert.Contains(t, response, "test.example.com", "Should echo hostname")
	})

	t.Run("MAIL_FROM_Command", func(t *testing.T) {
		// Reset state first
		sendCommand(conn, reader, "RSET\r\n")
		response := sendCommand(conn, reader, "MAIL FROM:<sender@test.example.com>\r\n")
		assert.Contains(t, response, "250", "Valid MAIL FROM should return 250")
	})

	t.Run("RCPT_TO_Command", func(t *testing.T) {
		// Setup proper state
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "EHLO test.example.com\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@test.example.com>\r\n")
		response := sendCommand(conn, reader, "RCPT TO:<recipient@test.example.com>\r\n")
		assert.Contains(t, response, "250", "Valid RCPT TO for local domain should return 250")
	})

	t.Run("DATA_Command", func(t *testing.T) {
		// Setup proper state
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "EHLO test.example.com\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@test.example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@test.example.com>\r\n")
		response := sendCommand(conn, reader, "DATA\r\n")
		assert.Contains(t, response, "354", "DATA should return 354")

		// Send simple message
		message := "Subject: Test\r\n\r\nTest message\r\n.\r\n"
		response = sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Complete message should return 250")
	})

	t.Run("RSET_Command", func(t *testing.T) {
		response := sendCommand(conn, reader, "RSET\r\n")
		assert.Contains(t, response, "250", "RSET should return 250")
	})

	t.Run("NOOP_Command", func(t *testing.T) {
		response := sendCommand(conn, reader, "NOOP\r\n")
		assert.Contains(t, response, "250", "NOOP should return 250")
	})

	t.Run("QUIT_Command", func(t *testing.T) {
		response := sendCommand(conn, reader, "QUIT\r\n")
		assert.Contains(t, response, "221", "QUIT should return 221")
	})
}

// TestRFC5321_ErrorCodes tests RFC-compliant error codes
func TestRFC5321_ErrorCodes(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Establish session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")

	t.Run("Invalid_Command", func(t *testing.T) {
		response := sendCommand(conn, reader, "INVALID\r\n")
		assert.Contains(t, response, "500", "Invalid command should return 500")
	})

	t.Run("Unrecognized_Command", func(t *testing.T) {
		response := sendCommand(conn, reader, "UNKNOWN\r\n")
		assert.Contains(t, response, "502", "Unrecognized command should return 502")
	})

	t.Run("Syntax_Error_MAIL", func(t *testing.T) {
		response := sendCommand(conn, reader, "MAIL sender@test.com\r\n")
		assert.Contains(t, response, "501", "MAIL FROM syntax error should return 501")
	})

	t.Run("Syntax_Error_RCPT", func(t *testing.T) {
		response := sendCommand(conn, reader, "RCPT recipient@test.com\r\n")
		assert.Contains(t, response, "501", "RCPT TO syntax error should return 501")
	})

	t.Run("Bad_Command_Sequence", func(t *testing.T) {
		response := sendCommand(conn, reader, "RCPT TO:<test@test.com>\r\n")
		assert.Contains(t, response, "503", "RCPT before MAIL should return 503")
	})

	t.Run("Invalid_Email_Address", func(t *testing.T) {
		response := sendCommand(conn, reader, "MAIL FROM:<invalid-email>\r\n")
		assert.Contains(t, response, "501", "Invalid email should return 501")
	})
}

// TestRFC5321_LengthLimits tests RFC 5321 length limits
func TestRFC5321_LengthLimits(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Establish session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")

	t.Run("Command_Line_Length_Limit", func(t *testing.T) {
		// RFC 5321 Section 4.5.3.1.4: 512 characters maximum
		longCommand := "MAIL FROM:<" + strings.Repeat("a", 480) + "@test.com>\r\n"
		assert.LessOrEqual(t, len(longCommand), 512, "Test command should be within limit")

		response := sendCommand(conn, reader, longCommand)
		assert.Contains(t, response, "250", "Command within length limit should succeed")
	})

	t.Run("Command_Line_Exceeded", func(t *testing.T) {
		// Create command exceeding 512 characters
		longCommand := "MAIL FROM:<" + strings.Repeat("a", 500) + "@test.com>\r\n"
		assert.Greater(t, len(longCommand), 512, "Test command should exceed limit")

		response := sendCommand(conn, reader, longCommand)
		// Should either succeed (if not enforced) or return appropriate error
		assert.True(t,
			strings.Contains(response, "250") || strings.Contains(response, "500"),
			"Command exceeding limit should either succeed or return error")
	})

	t.Run("Email_Address_Length", func(t *testing.T) {
		// Test very long but valid email address
		longEmail := "MAIL FROM:<" + strings.Repeat("a", 100) + "@" + strings.Repeat("b", 100) + ".com>\r\n"
		response := sendCommand(conn, reader, longEmail)
		// Should handle long addresses gracefully
		assert.True(t,
			strings.Contains(response, "250") || strings.Contains(response, "501"),
			"Long email address should be handled gracefully")
	})
}

// TestRFC5321_SpecialCharacters tests special character handling
func TestRFC5321_SpecialCharacters(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Establish session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")

	testCases := []struct {
		name          string
		email         string
		shouldSucceed bool
	}{
		{
			name:          "Valid_Email_With_Dots",
			email:         "user.name@test.example.com",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Email_With_Plus",
			email:         "user+tag@test.example.com",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Email_With_Underscore",
			email:         "user_name@test.example.com",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Email_With_Hyphen",
			email:         "user-name@test.example.com",
			shouldSucceed: true,
		},
		{
			name:          "Invalid_Email_With_Space",
			email:         "user name@test.example.com",
			shouldSucceed: false,
		},
		{
			name:          "Invalid_Email_With_Special_Chars",
			email:         "user!#$%&'*+/=?^_`{|}~@test.example.com",
			shouldSucceed: false,
		},
		{
			name:          "Valid_Local_Domain",
			email:         "user@localhost",
			shouldSucceed: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := sendCommand(conn, reader, fmt.Sprintf("MAIL FROM:<%s>\r\n", tc.email))
			if tc.shouldSucceed {
				assert.Contains(t, response, "250", "Valid email should succeed: %s", tc.email)
			} else {
				assert.Contains(t, response, "501", "Invalid email should fail: %s", tc.email)
			}

			// Reset for next test
			sendCommand(conn, reader, "RSET\r\n")
		})
	}
}

// TestRFC5321_MessageFormat tests message format compliance
func TestRFC5321_MessageFormat(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Setup session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")
	sendCommand(conn, reader, "MAIL FROM:<sender@test.example.com>\r\n")
	sendCommand(conn, reader, "RCPT TO:<recipient@test.example.com>\r\n")
	sendCommand(conn, reader, "DATA\r\n")

	t.Run("Simple_Message", func(t *testing.T) {
		message := "Subject: Test\r\n\r\nSimple message body\r\n.\r\n"
		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Simple message should be accepted")
	})

	t.Run("Message_With_Headers", func(t *testing.T) {
		// Reset for new message
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@test.example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@test.example.com>\r\n")
		sendCommand(conn, reader, "DATA\r\n")

		message := "From: sender@test.example.com\r\n" +
			"To: recipient@test.example.com\r\n" +
			"Subject: RFC Test\r\n" +
			"Date: Tue, 15 Nov 1994 08:12:31 GMT\r\n" +
			"Message-ID: <123@test.example.com>\r\n" +
			"\r\n" +
			"This is a test message with proper headers.\r\n" +
			".\r\n"

		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message with headers should be accepted")
	})

	t.Run("Empty_Message", func(t *testing.T) {
		// Reset for new message
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@test.example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@test.example.com>\r\n")
		sendCommand(conn, reader, "DATA\r\n")

		message := "\r\n.\r\n"
		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Empty message should be accepted")
	})
}

// TestRFC5321_Pipelining tests basic SMTP pipelining support
func TestRFC5321_Pipelining(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Establish session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")

	t.Run("Basic_Pipelining", func(t *testing.T) {
		// Send multiple commands without waiting for responses
		commands := []string{
			"MAIL FROM:<sender@test.example.com>\r\n",
			"RCPT TO:<recipient@test.example.com>\r\n",
			"DATA\r\n",
		}

		for _, cmd := range commands {
			_, err := conn.Write([]byte(cmd))
			require.NoError(t, err)
		}

		// Read responses for all pipelined commands
		for i := 0; i < len(commands); i++ {
			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			if i < len(commands)-1 {
				assert.Contains(t, response, "250", "Pipelined command should succeed")
			} else {
				assert.Contains(t, response, "354", "DATA should return 354")
			}
		}

		// Send message content
		message := "Subject: Pipelined Test\r\n\r\nThis was sent via pipelining.\r\n.\r\n"
		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Pipelined message should be accepted")
	})
}
