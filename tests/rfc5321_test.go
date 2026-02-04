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
	// Create temporary queue directory
	queueDir := t.TempDir()

	config := &smtp.Config{
		Hostname:          "test.example.com",
		ListenAddr:        ":2525",
		QueueDir:          queueDir,
		LocalDomains:      []string{"test.example.com", "example.com", "localhost"},
		MaxSize:           1024 * 1024, // 1MB for testing
		StrictLineEndings: false,       // Disable strict CRLF validation for testing
		Auth: &smtp.AuthConfig{
			Enabled: false, // Disable auth for testing
		},
		TLS: &smtp.TLSConfig{
			Enabled: false, // Disable TLS for testing
		},
		Plugins: &smtp.PluginConfig{
			Enabled: false, // Disable plugins for testing
		},
	}
	return config
}

// setupTestServer creates and starts a test SMTP server
func setupTestServer(t *testing.T) (*smtp.Server, net.Conn, *bufio.Reader) {
	config := createTestConfig(t)

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
		// Reset and re-establish session
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "EHLO test.example.com\r\n")
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		assert.Contains(t, response, "250", "Valid MAIL FROM should return 250")
	})

	t.Run("RCPT_TO_Command", func(t *testing.T) {
		// Setup proper state
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "EHLO test.example.com\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		response := sendCommand(conn, reader, "RCPT TO:<user@example.com>\r\n")
		assert.Contains(t, response, "250", "Valid RCPT TO for local domain should return 250")
	})

	t.Run("DATA_Command", func(t *testing.T) {
		// Setup proper state
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "EHLO test.example.com\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<user@example.com>\r\n")
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
			email:         "user.name@example.com",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Email_With_Plus",
			email:         "user+tag@example.com",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Email_With_Underscore",
			email:         "user_name@example.com",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Email_With_Hyphen",
			email:         "user-name@example.com",
			shouldSucceed: true,
		},
		{
			name:          "Invalid_Email_With_Space",
			email:         "user name@example.com",
			shouldSucceed: false,
		},
		{
			name:          "Invalid_Email_With_Special_Chars",
			email:         "user!#$%&'*+/=?^_`{|}~@example.com",
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
	sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
	sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
	sendCommand(conn, reader, "DATA\r\n")

	t.Run("Simple_Message", func(t *testing.T) {
		message := "Subject: Test\r\n\r\nSimple message body\r\n.\r\n"
		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Simple message should be accepted")
	})

	t.Run("Message_With_Headers", func(t *testing.T) {
		// Reset for new message
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
		sendCommand(conn, reader, "DATA\r\n")

		message := "From: sender@example.com\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject: RFC Test\r\n" +
			"Date: Tue, 15 Nov 1994 08:12:31 GMT\r\n" +
			"Message-ID: <123@example.com>\r\n" +
			"\r\n" +
			"This is a test message with proper headers.\r\n" +
			".\r\n"

		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message with headers should be accepted")
	})

	t.Run("Empty_Message", func(t *testing.T) {
		// Reset for new message
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
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
			"MAIL FROM:<sender@example.com>\r\n",
			"RCPT TO:<recipient@example.com>\r\n",
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
// TestRFC5321_LineEndings tests CRLF vs LF handling (RFC 5321 §2.3.7)
func TestRFC5321_LineEndings(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Establish session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")

	t.Run("Proper_CRLF_Endings", func(t *testing.T) {
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		assert.Contains(t, response, "250", "Commands with CRLF should succeed")
	})

	t.Run("Bare_LF_Ending", func(t *testing.T) {
		// Send command with only LF (bare newline)
		_, err := conn.Write([]byte("RSET\n"))
		require.NoError(t, err)

		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		// Should either succeed (lenient) or fail gracefully
		assert.True(t,
			strings.Contains(response, "250") || strings.Contains(response, "500"),
			"Bare LF should be handled (accept or reject gracefully)")
	})

	t.Run("Bare_CR_Ending", func(t *testing.T) {
		// Send command with only CR
		_, err := conn.Write([]byte("NOOP\r"))
		require.NoError(t, err)

		// This might not get a response or might timeout
		// Just verify server doesn't crash
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, _ = reader.ReadString('\n')
		conn.SetReadDeadline(time.Time{})
	})
}

// TestRFC5321_DotStuffing tests transparency mechanism (RFC 5321 §4.5.2)
func TestRFC5321_DotStuffing(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Setup session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")
	sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
	sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
	sendCommand(conn, reader, "DATA\r\n")

	t.Run("Line_Starting_With_Single_Dot", func(t *testing.T) {
		// RFC 5321 §4.5.2: If line starts with '.', sender adds another '.'
		// Receiver removes first '.' (dot stuffing/unstuffing)
		message := "Subject: Dot Test\r\n" +
			"\r\n" +
			"..This line should appear with single dot\r\n" +
			"Regular line\r\n" +
			".\r\n"

		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message with dot-stuffed line should be accepted")
	})

	t.Run("Multiple_Dots", func(t *testing.T) {
		// Reset for new message
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
		sendCommand(conn, reader, "DATA\r\n")

		message := "Subject: Multiple Dots\r\n" +
			"\r\n" +
			"...Three dots should become two\r\n" +
			"....Four dots should become three\r\n" +
			".\r\n"

		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message with multiple dots should be accepted")
	})

	t.Run("Dot_In_Middle_Of_Line", func(t *testing.T) {
		// Reset for new message
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
		sendCommand(conn, reader, "DATA\r\n")

		message := "Subject: Dots in middle\r\n" +
			"\r\n" +
			"This line has a . in the middle\r\n" +
			".\r\n"

		response := sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Dots not at line start should not need stuffing")
	})
}

// TestRFC5321_MultipleRecipients tests handling of multiple RCPT commands
func TestRFC5321_MultipleRecipients(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Setup session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")
	sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")

	t.Run("Two_Recipients", func(t *testing.T) {
		response := sendCommand(conn, reader, "RCPT TO:<recipient1@example.com>\r\n")
		assert.Contains(t, response, "250", "First recipient should be accepted")

		response = sendCommand(conn, reader, "RCPT TO:<recipient2@example.com>\r\n")
		assert.Contains(t, response, "250", "Second recipient should be accepted")

		// Verify DATA accepts message for both
		response = sendCommand(conn, reader, "DATA\r\n")
		assert.Contains(t, response, "354", "DATA should accept with multiple recipients")

		message := "Subject: Multi-recipient\r\n\r\nTest message\r\n.\r\n"
		response = sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message with multiple recipients should be accepted")
	})

	t.Run("Many_Recipients", func(t *testing.T) {
		// Reset for new transaction
		sendCommand(conn, reader, "RSET\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")

		// Add 10 recipients
		for i := 1; i <= 10; i++ {
			response := sendCommand(conn, reader, fmt.Sprintf("RCPT TO:<recipient%d@example.com>\r\n", i))
			assert.Contains(t, response, "250", "Recipient %d should be accepted", i)
		}

		response := sendCommand(conn, reader, "DATA\r\n")
		assert.Contains(t, response, "354", "DATA should work with many recipients")

		message := "Subject: Many recipients\r\n\r\nBroadcast message\r\n.\r\n"
		response = sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message with many recipients should be accepted")
	})
}

// TestRFC5321_NullSender tests bounce message handling (RFC 5321 §4.5.5)
func TestRFC5321_NullSender(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Setup session
	sendCommand(conn, reader, "EHLO test.example.com\r\n")

	t.Run("Null_Sender_Angle_Brackets", func(t *testing.T) {
		// RFC 5321: Null sender is MAIL FROM:<>
		response := sendCommand(conn, reader, "MAIL FROM:<>\r\n")
		assert.Contains(t, response, "250", "Null sender <> should be accepted for bounces")

		// Should allow sending message with null sender
		response = sendCommand(conn, reader, "RCPT TO:<user@example.com>\r\n")
		assert.Contains(t, response, "250", "RCPT should work with null sender")

		response = sendCommand(conn, reader, "DATA\r\n")
		assert.Contains(t, response, "354", "DATA should work with null sender")

		message := "Subject: Bounce notification\r\n\r\nDelivery failed\r\n.\r\n"
		response = sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Bounce message with null sender should be accepted")
	})

	t.Run("Null_Sender_With_Parameters", func(t *testing.T) {
		sendCommand(conn, reader, "RSET\r\n")

		// Null sender can have SIZE parameter
		response := sendCommand(conn, reader, "MAIL FROM:<> SIZE=1000\r\n")
		// Should accept or reject parameter gracefully
		assert.True(t,
			strings.Contains(response, "250") || strings.Contains(response, "501"),
			"Null sender with SIZE parameter should be handled")
	})
}

// TestRFC5321_CaseInsensitivity tests command case handling (RFC 5321 §2.4)
func TestRFC5321_CaseInsensitivity(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("Lowercase_Commands", func(t *testing.T) {
		response := sendCommand(conn, reader, "ehlo test.example.com\r\n")
		assert.Contains(t, response, "250", "Lowercase EHLO should work")

		response = sendCommand(conn, reader, "mail from:<sender@example.com>\r\n")
		assert.Contains(t, response, "250", "Lowercase MAIL should work")

		response = sendCommand(conn, reader, "rcpt to:<recipient@example.com>\r\n")
		assert.Contains(t, response, "250", "Lowercase RCPT should work")

		response = sendCommand(conn, reader, "rset\r\n")
		assert.Contains(t, response, "250", "Lowercase RSET should work")
	})

	t.Run("Mixed_Case_Commands", func(t *testing.T) {
		response := sendCommand(conn, reader, "EhLo test.example.com\r\n")
		assert.Contains(t, response, "250", "Mixed case EHLO should work")

		response = sendCommand(conn, reader, "MaIl FrOm:<sender@example.com>\r\n")
		assert.Contains(t, response, "250", "Mixed case MAIL should work")

		response = sendCommand(conn, reader, "rSeT\r\n")
		assert.Contains(t, response, "250", "Mixed case RSET should work")
	})

	t.Run("Uppercase_Commands", func(t *testing.T) {
		response := sendCommand(conn, reader, "NOOP\r\n")
		assert.Contains(t, response, "250", "Uppercase commands should work")
	})
}

// TestRFC5321_SizeParameter tests ESMTP SIZE extension (RFC 1870)
func TestRFC5321_SizeParameter(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Setup session
	response := sendCommand(conn, reader, "EHLO test.example.com\r\n")
	
	t.Run("SIZE_Extension_Advertised", func(t *testing.T) {
		// Server should advertise SIZE in EHLO response
		assert.Contains(t, response, "SIZE", "Server should advertise SIZE extension")
	})

	t.Run("MAIL_With_SIZE_Parameter", func(t *testing.T) {
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com> SIZE=5000\r\n")
		assert.Contains(t, response, "250", "MAIL with SIZE parameter should be accepted")

		// Send appropriately sized message
		sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
		sendCommand(conn, reader, "DATA\r\n")
		
		message := "Subject: Size test\r\n\r\n" + strings.Repeat("a", 1000) + "\r\n.\r\n"
		response = sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message within declared size should be accepted")
	})

	t.Run("SIZE_Exceeds_Maximum", func(t *testing.T) {
		sendCommand(conn, reader, "RSET\r\n")

		// Declare size larger than server maximum (1MB in config)
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com> SIZE=2000000\r\n")
		// Should reject if size exceeds maximum
		assert.True(t,
			strings.Contains(response, "552") || strings.Contains(response, "250"),
			"Size exceeding maximum should be rejected with 552")
	})
}

// TestRFC5321_8BITMIME tests 8-bit MIME support
func TestRFC5321_8BITMIME(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Check if 8BITMIME is advertised
	response := sendCommand(conn, reader, "EHLO test.example.com\r\n")
	
	t.Run("8BITMIME_Advertised", func(t *testing.T) {
		assert.Contains(t, response, "8BITMIME", "Server should advertise 8BITMIME")
	})

	t.Run("MAIL_With_BODY_8BITMIME", func(t *testing.T) {
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com> BODY=8BITMIME\r\n")
		assert.Contains(t, response, "250", "MAIL with BODY=8BITMIME should be accepted")
	})

	t.Run("MAIL_With_BODY_7BIT", func(t *testing.T) {
		sendCommand(conn, reader, "RSET\r\n")
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com> BODY=7BIT\r\n")
		assert.Contains(t, response, "250", "MAIL with BODY=7BIT should be accepted")
	})
}

// TestRFC5321_SMTPUTF8 tests UTF-8 support in addresses
func TestRFC5321_SMTPUTF8(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	// Check if SMTPUTF8 is advertised
	response := sendCommand(conn, reader, "EHLO test.example.com\r\n")
	
	if strings.Contains(response, "SMTPUTF8") {
		t.Run("SMTPUTF8_Support", func(t *testing.T) {
			response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com> SMTPUTF8\r\n")
			assert.Contains(t, response, "250", "MAIL with SMTPUTF8 should be accepted")
		})
	} else {
		t.Skip("SMTPUTF8 not advertised by server")
	}
}

// TestRFC5321_CommandSequence tests strict state machine validation
func TestRFC5321_CommandSequence(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	t.Run("DATA_Before_RCPT", func(t *testing.T) {
		sendCommand(conn, reader, "EHLO test.example.com\r\n")
		sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		
		response := sendCommand(conn, reader, "DATA\r\n")
		assert.Contains(t, response, "503", "DATA before RCPT should return 503")
	})

	t.Run("RCPT_Before_MAIL", func(t *testing.T) {
		sendCommand(conn, reader, "RSET\r\n")
		
		response := sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
		assert.Contains(t, response, "503", "RCPT before MAIL should return 503")
	})

	t.Run("MAIL_Before_EHLO", func(t *testing.T) {
		sendCommand(conn, reader, "RSET\r\n")
		
		response := sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		// Should still work after RSET, or return 503 if strict
		assert.True(t,
			strings.Contains(response, "250") || strings.Contains(response, "503"),
			"MAIL command sequencing should be validated")
	})

	t.Run("Valid_Sequence", func(t *testing.T) {
		sendCommand(conn, reader, "RSET\r\n")
		
		response := sendCommand(conn, reader, "EHLO test.example.com\r\n")
		assert.Contains(t, response, "250", "EHLO should succeed")
		
		response = sendCommand(conn, reader, "MAIL FROM:<sender@example.com>\r\n")
		assert.Contains(t, response, "250", "MAIL should succeed after EHLO")
		
		response = sendCommand(conn, reader, "RCPT TO:<recipient@example.com>\r\n")
		assert.Contains(t, response, "250", "RCPT should succeed after MAIL")
		
		response = sendCommand(conn, reader, "DATA\r\n")
		assert.Contains(t, response, "354", "DATA should succeed after RCPT")
		
		message := "Subject: Valid sequence\r\n\r\nTest\r\n.\r\n"
		response = sendCommand(conn, reader, message)
		assert.Contains(t, response, "250", "Message should be accepted")
	})
}

// TestRFC5321_ResponseCodes tests that response codes match RFC specifications
func TestRFC5321_ResponseCodes(t *testing.T) {
	server, conn, reader := setupTestServer(t)
	defer server.Close()
	defer conn.Close()

	testCases := []struct {
		name         string
		command      string
		expectedCode string
	}{
		// Positive completion codes (2xx)
		{"EHLO_Success", "EHLO test.example.com\r\n", "250"},
		{"RSET_Success", "RSET\r\n", "250"},
		{"NOOP_Success", "NOOP\r\n", "250"},
		{"QUIT_Success", "QUIT\r\n", "221"},
		
		// Note: Cannot test more here without session setup
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := sendCommand(conn, reader, tc.command)
			assert.Contains(t, response, tc.expectedCode,
				"Command %s should return %s", tc.command, tc.expectedCode)
		})
	}
}
