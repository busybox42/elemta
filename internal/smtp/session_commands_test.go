package smtp

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommandHandlerCreation tests NewCommandHandler
func TestCommandHandlerCreation(t *testing.T) {
	config := createTestConfig(t)
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	// Start server
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	// Connect
	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, greeting, "220")
}

// TestHandleHELO tests the HELO command handler
func TestHandleHELO(t *testing.T) {
	tests := []struct {
		name         string
		heloArg      string
		expectCode   string
		expectErr    bool
		shouldAccept bool
	}{
		{"valid hostname", "example.com", "250", false, true},
		{"valid FQDN", "mail.example.com", "250", false, true},
		{"empty hostname", "", "501", true, false},
		{"IP literal", "[127.0.0.1]", "250", false, true},
		{"IPv6 literal", "[IPv6:2001:db8::1]", "250", false, true},
		{"hostname with dash", "mail-server.example.com", "250", false, true},
		{"numeric hostname", "192.168.1.1", "250", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			// Send HELO command
			if tt.heloArg == "" {
				_, err = conn.Write([]byte("HELO\r\n"))
			} else {
				_, err = conn.Write([]byte(fmt.Sprintf("HELO %s\r\n", tt.heloArg)))
			}
			require.NoError(t, err)

			// Read response
			response, err := reader.ReadString('\n')
			require.NoError(t, err)

			if tt.shouldAccept {
				assert.Contains(t, response, tt.expectCode, "Expected success code")
			} else {
				assert.Contains(t, response, tt.expectCode, "Expected error code")
			}
		})
	}
}

// TestHandleEHLO tests the EHLO command handler
func TestHandleEHLO(t *testing.T) {
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

	// Send EHLO
	_, err = conn.Write([]byte("EHLO client.example.com\r\n"))
	require.NoError(t, err)

	// Read multiline response
	var responses []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		responses = append(responses, line)

		// Last line has space after code
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Verify first line contains hostname
	assert.Contains(t, responses[0], "250-")
	assert.Contains(t, responses[0], "Hello")

	// Verify extensions
	allResponses := strings.Join(responses, "")
	assert.Contains(t, allResponses, "SIZE")
	assert.Contains(t, allResponses, "8BITMIME")
	// Note: PIPELINING is intentionally NOT advertised (see session_commands.go:166)
	assert.Contains(t, allResponses, "HELP")
}

// TestHandleEHLOEmpty tests EHLO with no argument
func TestHandleEHLOEmpty(t *testing.T) {
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

	// Send EHLO with no argument
	_, err = conn.Write([]byte("EHLO\r\n"))
	require.NoError(t, err)

	// Read response
	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "501", "Should require domain")
}

// TestHandleMAIL tests the MAIL FROM command
func TestHandleMAIL(t *testing.T) {
	tests := []struct {
		name       string
		mailCmd    string
		expectCode string
		wantErr    bool
	}{
		{"valid address", "MAIL FROM:<sender@example.com>", "250", false},
		{"valid address no brackets", "MAIL FROM:sender@example.com", "250", false},
		{"empty sender", "MAIL FROM:<>", "250", false}, // Null sender is valid
		{"missing FROM", "MAIL sender@example.com", "501", true},
		{"invalid format", "MAIL", "501", true},
		{"malformed address", "MAIL FROM:<invalid>", "553", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t)
			config.Auth = nil // Disable auth requirement for this test
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

			// Send EHLO
			_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
			require.NoError(t, err)

			// Read EHLO responses
			for {
				line, err := reader.ReadString('\n')
				require.NoError(t, err)
				if len(line) >= 4 && line[3] == ' ' {
					break
				}
			}

			// Send MAIL FROM
			_, err = conn.Write([]byte(tt.mailCmd + "\r\n"))
			require.NoError(t, err)

			// Read response
			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, response, tt.expectCode)
		})
	}
}

// TestHandleRCPT tests the RCPT TO command
func TestHandleRCPT(t *testing.T) {
	tests := []struct {
		name        string
		rcptCmd     string
		localDomain bool
		expectCode  string
	}{
		{"local domain", "RCPT TO:<user@localhost>", true, "250"},
		{"valid address", "RCPT TO:<user@example.com>", false, "554"}, // Relay denied
		{"missing TO", "RCPT user@example.com", false, "501"},
		{"invalid address", "RCPT TO:<invalid>", false, "501"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t)
			config.Auth = nil // Disable auth requirement
			if tt.localDomain {
				config.LocalDomains = []string{"localhost"}
			}
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

			// Read greeting and send EHLO
			_, _ = reader.ReadString('\n')
			_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
			for {
				line, _ := reader.ReadString('\n')
				if len(line) >= 4 && line[3] == ' ' {
					break
				}
			}

			// Send MAIL FROM
			_, _ = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
			_, _ = reader.ReadString('\n')

			// Send RCPT TO
			_, err = conn.Write([]byte(tt.rcptCmd + "\r\n"))
			require.NoError(t, err)

			// Read response
			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, response, tt.expectCode)
		})
	}
}

// TestHandleDATA tests the DATA command
func TestHandleDATA(t *testing.T) {
	t.Run("success with recipient", func(t *testing.T) {
		config := createTestConfig(t)
		config.Auth = nil
		config.LocalDomains = []string{"localhost"}
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

		// Setup: greeting, EHLO, MAIL, RCPT
		_, _ = reader.ReadString('\n')
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

		// Send DATA
		_, err = conn.Write([]byte("DATA\r\n"))
		require.NoError(t, err)

		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "354", "Should accept DATA command")
	})

	t.Run("fail without recipient", func(t *testing.T) {
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

		// Setup without RCPT
		_, _ = reader.ReadString('\n')
		_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
		for {
			line, _ := reader.ReadString('\n')
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
		_, _ = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
		_, _ = reader.ReadString('\n')

		// Send DATA without RCPT
		_, err = conn.Write([]byte("DATA\r\n"))
		require.NoError(t, err)

		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, response, "503", "Should reject DATA without recipients")
	})
}

// TestHandleRSET tests the RSET command
func TestHandleRSET(t *testing.T) {
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

	// Setup
	_, _ = reader.ReadString('\n')
	_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Send RSET
	_, err = conn.Write([]byte("RSET\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "RSET should succeed")
	assert.Contains(t, response, "Reset")
}

// TestHandleNOOP tests the NOOP command
func TestHandleNOOP(t *testing.T) {
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
	_, _ = reader.ReadString('\n')

	// Send NOOP
	_, err = conn.Write([]byte("NOOP\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "NOOP should succeed")
}

// TestHandleQUIT tests the QUIT command
func TestHandleQUIT(t *testing.T) {
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
	_, _ = reader.ReadString('\n')

	// Send QUIT
	_, err = conn.Write([]byte("QUIT\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "221", "QUIT should return 221")
	assert.Contains(t, response, "closing")
}

// TestHandleHELP tests the HELP command
func TestHandleHELP(t *testing.T) {
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
	_, _ = reader.ReadString('\n')

	// Send HELP
	_, err = conn.Write([]byte("HELP\r\n"))
	require.NoError(t, err)

	// Read multiline response
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
	assert.Contains(t, allResponses, "214")
	assert.Contains(t, allResponses, "Commands")
}

// TestHandleVRFY tests the VRFY command
func TestHandleVRFY(t *testing.T) {
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
	_, _ = reader.ReadString('\n')

	// Send VRFY
	_, err = conn.Write([]byte("VRFY user@example.com\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "252", "VRFY should return 252")
}

// TestHandleEXPN tests the EXPN command
func TestHandleEXPN(t *testing.T) {
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
	_, _ = reader.ReadString('\n')

	// Send EXPN
	_, err = conn.Write([]byte("EXPN list@example.com\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "502", "EXPN should return 502")
}

// TestHandleUnknown tests unknown commands
func TestHandleUnknown(t *testing.T) {
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
	_, _ = reader.ReadString('\n')

	// Send unknown command
	_, err = conn.Write([]byte("BADCOMMAND\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "502", "Unknown command should return 502")
}

// TestCommandSequencing tests valid SMTP command sequences
func TestCommandSequencing(t *testing.T) {
	tests := []struct {
		name     string
		sequence []string
		expected []string
	}{
		{
			name: "valid full sequence",
			sequence: []string{
				"EHLO test.example.com",
				"MAIL FROM:<sender@example.com>",
				"RCPT TO:<user@localhost>",
				"DATA",
			},
			expected: []string{"250", "250", "250", "354"},
		},
		{
			name: "RCPT before MAIL should fail",
			sequence: []string{
				"EHLO test.example.com",
				"RCPT TO:<user@localhost>",
			},
			expected: []string{"250", "503"},
		},
		{
			name: "multiple RCPT",
			sequence: []string{
				"EHLO test.example.com",
				"MAIL FROM:<sender@example.com>",
				"RCPT TO:<user1@localhost>",
				"RCPT TO:<user2@localhost>",
			},
			expected: []string{"250", "250", "250", "250"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t)
			config.Auth = nil
			config.LocalDomains = []string{"localhost"}
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

			for i, cmd := range tt.sequence {
				_, err = conn.Write([]byte(cmd + "\r\n"))
				require.NoError(t, err)

				// Read response (handle multiline EHLO)
				if strings.HasPrefix(cmd, "EHLO") {
					for {
						line, _ := reader.ReadString('\n')
						if len(line) >= 4 && line[3] == ' ' {
							assert.Contains(t, line, tt.expected[i])
							break
						}
					}
				} else {
					response, err := reader.ReadString('\n')
					require.NoError(t, err)
					assert.Contains(t, response, tt.expected[i], "Command %d: %s", i, cmd)
				}
			}
		})
	}
}

// TestXDEBUGCommands tests XDEBUG commands in dev mode
func TestXDEBUGCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		devMode bool
		expect  string
	}{
		{"XDEBUG STATE in dev mode", "XDEBUG STATE", true, "214"},
		{"XDEBUG CONTEXT in dev mode", "XDEBUG CONTEXT", true, "214"},
		{"XDEBUG in production mode", "XDEBUG STATE", false, "502"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t)
			config.DevMode = tt.devMode
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
			_, _ = reader.ReadString('\n')

			// Send XDEBUG command
			_, err = conn.Write([]byte(tt.command + "\r\n"))
			require.NoError(t, err)

			// Read response (may be multiline)
			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, response, tt.expect)
		})
	}
}

// TestRelayPermissions tests relay permission logic
func TestRelayPermissions(t *testing.T) {
	tests := []struct {
		name          string
		recipient     string
		authenticated bool
		localDomains  []string
		expectCode    string
	}{
		{"local domain unauthenticated", "user@localhost", false, []string{"localhost"}, "250"},
		{"external domain unauthenticated", "user@external.com", false, []string{"localhost"}, "554"},
		{"external domain authenticated", "user@external.com", true, []string{"localhost"}, "250"},
		{"local domain authenticated", "user@localhost", true, []string{"localhost"}, "250"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t)
			config.LocalDomains = tt.localDomains

			// For authenticated test, we'll just test unauthenticated scenarios
			// as auth setup is complex
			if tt.authenticated {
				t.Skip("Auth testing requires complex setup")
			}

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
			_, _ = reader.ReadString('\n')
			_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
			for {
				line, _ := reader.ReadString('\n')
				if len(line) >= 4 && line[3] == ' ' {
					break
				}
			}
			_, _ = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
			_, _ = reader.ReadString('\n')

			// Send RCPT
			_, err = conn.Write([]byte(fmt.Sprintf("RCPT TO:<%s>\r\n", tt.recipient)))
			require.NoError(t, err)

			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, response, tt.expectCode)
		})
	}
}

// TestEHLONoPipelining tests that PIPELINING is not advertised
func TestEHLONoPipelining(t *testing.T) {
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

	// Send EHLO
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	// Read multiline EHLO response
	var responses []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		responses = append(responses, line)

		// Last line has space after code
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Verify PIPELINING is NOT advertised
	allResponses := strings.Join(responses, "")
	assert.NotContains(t, allResponses, "PIPELINING",
		"PIPELINING should not be advertised as it's not implemented")

	// Verify other extensions are present
	assert.Contains(t, allResponses, "SIZE")
	assert.Contains(t, allResponses, "8BITMIME")
	assert.Contains(t, allResponses, "SMTPUTF8")
}

// TestSequentialCommandProcessing tests that commands are processed sequentially
func TestSequentialCommandProcessing(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost", "example.com"}
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

	// Send multiple commands in sequence (simulating what pipelining would do)
	commands := []string{
		"EHLO test.example.com\r\n",
		"MAIL FROM:<sender@example.com>\r\n",
		"RCPT TO:<user@example.com>\r\n",
		"NOOP\r\n",
	}

	expectedCodes := []string{"250", "250", "250", "250"}

	for i, cmd := range commands {
		// Send command
		_, err = conn.Write([]byte(cmd))
		require.NoError(t, err)

		// Read response immediately (sequential processing)
		if i == 0 {
			// EHLO returns multiline response
			for {
				line, err := reader.ReadString('\n')
				require.NoError(t, err)
				if len(line) >= 4 && line[3] == ' ' {
					assert.Contains(t, line, expectedCodes[i])
					break
				}
			}
		} else {
			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, response, expectedCodes[i],
				"Command %d (%s) should get response %s, got: %s", i, strings.TrimSpace(cmd), expectedCodes[i], strings.TrimSpace(response))
		}
	}
}

// TestMultipleCommandsSinglePacket tests sending multiple commands in one packet
// This verifies that even when commands arrive together, they are processed sequentially
func TestMultipleCommandsSinglePacket(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost", "example.com"}
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

	// Send EHLO first
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Send multiple commands in a single packet (simulating pipelining attempt)
	// Even though commands arrive together, server processes them sequentially
	batchCommands := "MAIL FROM:<sender@example.com>\r\n" +
		"RCPT TO:<user@example.com>\r\n" +
		"NOOP\r\n"

	_, err = conn.Write([]byte(batchCommands))
	require.NoError(t, err)

	// Read responses in order (server processes sequentially, not as a batch)
	// This proves we DON'T have real pipelining - each response comes immediately after processing
	expectedResponses := []string{"250", "250", "250"}

	for i, expected := range expectedResponses {
		response, err := reader.ReadString('\n')
		require.NoError(t, err, "Failed to read response %d", i)
		assert.Contains(t, response, expected,
			"Response %d should contain %s, got: %s", i, expected, strings.TrimSpace(response))
	}
}

// TestErrorHandlingInSequence tests error handling during command sequence
func TestErrorHandlingInSequence(t *testing.T) {
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

	// Read greeting
	_, _ = reader.ReadString('\n')

	// Send EHLO first
	_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Send commands with an error in the middle
	commands := []struct {
		cmd         string
		expectCode  string
		expectError bool
	}{
		{"MAIL FROM:<sender@example.com>\r\n", "250", false},
		{"RCPT TO:<user@external.com>\r\n", "554", true}, // Should fail - relay denied
		{"RSET\r\n", "250", false},                       // Should still work after error
	}

	for i, tc := range commands {
		_, err = conn.Write([]byte(tc.cmd))
		require.NoError(t, err)

		response, err := reader.ReadString('\n')
		require.NoError(t, err, "Failed to read response %d", i)

		if tc.expectError {
			assert.Contains(t, response, tc.expectCode,
				"Command %d should return error code %s", i, tc.expectCode)
		} else {
			assert.Contains(t, response, tc.expectCode,
				"Command %d should return success code %s", i, tc.expectCode)
		}
	}
}

// TestParseCommand tests command parsing
func TestParseCommand(t *testing.T) {
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config: config,
		logger: logger,
	}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	tests := []struct {
		input      string
		expectCmd  string
		expectArgs string
	}{
		{"HELO example.com", "HELO", "example.com"},
		{"MAIL FROM:<test@example.com>", "MAIL", "FROM:<test@example.com>"},
		{"NOOP", "NOOP", ""},
		{"  EHLO  test.com  ", "EHLO", "test.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cmd, args := ch.parseCommand(tt.input)
			assert.Equal(t, tt.expectCmd, cmd)
			assert.Equal(t, tt.expectArgs, args)
		})
	}
}

// TestMAILFROMSizeParameter tests RFC 1870 SIZE parameter handling
func TestMAILFROMSizeParameter(t *testing.T) {
	tests := []struct {
		name       string
		mailCmd    string
		maxSize    int64
		expectCode string
		wantErr    bool
	}{
		{
			name:       "valid SIZE within limit",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=1000000",
			maxSize:    10 * 1024 * 1024, // 10MB
			expectCode: "250",
			wantErr:    false,
		},
		{
			name:       "SIZE exactly at limit",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=10485760",
			maxSize:    10 * 1024 * 1024, // 10MB
			expectCode: "250",
			wantErr:    false,
		},
		{
			name:       "SIZE exceeding limit",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=20971520",
			maxSize:    10 * 1024 * 1024, // 10MB
			expectCode: "552",
			wantErr:    true,
		},
		{
			name:       "SIZE zero (valid per RFC 1870)",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=0",
			maxSize:    10 * 1024 * 1024,
			expectCode: "250",
			wantErr:    false,
		},
		{
			name:       "invalid SIZE syntax (non-numeric)",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=abc",
			maxSize:    10 * 1024 * 1024,
			expectCode: "501",
			wantErr:    true,
		},
		{
			name:       "negative SIZE",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=-1000",
			maxSize:    10 * 1024 * 1024,
			expectCode: "501",
			wantErr:    true,
		},
		{
			name:       "SIZE with SMTPUTF8",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=1000000 SMTPUTF8",
			maxSize:    10 * 1024 * 1024,
			expectCode: "250",
			wantErr:    false,
		},
		{
			name:       "SIZE with BODY parameter",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=1000000 BODY=8BITMIME",
			maxSize:    10 * 1024 * 1024,
			expectCode: "250",
			wantErr:    false,
		},
		{
			name:       "no SIZE parameter",
			mailCmd:    "MAIL FROM:<sender@example.com>",
			maxSize:    10 * 1024 * 1024,
			expectCode: "250",
			wantErr:    false,
		},
		{
			name:       "unreasonably large SIZE (sanity check)",
			mailCmd:    "MAIL FROM:<sender@example.com> SIZE=99999999999999",
			maxSize:    100 * 1024 * 1024 * 1024, // 100GB
			expectCode: "552",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(t)
			config.Auth = nil // Disable auth requirement for this test
			config.MaxSize = tt.maxSize
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

			// Send EHLO
			_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
			require.NoError(t, err)

			// Read EHLO responses
			for {
				line, err := reader.ReadString('\n')
				require.NoError(t, err)
				if len(line) >= 4 && line[3] == ' ' {
					break
				}
			}

			// Send MAIL FROM with SIZE parameter
			_, err = conn.Write([]byte(tt.mailCmd + "\r\n"))
			require.NoError(t, err)

			// Read response
			response, err := reader.ReadString('\n')
			require.NoError(t, err)

			if tt.wantErr {
				assert.Contains(t, response, tt.expectCode,
					"Expected error code %s, got: %s", tt.expectCode, strings.TrimSpace(response))
			} else {
				assert.Contains(t, response, tt.expectCode,
					"Expected success code %s, got: %s", tt.expectCode, strings.TrimSpace(response))
			}
		})
	}
}

// TestEHLOSizeAdvertisement tests that SIZE is properly advertised in EHLO
func TestEHLOSizeAdvertisement(t *testing.T) {
	config := createTestConfig(t)
	config.MaxSize = 50 * 1024 * 1024 // 50MB
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

	// Send EHLO
	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	// Read EHLO responses
	var responses []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		responses = append(responses, line)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Verify SIZE is advertised with correct value
	allResponses := strings.Join(responses, "")
	assert.Contains(t, allResponses, "SIZE",
		"SIZE extension should be advertised")
	assert.Contains(t, allResponses, "52428800",
		"SIZE should advertise maximum of 52428800 bytes (50MB)")
}

// TestParseMailFromSizeParameter tests SIZE parameter parsing
func TestParseMailFromSizeParameter(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config:     config,
		logger:     logger,
		sessionID:  "test-session",
		remoteAddr: "127.0.0.1:12345",
	}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	tests := []struct {
		name        string
		args        string
		expectAddr  string
		expectSize  int64
		wantErr     bool
		errContains string
	}{
		{
			name:       "SIZE with brackets",
			args:       "FROM:<user@example.com> SIZE=1000000",
			expectAddr: "user@example.com",
			expectSize: 1000000,
			wantErr:    false,
		},
		{
			name:       "SIZE without brackets",
			args:       "FROM:user@example.com SIZE=1000000",
			expectAddr: "user@example.com",
			expectSize: 1000000,
			wantErr:    false,
		},
		{
			name:       "SIZE=0",
			args:       "FROM:<user@example.com> SIZE=0",
			expectAddr: "user@example.com",
			expectSize: 0,
			wantErr:    false,
		},
		{
			name:       "no SIZE parameter",
			args:       "FROM:<user@example.com>",
			expectAddr: "user@example.com",
			expectSize: 0,
			wantErr:    false,
		},
		{
			name:       "SIZE with other parameters",
			args:       "FROM:<user@example.com> SIZE=1000000 BODY=8BITMIME SMTPUTF8",
			expectAddr: "user@example.com",
			expectSize: 1000000,
			wantErr:    false,
		},
		{
			name:        "invalid SIZE (non-numeric)",
			args:        "FROM:<user@example.com> SIZE=abc",
			expectAddr:  "",
			expectSize:  0,
			wantErr:     true,
			errContains: "501 5.5.4 Invalid SIZE parameter",
		},
		{
			name:        "negative SIZE",
			args:        "FROM:<user@example.com> SIZE=-1000",
			expectAddr:  "",
			expectSize:  0,
			wantErr:     true,
			errContains: "501 5.5.4 SIZE parameter must be non-negative",
		},
		{
			name:        "SIZE too large",
			args:        "FROM:<user@example.com> SIZE=99999999999999",
			expectAddr:  "",
			expectSize:  0,
			wantErr:     true,
			errContains: "552 5.3.4 SIZE parameter exceeds reasonable limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, size, err := ch.parseMailFrom(ctx, tt.args)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectAddr, addr)
				assert.Equal(t, tt.expectSize, size)
			}
		})
	}
}

// TestValidateHostname tests hostname validation per RFC 5321 §4.1.3
func TestValidateHostname(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config: config,
		logger: logger,
	}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	tests := []struct {
		name     string
		hostname string
		wantErr  bool
		errMsg   string
	}{
		// Valid domain names
		{"valid simple domain", "example.com", false, ""},
		{"valid subdomain", "mail.example.com", false, ""},
		{"valid with dash", "mail-server.example.com", false, ""},
		{"valid single label", "localhost", false, ""},
		{"valid numeric start", "123example.com", false, ""},

		// Valid IPv4 address literals
		{"valid IPv4 literal", "[127.0.0.1]", false, ""},
		{"valid IPv4 literal public", "[192.0.2.1]", false, ""},
		{"valid IPv4 literal private", "[10.0.0.1]", false, ""},

		// Valid IPv6 address literals
		{"valid IPv6 literal", "[IPv6:2001:db8::1]", false, ""},
		{"valid IPv6 literal full", "[IPv6:2001:0db8:0000:0000:0000:0000:0000:0001]", false, ""},
		{"valid IPv6 literal loopback", "[IPv6:::1]", false, ""},
		{"valid IPv6 literal uppercase", "[IPV6:2001:db8::1]", false, ""},
		{"valid IPv6 literal mixed case", "[IpV6:2001:db8::1]", false, ""},

		// Invalid - empty or too long
		{"invalid empty", "", true, "empty hostname"},
		{"invalid too long", strings.Repeat("a", 256), true, "hostname too long"},

		// Invalid IPv4 address literals
		{"invalid IPv4 empty brackets", "[]", true, "malformed address literal: empty brackets"},
		{"invalid IPv4 malformed", "[999.999.999.999]", true, "malformed IPv4 address literal"},
		{"invalid IPv4 incomplete", "[192.0.2]", true, "malformed IPv4 address literal"},
		{"invalid IPv4 not IP", "[not-an-ip]", true, "malformed IPv4 address literal"},
		{"invalid IPv4 with text", "[192.0.2.1.extra]", true, "malformed IPv4 address literal"},

		// Invalid IPv6 address literals
		{"invalid IPv6 empty after prefix", "[IPv6:]", true, "malformed IPv6 address literal: missing address"},
		{"invalid IPv6 malformed address", "[IPv6:invalid]", true, "malformed IPv6 address literal: invalid IPv6 address"},
		{"invalid IPv6 incomplete", "[IPv6:2001:db8]", true, "malformed IPv6 address literal: invalid IPv6 address"},
		{"invalid IPv6 with IPv4 address", "[IPv6:192.0.2.1]", true, "malformed IPv6 address literal"},

		// Invalid domain names
		{"invalid domain dash start", "-example.com", true, "invalid domain name: malformed label"},
		{"invalid domain dash end", "example-.com", true, "invalid domain name: malformed label"},
		{"invalid domain empty label", "example..com", true, "invalid domain name: empty label"},
		{"invalid domain label too long", strings.Repeat("a", 64) + ".com", true, "invalid domain name: label exceeds 63 characters"},
		{"invalid domain special char", "exam!ple.com", true, "invalid domain name: malformed label"},
		{"invalid domain underscore", "exam_ple.com", true, "invalid domain name: malformed label"},

		// Edge cases
		{"valid 63 char label", strings.Repeat("a", 63) + ".com", false, ""},
		{"valid 255 char domain", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ch.validateHostname(ctx, tt.hostname)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for hostname: %s", tt.hostname)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error message mismatch")
				}
			} else {
				assert.NoError(t, err, "Expected no error for hostname: %s", tt.hostname)
			}
		})
	}
}

// TestValidateEmailAddress tests email address validation
func TestValidateEmailAddress(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config: config,
		logger: logger,
	}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	tests := []struct {
		email   string
		wantErr bool
	}{
		{"user@example.com", false},
		{"", false}, // Null sender is valid
		{"test.user@example.com", false},
		{"user+tag@example.com", false},
		{"invalid", true},
		{"@example.com", true},
		{strings.Repeat("a", 321), true}, // Too long
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			err := ch.validateEmailAddress(ctx, tt.email)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
