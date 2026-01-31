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
	conn, err := net.Dial("tcp", "localhost:2525")
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

			conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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
	assert.Contains(t, allResponses, "PIPELINING")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

			conn, err := net.Dial("tcp", "localhost:2525")
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
		name       string
		rcptCmd    string
		localDomain bool
		expectCode string
	}{
		{"local domain", "RCPT TO:<user@localhost>", true, "250"},
		{"valid address", "RCPT TO:<user@example.com>", false, "554"}, // Relay denied
		{"missing TO", "RCPT user@example.com", false, "501"},
		{"invalid address", "RCPT TO:<invalid>", false, "553"},
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

			conn, err := net.Dial("tcp", "localhost:2525")
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

		conn, err := net.Dial("tcp", "localhost:2525")
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

		conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

			conn, err := net.Dial("tcp", "localhost:2525")
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

			conn, err := net.Dial("tcp", "localhost:2525")
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

			conn, err := net.Dial("tcp", "localhost:2525")
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
		input       string
		expectCmd   string
		expectArgs  string
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

// TestValidateHostname tests hostname validation
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
		hostname string
		wantErr  bool
	}{
		{"example.com", false},
		{"mail.example.com", false},
		{"[127.0.0.1]", false},
		{"[IPv6:2001:db8::1]", false},
		{"", true},
		{strings.Repeat("a", 256), true}, // Too long
		{"mail-server.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			err := ch.validateHostname(ctx, tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
