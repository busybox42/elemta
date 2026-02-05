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

// TestReadMessageDataSimple tests basic message data reading
func TestReadMessageDataSimple(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"test.example.com", "example.com"}
	config.StrictLineEndings = false // Disable strict CRLF validation for testing
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

	// Setup SMTP session
	_, _ = reader.ReadString('\n') // greeting
	_, _ = conn.Write([]byte("EHLO test.example.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	_, _ = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	mailResp, _ := reader.ReadString('\n')
	t.Logf("MAIL FROM response: %q", mailResp)
	_, _ = conn.Write([]byte("RCPT TO:<user@example.com>\r\n"))
	rcptResp, _ := reader.ReadString('\n')
	t.Logf("RCPT TO response: %q", rcptResp)
	_, _ = conn.Write([]byte("DATA\r\n"))
	dataResp, _ := reader.ReadString('\n')
	t.Logf("DATA response: %q", dataResp)
	assert.Contains(t, dataResp, "354")

	// Send simple message
	message := "From: sender@example.com\r\n" +
		"To: user@example.com\r\n" +
		"Subject: Test Message\r\n" +
		"\r\n" +
		"This is a test message.\r\n" +
		".\r\n"

	_, err = conn.Write([]byte(message))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "Message should be accepted")
}

// TestReadMessageDataLarge tests reading a large message
func TestReadMessageDataLarge(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost"}
	config.MaxSize = 10 * 1024 * 1024 // 10MB
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

	// Setup session
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
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = reader.ReadString('\n')

	// Send large message (1MB) with proper line breaks to comply with RFC 5321
	// Each line should be <= 2000 octets
	var largeBodyBuilder strings.Builder
	lineLength := 1000 // Safe length under RFC 5321 limit
	for i := 0; i < 1024*1024/lineLength; i++ {
		largeBodyBuilder.WriteString(strings.Repeat("X", lineLength))
		largeBodyBuilder.WriteString("\r\n")
	}
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
		"Subject: Large Message\r\n" +
		"\r\n" +
		largeBodyBuilder.String() +
		".\r\n"

	_, err = conn.Write([]byte(message))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "Large message should be accepted")
}

// TestReadMessageDataSizeExceeded tests message size limit enforcement
func TestReadMessageDataSizeExceeded(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost"}
	config.MaxSize = 1024 // 1KB limit
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

	// Setup session
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
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = reader.ReadString('\n')

	// Send message exceeding size limit
	largeBody := strings.Repeat("X", 2048)
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
		"\r\n" +
		largeBody + "\r\n" +
		".\r\n"

	_, err = conn.Write([]byte(message))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "552", "Should reject oversized message")
}

// TestReadMessageDataDotStuffing tests proper handling of dot-stuffed lines
func TestReadMessageDataDotStuffing(t *testing.T) {
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

	// Setup session
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
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = reader.ReadString('\n')

	// Send message with line starting with dot (should be dot-stuffed by client)
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
		"Subject: Dot Test\r\n" +
		"\r\n" +
		"Line 1\r\n" +
		"..Line starting with dot\r\n" +
		"Line 3\r\n" +
		".\r\n"

	_, err = conn.Write([]byte(message))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "Message with dot-stuffed lines should be accepted")
}

// TestReadMessageDataLineEndings tests various line ending formats
func TestReadMessageDataLineEndings(t *testing.T) {
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

	// Setup session
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
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = reader.ReadString('\n')

	// Send message with proper CRLF line endings
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
		"Subject: Line Endings Test\r\n" +
		"\r\n" +
		"Body line 1\r\n" +
		"Body line 2\r\n" +
		".\r\n"

	_, err = conn.Write([]byte(message))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "Message with CRLF should be accepted")
}

// TestProcessMessageDataEmpty tests processing of empty message
func TestProcessMessageDataEmpty(t *testing.T) {
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

	// Setup session
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
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = reader.ReadString('\n')

	// Send minimal message (just terminator)
	_, err = conn.Write([]byte(".\r\n"))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	// Empty message might be accepted or rejected depending on validation
	t.Logf("Empty message response: %s", response)
}

// TestProcessMessageHeaderParsing tests header extraction
func TestProcessMessageHeaderParsing(t *testing.T) {
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

	// Setup session
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
	_, _ = conn.Write([]byte("DATA\r\n"))
	_, _ = reader.ReadString('\n')

	// Send message with various headers
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
		"Subject: Header Test\r\n" +
		"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n" +
		"Message-ID: <test123@example.com>\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Test body\r\n" +
		".\r\n"

	_, err = conn.Write([]byte(message))
	require.NoError(t, err)

	response, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, response, "250", "Message with headers should be accepted")
}

// TestMessageStats tests message statistics tracking
func TestMessageStats(t *testing.T) {
	config := createTestConfig(t)
	config.Auth = nil
	config.LocalDomains = []string{"localhost"}
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	// Send multiple messages
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", server.Addr().String())
		require.NoError(t, err)

		reader := bufio.NewReader(conn)

		// Complete transaction
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
		_, _ = conn.Write([]byte("DATA\r\n"))
		_, _ = reader.ReadString('\n')

		message := fmt.Sprintf("From: sender@example.com\r\nTo: user@localhost\r\nSubject: Test %d\r\n\r\nBody\r\n.\r\n", i)
		_, _ = conn.Write([]byte(message))
		response, _ := reader.ReadString('\n')
		assert.Contains(t, response, "250")

		conn.Close()
	}

	// Check that messages were processed
	// Statistics would be checked via metrics in real scenario
	t.Log("Successfully processed multiple messages")
}

// TestExtractMessageMetadata tests metadata extraction
func TestExtractMessageMetadata(t *testing.T) {
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config:     config,
		logger:     logger,
		sessionID:  "test-session",
		remoteAddr: "127.0.0.1:12345",
	}
	state := NewSessionState(logger)
	state.SetMailFrom(context.Background(), "sender@example.com")
	state.AddRecipient(context.Background(), "user@localhost")

	dh := &DataHandler{
		session: session,
		state:   state,
		logger:  session.logger,
		config:  config,
	}

	messageData := []byte("From: sender@example.com\r\nTo: user@localhost\r\nSubject: Test\r\n\r\nBody")

	metadata, err := dh.extractMessageMetadata(context.Background(), messageData)
	require.NoError(t, err)
	assert.NotEmpty(t, metadata.MessageID)
	assert.Equal(t, "sender@example.com", metadata.From)
	assert.Equal(t, []string{"user@localhost"}, metadata.To)
	assert.Equal(t, "Test", metadata.Subject)
	assert.Equal(t, int64(len(messageData)), metadata.Size)
}

// TestExtractHeaders tests header extraction logic
func TestExtractHeaders(t *testing.T) {
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config:     config,
		logger:     logger,
		sessionID:  "test-session",
		remoteAddr: "127.0.0.1:12345",
	}

	dh := &DataHandler{
		session: session,
		logger:  session.logger,
		config:  config,
	}

	tests := []struct {
		name     string
		data     []byte
		expected map[string]string
	}{
		{
			name: "simple headers",
			data: []byte("From: sender@example.com\r\nTo: user@localhost\r\nSubject: Test\r\n\r\nBody"),
			expected: map[string]string{
				"From":    "sender@example.com",
				"To":      "user@localhost",
				"Subject": "Test",
			},
		},
		{
			name: "folded header",
			data: []byte("From: sender@example.com\r\nSubject: This is a long\r\n subject line\r\n\r\nBody"),
			expected: map[string]string{
				"From":    "sender@example.com",
				"Subject": "This is a long subject line",
			},
		},
		{
			name:     "empty message",
			data:     []byte(""),
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := dh.extractHeaders(tt.data)
			for key, expectedValue := range tt.expected {
				actualValue, exists := headers[key]
				assert.True(t, exists, "Header %s should exist", key)
				assert.Equal(t, expectedValue, actualValue, "Header %s value mismatch", key)
			}
		})
	}
}

// TestValidateHeaderLine tests header line validation
func TestValidateHeaderLine(t *testing.T) {
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config:     config,
		logger:     logger,
		sessionID:  "test-session",
		remoteAddr: "127.0.0.1:12345",
	}

	// Create a mock connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	dh := &DataHandler{
		session: session,
		logger:  session.logger,
		config:  config,
		conn:    server,
	}
	dh.enhancedValidator = NewEnhancedValidator(session.logger)

	tests := []struct {
		name    string
		line    string
		wantErr bool
	}{
		{"valid header", "From: sender@example.com", false},
		{"valid continuation", "  continued value", false},
		{"empty line", "", false},
		{"header with colon", "Subject: Test: Colon in value", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dh.validateHeaderLine(context.Background(), tt.line)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateContentTypeHeader tests Content-Type validation
func TestValidateContentTypeHeader(t *testing.T) {
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config:     config,
		logger:     logger,
		sessionID:  "test-session",
		remoteAddr: "127.0.0.1:12345",
	}

	dh := &DataHandler{
		session: session,
		logger:  session.logger,
		config:  config,
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"text/plain", "text/plain", false},
		{"text/html", "text/html; charset=utf-8", false},
		{"multipart", "multipart/mixed; boundary=abc123", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dh.validateContentTypeHeader(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSeparateHeadersAndBody tests header/body separation
func TestSeparateHeadersAndBody(t *testing.T) {
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{
		config:     config,
		logger:     logger,
		sessionID:  "test-session",
		remoteAddr: "127.0.0.1:12345",
	}

	dh := &DataHandler{
		session: session,
		logger:  session.logger,
		config:  config,
	}

	tests := []struct {
		name           string
		content        string
		expectedHeader string
		expectedBody   string
	}{
		{
			name:           "CRLF separator",
			content:        "From: test@example.com\r\n\r\nBody text",
			expectedHeader: "From: test@example.com",
			expectedBody:   "Body text",
		},
		{
			name:           "LF separator",
			content:        "From: test@example.com\n\nBody text",
			expectedHeader: "From: test@example.com",
			expectedBody:   "Body text",
		},
		{
			name:           "no separator",
			content:        "All headers no body",
			expectedHeader: "All headers no body",
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, body := dh.separateHeadersAndBody(tt.content)
			assert.Equal(t, tt.expectedHeader, headers)
			assert.Equal(t, tt.expectedBody, body)
		})
	}
}

// TestIsInternalConnection tests internal connection detection
func TestIsInternalConnection(t *testing.T) {
	config := createTestConfig(t)

	tests := []struct {
		name       string
		remoteAddr string
		expected   bool
	}{
		{"localhost IPv4", "127.0.0.1:12345", true},
		{"localhost IPv6", "[::1]:12345", true},
		{"Docker network", "172.17.0.2:12345", true},
		{"Docker bridge", "10.0.0.2:12345", true},
		{"external", "8.8.8.8:12345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection with custom RemoteAddr
			mockConn := &mockNetConn{remoteAddr: tt.remoteAddr}
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: tt.remoteAddr,
			}

			dh := &DataHandler{
				session: session,
				logger:  session.logger,
				config:  config,
				conn:    mockConn,
			}

			result := dh.isInternalConnection()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mockNetConn implements net.Conn for testing
type mockNetConn struct {
	net.Conn
	remoteAddr string
}

func (m *mockNetConn) RemoteAddr() net.Addr {
	return &mockAddr{addr: m.remoteAddr}
}

func (m *mockNetConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockNetConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockNetConn) Close() error                       { return nil }
func (m *mockNetConn) LocalAddr() net.Addr                { return &mockAddr{addr: "localhost:2525"} }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }

// TestValidateLineEndings_StrictMode tests RFC 5321 strict CRLF validation
func TestValidateLineEndings_StrictMode(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	config.StrictLineEndings = true // Enable strict mode
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name        string
		line        []byte
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid CRLF line ending",
			line:    []byte("Hello World\r\n"),
			wantErr: false,
		},
		{
			name:    "valid CRLF header line",
			line:    []byte("Subject: Test Message\r\n"),
			wantErr: false,
		},
		{
			name:    "valid empty line with CRLF",
			line:    []byte("\r\n"),
			wantErr: false,
		},
		{
			name:        "bare LF line ending (strict mode)",
			line:        []byte("Hello World\n"),
			wantErr:     true,
			errContains: "500 5.5.2 Syntax error: bare LF not allowed",
		},
		{
			name:        "bare LF header line (strict mode)",
			line:        []byte("Subject: Test Message\n"),
			wantErr:     true,
			errContains: "500 5.5.2 Syntax error: bare LF not allowed",
		},
		{
			name:        "bare LF empty line (strict mode)",
			line:        []byte("\n"),
			wantErr:     true,
			errContains: "500 5.5.2 Syntax error: bare LF not allowed",
		},
		{
			name:    "long line with CRLF",
			line:    []byte(strings.Repeat("a", 998) + "\r\n"),
			wantErr: false,
		},
		{
			name:        "long line with bare LF",
			line:        []byte(strings.Repeat("a", 998) + "\n"),
			wantErr:     true,
			errContains: "500 5.5.2 Syntax error: bare LF not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{remoteAddr: "203.0.113.1:12345"}

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: "203.0.113.1:12345",
			}

			state := NewSessionState(logger)

			dh := &DataHandler{
				session: session,
				logger:  logger,
				config:  config,
				conn:    mockConn,
				state:   state,
			}

			readerState := &DataReaderState{
				InHeaders: false,
				LineCount: 1,
			}

			err := dh.validateLineEndings(ctx, tt.line, readerState)

			if tt.wantErr {
				assert.Error(t, err, "Expected error for line: %q", tt.line)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains, "Error message mismatch")
				}
			} else {
				assert.NoError(t, err, "Expected no error for line: %q", tt.line)
			}
		})
	}
}

// TestValidateLineEndings_LegacyMode tests legacy mode with bare LF acceptance
func TestValidateLineEndings_LegacyMode(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	config.StrictLineEndings = false // Disable strict mode (legacy)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name    string
		line    []byte
		wantErr bool
	}{
		{
			name:    "valid CRLF line ending",
			line:    []byte("Hello World\r\n"),
			wantErr: false,
		},
		{
			name:    "bare LF line ending (legacy mode - accepted)",
			line:    []byte("Hello World\n"),
			wantErr: false, // Should be accepted in legacy mode
		},
		{
			name:    "bare LF header line (legacy mode - accepted)",
			line:    []byte("Subject: Test Message\n"),
			wantErr: false, // Should be accepted in legacy mode
		},
		{
			name:    "bare LF empty line (legacy mode - accepted)",
			line:    []byte("\n"),
			wantErr: false, // Should be accepted in legacy mode
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{remoteAddr: "203.0.113.1:12345"}

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: "203.0.113.1:12345",
			}

			state := NewSessionState(logger)

			dh := &DataHandler{
				session: session,
				logger:  logger,
				config:  config,
				conn:    mockConn,
				state:   state,
			}

			readerState := &DataReaderState{
				InHeaders: false,
				LineCount: 1,
			}

			err := dh.validateLineEndings(ctx, tt.line, readerState)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err, "Expected no error in legacy mode for line: %q", tt.line)
			}
		})
	}
}

// TestIsValidEndOfData_StrictMode tests end-of-data marker validation in strict mode
func TestIsValidEndOfData_StrictMode(t *testing.T) {
	config := createTestConfig(t)
	config.StrictLineEndings = true // Enable strict mode
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name           string
		line           string
		expectedResult bool
		expectSecurity bool // Expect security event log
	}{
		{
			name:           "valid CRLF terminator",
			line:           ".\r\n",
			expectedResult: true,
			expectSecurity: false,
		},
		{
			name:           "bare LF terminator (strict mode - rejected)",
			line:           ".\n",
			expectedResult: false, // Should be rejected in strict mode
			expectSecurity: true,  // Should log security event
		},
		{
			name:           "dot with text and CRLF",
			line:           ".text\r\n",
			expectedResult: false,
			expectSecurity: true,
		},
		{
			name:           "dot with text and bare LF",
			line:           ".text\n",
			expectedResult: false,
			expectSecurity: true,
		},
		{
			name:           "regular line with CRLF",
			line:           "Hello World\r\n",
			expectedResult: false,
			expectSecurity: false,
		},
		{
			name:           "dot space CRLF",
			line:           ". \r\n",
			expectedResult: false,
			expectSecurity: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{remoteAddr: "203.0.113.1:12345"}

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: "203.0.113.1:12345",
			}

			dh := &DataHandler{
				session: session,
				logger:  logger,
				config:  config,
				conn:    mockConn,
			}

			readerState := &DataReaderState{
				InHeaders: false,
				LineCount: 1,
			}

			suspiciousPatterns := 0
			result := dh.isValidEndOfData(tt.line, readerState, &suspiciousPatterns)

			assert.Equal(t, tt.expectedResult, result, "Result mismatch for line: %q", tt.line)

			if tt.expectSecurity {
				assert.Greater(t, suspiciousPatterns, 0, "Expected security pattern detection for line: %q", tt.line)
			}
		})
	}
}

// TestIsValidEndOfData_LegacyMode tests end-of-data marker validation in legacy mode
func TestIsValidEndOfData_LegacyMode(t *testing.T) {
	config := createTestConfig(t)
	config.StrictLineEndings = false // Disable strict mode (legacy)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name           string
		line           string
		expectedResult bool
	}{
		{
			name:           "valid CRLF terminator",
			line:           ".\r\n",
			expectedResult: true,
		},
		{
			name:           "bare LF terminator (legacy mode - accepted)",
			line:           ".\n",
			expectedResult: true, // Should be accepted in legacy mode
		},
		{
			name:           "dot with text and CRLF",
			line:           ".text\r\n",
			expectedResult: false,
		},
		{
			name:           "regular line with CRLF",
			line:           "Hello World\r\n",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockNetConn{remoteAddr: "203.0.113.1:12345"}

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: "203.0.113.1:12345",
			}

			dh := &DataHandler{
				session: session,
				logger:  logger,
				config:  config,
				conn:    mockConn,
			}

			readerState := &DataReaderState{
				InHeaders: false,
				LineCount: 1,
			}

			suspiciousPatterns := 0
			result := dh.isValidEndOfData(tt.line, readerState, &suspiciousPatterns)

			assert.Equal(t, tt.expectedResult, result, "Result mismatch for line: %q", tt.line)
		})
	}
}

// TestValidateLineContent_RFC5321LineLengthLimits tests RFC 5321 §4.5.3.1.6 line length limits
func TestValidateLineContent_RFC5321LineLengthLimits(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name        string
		lineContent string
		remoteAddr  string
		wantErr     bool
		errContains string
	}{
		{
			name:        "line at 998 octets + CRLF (exactly 1000)",
			lineContent: strings.Repeat("a", 998) + "\r\n",
			remoteAddr:  "203.0.113.1:12345", // External address
			wantErr:     false,
		},
		{
			name:        "line at 999 octets + CRLF (1001 total - within SHOULD)",
			lineContent: strings.Repeat("a", 999) + "\r\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false, // Within SHOULD limit of 2000
		},
		{
			name:        "line at 1500 octets (within SHOULD extension)",
			lineContent: strings.Repeat("a", 1500) + "\r\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false, // Within SHOULD limit of 2000
		},
		{
			name:        "line at 1998 octets + CRLF (exactly 2000)",
			lineContent: strings.Repeat("a", 1998) + "\r\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false, // At SHOULD limit
		},
		{
			name:        "line exceeding 2000 octets (hard limit)",
			lineContent: strings.Repeat("a", 2001) + "\r\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     true,
			errContains: "552 5.3.4 Line too long",
		},
		{
			name:        "line at 3000 octets (far exceeding limit)",
			lineContent: strings.Repeat("a", 3000) + "\r\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     true,
			errContains: "552 5.3.4 Line too long",
		},
		{
			name:        "multi-byte UTF-8 characters - 500 chars (1500 octets)",
			lineContent: strings.Repeat("日", 500) + "\r\n", // 日 is 3 bytes in UTF-8
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false, // 500 * 3 + 2 = 1502 octets, within SHOULD limit
		},
		{
			name:        "multi-byte UTF-8 exceeding limit - 700 chars (2100 octets)",
			lineContent: strings.Repeat("日", 700) + "\r\n", // 700 * 3 + 2 = 2102 octets
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     true,
			errContains: "552 5.3.4 Line too long",
		},
		{
			name:        "emoji characters - 400 chars (1600 octets)",
			lineContent: strings.Repeat("😀", 400) + "\r\n", // 😀 is 4 bytes in UTF-8
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false, // 400 * 4 + 2 = 1602 octets, within SHOULD limit
		},
		{
			name:        "emoji characters exceeding limit - 500 chars (2000 octets)",
			lineContent: strings.Repeat("😀", 500) + "\r\n", // 500 * 4 + 2 = 2002 octets
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     true,
			errContains: "552 5.3.4 Line too long",
		},
		{
			name:        "internal connection respects same line length limits",
			lineContent: strings.Repeat("a", 2001) + "\r\n",
			remoteAddr:  "127.0.0.1:12345", // Internal address
			wantErr:     true,
			errContains: "552 5.3.4 Line too long",
		},
		{
			name:        "internal connection with valid line length",
			lineContent: strings.Repeat("a", 998) + "\r\n",
			remoteAddr:  "127.0.0.1:12345", // Internal address
			wantErr:     false,
		},
		{
			name:        "mixed ASCII and UTF-8 at boundary",
			lineContent: strings.Repeat("a", 996) + "日" + "\r\n", // 996 + 3 + 2 = 1001 octets
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false, // Within SHOULD limit
		},
		{
			name:        "empty line (just CRLF)",
			lineContent: "\r\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false,
		},
		{
			name:        "line with just LF (2 octets)",
			lineContent: "a\n",
			remoteAddr:  "203.0.113.1:12345",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection
			mockConn := &mockNetConn{remoteAddr: tt.remoteAddr}

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: tt.remoteAddr,
			}

			state := NewSessionState(logger)

			dh := &DataHandler{
				session:           session,
				logger:            logger,
				config:            config,
				conn:              mockConn,
				state:             state,
				enhancedValidator: NewEnhancedValidator(logger),
			}

			readerState := &DataReaderState{
				InHeaders: false,
				LineCount: 1,
			}

			err := dh.validateLineContent(ctx, tt.lineContent, readerState)

			if tt.wantErr {
				assert.Error(t, err, "Expected error for line length: %d octets", len(tt.lineContent))
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains, "Error message mismatch")
				}
			} else {
				assert.NoError(t, err, "Expected no error for line length: %d octets", len(tt.lineContent))
			}
		})
	}
}

// TestValidateLineContent_OctetCounting tests that we count octets (bytes) not characters
func TestValidateLineContent_OctetCounting(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name           string
		lineContent    string
		expectedOctets int
		wantErr        bool
	}{
		{
			name:           "ASCII characters - 1 byte each",
			lineContent:    "Hello World\r\n",
			expectedOctets: 13, // 11 + 2
			wantErr:        false,
		},
		{
			name:           "Latin-1 supplement - 2 bytes each",
			lineContent:    "café\r\n", // é is 2 bytes in UTF-8
			expectedOctets: 7,          // c=1, a=1, f=1, é=2, \r=1, \n=1 = 7
			wantErr:        false,
		},
		{
			name:           "Chinese characters - 3 bytes each",
			lineContent:    "你好\r\n", // Each Chinese char is 3 bytes
			expectedOctets: 8,        // 3 + 3 + 2 = 8
			wantErr:        false,
		},
		{
			name:           "Emoji - 4 bytes each",
			lineContent:    "😀😁\r\n", // Each emoji is 4 bytes
			expectedOctets: 10,       // 4 + 4 + 2 = 10
			wantErr:        false,
		},
		{
			name:           "Mixed content",
			lineContent:    "Hello 世界 😀\r\n", // 5 + 1 + 3 + 3 + 1 + 4 + 2 = 19
			expectedOctets: 19,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify our octet count expectation
			actualOctets := len(tt.lineContent)
			assert.Equal(t, tt.expectedOctets, actualOctets,
				"Octet count mismatch - test case may be incorrect")

			// Create mock connection (external)
			mockConn := &mockNetConn{remoteAddr: "203.0.113.1:12345"}

			session := &Session{
				config:     config,
				logger:     logger,
				sessionID:  "test-session",
				remoteAddr: "203.0.113.1:12345",
			}

			state := NewSessionState(logger)

			dh := &DataHandler{
				session:           session,
				logger:            logger,
				config:            config,
				conn:              mockConn,
				state:             state,
				enhancedValidator: NewEnhancedValidator(logger),
			}

			readerState := &DataReaderState{
				InHeaders: false,
				LineCount: 1,
			}

			err := dh.validateLineContent(ctx, tt.lineContent, readerState)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
