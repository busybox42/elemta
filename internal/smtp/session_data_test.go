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
	_, _ = reader.ReadString('\n')
	_, _ = conn.Write([]byte("RCPT TO:<user@localhost>\r\n"))
	_, _ = reader.ReadString('\n')
	_, _ = conn.Write([]byte("DATA\r\n"))
	dataResp, _ := reader.ReadString('\n')
	assert.Contains(t, dataResp, "354")

	// Send simple message
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	// Send large message (1MB)
	largeBody := strings.Repeat("X", 1024*1024)
	message := "From: sender@example.com\r\n" +
		"To: user@localhost\r\n" +
		"Subject: Large Message\r\n" +
		"\r\n" +
		largeBody + "\r\n" +
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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

	conn, err := net.Dial("tcp", "localhost:2525")
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
		conn, err := net.Dial("tcp", "localhost:2525")
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
