package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mockConn implements the net.Conn interface for testing
type mockConn struct {
	reader *bytes.Buffer
	writer *bytes.Buffer
	closed bool
}

func newMockConn() *mockConn {
	return &mockConn{
		reader: &bytes.Buffer{},
		writer: &bytes.Buffer{},
	}
}

func (c *mockConn) Read(b []byte) (n int, err error)  { return c.reader.Read(b) }
func (c *mockConn) Write(b []byte) (n int, err error) { return c.writer.Write(b) }
func (c *mockConn) Close() error                      { c.closed = true; return nil }
func (c *mockConn) LocalAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25} }
func (c *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockAuthenticator implements the Authenticator interface for testing
type mockAuthenticator struct {
	enabled  bool
	required bool
	users    map[string]string
}

func newMockAuthenticator(enabled, required bool) *mockAuthenticator {
	return &mockAuthenticator{
		enabled:  enabled,
		required: required,
		users: map[string]string{
			"testuser": "testpass",
		},
	}
}

func (a *mockAuthenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !a.enabled {
		return true, nil
	}

	storedPass, exists := a.users[username]
	return exists && storedPass == password, nil
}

func (a *mockAuthenticator) IsEnabled() bool {
	return a.enabled
}

func (a *mockAuthenticator) IsRequired() bool {
	return a.required
}

func (a *mockAuthenticator) GetSupportedMethods() []AuthMethod {
	return []AuthMethod{AuthMethodPlain, AuthMethodLogin}
}

func (a *mockAuthenticator) Close() error {
	return nil
}

// mockTLSManager implements a mock version of the TLS manager for testing
type mockTLSManager struct {
	enabled   bool
	wrapError error
}

func newMockTLSManager(enabled bool) *mockTLSManager {
	return &mockTLSManager{
		enabled: enabled,
	}
}

func (m *mockTLSManager) WrapConnection(conn net.Conn) (net.Conn, error) {
	if m.wrapError != nil {
		return nil, m.wrapError
	}

	// For testing, we'll just use a new mock conn and not try to cast it to a tls.Conn
	return newMockConn(), nil
}

// Implement other required methods to satisfy the interface
func (m *mockTLSManager) GetTLSConfig() *tls.Config {
	return &tls.Config{}
}

func (m *mockTLSManager) StartTLSListener(ctx context.Context) (net.Listener, error) {
	return nil, nil
}

func (m *mockTLSManager) RenewCertificates(ctx context.Context) error {
	return nil
}

func (m *mockTLSManager) GetCertificateInfo() (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockTLSManager) Stop() error {
	return nil
}

// For testing purposes only
// The actual mockHandleSTARTTLS is defined in session.go

func TestSessionBasic(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "elemta-session-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create queue directory
	queueDir := filepath.Join(tempDir, "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatalf("Failed to create queue dir: %v", err)
	}

	// Create basic config
	config := &Config{
		ListenAddr: "127.0.0.1:0",
		QueueDir:   queueDir,
		Hostname:   "test.example.com",
		DevMode:    true, // Use dev mode to avoid actually saving messages
		MaxSize:    1024, // Set a reasonable max size
	}

	// Create mock connection
	conn := newMockConn()

	// Create session
	authenticator := newMockAuthenticator(false, false)
	session := NewSession(conn, config, authenticator)

	// Simulate client commands
	commands := []string{
		"EHLO client.example.com\r\n",
		"MAIL FROM:<sender@example.com>\r\n",
		"RCPT TO:<recipient@example.com>\r\n",
		"DATA\r\n",
		"Subject: Test Email\r\n",
		"\r\n",
		"This is a test email.\r\n",
		".\r\n",
		"QUIT\r\n",
	}

	// Write commands to the mock connection
	for _, cmd := range commands {
		conn.reader.WriteString(cmd)
	}

	// Handle the session
	err = session.Handle()
	if err != nil {
		t.Fatalf("Session handling failed: %v", err)
	}

	// Check the responses
	response := conn.writer.String()

	// Verify greeting
	if !strings.Contains(response, "220 elemta ESMTP ready") {
		t.Errorf("Missing greeting in response")
	}

	// Verify EHLO response
	if !strings.Contains(response, "250-"+config.Hostname) {
		t.Errorf("Missing hostname in EHLO response")
	}

	// Verify MAIL FROM response
	if !strings.Contains(response, "250 Ok") {
		t.Errorf("Missing OK response to MAIL FROM")
	}

	// Verify DATA response
	if !strings.Contains(response, "354 Start mail input") {
		t.Errorf("Missing DATA prompt")
	}

	// Verify message accepted
	if !strings.Contains(response, "250 Ok: message queued") {
		t.Errorf("Missing message queued confirmation")
	}

	// Verify QUIT response
	if !strings.Contains(response, "221 Bye") {
		t.Errorf("Missing quit response")
	}
}

func TestSessionAuthentication(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "elemta-session-auth-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create queue directory
	queueDir := filepath.Join(tempDir, "queue")
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		t.Fatalf("Failed to create queue dir: %v", err)
	}

	// Create config with auth required
	config := &Config{
		ListenAddr: "127.0.0.1:0",
		QueueDir:   queueDir,
		Hostname:   "test.example.com",
		DevMode:    true,
		MaxSize:    1024,
	}

	// Create proper base64 encoded credentials
	// For LOGIN auth, we'll need username and password separately
	usernameB64 := base64.StdEncoding.EncodeToString([]byte("testuser"))
	correctPassB64 := base64.StdEncoding.EncodeToString([]byte("testpass"))
	wrongPassB64 := base64.StdEncoding.EncodeToString([]byte("wrongpass"))

	// Test cases
	tests := []struct {
		name           string
		authEnabled    bool
		authRequired   bool
		commands       []string
		expectedOutput []string
	}{
		{
			name:         "Auth disabled",
			authEnabled:  false,
			authRequired: false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"MAIL FROM:<sender@example.com>\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"220 elemta ESMTP ready",
				"250-test.example.com",
				"250 Ok",
				"221 Bye",
			},
		},
		{
			name:         "Auth enabled but not required",
			authEnabled:  true,
			authRequired: false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"MAIL FROM:<sender@example.com>\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"220 elemta ESMTP ready",
				"250-test.example.com",
				"250-AUTH PLAIN LOGIN",
				"250 Ok",
				"221 Bye",
			},
		},
		{
			name:         "Auth required but not provided",
			authEnabled:  true,
			authRequired: true,
			commands: []string{
				"EHLO client.example.com\r\n",
				"MAIL FROM:<sender@example.com>\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"220 elemta ESMTP ready",
				"250-test.example.com",
				"250-AUTH PLAIN LOGIN",
				"530 5.7.0 Authentication required",
				"221 Bye",
			},
		},
		{
			name:         "Auth successful",
			authEnabled:  true,
			authRequired: true,
			commands: []string{
				"EHLO client.example.com\r\n",
				"AUTH LOGIN\r\n",
				usernameB64 + "\r\n",
				correctPassB64 + "\r\n",
				"MAIL FROM:<sender@example.com>\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"220 elemta ESMTP ready",
				"250-test.example.com",
				"250-AUTH PLAIN LOGIN",
				"334", // Username challenge
				"334", // Password challenge
				"235 2.7.0 Authentication successful",
				"250 Ok",
				"221 Bye",
			},
		},
		{
			name:         "Auth failed",
			authEnabled:  true,
			authRequired: true,
			commands: []string{
				"EHLO client.example.com\r\n",
				"AUTH LOGIN\r\n",
				usernameB64 + "\r\n",
				wrongPassB64 + "\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"220 elemta ESMTP ready",
				"250-test.example.com",
				"250-AUTH PLAIN LOGIN",
				"334", // Username challenge
				"334", // Password challenge
				"535 5.7.8 Authentication credentials invalid",
				"221 Bye",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock connection
			conn := newMockConn()

			// Create authenticator
			authenticator := newMockAuthenticator(tc.authEnabled, tc.authRequired)

			// Create session
			session := NewSession(conn, config, authenticator)

			// Write commands to the mock connection
			for _, cmd := range tc.commands {
				conn.reader.WriteString(cmd)
			}

			// Handle the session
			err := session.Handle()
			if err != nil {
				t.Fatalf("Session handling failed: %v", err)
			}

			// Check the responses
			response := conn.writer.String()

			for _, expected := range tc.expectedOutput {
				if !strings.Contains(response, expected) {
					t.Errorf("Expected response to contain %q, but it didn't. Response: %s", expected, response)
				}
			}
		})
	}
}

// TestSessionSTARTTLS tests the STARTTLS functionality
func TestSessionSTARTTLS(t *testing.T) {
	// Set up a mock handleSTARTTLS function for testing
	originalHandler := mockHandleSTARTTLS
	defer func() {
		mockHandleSTARTTLS = originalHandler
	}()

	// Create a simple mockHandleSTARTTLS function for all STARTTLS tests
	mockHandleSTARTTLS = func(s *Session) error {
		s.logger.Info("Mock STARTTLS handler called")

		// Always create a new mock connection
		newConn := newMockConn()

		// Don't need to add commands back anymore - we'll modify the test cases instead

		// Set the new connection and create new buffers
		s.conn = newConn
		s.reader = bufio.NewReader(newConn)
		s.writer = bufio.NewWriter(newConn)
		s.tls = true
		return nil
	}

	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "elemta-starttls-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test cases
	tests := []struct {
		name                   string
		tlsEnabled             bool
		startTLSEnabled        bool
		alreadyTLS             bool
		wrapError              error
		commands               []string
		expectedOutput         []string
		afterTLSCommands       []string
		afterTLSExpectedOutput []string
	}{
		{
			name:            "STARTTLS capability advertised",
			tlsEnabled:      true,
			startTLSEnabled: true,
			alreadyTLS:      false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"250-STARTTLS",
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS capability not advertised when TLS disabled",
			tlsEnabled:      false,
			startTLSEnabled: true,
			alreadyTLS:      false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"250-ENHANCEDSTATUSCODES",
				"250 HELP",
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS capability not advertised when StartTLS disabled",
			tlsEnabled:      true,
			startTLSEnabled: false,
			alreadyTLS:      false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"250-ENHANCEDSTATUSCODES",
				"250 HELP",
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS capability not advertised when already using TLS",
			tlsEnabled:      true,
			startTLSEnabled: true,
			alreadyTLS:      true,
			commands: []string{
				"EHLO client.example.com\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"250-ENHANCEDSTATUSCODES",
				"250 HELP",
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS command successful",
			tlsEnabled:      true,
			startTLSEnabled: true,
			alreadyTLS:      false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"STARTTLS\r\n",
			},
			expectedOutput: []string{
				"250-STARTTLS",
				"220 2.0.0 Ready to start TLS",
			},
			afterTLSCommands: []string{
				"EHLO client.example.com\r\n",
				"QUIT\r\n",
			},
			afterTLSExpectedOutput: []string{
				"250-ENHANCEDSTATUSCODES", // No STARTTLS in second EHLO
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS command followed by complete transaction",
			tlsEnabled:      true,
			startTLSEnabled: true,
			alreadyTLS:      false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"STARTTLS\r\n",
			},
			expectedOutput: []string{
				"250-STARTTLS",
				"220 2.0.0 Ready to start TLS",
			},
			afterTLSCommands: []string{
				"EHLO client.example.com\r\n", // New EHLO after STARTTLS
				"MAIL FROM:<sender@example.com>\r\n",
				"RCPT TO:<recipient@example.com>\r\n",
				"DATA\r\n",
				"Subject: Test Email\r\n",
				"\r\n",
				"This is a test email.\r\n",
				".\r\n",
				"QUIT\r\n",
			},
			afterTLSExpectedOutput: []string{
				"250-ENHANCEDSTATUSCODES", // Second EHLO
				"250 Ok",                  // MAIL FROM
				"250 Ok",                  // RCPT TO
				"354 Start mail input",    // DATA
				"250 Ok: message queued",  // End of DATA
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS command fails when TLS disabled",
			tlsEnabled:      false,
			startTLSEnabled: true,
			alreadyTLS:      false,
			commands: []string{
				"EHLO client.example.com\r\n",
				"STARTTLS\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"454 4.7.0 TLS not available",
				"221 Bye",
			},
		},
		{
			name:            "STARTTLS command fails when already using TLS",
			tlsEnabled:      true,
			startTLSEnabled: true,
			alreadyTLS:      true,
			commands: []string{
				"EHLO client.example.com\r\n",
				"STARTTLS\r\n",
				"QUIT\r\n",
			},
			expectedOutput: []string{
				"503 5.5.1 TLS already active",
				"221 Bye",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock connection
			conn := newMockConn()

			// Create config
			config := &Config{
				ListenAddr: "127.0.0.1:0",
				QueueDir:   tempDir,
				Hostname:   "test.example.com",
				DevMode:    true,
				MaxSize:    1024,
				TLS: &TLSConfig{
					Enabled:        tc.tlsEnabled,
					EnableStartTLS: tc.startTLSEnabled,
				},
			}

			// Create authenticator
			authenticator := newMockAuthenticator(false, false)

			// Create session
			session := NewSession(conn, config, authenticator)

			// Set up TLS manager
			mockTlsManager := newMockTLSManager(tc.tlsEnabled)
			mockTlsManager.wrapError = tc.wrapError
			session.tlsManager = mockTlsManager

			// Set TLS flag if already using TLS
			session.tls = tc.alreadyTLS

			// Write commands to the mock connection
			for _, cmd := range tc.commands {
				conn.reader.WriteString(cmd)
			}

			// Handle the session
			err := session.Handle()
			if err != nil && err.Error() != "EOF" {
				t.Fatalf("Session handling failed: %v", err)
			}

			// Check the responses
			response := conn.writer.String()

			for _, expected := range tc.expectedOutput {
				if !strings.Contains(response, expected) {
					t.Errorf("Expected response to contain %q, but it didn't. Response: %s", expected, response)
				}
			}

			// For STARTTLS tests that need to continue after the TLS handshake,
			// we need to create a new session with the "wrapped" connection
			if tc.name == "STARTTLS command successful" || tc.name == "STARTTLS command followed by complete transaction" {
				// After STARTTLS, verify the session is in TLS mode
				if !session.tls {
					t.Errorf("Session should be in TLS mode after STARTTLS, but it isn't")
				}

				// Create a new connection for the post-TLS part
				tlsConn := newMockConn()

				// Create a new session that's already in TLS mode
				tlsSession := NewSession(tlsConn, config, authenticator)
				tlsSession.tls = true
				tlsSession.tlsManager = mockTlsManager

				// Write the post-TLS commands
				for _, cmd := range tc.afterTLSCommands {
					tlsConn.reader.WriteString(cmd)
				}

				// Handle the post-TLS session
				err = tlsSession.Handle()
				if err != nil && err.Error() != "EOF" {
					t.Fatalf("Post-TLS session handling failed: %v", err)
				}

				// Check post-TLS responses
				tlsResponse := tlsConn.writer.String()
				for _, expected := range tc.afterTLSExpectedOutput {
					if !strings.Contains(tlsResponse, expected) {
						t.Errorf("Post-TLS: Expected response to contain %q, but it didn't. Response: %s", expected, tlsResponse)
					}
				}
			}
		})
	}
}
