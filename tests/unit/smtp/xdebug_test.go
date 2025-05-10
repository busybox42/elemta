package smtp_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockConn is a mock implementation of net.Conn for testing
type MockConn struct {
	mock.Mock
	ReadBuffer  *bytes.Buffer
	WriteBuffer *bytes.Buffer
}

func NewMockConn() *MockConn {
	return &MockConn{
		ReadBuffer:  bytes.NewBuffer(nil),
		WriteBuffer: bytes.NewBuffer(nil),
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.ReadBuffer.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.WriteBuffer.Write(b)
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *MockConn) SetDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

// MockAddr is a mock implementation of net.Addr for testing
type MockAddr struct {
	mock.Mock
}

func (m *MockAddr) Network() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAddr) String() string {
	args := m.Called()
	return args.String(0)
}

// MockSession is a wrapper around a real Session with mocked components
type MockSession struct {
	*smtp.Session
	mockConn   *MockConn
	respBuffer *bytes.Buffer
}

// setupMockSession creates a new Session with mocked components for testing
func setupMockSession(t *testing.T) *MockSession {
	// Create a mock connection
	mockConn := NewMockConn()
	mockConn.On("SetDeadline", mock.Anything).Return(nil)
	mockConn.On("SetReadDeadline", mock.Anything).Return(nil)
	mockConn.On("SetWriteDeadline", mock.Anything).Return(nil)
	mockConn.On("Close").Return(nil)

	mockAddr := &MockAddr{}
	mockAddr.On("Network").Return("tcp")
	mockAddr.On("String").Return("127.0.0.1:12345")
	mockConn.On("LocalAddr").Return(mockAddr)

	// Create a minimal config
	config := &smtp.Config{
		Hostname: "test.example.com",
		DevMode:  true,
	}

	// Create a session with the mocked connection
	// We're using an exported constructor if it exists
	session := smtp.NewSession(mockConn, config, nil)

	// Create a wrapper to provide easy access to the mock and response buffer
	mockSession := &MockSession{
		Session:    session,
		mockConn:   mockConn,
		respBuffer: mockConn.WriteBuffer,
	}

	return mockSession
}

// executeCommand simulates sending a command to the SMTP session
func (m *MockSession) executeCommand(command string) string {
	// Reset the write buffer
	m.respBuffer.Reset()

	// Call the XDEBUG handler directly (using reflection to access private method)
	// Since we can't call private methods directly, we'll simulate the call through the Write method
	m.mockConn.ReadBuffer.WriteString(command + "\r\n")

	// Now we need to trigger processing
	// This is a bit of a hack, but we'll invoke the XDEBUG command handling
	// directly on the session
	smtp.HandleXDEBUGForTesting(m.Session, command)

	// Return the response from the write buffer
	return m.respBuffer.String()
}

// TestXDEBUGCommand tests the XDEBUG command functionality
func TestXDEBUGCommand(t *testing.T) {
	session := setupMockSession(t)

	// Test the basic XDEBUG command
	response := session.executeCommand("XDEBUG")

	// Verify the response
	assert.Contains(t, response, "250-Debug information:", "Response should start with debug information")
	assert.Contains(t, response, "Session ID:", "Response should include session ID")
	assert.Contains(t, response, "Client IP:", "Response should include client IP")
	assert.Contains(t, response, "Hostname:", "Response should include hostname")
	assert.Contains(t, response, "State:", "Response should include state")
}

// TestXDEBUGContextCommands tests the XDEBUG CONTEXT commands
func TestXDEBUGContextCommands(t *testing.T) {
	session := setupMockSession(t)

	// Test XDEBUG CONTEXT (dump)
	response := session.executeCommand("XDEBUG CONTEXT")
	assert.Contains(t, response, "250-Context dump:", "Response should start with context dump")

	// Test XDEBUG CONTEXT SET
	response = session.executeCommand("XDEBUG CONTEXT SET test_key test_value")
	assert.Contains(t, response, "250 Set test_key = test_value", "Response should confirm key was set")

	// Test XDEBUG CONTEXT GET
	response = session.executeCommand("XDEBUG CONTEXT GET test_key")
	assert.Contains(t, response, "250 test_key = test_value", "Response should return the set value")

	// Test XDEBUG CONTEXT DELETE
	response = session.executeCommand("XDEBUG CONTEXT DELETE test_key")
	assert.Contains(t, response, "250 Deleted key: test_key", "Response should confirm key was deleted")

	// Verify key was deleted
	response = session.executeCommand("XDEBUG CONTEXT GET test_key")
	assert.Contains(t, response, "250 Key not found: test_key", "Response should indicate key not found")

	// Test XDEBUG CONTEXT CLEAR
	// First set a key
	session.executeCommand("XDEBUG CONTEXT SET test_key test_value")
	// Then clear all
	response = session.executeCommand("XDEBUG CONTEXT CLEAR")
	assert.Contains(t, response, "250 Context cleared", "Response should confirm context was cleared")

	// Verify context was cleared
	response = session.executeCommand("XDEBUG CONTEXT GET test_key")
	assert.Contains(t, response, "250 Key not found: test_key", "Response should indicate key not found after clear")
}

// TestXDEBUGSessionCommand tests the XDEBUG SESSION command
func TestXDEBUGSessionCommand(t *testing.T) {
	session := setupMockSession(t)

	// Test XDEBUG HELP
	response := session.executeCommand("XDEBUG HELP")
	assert.Contains(t, response, "250-XDEBUG Commands:", "Response should list available commands")
	assert.Contains(t, response, "XDEBUG HELP", "Response should include help command")
}

// TestXDEBUGInvalidCommands tests invalid XDEBUG commands
func TestXDEBUGInvalidCommands(t *testing.T) {
	session := setupMockSession(t)

	// Test invalid subcommand
	response := session.executeCommand("XDEBUG INVALID")
	assert.Contains(t, response, "501 Unknown XDEBUG command: INVALID", "Response should indicate invalid command")

	// Test invalid CONTEXT operation
	response = session.executeCommand("XDEBUG CONTEXT INVALID")
	assert.Contains(t, response, "501 Unknown context operation: INVALID", "Response should indicate invalid context operation")

	// Test missing key for GET
	response = session.executeCommand("XDEBUG CONTEXT GET")
	assert.Contains(t, response, "501 Missing key", "Response should indicate missing key")

	// Test missing key/value for SET
	response = session.executeCommand("XDEBUG CONTEXT SET")
	assert.Contains(t, response, "501 Missing key and value", "Response should indicate missing key and value")

	// Test missing value for SET
	response = session.executeCommand("XDEBUG CONTEXT SET test_key")
	assert.Contains(t, response, "501 Missing value", "Response should indicate missing value")
}
