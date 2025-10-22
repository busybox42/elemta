package smtp

import (
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// TestResourceManagerAtomicOperations tests atomic operations in resource manager
func TestResourceManagerAtomicOperations(t *testing.T) {
	limits := &ResourceLimits{
		MaxConnections:        5,
		MaxConnectionsPerIP:   3,
		ConnectionTimeout:     1 * time.Second,
		SessionTimeout:        2 * time.Second,
		IdleTimeout:           500 * time.Millisecond,
		GoroutinePoolSize:     5,
		CircuitBreakerEnabled: true,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	resourceManager := NewResourceManager(limits, logger)

	// Test concurrent connection acceptance
	var wg sync.WaitGroup
	connections := make([]string, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			conn := &testConn{}
			sessionID := resourceManager.AcceptConnection(conn)
			connections[index] = sessionID
		}(i)
	}

	wg.Wait()

	// Verify atomic operations
	stats := resourceManager.GetStats()
	activeConnections := stats["active_connections"].(int32)

	acceptedCount := 0
	for _, sessionID := range connections {
		if sessionID != "" {
			acceptedCount++
		}
	}

	if int32(acceptedCount) != activeConnections {
		t.Errorf("Atomic operation failed: accepted=%d, active=%d", acceptedCount, activeConnections)
	}

	// Cleanup
	for _, sessionID := range connections {
		if sessionID != "" {
			resourceManager.ReleaseConnection(sessionID)
		}
	}
}

// TestResourceManagerConnectionLimits tests connection limits
func TestResourceManagerConnectionLimits(t *testing.T) {
	limits := &ResourceLimits{
		MaxConnections:        3,
		MaxConnectionsPerIP:   2,
		ConnectionTimeout:     1 * time.Second,
		SessionTimeout:        2 * time.Second,
		IdleTimeout:           500 * time.Millisecond,
		GoroutinePoolSize:     5,
		CircuitBreakerEnabled: true,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	resourceManager := NewResourceManager(limits, logger)

	// Test global connection limit
	var connections []string
	for i := 0; i < 3; i++ { // MaxConnections is 3
		conn := &testConn{}
		sessionID := resourceManager.AcceptConnection(conn)
		if sessionID != "" {
			connections = append(connections, sessionID)
		}
	}

	// Try to accept one more connection (should fail)
	conn := &testConn{}
	sessionID := resourceManager.AcceptConnection(conn)
	if sessionID != "" {
		t.Error("Should not accept connection when pool is full")
	}

	// Cleanup
	for _, sessionID := range connections {
		resourceManager.ReleaseConnection(sessionID)
	}

	// Test IP-based connection limit
	var ipConnections []string
	for i := 0; i < 2; i++ { // MaxConnectionsPerIP is 2
		conn := &testConn{remoteAddr: "192.168.1.1:1234"}
		sessionID := resourceManager.AcceptConnection(conn)
		if sessionID != "" {
			ipConnections = append(ipConnections, sessionID)
		}
	}

	// Try to accept one more connection from the same IP (should fail)
	conn = &testConn{remoteAddr: "192.168.1.1:1235"}
	sessionID = resourceManager.AcceptConnection(conn)
	if sessionID != "" {
		t.Error("Should not accept connection when IP limit is reached")
	}

	// Cleanup
	for _, sessionID := range ipConnections {
		resourceManager.ReleaseConnection(sessionID)
	}
}

// TestResourceManagerTimeoutMethods tests timeout getter methods
func TestResourceManagerTimeoutMethods(t *testing.T) {
	limits := &ResourceLimits{
		ConnectionTimeout: 5 * time.Second,
		SessionTimeout:    10 * time.Second,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	resourceManager := NewResourceManager(limits, logger)

	if resourceManager.GetConnectionTimeout() != 5*time.Second {
		t.Errorf("Expected connection timeout 5s, got %v", resourceManager.GetConnectionTimeout())
	}

	if resourceManager.GetSessionTimeout() != 10*time.Second {
		t.Errorf("Expected session timeout 10s, got %v", resourceManager.GetSessionTimeout())
	}
}

// testConn is a simple mock net.Conn for testing
type testConn struct {
	remoteAddr string
}

func (t *testConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (t *testConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (t *testConn) Close() error {
	return nil
}

func (t *testConn) LocalAddr() net.Addr {
	return &testAddr{"127.0.0.1:2525"}
}

func (t *testConn) RemoteAddr() net.Addr {
	if t.remoteAddr != "" {
		return &testAddr{t.remoteAddr}
	}
	return &testAddr{"127.0.0.1:1234"}
}

func (t *testConn) SetDeadline(deadline time.Time) error {
	return nil
}

func (t *testConn) SetReadDeadline(deadline time.Time) error {
	return nil
}

func (t *testConn) SetWriteDeadline(deadline time.Time) error {
	return nil
}

// testAddr is a simple mock net.Addr for testing
type testAddr struct {
	addr string
}

func (t *testAddr) Network() string {
	return "tcp"
}

func (t *testAddr) String() string {
	return t.addr
}
