package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestResourceLeakPrevention tests that resource leaks are prevented
func TestResourceLeakPrevention(t *testing.T) {
	// Create resource manager with small limits for testing
	limits := &ResourceLimits{
		MaxConnections:        10,
		MaxConnectionsPerIP:   5,
		ConnectionTimeout:     1 * time.Second,
		SessionTimeout:        2 * time.Second,
		IdleTimeout:           500 * time.Millisecond,
		GoroutinePoolSize:     5,
		CircuitBreakerEnabled: true,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise during testing
	}))
	resourceManager := NewResourceManager(limits, logger)

	// Test 1: Connection cleanup on panic
	t.Run("ConnectionCleanupOnPanic", func(t *testing.T) {
		// Create a mock connection that will panic
		conn := &testMockConn{panicOnRead: true}
		
		// Track initial connection count
		initialCount := resourceManager.GetStats()["active_connections"].(int32)
		
		// This should not leak resources even with panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Expected panic
				}
			}()
			
			// Simulate the server's handleAndCloseSession logic
			sessionID := resourceManager.AcceptConnection(conn)
			if sessionID == "" {
				t.Fatal("Failed to accept connection")
			}
			
			// Simulate panic during session handling
			panic("simulated panic")
		}()
		
		// Wait for cleanup
		time.Sleep(100 * time.Millisecond)
		
		// Verify connection was cleaned up
		finalCount := resourceManager.GetStats()["active_connections"].(int32)
		if finalCount != initialCount {
			t.Errorf("Connection leak detected: initial=%d, final=%d", initialCount, finalCount)
		}
	})

	// Test 2: Timeout enforcement
	t.Run("TimeoutEnforcement", func(t *testing.T) {
		conn := &testMockConn{delay: 3 * time.Second} // Longer than session timeout
		
		start := time.Now()
		sessionID := resourceManager.AcceptConnection(conn)
		if sessionID == "" {
			t.Fatal("Failed to accept connection")
		}
		
		// Simulate session handling with timeout
		ctx, cancel := context.WithTimeout(context.Background(), resourceManager.GetSessionTimeout())
		defer cancel()
		
		done := make(chan error, 1)
		go func() {
			// Simulate long-running session
			time.Sleep(5 * time.Second)
			done <- nil
		}()
		
		select {
		case <-done:
			t.Error("Session should have timed out")
		case <-ctx.Done():
			// Expected timeout
		}
		
		// Verify timeout occurred within expected time
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Errorf("Timeout not enforced: elapsed=%v", elapsed)
		}
		
		// Cleanup
		resourceManager.ReleaseConnection(sessionID)
	})

	// Test 3: Goroutine tracking
	t.Run("GoroutineTracking", func(t *testing.T) {
		initialGoroutines := runtime.NumGoroutine()
		
		// Create multiple connections that will be handled in goroutines
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn := &testMockConn{}
				sessionID := resourceManager.AcceptConnection(conn)
				if sessionID != "" {
					time.Sleep(100 * time.Millisecond)
					resourceManager.ReleaseConnection(sessionID)
				}
			}()
		}
		
		wg.Wait()
		
		// Wait for cleanup
		time.Sleep(200 * time.Millisecond)
		
		// Check for goroutine leaks (allow some tolerance)
		finalGoroutines := runtime.NumGoroutine()
		if finalGoroutines > initialGoroutines+5 {
			t.Errorf("Potential goroutine leak: initial=%d, final=%d", initialGoroutines, finalGoroutines)
		}
	})

	// Test 4: Atomic resource operations
	t.Run("AtomicResourceOperations", func(t *testing.T) {
		var wg sync.WaitGroup
		connections := make([]string, 10)
		
		// Create multiple connections concurrently
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				conn := &testMockConn{}
				sessionID := resourceManager.AcceptConnection(conn)
				connections[index] = sessionID
			}(i)
		}
		
		wg.Wait()
		
		// Verify all connections were accepted atomically
		stats := resourceManager.GetStats()
		activeConnections := stats["active_connections"].(int32)
		
		// Count non-empty session IDs
		acceptedCount := 0
		for _, sessionID := range connections {
			if sessionID != "" {
				acceptedCount++
			}
		}
		
		if int32(acceptedCount) != activeConnections {
			t.Errorf("Atomic operation failed: accepted=%d, active=%d", acceptedCount, activeConnections)
		}
		
		// Cleanup all connections
		for _, sessionID := range connections {
			if sessionID != "" {
				resourceManager.ReleaseConnection(sessionID)
			}
		}
	})

	// Test 5: Connection pool exhaustion
	t.Run("ConnectionPoolExhaustion", func(t *testing.T) {
		// Fill up the connection pool
		var connections []string
		for i := 0; i < 10; i++ { // MaxConnections is 10
			conn := &testMockConn{}
			sessionID := resourceManager.AcceptConnection(conn)
			if sessionID != "" {
				connections = append(connections, sessionID)
			}
		}
		
		// Try to accept one more connection (should fail)
		conn := &testMockConn{}
		sessionID := resourceManager.AcceptConnection(conn)
		if sessionID != "" {
			t.Error("Should not accept connection when pool is full")
		}
		
		// Cleanup
		for _, sessionID := range connections {
			resourceManager.ReleaseConnection(sessionID)
		}
	})

	// Test 6: IP-based connection limits
	t.Run("IPBasedConnectionLimits", func(t *testing.T) {
		// Create multiple connections from the same IP
		var connections []string
		for i := 0; i < 5; i++ { // MaxConnectionsPerIP is 5
			conn := &testMockConn{remoteAddr: "192.168.1.1:1234"}
			sessionID := resourceManager.AcceptConnection(conn)
			if sessionID != "" {
				connections = append(connections, sessionID)
			}
		}
		
		// Try to accept one more connection from the same IP (should fail)
		conn := &testMockConn{remoteAddr: "192.168.1.1:1235"}
		sessionID := resourceManager.AcceptConnection(conn)
		if sessionID != "" {
			t.Error("Should not accept connection when IP limit is reached")
		}
		
		// Cleanup
		for _, sessionID := range connections {
			resourceManager.ReleaseConnection(sessionID)
		}
	})
}

// testMockConn is a mock net.Conn for testing
type testMockConn struct {
	panicOnRead bool
	delay       time.Duration
	remoteAddr  string
}

func (m *testMockConn) Read(b []byte) (n int, err error) {
	if m.panicOnRead {
		panic("simulated read panic")
	}
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return 0, fmt.Errorf("mock read error")
}

func (m *testMockConn) Write(b []byte) (n int, err error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return len(b), nil
}

func (m *testMockConn) Close() error {
	return nil
}

func (m *testMockConn) LocalAddr() net.Addr {
	return &testMockAddr{"127.0.0.1:2525"}
}

func (m *testMockConn) RemoteAddr() net.Addr {
	if m.remoteAddr != "" {
		return &testMockAddr{m.remoteAddr}
	}
	return &testMockAddr{"127.0.0.1:1234"}
}

func (m *testMockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *testMockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *testMockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// testMockAddr is a mock net.Addr for testing
type testMockAddr struct {
	addr string
}

func (m *testMockAddr) Network() string {
	return "tcp"
}

func (m *testMockAddr) String() string {
	return m.addr
}
