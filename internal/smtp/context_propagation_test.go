package smtp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestServerContextPropagation verifies that server shutdown cancels all sessions
func TestServerContextPropagation(t *testing.T) {
	config := &Config{
		Hostname:   "localhost",
		ListenAddr: ":0",              // Use random port
		QueueDir:   "/tmp/test-queue", // Add required queue directory
		Timeouts: TimeoutConfig{
			SessionTimeout:  30 * time.Second,
			ShutdownTimeout: 5 * time.Second,
		},
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	err = server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Create multiple connections
	var sessions []*Session
	var wg sync.WaitGroup

	// Create 5 concurrent sessions
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 1*time.Second)
			if err != nil {
				t.Errorf("Failed to connect: %v", err)
				return
			}
			defer conn.Close()

			// Create session with server context
			session := NewSession(server.ctx, conn, config, nil)
			sessions = append(sessions, session)

			// Start session in goroutine
			go func() {
				session.Handle()
			}()
		}()
	}

	// Wait for sessions to be created
	time.Sleep(100 * time.Millisecond)

	// Verify all sessions have contexts that derive from server
	for i, session := range sessions {
		if session.ctx == nil {
			t.Errorf("Session %d has nil context", i)
		}

		// Check that session context is not cancelled yet
		select {
		case <-session.ctx.Done():
			t.Errorf("Session %d context cancelled before shutdown", i)
		default:
			// Good - context is still active
		}
	}

	// Initiate server shutdown
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- server.Close()
	}()

	// Wait for shutdown or timeout
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Errorf("Server shutdown failed: %v", err)
		}
	case <-time.After(config.Timeouts.ShutdownTimeout + 1*time.Second):
		t.Error("Server shutdown timeout")
	}

	// Verify all session contexts are cancelled
	for i, session := range sessions {
		select {
		case <-session.ctx.Done():
			// Good - session context was cancelled
		case <-time.After(100 * time.Millisecond):
			t.Errorf("Session %d context not cancelled after shutdown", i)
		}
	}

	wg.Wait()
}

// TestSessionTimeout verifies that session contexts timeout correctly
func TestSessionTimeout(t *testing.T) {
	config := &Config{
		Hostname: "localhost",
		Timeouts: TimeoutConfig{
			SessionTimeout: 100 * time.Millisecond,
		},
	}

	// Create mock connection
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	// Create session with short timeout
	session := NewSession(context.Background(), conn1, config, nil)

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Check that session context is cancelled due to timeout
	select {
	case <-session.ctx.Done():
		// Good - context cancelled by timeout
		if session.ctx.Err() != context.DeadlineExceeded {
			t.Errorf("Expected deadline exceeded error, got: %v", session.ctx.Err())
		}
	default:
		t.Error("Session context not cancelled after timeout")
	}
}

// TestSessionContextValues verifies that context values are properly set
func TestSessionContextValues(t *testing.T) {
	config := &Config{
		Hostname: "localhost",
		Timeouts: TimeoutConfig{
			SessionTimeout: 30 * time.Second,
		},
	}

	// Create mock connection
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	// Create session
	session := NewSession(context.Background(), conn1, config, nil)

	// Verify session has context
	if session.ctx == nil {
		t.Fatal("Session has nil context")
	}

	// Verify session ID is set (this is done in NewSession)
	if session.sessionID == "" {
		t.Error("Session ID not set")
	}

	// Verify remote address is set
	if session.remoteAddr == "" {
		t.Error("Remote address not set")
	}
}
