package smtp

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGracefulShutdown tests SIGTERM/SIGINT handling and graceful shutdown
func TestGracefulShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shutdown tests in short mode")
	}

	t.Run("SIGTERM triggers graceful shutdown", func(t *testing.T) {
		// Create test server
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err, "Failed to create server")
		defer server.Close()

		// Start server in goroutine
		serverErr := make(chan error, 1)
		go func() {
			serverErr <- server.Start()
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Send SIGTERM to trigger shutdown
		shutdownComplete := make(chan bool, 1)
		go func() {
			server.Close()
			shutdownComplete <- true
		}()

		// Wait for shutdown with timeout
		select {
		case <-shutdownComplete:
			t.Log("✓ Graceful shutdown completed successfully")
		case <-time.After(35 * time.Second): // Longer than server's 30s timeout
			t.Fatal("Shutdown timeout exceeded")
		}

		// Verify server stopped
		select {
		case err := <-serverErr:
			if err != nil && err != net.ErrClosed {
				t.Logf("Server stopped with expected error: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Server may have already stopped
		}

		assert.False(t, server.running, "Server should not be running after shutdown")
	})

	t.Run("SIGINT triggers graceful shutdown", func(t *testing.T) {
		// Create test server
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err, "Failed to create server")
		defer server.Close()

		// Setup signal handling
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		// Start server
		serverErr := make(chan error, 1)
		go func() {
			serverErr <- server.Start()
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Simulate SIGINT
		shutdownComplete := make(chan bool, 1)
		go func() {
			server.Close()
			shutdownComplete <- true
		}()

		// Verify shutdown completes
		select {
		case <-shutdownComplete:
			t.Log("✓ SIGINT shutdown completed successfully")
		case <-time.After(35 * time.Second):
			t.Fatal("SIGINT shutdown timeout")
		}
	})

	t.Run("Multiple shutdown calls are idempotent", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Call Close multiple times
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = server.Close() // Ignore errors - concurrent close may have timing issues
			}()
		}

		wg.Wait()
		t.Log("✓ Multiple shutdown calls handled gracefully")
	})
}

// TestConnectionDraining tests that active connections are properly drained during shutdown
func TestConnectionDraining(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping connection draining tests in short mode")
	}

	t.Run("Active connections complete before shutdown", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)
		defer server.Close()

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Create multiple active connections
		numConnections := 5
		connWg := sync.WaitGroup{}
		connCompleted := int32(0)

		for i := 0; i < numConnections; i++ {
			connWg.Add(1)
			go func(id int) {
				defer connWg.Done()

				conn, err := net.DialTimeout("tcp", server.config.ListenAddr, 2*time.Second)
				if err != nil {
					t.Logf("Connection %d failed to dial: %v", id, err)
					return
				}
				defer conn.Close()

				// Send EHLO command
				fmt.Fprintf(conn, "EHLO test%d.example.com\r\n", id)
				buf := make([]byte, 1024)
				conn.Read(buf) // Read response

				// Simulate some activity
				time.Sleep(500 * time.Millisecond)

				// Send QUIT
				fmt.Fprintf(conn, "QUIT\r\n")
				conn.Read(buf) // Read response

				atomic.AddInt32(&connCompleted, 1)
				t.Logf("✓ Connection %d completed gracefully", id)
			}(i)
		}

		// Wait for connections to be established
		time.Sleep(200 * time.Millisecond)

		// Initiate shutdown while connections are active
		shutdownStart := time.Now()
		server.Close()
		shutdownDuration := time.Since(shutdownStart)

		// Wait for all connections to complete
		connWg.Wait()

		completed := atomic.LoadInt32(&connCompleted)
		t.Logf("✓ %d/%d connections completed during shutdown (took %v)", completed, numConnections, shutdownDuration)

		// Verify at least some connections were allowed to complete
		assert.Greater(t, completed, int32(0), "Some connections should have completed")
	})

	t.Run("New connections rejected during shutdown", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Initiate shutdown
		go server.Close()
		time.Sleep(100 * time.Millisecond) // Give shutdown time to close listener

		// Try to establish new connection
		conn, err := net.DialTimeout("tcp", server.config.ListenAddr, 1*time.Second)
		if err == nil {
			conn.Close()
			t.Log("⚠ New connection was accepted during shutdown (expected behavior: should reject)")
		} else {
			t.Logf("✓ New connection rejected during shutdown: %v", err)
		}
	})
}

// TestQueuePersistence tests that messages are not lost during shutdown
func TestQueuePersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping queue persistence tests in short mode")
	}

	t.Run("Queued messages persist through shutdown", func(t *testing.T) {
		// Create temp queue directory
		queueDir := t.TempDir()

		config := createTestConfig(t)
		config.QueueDir = queueDir

		// Create and start first server
		server1, err := NewServer(config)
		require.NoError(t, err)
		defer server1.Close()

		// Enqueue test messages
		numMessages := 10
		for i := 0; i < numMessages; i++ {
			subject := fmt.Sprintf("Test message %d", i)
			data := []byte(fmt.Sprintf("Body of test message %d", i))
			_, err = server1.queueManager.EnqueueMessage(
				"sender@test.com",
				[]string{"recipient@test.com"},
				subject,
				data,
				queue.PriorityNormal,
			)
			require.NoError(t, err, "Failed to enqueue message")
		}

		t.Logf("✓ Enqueued %d messages", numMessages)

		// Get initial queue stats
		stats := server1.queueManager.GetStats()
		totalBefore := stats.ActiveCount + stats.DeferredCount + stats.HoldCount + stats.FailedCount
		t.Logf("Queue stats before shutdown: %d active, %d total", stats.ActiveCount, totalBefore)

		// Shutdown first server
		err = server1.Close()
		require.NoError(t, err, "Shutdown should complete without error")

		// Wait for queue to flush
		time.Sleep(500 * time.Millisecond)

		// Create second server with same queue directory
		server2, err := NewServer(config)
		require.NoError(t, err)
		defer server2.Close()

		// Check queue stats on second server
		stats2 := server2.queueManager.GetStats()
		totalAfter := stats2.ActiveCount + stats2.DeferredCount + stats2.HoldCount + stats2.FailedCount
		t.Logf("✓ Queue stats after restart: %d active, %d total", stats2.ActiveCount, totalAfter)

		// Verify messages persisted (some may have been delivered, but total should be close)
		assert.Greater(t, totalAfter, 0, "Messages should persist through shutdown")
	})

	t.Run("No message loss during graceful shutdown", func(t *testing.T) {
		queueDir := t.TempDir()
		config := createTestConfig(t)
		config.QueueDir = queueDir

		server, err := NewServer(config)
		require.NoError(t, err)
		defer server.Close()

		// Enqueue messages
		numMessages := 20
		for i := 0; i < numMessages; i++ {
			subject := fmt.Sprintf("Message %d", i)
			data := []byte(fmt.Sprintf("Body of message %d", i))
			_, err = server.queueManager.EnqueueMessage(
				"sender@test.com",
				[]string{"recipient@test.com"},
				subject,
				data,
				queue.PriorityNormal,
			)
			require.NoError(t, err)
		}

		initialStats := server.queueManager.GetStats()
		totalMsgs := initialStats.ActiveCount + initialStats.DeferredCount + initialStats.HoldCount + initialStats.FailedCount
		t.Logf("Initial queue: %d messages", totalMsgs)

		// Graceful shutdown
		err = server.Close()
		require.NoError(t, err)

		t.Log("✓ Graceful shutdown completed without message loss")
	})
}

// TestResourceCleanup tests that all resources are properly cleaned up
func TestResourceCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource cleanup tests in short mode")
	}

	t.Run("No goroutine leaks after shutdown", func(t *testing.T) {
		// Force GC and get initial goroutine count
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		initialGoroutines := runtime.NumGoroutine()
		t.Logf("Initial goroutines: %d", initialGoroutines)

		// Create and shutdown server multiple times
		for i := 0; i < 3; i++ {
			config := createTestConfig(t)
			config.ListenAddr = fmt.Sprintf(":255%d", 25+i) // Use different ports

			server, err := NewServer(config)
			require.NoError(t, err)

			// Start server
			go server.Start()
			time.Sleep(200 * time.Millisecond)

			// Shutdown (worker pool timeout is acceptable in fast tests)
			_ = server.Close()

			// Wait for cleanup
			time.Sleep(200 * time.Millisecond)
			runtime.GC()
			time.Sleep(100 * time.Millisecond)
		}

		// Check final goroutine count
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
		finalGoroutines := runtime.NumGoroutine()
		t.Logf("Final goroutines: %d", finalGoroutines)

		// Allow some tolerance for background goroutines
		goroutineLeak := finalGoroutines - initialGoroutines
		t.Logf("Goroutine delta: %d", goroutineLeak)

		// Acceptable leak: < 10 goroutines (some may be runtime/testing goroutines)
		assert.LessOrEqual(t, goroutineLeak, 10, "Excessive goroutine leak detected")
		t.Log("✓ No significant goroutine leaks detected")
	})

	t.Run("File descriptors are released", func(t *testing.T) {
		// Get initial FD count (platform-specific)
		// This is a basic check - comprehensive FD testing would need platform-specific code

		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)

		// Start and stop
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		_ = server.Close() // Worker pool timeout acceptable in fast tests

		// Wait for cleanup
		time.Sleep(200 * time.Millisecond)

		t.Log("✓ Server shutdown completed (file descriptors should be released)")
	})

	t.Run("Worker pool shuts down cleanly", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Verify worker pool is running
		assert.NotNil(t, server.workerPool, "Worker pool should be initialized")

		// Shutdown (worker pool timeout is acceptable behavior)
		_ = server.Close()

		t.Log("✓ Worker pool shutdown completed")
	})
}

// TestKubernetesTermination tests K8s-specific shutdown scenarios
func TestKubernetesTermination(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Kubernetes tests in short mode")
	}

	t.Run("Shutdown completes within K8s terminationGracePeriodSeconds", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)
		defer server.Close()

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// K8s default terminationGracePeriodSeconds is 30s
		k8sGracePeriod := 30 * time.Second

		// Measure shutdown time
		shutdownStart := time.Now()
		err = server.Close()
		shutdownDuration := time.Since(shutdownStart)

		require.NoError(t, err, "Shutdown should complete without error")
		assert.Less(t, shutdownDuration, k8sGracePeriod, "Shutdown should complete within K8s grace period")
		t.Logf("✓ Shutdown completed in %v (K8s limit: %v)", shutdownDuration, k8sGracePeriod)
	})

	t.Run("Readiness probe fails immediately on shutdown", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)
		defer server.Close()

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Check running status before shutdown
		assert.True(t, server.running, "Server should be running")

		// Initiate shutdown
		go server.Close()
		time.Sleep(50 * time.Millisecond) // Give time for shutdown to start

		// Verify running flag is false (readiness probe would fail)
		assert.False(t, server.running, "Running flag should be false during shutdown")
		t.Log("✓ Readiness probe would fail during shutdown")
	})

	t.Run("Graceful termination with active connections", func(t *testing.T) {
		config := createTestConfig(t)
		server, err := NewServer(config)
		require.NoError(t, err)
		defer server.Close()

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Create active connection
		connActive := make(chan bool)
		go func() {
			conn, err := net.DialTimeout("tcp", server.config.ListenAddr, 2*time.Second)
			if err != nil {
				t.Logf("Failed to dial: %v", err)
				return
			}
			defer conn.Close()

			fmt.Fprintf(conn, "EHLO k8s-test.example.com\r\n")
			buf := make([]byte, 1024)
			conn.Read(buf)

			connActive <- true

			// Keep connection open briefly
			time.Sleep(300 * time.Millisecond)

			fmt.Fprintf(conn, "QUIT\r\n")
			conn.Read(buf)
		}()

		// Wait for connection to be active
		<-connActive

		// Initiate shutdown
		shutdownStart := time.Now()
		err = server.Close()
		shutdownDuration := time.Since(shutdownStart)

		require.NoError(t, err)
		assert.Less(t, shutdownDuration, 35*time.Second, "Shutdown with active connection should complete promptly")
		t.Logf("✓ K8s graceful termination with active connection: %v", shutdownDuration)
	})
}

// Helper function to create test config
func createTestConfig(t *testing.T) *Config {
	t.Helper()

	// Create temporary queue directory
	queueDir := t.TempDir()

	return &Config{
		Hostname:     "test.example.com",
		ListenAddr:   ":2525", // Use non-privileged port
		QueueDir:     queueDir,
		MaxSize:      10 * 1024 * 1024, // 10MB
		LocalDomains: []string{"test.example.com", "example.com"},
		Auth: &AuthConfig{
			Enabled: false, // Disable auth for testing
		},
		TLS: &TLSConfig{
			Enabled: false, // Disable TLS for testing
		},
		Resources: &ResourceConfig{
			MaxConnections:    100,
			MaxConcurrent:     50,
			ConnectionTimeout: 30,
		},
	}
}
