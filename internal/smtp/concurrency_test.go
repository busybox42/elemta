package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkerPoolConcurrency tests the worker pool under high concurrency
func TestWorkerPoolConcurrency(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := &WorkerPoolConfig{
		Size:               10,
		JobBufferSize:      100,
		ResultBufferSize:   100,
		CircuitBreakerName: "test-worker",
		MaxRequests:        1000,
		Interval:           time.Minute,
		Timeout:            10 * time.Second,
	}

	wp := NewWorkerPool(config, logger)
	require.NotNil(t, wp)

	// Start worker pool
	err := wp.Start()
	require.NoError(t, err)
	defer wp.Stop()

	// Test concurrent job submission
	numJobs := 1000
	var completedJobs int64
	var failedJobs int64
	var wg sync.WaitGroup

	// Create test jobs
	for i := 0; i < numJobs; i++ {
		wg.Add(1)
		go func(jobID int) {
			defer wg.Done()

			job := &TestJob{
				id:       fmt.Sprintf("job-%d", jobID),
				duration: time.Millisecond * time.Duration(jobID%100), // Variable duration
				shouldFail: jobID%50 == 0, // 2% failure rate
			}

			err := wp.Submit(job)
			if err != nil {
				atomic.AddInt64(&failedJobs, 1)
				return
			}

			atomic.AddInt64(&completedJobs, 1)
		}(i)
	}

	wg.Wait()

	// Wait for processing to complete
	time.Sleep(5 * time.Second)

	stats := wp.GetStats()
	t.Logf("Worker pool stats: Total=%d, Completed=%d, Failed=%d, Active=%d",
		stats.TotalJobs, stats.CompletedJobs, stats.FailedJobs, stats.ActiveWorkers)

	assert.True(t, stats.TotalJobs > 0, "Should have processed jobs")
	assert.True(t, stats.CompletedJobs > 0, "Should have completed jobs")
	assert.True(t, wp.IsHealthy(), "Worker pool should be healthy")
}

// TestJob is a test implementation of the Job interface
type TestJob struct {
	id         string
	duration   time.Duration
	shouldFail bool
	priority   int
}

func (tj *TestJob) Process(ctx context.Context) (interface{}, error) {
	// Simulate work
	select {
	case <-time.After(tj.duration):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if tj.shouldFail {
		return nil, fmt.Errorf("simulated failure for job %s", tj.id)
	}

	return fmt.Sprintf("result-%s", tj.id), nil
}

func (tj *TestJob) ID() string {
	return tj.id
}

func (tj *TestJob) Priority() int {
	return tj.priority
}

// TestCircuitBreakerIntegration tests circuit breaker behavior
func TestCircuitBreakerIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := &WorkerPoolConfig{
		Size:               2,
		JobBufferSize:      10,
		ResultBufferSize:   10,
		CircuitBreakerName: "test-circuit-breaker",
		MaxRequests:        5,
		Interval:           time.Second,
		Timeout:            time.Second,
	}

	wp := NewWorkerPool(config, logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)
	defer wp.Stop()

	// Submit jobs that will fail to trigger circuit breaker
	for i := 0; i < 10; i++ {
		job := &TestJob{
			id:         fmt.Sprintf("fail-job-%d", i),
			duration:   time.Millisecond * 10,
			shouldFail: true,
			priority:   1,
		}

		err := wp.Submit(job)
		require.NoError(t, err)
	}

	// Wait for jobs to be processed
	time.Sleep(3 * time.Second)

	// Check circuit breaker state
	cbStats := wp.GetCircuitBreakerStats()
	t.Logf("Circuit breaker stats: Requests=%d, Failures=%d, State=%s",
		cbStats.Requests, cbStats.TotalFailures, wp.circuitBreaker.State().String())

	// Circuit breaker should eventually open due to failures
	assert.True(t, cbStats.TotalFailures > 0, "Should have recorded failures")
}

// TestGracefulShutdown tests graceful shutdown behavior
func TestGracefulShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := DefaultWorkerPoolConfig()
	wp := NewWorkerPool(config, logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)

	// Submit some long-running jobs
	for i := 0; i < 5; i++ {
		job := &TestJob{
			id:       fmt.Sprintf("long-job-%d", i),
			duration: time.Second * 2,
			priority: 1,
		}

		err := wp.Submit(job)
		require.NoError(t, err)
	}

	// Start shutdown
	shutdownStart := time.Now()
	err = wp.Stop()
	shutdownDuration := time.Since(shutdownStart)

	assert.NoError(t, err, "Shutdown should not error")
	assert.True(t, shutdownDuration < time.Second*5, "Shutdown should complete within reasonable time")

	stats := wp.GetStats()
	t.Logf("Final stats after shutdown: Total=%d, Completed=%d, Failed=%d",
		stats.TotalJobs, stats.CompletedJobs, stats.FailedJobs)
}

// TestSMTPServerConcurrency tests SMTP server with high connection load
func TestSMTPServerConcurrency(t *testing.T) {
	// Skip this test in short mode as it's resource intensive
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	// Create test config
	config := &Config{
		Hostname:   "test.example.com",
		ListenAddr: ":0", // Let system choose port
		MaxSize:    1024 * 1024,
		Auth: &AuthConfig{
			Enabled:  false,
			Required: false,
		},
		QueueDir: t.TempDir(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start server
	err = server.Start()
	require.NoError(t, err)
	defer server.Close()

	// Get the actual listening address
	addr := server.listener.Addr().String()
	t.Logf("Test server listening on %s", addr)

	// Test concurrent connections
	numConnections := 50
	var successfulConnections int64
	var failedConnections int64
	var wg sync.WaitGroup

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, time.Second*5)
			if err != nil {
				atomic.AddInt64(&failedConnections, 1)
				t.Logf("Connection %d failed: %v", connID, err)
				return
			}
			defer conn.Close()

			// Set read timeout
			conn.SetReadDeadline(time.Now().Add(time.Second * 5))

			// Read greeting
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				atomic.AddInt64(&failedConnections, 1)
				t.Logf("Connection %d failed to read greeting: %v", connID, err)
				return
			}

			greeting := string(buffer[:n])
			if len(greeting) == 0 {
				atomic.AddInt64(&failedConnections, 1)
				t.Logf("Connection %d received empty greeting", connID)
				return
			}

			// Send QUIT
			_, err = conn.Write([]byte("QUIT\r\n"))
			if err != nil {
				atomic.AddInt64(&failedConnections, 1)
				t.Logf("Connection %d failed to send QUIT: %v", connID, err)
				return
			}

			atomic.AddInt64(&successfulConnections, 1)
		}(i)
	}

	wg.Wait()

	t.Logf("Connection test results: Successful=%d, Failed=%d",
		successfulConnections, failedConnections)

	assert.True(t, successfulConnections > 0, "Should have successful connections")
	assert.True(t, float64(successfulConnections)/float64(numConnections) > 0.8,
		"Should have >80% success rate")

	// Check worker pool stats
	stats := server.workerPool.GetStats()
	t.Logf("Server worker pool stats: Total=%d, Completed=%d, Failed=%d, Active=%d",
		stats.TotalJobs, stats.CompletedJobs, stats.FailedJobs, stats.ActiveWorkers)

	assert.True(t, stats.TotalJobs > 0, "Worker pool should have processed jobs")
}

// TestResourceLimiting tests resource limiting under load
func TestResourceLimiting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create worker pool with small limits
	config := &WorkerPoolConfig{
		Size:               2,  // Small pool
		JobBufferSize:      5,  // Small buffer
		ResultBufferSize:   5,
		CircuitBreakerName: "resource-limit-test",
		MaxRequests:        10,
		Interval:           time.Second,
		Timeout:            time.Second,
	}

	wp := NewWorkerPool(config, logger)
	require.NotNil(t, wp)

	err := wp.Start()
	require.NoError(t, err)
	defer wp.Stop()

	// Try to submit more jobs than the buffer can handle
	numJobs := 20
	var submittedJobs int64
	var rejectedJobs int64

	for i := 0; i < numJobs; i++ {
		job := &TestJob{
			id:       fmt.Sprintf("resource-job-%d", i),
			duration: time.Millisecond * 100,
			priority: 1,
		}

		err := wp.Submit(job)
		if err != nil {
			atomic.AddInt64(&rejectedJobs, 1)
		} else {
			atomic.AddInt64(&submittedJobs, 1)
		}
	}

	t.Logf("Resource limiting test: Submitted=%d, Rejected=%d",
		submittedJobs, rejectedJobs)

	assert.True(t, rejectedJobs > 0, "Should have rejected some jobs due to resource limits")
	assert.True(t, submittedJobs > 0, "Should have accepted some jobs")
	assert.True(t, wp.IsHealthy(), "Worker pool should remain healthy")
}

// BenchmarkWorkerPoolThroughput benchmarks worker pool throughput
func BenchmarkWorkerPoolThroughput(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce logging for benchmark
	}))

	config := &WorkerPoolConfig{
		Size:               10,
		JobBufferSize:      1000,
		ResultBufferSize:   1000,
		CircuitBreakerName: "benchmark-worker",
		MaxRequests:        10000,
		Interval:           time.Minute,
		Timeout:            time.Second,
	}

	wp := NewWorkerPool(config, logger)
	require.NotNil(b, wp)

	err := wp.Start()
	require.NoError(b, err)
	defer wp.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		jobID := 0
		for pb.Next() {
			job := &TestJob{
				id:       fmt.Sprintf("bench-job-%d", jobID),
				duration: time.Microsecond * 100, // Fast jobs
				priority: 1,
			}

			err := wp.Submit(job)
			if err != nil {
				b.Errorf("Failed to submit job: %v", err)
			}
			jobID++
		}
	})

	// Wait for all jobs to complete
	for {
		stats := wp.GetStats()
		if stats.QueuedJobs == 0 {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}

	stats := wp.GetStats()
	b.Logf("Benchmark completed: Total=%d, Completed=%d, Failed=%d",
		stats.TotalJobs, stats.CompletedJobs, stats.FailedJobs)
}
