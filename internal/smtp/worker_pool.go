package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sony/gobreaker"
	"golang.org/x/sync/errgroup"
)

// Job represents a unit of work to be processed by the worker pool
type Job interface {
	Process(ctx context.Context) (interface{}, error)
	ID() string
	Priority() int
}

// Result represents the result of processing a job
type Result struct {
	JobID string
	Data  interface{}
	Error error
}

// ConnectionJob represents an SMTP connection handling job
type ConnectionJob struct {
	id        string
	conn      interface{}
	handler   func(ctx context.Context, conn interface{}) error
	priority  int
	createdAt time.Time
}

func (cj *ConnectionJob) Process(ctx context.Context) (interface{}, error) {
	return nil, cj.handler(ctx, cj.conn)
}

func (cj *ConnectionJob) ID() string {
	return cj.id
}

func (cj *ConnectionJob) Priority() int {
	return cj.priority
}

// WorkerPool manages a pool of workers with proper error handling and resource management
type WorkerPool struct {
	config         *WorkerPoolConfig
	size           int
	jobs           chan Job
	results        chan Result
	ctx            context.Context
	cancel         context.CancelFunc
	errGroup       *errgroup.Group
	circuitBreaker *gobreaker.CircuitBreaker
	logger         *slog.Logger
	stats          *WorkerPoolStats
	mu             sync.RWMutex
	shutdown       int32
}

// WorkerPoolStats tracks worker pool performance metrics
type WorkerPoolStats struct {
	TotalJobs      int64
	CompletedJobs  int64
	FailedJobs     int64
	ActiveWorkers  int32
	QueuedJobs     int32
	GoroutineCount int32
	PanicCount     int64
	OrphanedJobs   int64
	CircuitBreaker struct {
		State     string
		Failures  int64
		Successes int64
		Timeouts  int64
	}
}

// WorkerPoolConfig configures the worker pool behavior
type WorkerPoolConfig struct {
	Size               int
	JobBufferSize      int
	ResultBufferSize   int
	CircuitBreakerName string
	MaxRequests        uint32
	Interval           time.Duration
	Timeout            time.Duration
	JobTimeout         time.Duration
	ShutdownTimeout    time.Duration
	MaxGoroutines      int32
	OnStateChange      func(name string, from gobreaker.State, to gobreaker.State)
}

// DefaultWorkerPoolConfig returns a sensible default configuration
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	return &WorkerPoolConfig{
		Size:               10,
		JobBufferSize:      100,
		ResultBufferSize:   100,
		CircuitBreakerName: "smtp-worker",
		MaxRequests:        100,
		Interval:           time.Minute,
		Timeout:            30 * time.Second,
		JobTimeout:         60 * time.Second,
		ShutdownTimeout:    30 * time.Second,
		MaxGoroutines:      1000,
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			slog.Info("Circuit breaker state changed",
				"name", name,
				"from", from.String(),
				"to", to.String(),
			)
		},
	}
}

// NewWorkerPool creates a new worker pool with the given configuration
func NewWorkerPool(config *WorkerPoolConfig, logger *slog.Logger) *WorkerPool {
	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	g, gctx := errgroup.WithContext(ctx)

	// Configure circuit breaker
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        config.CircuitBreakerName,
		MaxRequests: config.MaxRequests,
		Interval:    config.Interval,
		Timeout:     config.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 3 && failureRatio >= 0.6
		},
		OnStateChange: config.OnStateChange,
	})

	wp := &WorkerPool{
		config:         config,
		size:           config.Size,
		jobs:           make(chan Job, config.JobBufferSize),
		results:        make(chan Result, config.ResultBufferSize),
		ctx:            gctx,
		cancel:         cancel,
		errGroup:       g,
		circuitBreaker: cb,
		logger:         logger.With("component", "worker-pool"),
		stats:          &WorkerPoolStats{},
	}

	return wp
}

// Start initializes and starts all workers in the pool
func (wp *WorkerPool) Start() error {
	wp.logger.Info("Starting worker pool",
		"size", wp.size,
		"job_buffer", cap(wp.jobs),
		"result_buffer", cap(wp.results),
		"max_goroutines", wp.config.MaxGoroutines,
		"job_timeout", wp.config.JobTimeout,
		"shutdown_timeout", wp.config.ShutdownTimeout,
	)

	// Start workers
	for i := 0; i < wp.size; i++ {
		workerID := i
		wp.errGroup.Go(func() error {
			return wp.worker(workerID)
		})
	}

	// Start result processor
	wp.errGroup.Go(wp.resultProcessor)

	// Start goroutine monitoring
	wp.MonitorGoroutines()

	return nil
}

// Stop gracefully shuts down the worker pool with timeout
func (wp *WorkerPool) Stop() error {
	wp.logger.Info("Stopping worker pool")

	// Set shutdown flag
	atomic.StoreInt32(&wp.shutdown, 1)

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), wp.config.ShutdownTimeout)
	defer cancel()

	// Close jobs channel to signal workers to stop
	close(wp.jobs)

	// Cancel main context
	wp.cancel()

	// Wait for all workers to complete with timeout
	done := make(chan error, 1)
	go func() {
		done <- wp.errGroup.Wait()
	}()

	select {
	case err := <-done:
		// All workers completed normally
		wp.logger.Info("All workers completed gracefully")

		// Close results channel
		close(wp.results)

		wp.logger.Info("Worker pool stopped",
			"final_stats", wp.GetStats(),
		)

		return err

	case <-shutdownCtx.Done():
		// Shutdown timeout exceeded
		wp.logger.Error("Worker pool shutdown timeout exceeded",
			"timeout", wp.config.ShutdownTimeout,
			"active_workers", atomic.LoadInt32(&wp.stats.ActiveWorkers),
		)

		// Force close results channel
		close(wp.results)

		return fmt.Errorf("worker pool shutdown timeout exceeded")
	}
}

// Submit adds a job to the worker pool queue
func (wp *WorkerPool) Submit(job Job) error {
	// Check if we're shutting down
	if atomic.LoadInt32(&wp.shutdown) == 1 {
		return fmt.Errorf("worker pool is shutting down")
	}

	// Check goroutine count
	if atomic.LoadInt32(&wp.stats.GoroutineCount) > wp.config.MaxGoroutines {
		return fmt.Errorf("maximum goroutine limit exceeded")
	}

	select {
	case wp.jobs <- job:
		atomic.AddInt64(&wp.stats.TotalJobs, 1)
		atomic.AddInt32(&wp.stats.QueuedJobs, 1)
		return nil
	case <-wp.ctx.Done():
		return wp.ctx.Err()
	default:
		return fmt.Errorf("worker pool queue is full")
	}
}

// SubmitWithTimeout adds a job to the worker pool queue with a timeout
func (wp *WorkerPool) SubmitWithTimeout(job Job, timeout time.Duration) error {
	// Check if we're shutting down
	if atomic.LoadInt32(&wp.shutdown) == 1 {
		return fmt.Errorf("worker pool is shutting down")
	}

	// Check goroutine count
	if atomic.LoadInt32(&wp.stats.GoroutineCount) > wp.config.MaxGoroutines {
		return fmt.Errorf("maximum goroutine limit exceeded")
	}

	ctx, cancel := context.WithTimeout(wp.ctx, timeout)
	defer cancel()

	select {
	case wp.jobs <- job:
		atomic.AddInt64(&wp.stats.TotalJobs, 1)
		atomic.AddInt32(&wp.stats.QueuedJobs, 1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// worker processes jobs from the jobs channel with panic recovery
func (wp *WorkerPool) worker(workerID int) error {
	workerLogger := wp.logger.With("worker_id", workerID)
	workerLogger.Debug("Worker started")

	// Update active worker count and goroutine count
	atomic.AddInt32(&wp.stats.ActiveWorkers, 1)
	atomic.AddInt32(&wp.stats.GoroutineCount, 1)
	defer func() {
		atomic.AddInt32(&wp.stats.ActiveWorkers, -1)
		atomic.AddInt32(&wp.stats.GoroutineCount, -1)
		workerLogger.Debug("Worker stopped")
	}()

	// Panic recovery wrapper
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&wp.stats.PanicCount, 1)
			workerLogger.Error("Worker panicked, recovering",
				"panic", r,
				"worker_id", workerID,
			)
			// Don't re-panic, just log and continue
		}
	}()

	for {
		// Check if we're shutting down
		if atomic.LoadInt32(&wp.shutdown) == 1 {
			workerLogger.Debug("Shutdown signal received, worker exiting")
			return nil
		}

		select {
		case job, ok := <-wp.jobs:
			if !ok {
				workerLogger.Debug("Jobs channel closed, worker exiting")
				return nil
			}

			// Update queued jobs count
			atomic.AddInt32(&wp.stats.QueuedJobs, -1)

			// Process job with timeout and panic recovery
			result := wp.processJobWithTimeout(job, workerLogger)

			// Send result with timeout
			select {
			case wp.results <- result:
			case <-wp.ctx.Done():
				// Mark job as orphaned
				atomic.AddInt64(&wp.stats.OrphanedJobs, 1)
				workerLogger.Warn("Context cancelled while sending result, job orphaned",
					"job_id", job.ID(),
				)
				return wp.ctx.Err()
			case <-time.After(5 * time.Second):
				// Timeout sending result
				atomic.AddInt64(&wp.stats.OrphanedJobs, 1)
				workerLogger.Warn("Timeout sending result, job orphaned",
					"job_id", job.ID(),
				)
			}

		case <-wp.ctx.Done():
			workerLogger.Debug("Context cancelled, worker exiting")
			return wp.ctx.Err()
		}
	}
}

// processJobWithTimeout processes a job with timeout protection and panic recovery
func (wp *WorkerPool) processJobWithTimeout(job Job, logger *slog.Logger) Result {
	startTime := time.Now()

	logger.Debug("Processing job",
		"job_id", job.ID(),
		"priority", job.Priority(),
	)

	// Create context with timeout for job execution
	timeoutCtx, cancel := context.WithTimeout(wp.ctx, wp.config.JobTimeout)
	defer cancel()

	// Execute job with circuit breaker and timeout
	var data interface{}
	var err error

	// Panic recovery for job processing
	func() {
		defer func() {
			if r := recover(); r != nil {
				atomic.AddInt64(&wp.stats.PanicCount, 1)
				logger.Error("Job processing panicked",
					"job_id", job.ID(),
					"panic", r,
				)
				err = fmt.Errorf("job processing panicked: %v", r)
			}
		}()

		// Execute job with timeout context
		data, err = wp.circuitBreaker.Execute(func() (interface{}, error) {
			return job.Process(timeoutCtx)
		})
	}()

	duration := time.Since(startTime)

	result := Result{
		JobID: job.ID(),
		Data:  data,
		Error: err,
	}

	// Update statistics atomically
	if err != nil {
		atomic.AddInt64(&wp.stats.FailedJobs, 1)
		atomic.AddInt64(&wp.stats.CircuitBreaker.Failures, 1)
	} else {
		atomic.AddInt64(&wp.stats.CompletedJobs, 1)
		atomic.AddInt64(&wp.stats.CircuitBreaker.Successes, 1)
	}

	// Update circuit breaker stats
	cbStats := wp.circuitBreaker.Counts()
	wp.mu.Lock()
	wp.stats.CircuitBreaker.State = wp.circuitBreaker.State().String()
	wp.stats.CircuitBreaker.Failures = int64(cbStats.TotalFailures)
	wp.stats.CircuitBreaker.Successes = int64(cbStats.TotalSuccesses)
	wp.mu.Unlock()

	logger.Debug("Job processed",
		"job_id", job.ID(),
		"duration", duration,
		"success", err == nil,
		"circuit_breaker_state", wp.circuitBreaker.State().String(),
	)

	return result
}

// processJob processes a single job with circuit breaker protection (legacy method)
// Currently unused but kept for backward compatibility
//
//nolint:unused
func (wp *WorkerPool) processJob(job Job, logger *slog.Logger) Result {
	return wp.processJobWithTimeout(job, logger)
}

// resultProcessor handles results from workers
func (wp *WorkerPool) resultProcessor() error {
	atomic.AddInt32(&wp.stats.GoroutineCount, 1)
	defer atomic.AddInt32(&wp.stats.GoroutineCount, -1)

	wp.logger.Debug("Result processor started")
	defer wp.logger.Debug("Result processor stopped")

	for {
		select {
		case result, ok := <-wp.results:
			if !ok {
				wp.logger.Debug("Results channel closed, result processor exiting")
				return nil
			}

			// Log result for monitoring
			if result.Error != nil {
				wp.logger.Error("Job failed",
					"job_id", result.JobID,
					"error", result.Error,
				)
			} else {
				wp.logger.Debug("Job completed successfully",
					"job_id", result.JobID,
				)
			}

		case <-wp.ctx.Done():
			wp.logger.Debug("Context cancelled, result processor exiting")
			return wp.ctx.Err()
		}
	}
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() WorkerPoolStats {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	// Create a copy to avoid race conditions and lock copying
	stats := WorkerPoolStats{
		TotalJobs:      wp.stats.TotalJobs,
		CompletedJobs:  wp.stats.CompletedJobs,
		FailedJobs:     wp.stats.FailedJobs,
		ActiveWorkers:  wp.stats.ActiveWorkers,
		QueuedJobs:     wp.stats.QueuedJobs,
		GoroutineCount: wp.stats.GoroutineCount,
		PanicCount:     wp.stats.PanicCount,
		OrphanedJobs:   wp.stats.OrphanedJobs,
		CircuitBreaker: struct {
			State     string
			Failures  int64
			Successes int64
			Timeouts  int64
		}{
			State:     wp.stats.CircuitBreaker.State,
			Failures:  wp.stats.CircuitBreaker.Failures,
			Successes: wp.stats.CircuitBreaker.Successes,
			Timeouts:  wp.stats.CircuitBreaker.Timeouts,
		},
	}

	return stats
}

// GetCircuitBreakerStats returns circuit breaker statistics
func (wp *WorkerPool) GetCircuitBreakerStats() gobreaker.Counts {
	return wp.circuitBreaker.Counts()
}

// IsHealthy returns true if the worker pool is healthy
func (wp *WorkerPool) IsHealthy() bool {
	stats := wp.GetStats()

	// Consider healthy if:
	// - Circuit breaker is not open
	// - At least one worker is active
	// - Job queue is not completely full
	// - Goroutine count is within limits
	// - No excessive panics
	// - Not shutting down
	return wp.circuitBreaker.State() != gobreaker.StateOpen &&
		stats.ActiveWorkers > 0 &&
		len(wp.jobs) < cap(wp.jobs) &&
		stats.GoroutineCount < wp.config.MaxGoroutines &&
		stats.PanicCount < 100 && // Allow some panics but not excessive
		atomic.LoadInt32(&wp.shutdown) == 0
}

// MonitorGoroutines starts a goroutine monitoring routine
func (wp *WorkerPool) MonitorGoroutines() {
	go func() {
		atomic.AddInt32(&wp.stats.GoroutineCount, 1)
		defer atomic.AddInt32(&wp.stats.GoroutineCount, -1)

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				stats := wp.GetStats()
				if stats.GoroutineCount > wp.config.MaxGoroutines {
					wp.logger.Error("Goroutine limit exceeded",
						"current", stats.GoroutineCount,
						"limit", wp.config.MaxGoroutines,
					)
				}

				if stats.PanicCount > 0 {
					wp.logger.Warn("Panic count detected",
						"panic_count", stats.PanicCount,
					)
				}

			case <-wp.ctx.Done():
				wp.logger.Debug("Goroutine monitor stopped")
				return
			}
		}
	}()
}
