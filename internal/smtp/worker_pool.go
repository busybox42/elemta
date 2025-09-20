package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"github.com/sony/gobreaker"
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
	id         string
	conn       interface{}
	handler    func(ctx context.Context, conn interface{}) error
	priority   int
	createdAt  time.Time
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
	size           int
	jobs           chan Job
	results        chan Result
	ctx            context.Context
	cancel         context.CancelFunc
	errGroup       *errgroup.Group
	circuitBreaker *gobreaker.CircuitBreaker
	logger         *slog.Logger
	wg             sync.WaitGroup
	stats          *WorkerPoolStats
	mu             sync.RWMutex
}

// WorkerPoolStats tracks worker pool performance metrics
type WorkerPoolStats struct {
	TotalJobs      int64
	CompletedJobs  int64
	FailedJobs     int64
	ActiveWorkers  int32
	QueuedJobs     int32
	CircuitBreaker struct {
		State     string
		Failures  int64
		Successes int64
		Timeouts  int64
	}
	mu sync.RWMutex
}

// WorkerPoolConfig configures the worker pool behavior
type WorkerPoolConfig struct {
	Size                int
	JobBufferSize       int
	ResultBufferSize    int
	CircuitBreakerName  string
	MaxRequests         uint32
	Interval            time.Duration
	Timeout             time.Duration
	OnStateChange       func(name string, from gobreaker.State, to gobreaker.State)
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

	return nil
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() error {
	wp.logger.Info("Stopping worker pool")
	
	// Close jobs channel to signal workers to stop
	close(wp.jobs)
	
	// Cancel context to ensure all workers exit
	wp.cancel()
	
	// Wait for all workers to complete
	err := wp.errGroup.Wait()
	
	// Close results channel
	close(wp.results)
	
	wp.logger.Info("Worker pool stopped",
		"final_stats", wp.GetStats(),
	)
	
	return err
}

// Submit adds a job to the worker pool queue
func (wp *WorkerPool) Submit(job Job) error {
	select {
	case wp.jobs <- job:
		wp.stats.mu.Lock()
		wp.stats.TotalJobs++
		wp.stats.QueuedJobs++
		wp.stats.mu.Unlock()
		return nil
	case <-wp.ctx.Done():
		return wp.ctx.Err()
	default:
		return fmt.Errorf("worker pool queue is full")
	}
}

// SubmitWithTimeout adds a job to the worker pool queue with a timeout
func (wp *WorkerPool) SubmitWithTimeout(job Job, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(wp.ctx, timeout)
	defer cancel()
	
	select {
	case wp.jobs <- job:
		wp.stats.mu.Lock()
		wp.stats.TotalJobs++
		wp.stats.QueuedJobs++
		wp.stats.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// worker processes jobs from the jobs channel
func (wp *WorkerPool) worker(workerID int) error {
	workerLogger := wp.logger.With("worker_id", workerID)
	workerLogger.Debug("Worker started")
	
	wp.stats.mu.Lock()
	wp.stats.ActiveWorkers++
	wp.stats.mu.Unlock()
	
	defer func() {
		wp.stats.mu.Lock()
		wp.stats.ActiveWorkers--
		wp.stats.mu.Unlock()
		workerLogger.Debug("Worker stopped")
	}()

	for {
		select {
		case job, ok := <-wp.jobs:
			if !ok {
				workerLogger.Debug("Jobs channel closed, worker exiting")
				return nil
			}

			wp.stats.mu.Lock()
			wp.stats.QueuedJobs--
			wp.stats.mu.Unlock()

			// Process job with circuit breaker protection
			result := wp.processJob(job, workerLogger)
			
			// Send result
			select {
			case wp.results <- result:
			case <-wp.ctx.Done():
				return wp.ctx.Err()
			default:
				workerLogger.Warn("Results channel full, dropping result",
					"job_id", job.ID(),
				)
			}

		case <-wp.ctx.Done():
			workerLogger.Debug("Context cancelled, worker exiting")
			return wp.ctx.Err()
		}
	}
}

// processJob processes a single job with circuit breaker protection
func (wp *WorkerPool) processJob(job Job, logger *slog.Logger) Result {
	startTime := time.Now()
	
	logger.Debug("Processing job",
		"job_id", job.ID(),
		"priority", job.Priority(),
	)

	// Execute job with circuit breaker
	data, err := wp.circuitBreaker.Execute(func() (interface{}, error) {
		return job.Process(wp.ctx)
	})

	duration := time.Since(startTime)
	
	result := Result{
		JobID: job.ID(),
		Data:  data,
		Error: err,
	}

	// Update statistics
	wp.stats.mu.Lock()
	if err != nil {
		wp.stats.FailedJobs++
		wp.stats.CircuitBreaker.Failures++
	} else {
		wp.stats.CompletedJobs++
		wp.stats.CircuitBreaker.Successes++
	}
	wp.stats.mu.Unlock()

	// Update circuit breaker stats
	cbStats := wp.circuitBreaker.Counts()
	wp.stats.mu.Lock()
	wp.stats.CircuitBreaker.State = wp.circuitBreaker.State().String()
	wp.stats.CircuitBreaker.Failures = int64(cbStats.TotalFailures)
	wp.stats.CircuitBreaker.Successes = int64(cbStats.TotalSuccesses)
	wp.stats.mu.Unlock()

	logger.Debug("Job processed",
		"job_id", job.ID(),
		"duration", duration,
		"success", err == nil,
		"circuit_breaker_state", wp.circuitBreaker.State().String(),
	)

	return result
}

// resultProcessor handles results from workers
func (wp *WorkerPool) resultProcessor() error {
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
	wp.stats.mu.RLock()
	defer wp.stats.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	stats := *wp.stats
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
	return wp.circuitBreaker.State() != gobreaker.StateOpen &&
		   stats.ActiveWorkers > 0 &&
		   len(wp.jobs) < cap(wp.jobs)
}
