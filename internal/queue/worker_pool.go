package queue

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"github.com/sony/gobreaker"
)

// QueueJob represents a queue processing job
type QueueJob struct {
	id        string
	message   *Message
	processor func(ctx context.Context, msg *Message) error
	priority  int
	createdAt time.Time
}

func (qj *QueueJob) Process(ctx context.Context) (interface{}, error) {
	return nil, qj.processor(ctx, qj.message)
}

func (qj *QueueJob) ID() string {
	return qj.id
}

func (qj *QueueJob) Priority() int {
	return qj.priority
}

// QueueWorkerPool manages queue processing with standardized concurrency patterns
type QueueWorkerPool struct {
	size           int
	jobs           chan QueueJob
	results        chan QueueResult
	ctx            context.Context
	cancel         context.CancelFunc
	errGroup       *errgroup.Group
	circuitBreaker *gobreaker.CircuitBreaker
	logger         *slog.Logger
	stats          *QueueWorkerStats
	mu             sync.RWMutex
}

// QueueResult represents the result of processing a queue job
type QueueResult struct {
	JobID     string
	MessageID string
	Success   bool
	Error     error
	Duration  time.Duration
}

// QueueWorkerStats tracks queue worker performance
type QueueWorkerStats struct {
	TotalJobs      int64
	CompletedJobs  int64
	FailedJobs     int64
	ActiveWorkers  int32
	QueuedJobs     int32
	ProcessingTime struct {
		Average time.Duration
		Min     time.Duration
		Max     time.Duration
		Total   time.Duration
	}
	CircuitBreaker struct {
		State     string
		Failures  int64
		Successes int64
	}
	mu sync.RWMutex
}

// QueueWorkerConfig configures the queue worker pool
type QueueWorkerConfig struct {
	Size                int
	JobBufferSize       int
	ResultBufferSize    int
	CircuitBreakerName  string
	MaxRequests         uint32
	Interval            time.Duration
	Timeout             time.Duration
	RetryAttempts       int
	RetryDelay          time.Duration
}

// DefaultQueueWorkerConfig returns default configuration for queue workers
func DefaultQueueWorkerConfig() *QueueWorkerConfig {
	return &QueueWorkerConfig{
		Size:               5,  // Conservative default for queue processing
		JobBufferSize:      50,
		ResultBufferSize:   50,
		CircuitBreakerName: "queue-processor",
		MaxRequests:        50,
		Interval:           time.Minute,
		Timeout:            60 * time.Second, // Longer timeout for mail delivery
		RetryAttempts:      3,
		RetryDelay:         5 * time.Second,
	}
}

// NewQueueWorkerPool creates a new queue worker pool
func NewQueueWorkerPool(config *QueueWorkerConfig, logger *slog.Logger) *QueueWorkerPool {
	if config == nil {
		config = DefaultQueueWorkerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	g, gctx := errgroup.WithContext(ctx)

	// Configure circuit breaker for queue processing
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        config.CircuitBreakerName,
		MaxRequests: config.MaxRequests,
		Interval:    config.Interval,
		Timeout:     config.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			// More conservative for queue processing - open if 50% fail
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 5 && failureRatio >= 0.5
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Queue circuit breaker state changed",
				"name", name,
				"from", from.String(),
				"to", to.String(),
			)
		},
	})

	return &QueueWorkerPool{
		size:           config.Size,
		jobs:           make(chan QueueJob, config.JobBufferSize),
		results:        make(chan QueueResult, config.ResultBufferSize),
		ctx:            gctx,
		cancel:         cancel,
		errGroup:       g,
		circuitBreaker: cb,
		logger:         logger.With("component", "queue-worker-pool"),
		stats:          &QueueWorkerStats{},
	}
}

// Start initializes and starts all queue workers
func (qwp *QueueWorkerPool) Start() error {
	qwp.logger.Info("Starting queue worker pool",
		"size", qwp.size,
		"job_buffer", cap(qwp.jobs),
		"result_buffer", cap(qwp.results),
	)

	// Start workers
	for i := 0; i < qwp.size; i++ {
		workerID := i
		qwp.errGroup.Go(func() error {
			return qwp.worker(workerID)
		})
	}

	// Start result processor
	qwp.errGroup.Go(qwp.resultProcessor)

	return nil
}

// Stop gracefully shuts down the queue worker pool
func (qwp *QueueWorkerPool) Stop() error {
	qwp.logger.Info("Stopping queue worker pool")
	
	// Close jobs channel to signal workers to stop
	close(qwp.jobs)
	
	// Cancel context
	qwp.cancel()
	
	// Wait for all workers to complete
	err := qwp.errGroup.Wait()
	
	// Close results channel
	close(qwp.results)
	
	qwp.logger.Info("Queue worker pool stopped",
		"final_stats", qwp.GetStats(),
	)
	
	return err
}

// Submit adds a queue job to the worker pool
func (qwp *QueueWorkerPool) Submit(job QueueJob) error {
	select {
	case qwp.jobs <- job:
		qwp.stats.mu.Lock()
		qwp.stats.TotalJobs++
		qwp.stats.QueuedJobs++
		qwp.stats.mu.Unlock()
		return nil
	case <-qwp.ctx.Done():
		return qwp.ctx.Err()
	default:
		return fmt.Errorf("queue worker pool is full")
	}
}

// worker processes queue jobs
func (qwp *QueueWorkerPool) worker(workerID int) error {
	workerLogger := qwp.logger.With("worker_id", workerID)
	workerLogger.Debug("Queue worker started")
	
	qwp.stats.mu.Lock()
	qwp.stats.ActiveWorkers++
	qwp.stats.mu.Unlock()
	
	defer func() {
		qwp.stats.mu.Lock()
		qwp.stats.ActiveWorkers--
		qwp.stats.mu.Unlock()
		workerLogger.Debug("Queue worker stopped")
	}()

	for {
		select {
		case job, ok := <-qwp.jobs:
			if !ok {
				workerLogger.Debug("Jobs channel closed, worker exiting")
				return nil
			}

			qwp.stats.mu.Lock()
			qwp.stats.QueuedJobs--
			qwp.stats.mu.Unlock()

			// Process job with circuit breaker and retry logic
			result := qwp.processJobWithRetry(job, workerLogger)
			
			// Send result
			select {
			case qwp.results <- result:
			case <-qwp.ctx.Done():
				return qwp.ctx.Err()
			default:
				workerLogger.Warn("Results channel full, dropping result",
					"job_id", job.ID(),
					"message_id", job.message.ID,
				)
			}

		case <-qwp.ctx.Done():
			workerLogger.Debug("Context cancelled, queue worker exiting")
			return qwp.ctx.Err()
		}
	}
}

// processJobWithRetry processes a queue job with retry logic and circuit breaker
func (qwp *QueueWorkerPool) processJobWithRetry(job QueueJob, logger *slog.Logger) QueueResult {
	startTime := time.Now()
	
	logger.Debug("Processing queue job",
		"job_id", job.ID(),
		"message_id", job.message.ID,
		"priority", job.Priority(),
		"queue_type", job.message.QueueType,
	)

	var lastErr error
	maxRetries := 3
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			delay := time.Duration(attempt) * 5 * time.Second
			logger.Debug("Retrying queue job",
				"job_id", job.ID(),
				"attempt", attempt+1,
				"delay", delay,
			)
			
			select {
			case <-time.After(delay):
			case <-qwp.ctx.Done():
				break
			}
		}
		
		// Execute job with circuit breaker
		_, err := qwp.circuitBreaker.Execute(func() (interface{}, error) {
			return job.Process(qwp.ctx)
		})
		
		if err == nil {
			// Success
			duration := time.Since(startTime)
			qwp.updateStats(true, duration)
			
			logger.Debug("Queue job completed successfully",
				"job_id", job.ID(),
				"message_id", job.message.ID,
				"duration", duration,
				"attempts", attempt+1,
			)
			
			return QueueResult{
				JobID:     job.ID(),
				MessageID: job.message.ID,
				Success:   true,
				Duration:  duration,
			}
		}
		
		lastErr = err
		
		// Check if we should retry
		if qwp.circuitBreaker.State() == gobreaker.StateOpen {
			logger.Warn("Circuit breaker open, not retrying",
				"job_id", job.ID(),
				"message_id", job.message.ID,
			)
			break
		}
		
		logger.Warn("Queue job attempt failed",
			"job_id", job.ID(),
			"message_id", job.message.ID,
			"attempt", attempt+1,
			"error", err,
		)
	}
	
	// All attempts failed
	duration := time.Since(startTime)
	qwp.updateStats(false, duration)
	
	logger.Error("Queue job failed after all retries",
		"job_id", job.ID(),
		"message_id", job.message.ID,
		"duration", duration,
		"final_error", lastErr,
	)
	
	return QueueResult{
		JobID:     job.ID(),
		MessageID: job.message.ID,
		Success:   false,
		Error:     lastErr,
		Duration:  duration,
	}
}

// updateStats updates worker pool statistics
func (qwp *QueueWorkerPool) updateStats(success bool, duration time.Duration) {
	qwp.stats.mu.Lock()
	defer qwp.stats.mu.Unlock()
	
	if success {
		qwp.stats.CompletedJobs++
		qwp.stats.CircuitBreaker.Successes++
	} else {
		qwp.stats.FailedJobs++
		qwp.stats.CircuitBreaker.Failures++
	}
	
	// Update processing time stats
	qwp.stats.ProcessingTime.Total += duration
	if qwp.stats.ProcessingTime.Min == 0 || duration < qwp.stats.ProcessingTime.Min {
		qwp.stats.ProcessingTime.Min = duration
	}
	if duration > qwp.stats.ProcessingTime.Max {
		qwp.stats.ProcessingTime.Max = duration
	}
	
	totalJobs := qwp.stats.CompletedJobs + qwp.stats.FailedJobs
	if totalJobs > 0 {
		qwp.stats.ProcessingTime.Average = qwp.stats.ProcessingTime.Total / time.Duration(totalJobs)
	}
	
	// Update circuit breaker state
	qwp.stats.CircuitBreaker.State = qwp.circuitBreaker.State().String()
}

// resultProcessor handles results from queue workers
func (qwp *QueueWorkerPool) resultProcessor() error {
	qwp.logger.Debug("Queue result processor started")
	defer qwp.logger.Debug("Queue result processor stopped")

	for {
		select {
		case result, ok := <-qwp.results:
			if !ok {
				qwp.logger.Debug("Results channel closed, result processor exiting")
				return nil
			}

			// Log result for monitoring and metrics
			if result.Success {
				qwp.logger.Info("Queue job completed",
					"job_id", result.JobID,
					"message_id", result.MessageID,
					"duration", result.Duration,
				)
			} else {
				qwp.logger.Error("Queue job failed",
					"job_id", result.JobID,
					"message_id", result.MessageID,
					"duration", result.Duration,
					"error", result.Error,
				)
			}

		case <-qwp.ctx.Done():
			qwp.logger.Debug("Context cancelled, result processor exiting")
			return qwp.ctx.Err()
		}
	}
}

// GetStats returns current queue worker pool statistics
func (qwp *QueueWorkerPool) GetStats() QueueWorkerStats {
	qwp.stats.mu.RLock()
	defer qwp.stats.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	stats := *qwp.stats
	return stats
}

// IsHealthy returns true if the queue worker pool is healthy
func (qwp *QueueWorkerPool) IsHealthy() bool {
	stats := qwp.GetStats()
	
	// Consider healthy if:
	// - Circuit breaker is not open
	// - At least one worker is active
	// - Job queue is not completely full
	return qwp.circuitBreaker.State() != gobreaker.StateOpen &&
		   stats.ActiveWorkers > 0 &&
		   len(qwp.jobs) < cap(qwp.jobs)
}
