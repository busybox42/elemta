package queue

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/logging"
)

// ProcessorConfig holds configuration for the queue processor
type ProcessorConfig struct {
	Enabled       bool          `json:"enabled" yaml:"enabled" toml:"enabled"`
	Interval      time.Duration `json:"interval" yaml:"interval" toml:"interval"`
	MaxConcurrent int           `json:"max_concurrent" yaml:"max_concurrent" toml:"max_concurrent"`
	MaxRetries    int           `json:"max_retries" yaml:"max_retries" toml:"max_retries"`
	RetrySchedule []int         `json:"retry_schedule" yaml:"retry_schedule" toml:"retry_schedule"`
	CleanupAge    time.Duration `json:"cleanup_age" yaml:"cleanup_age" toml:"cleanup_age"`
}

// DefaultProcessorConfig returns sensible defaults
func DefaultProcessorConfig() ProcessorConfig {
	return ProcessorConfig{
		Enabled:       true,
		Interval:      10 * time.Second,
		MaxConcurrent: 5,
		MaxRetries:    5,
		RetrySchedule: []int{60, 300, 900, 3600, 10800, 21600}, // 1m, 5m, 15m, 1h, 3h, 6h
		CleanupAge:    24 * time.Hour,
	}
}

// DeliveryHandler defines the interface for actual message delivery
// DeliveryResult contains metadata about a delivery attempt
type DeliveryResult struct {
	Success         bool
	Error           error
	DeliveryIP      string
	DeliveryHost    string
	DeliveryTime    time.Time
	ResponseMessage string
}

type DeliveryHandler interface {
	DeliverMessage(ctx context.Context, msg Message, content []byte) error
	DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error)
}

// MetricsRecorder interface for recording delivery metrics
type MetricsRecorder interface {
	IncrDelivered(ctx context.Context) error
	IncrFailed(ctx context.Context) error
	IncrDeferred(ctx context.Context) error
	AddRecentError(ctx context.Context, messageID, recipient, errorMsg string) error
}

// Processor orchestrates queue processing and delivery
type Processor struct {
	manager   *Manager
	config    ProcessorConfig
	handler   DeliveryHandler
	logger    *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	workerSem chan struct{}

	// Metrics
	metricsLock     sync.RWMutex
	processedCount  int64
	deliveredCount  int64
	failedCount     int64
	retryCount      int64
	metricsRecorder MetricsRecorder

	// New field for processing messages
	processingMessages map[string]bool

	// Message lifecycle logger
	msgLogger *logging.MessageLogger
}

// NewProcessor creates a new queue processor
func NewProcessor(manager *Manager, config ProcessorConfig, handler DeliveryHandler) *Processor {
	ctx, cancel := context.WithCancel(context.Background())

	baseLogger := slog.Default().With("component", "queue-processor")
	return &Processor{
		manager:            manager,
		config:             config,
		handler:            handler,
		logger:             baseLogger,
		ctx:                ctx,
		cancel:             cancel,
		workerSem:          make(chan struct{}, config.MaxConcurrent),
		processingMessages: make(map[string]bool),
		msgLogger:          logging.NewMessageLogger(baseLogger),
	}
}

// SetMetricsRecorder sets the metrics recorder for the processor
func (p *Processor) SetMetricsRecorder(recorder MetricsRecorder) {
	p.metricsRecorder = recorder
}

// Start begins processing queues
func (p *Processor) Start() error {
	if !p.config.Enabled {
		p.logger.Info("Queue processor disabled, not starting")
		return nil
	}

	p.logger.Info("Starting queue processor",
		"interval", p.config.Interval,
		"max_concurrent", p.config.MaxConcurrent,
		"max_retries", p.config.MaxRetries)

	// Start active queue processor
	p.wg.Add(1)
	go p.processActiveQueue()

	// Start deferred queue processor
	p.wg.Add(1)
	go p.processDeferredQueue()

	// Start cleanup processor
	p.wg.Add(1)
	go p.processCleanup()

	// Start metrics reporter
	p.wg.Add(1)
	go p.reportMetrics()

	return nil
}

// Stop stops the queue processor
func (p *Processor) Stop() error {
	p.logger.Info("Stopping queue processor")
	p.cancel()
	p.wg.Wait()
	p.logger.Info("Queue processor stopped")
	return nil
}

// processActiveQueue continuously processes messages in the active queue
func (p *Processor) processActiveQueue() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.processQueue(Active); err != nil {
				p.logger.Error("Failed to process active queue", "error", err)
			}
		}
	}
}

// processDeferredQueue moves ready deferred messages back to active queue
func (p *Processor) processDeferredQueue() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.Interval * 2) // Check less frequently
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.processDeferredMessages(); err != nil {
				p.logger.Error("Failed to process deferred queue", "error", err)
			}
		}
	}
}

// processCleanup periodically cleans up old messages
func (p *Processor) processCleanup() {
	defer p.wg.Done()

	ticker := time.NewTicker(time.Hour) // Cleanup hourly
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			retentionHours := int(p.config.CleanupAge.Hours())
			deleted, err := p.manager.CleanupExpiredMessages(retentionHours)
			if err != nil {
				p.logger.Error("Cleanup failed", "error", err)
			} else if deleted > 0 {
				p.logger.Info("Cleanup completed", "deleted", deleted)
			}
		}
	}
}

// reportMetrics periodically logs processing metrics
func (p *Processor) reportMetrics() {
	defer p.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.logMetrics()
		}
	}
}

// processQueue processes messages in a specific queue
func (p *Processor) processQueue(queueType QueueType) error {
	messages, err := p.manager.ListMessages(queueType)
	if err != nil {
		return fmt.Errorf("failed to list messages: %w", err)
	}

	// Process messages with concurrency control
	for _, msg := range messages {
		select {
		case <-p.ctx.Done():
			return nil
		case p.workerSem <- struct{}{}: // Acquire worker
			// Check if we're already processing this message
			p.manager.mutex.Lock()
			if _, exists := p.processingMessages[msg.ID]; exists {
				p.manager.mutex.Unlock()
				<-p.workerSem // Release worker
				continue
			}
			p.processingMessages[msg.ID] = true
			p.manager.mutex.Unlock()

			p.wg.Add(1)
			go p.processMessage(msg)
		}
	}

	return nil
}

// processMessage processes a single message
func (p *Processor) processMessage(msg Message) {
	defer func() {
		<-p.workerSem // Release worker

		// Remove from processing messages
		p.manager.mutex.Lock()
		delete(p.processingMessages, msg.ID)
		p.manager.mutex.Unlock()

		p.wg.Done()
	}()

	// Increment processed count
	p.metricsLock.Lock()
	p.processedCount++
	p.metricsLock.Unlock()

	logger := p.logger.With(
		"message_id", msg.ID,
		"from", msg.From,
		"to", msg.To,
		"retry_count", msg.RetryCount,
	)

	logger.Debug("Processing message")
	startTime := time.Now()

	// Get message content
	content, err := p.manager.GetMessageContent(msg.ID)
	if err != nil {
		logger.Error("Failed to get message content", "error", err)
		p.moveToFailed(msg, fmt.Sprintf("Failed to read content: %v", err))
		return
	}

	// Attempt delivery
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Minute)
	defer cancel()

	deliveryResult, deliveryErr := p.handler.DeliverMessageWithMetadata(ctx, msg, content)

	if deliveryErr == nil && deliveryResult != nil && deliveryResult.Success {
		// Success - Log comprehensive delivery success with delivery IP
		p.msgLogger.LogDelivery(logging.MessageContext{
			MessageID:      msg.ID,
			QueueID:        msg.ID,
			From:           msg.From,
			To:             msg.To,
			Subject:        msg.Subject,
			Size:           msg.Size,
			ReceptionTime:  msg.ReceivedAt,
			ProcessingTime: msg.CreatedAt,
			DeliveryTime:   deliveryResult.DeliveryTime,
			DeliveryIP:     deliveryResult.DeliveryIP,
			DeliveryHost:   deliveryResult.DeliveryHost,
			RetryCount:     msg.RetryCount,
			DeliveryMethod: "lmtp",
		})

		p.metricsLock.Lock()
		p.deliveredCount++
		p.metricsLock.Unlock()

		// Record to external metrics store (Valkey)
		if p.metricsRecorder != nil {
			if err := p.metricsRecorder.IncrDelivered(p.ctx); err != nil {
				logger.Debug("Failed to record delivered metric", "error", err)
			}
		}

		// Record successful attempt (ignore error if message already deleted)
		if err := p.manager.AddAttempt(msg.ID, "delivered", ""); err != nil {
			logger.Debug("Could not record successful attempt (message may already be deleted)", "error", err)
		}

		// Delete successful message
		if err := p.manager.DeleteMessage(msg.ID); err != nil {
			logger.Debug("Could not delete delivered message (may already be deleted)", "error", err)
		}

		return
	}

	// Delivery failed - determine if it's a tempfail or permanent failure
	isTemporary := p.isTemporaryFailure(deliveryErr)

	if isTemporary {
		// Log temporary failure (will retry)
		p.msgLogger.LogTempFail(logging.MessageContext{
			MessageID:      msg.ID,
			QueueID:        msg.ID,
			From:           msg.From,
			To:             msg.To,
			Subject:        msg.Subject,
			Size:           msg.Size,
			ReceptionTime:  msg.ReceivedAt,
			ProcessingTime: msg.CreatedAt,
			RetryCount:     msg.RetryCount,
			Error:          deliveryErr.Error(),
			DeliveryMethod: "lmtp",
		})
	} else {
		// Log permanent failure
		logger.Error("message_bounced",
			"event_type", "bounce",
			"message_id", msg.ID,
			"from_envelope", msg.From,
			"to_envelope", msg.To,
			"message_subject", msg.Subject,
			"message_size", msg.Size,
			"delivery_method", "lmtp",
			"retry_count", msg.RetryCount,
			"error", deliveryErr.Error(),
			"status", "permanent_failure",
			"processing_time_ms", time.Since(startTime).Milliseconds(),
		)
	}

	p.metricsLock.Lock()
	p.retryCount++
	p.metricsLock.Unlock()

	// Record failed attempt (ignore error if message state changed)
	if err := p.manager.AddAttempt(msg.ID, "failed", deliveryErr.Error()); err != nil {
		logger.Debug("Could not record failed attempt (message may have changed state)", "error", err)
	}

	// Permanent failures go directly to failed queue
	if !isTemporary {
		p.moveToFailed(msg, fmt.Sprintf("Permanent failure: %v", deliveryErr))
		return
	}

	// For temporary failures, check if we should retry or give up
	if msg.RetryCount >= p.config.MaxRetries {
		p.moveToFailed(msg, fmt.Sprintf("Max retries exceeded: %v", deliveryErr))
		return
	}

	// Move to deferred queue for retry (temporary failures only)
	if err := p.manager.MoveMessage(msg.ID, Deferred, deliveryErr.Error()); err != nil {
		logger.Error("Failed to move message to deferred queue", "error", err)
	} else {
		// Record deferred to external metrics store (Valkey)
		if p.metricsRecorder != nil {
			if err := p.metricsRecorder.IncrDeferred(p.ctx); err != nil {
				logger.Debug("Failed to record deferred metric", "error", err)
			}
		}
		// Log deferral with timing information
		p.msgLogger.LogDeferral(logging.MessageContext{
			MessageID:      msg.ID,
			QueueID:        msg.ID,
			From:           msg.From,
			To:             msg.To,
			Subject:        msg.Subject,
			Size:           msg.Size,
			ReceptionTime:  msg.ReceivedAt,
			ProcessingTime: msg.CreatedAt,
			NextRetry:      msg.NextRetry,
			RetryCount:     msg.RetryCount,
			Error:          deliveryErr.Error(),
			DeliveryMethod: "lmtp",
		})
	}
}

// processDeferredMessages checks deferred messages and moves ready ones to active
func (p *Processor) processDeferredMessages() error {
	messages, err := p.manager.ListMessages(Deferred)
	if err != nil {
		return fmt.Errorf("failed to list deferred messages: %w", err)
	}

	now := time.Now()
	moved := 0

	for _, msg := range messages {
		if !msg.NextRetry.IsZero() && now.After(msg.NextRetry) {
			if err := p.manager.MoveMessage(msg.ID, Active, "Retry time reached"); err != nil {
				p.logger.Error("Failed to move deferred message to active",
					"message_id", msg.ID,
					"error", err)
			} else {
				moved++
			}
		}
	}

	if moved > 0 {
		p.logger.Info("Moved deferred messages to active queue", "count", moved)
	}

	return nil
}

// moveToFailed moves a message to the failed queue
func (p *Processor) moveToFailed(msg Message, reason string) {
	p.metricsLock.Lock()
	p.failedCount++
	p.metricsLock.Unlock()

	// Record to external metrics store (Valkey)
	if p.metricsRecorder != nil {
		if err := p.metricsRecorder.IncrFailed(p.ctx); err != nil {
			p.logger.Debug("Failed to record failed metric", "error", err)
		}
		// Record the error details
		recipient := ""
		if len(msg.To) > 0 {
			recipient = strings.Join(msg.To, ", ")
		}
		if err := p.metricsRecorder.AddRecentError(p.ctx, msg.ID, recipient, reason); err != nil {
			p.logger.Debug("Failed to record error details", "error", err)
		}
	}

	// Log comprehensive bounce information
	p.msgLogger.LogBounce(logging.MessageContext{
		MessageID:      msg.ID,
		QueueID:        msg.ID,
		From:           msg.From,
		To:             msg.To,
		Subject:        msg.Subject,
		Size:           msg.Size,
		ReceptionTime:  msg.ReceivedAt,
		ProcessingTime: msg.CreatedAt,
		RetryCount:     msg.RetryCount,
		Error:          reason,
		DeliveryMethod: "lmtp",
	})

	if err := p.manager.MoveMessage(msg.ID, Failed, reason); err != nil {
		p.logger.Error("Failed to move message to failed queue",
			"message_id", msg.ID,
			"error", err)
	}
}

// isTemporaryFailure determines if a delivery error is temporary (4xx) or permanent (5xx)
func (p *Processor) isTemporaryFailure(err error) bool {
	if err == nil {
		return false
	}

	// Check for explicit temporary error interface
	if tempErr, ok := err.(interface{ Temporary() bool }); ok && tempErr.Temporary() {
		return true
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	// Check for explicit 4xx SMTP response codes
	// These indicate temporary failures that should be retried
	if strings.Contains(errStr, " 452") || // Insufficient system storage
		strings.Contains(errStr, " 450") || // Mailbox unavailable
		strings.Contains(errStr, " 451") || // Local error in processing
		strings.Contains(errStr, " 421") || // Service not available
		strings.Contains(errStr, " 454") || // Temporary authentication failure
		strings.HasPrefix(errStr, "452") ||
		strings.HasPrefix(errStr, "450") ||
		strings.HasPrefix(errStr, "451") ||
		strings.HasPrefix(errStr, "421") ||
		strings.HasPrefix(errStr, "454") {
		return true
	}

	// Check for common temporary failure patterns
	tempPatterns := []string{
		"temporary",
		"try again",
		"busy",
		"throttled",
		"rate limit",
		"connection timeout",
		"network error",
		"dns",
		"insufficient system storage",
		"mailbox unavailable",
		"local error",
		"service not available",
	}

	for _, pattern := range tempPatterns {
		if strings.Contains(errLower, pattern) {
			return true
		}
	}

	// Check for 5xx codes which are permanent failures
	if strings.Contains(errStr, "550 ") || // Mailbox unavailable (permanent)
		strings.Contains(errStr, "551 ") || // User not local
		strings.Contains(errStr, "552 ") || // Exceeded storage allocation
		strings.Contains(errStr, "553 ") || // Mailbox name not allowed
		strings.Contains(errStr, "554 ") { // Transaction failed
		return false
	}

	// Default to permanent failure for unknown errors
	return false
}

// logMetrics logs current processing metrics
func (p *Processor) logMetrics() {
	p.metricsLock.RLock()
	processed := p.processedCount
	delivered := p.deliveredCount
	failed := p.failedCount
	retries := p.retryCount
	p.metricsLock.RUnlock()

	stats := p.manager.GetStats()

	p.logger.Info("Queue processor metrics",
		"processed_total", processed,
		"delivered_total", delivered,
		"failed_total", failed,
		"retries_total", retries,
		"active_count", stats.ActiveCount,
		"deferred_count", stats.DeferredCount,
		"hold_count", stats.HoldCount,
		"failed_count", stats.FailedCount,
		"total_size_bytes", stats.TotalSize)
}

// GetMetrics returns current processor metrics
func (p *Processor) GetMetrics() ProcessorMetrics {
	p.metricsLock.RLock()
	defer p.metricsLock.RUnlock()

	return ProcessorMetrics{
		ProcessedTotal: p.processedCount,
		DeliveredTotal: p.deliveredCount,
		FailedTotal:    p.failedCount,
		RetryTotal:     p.retryCount,
		QueueStats:     p.manager.GetStats(),
	}
}

// ProcessorMetrics holds processor performance metrics
type ProcessorMetrics struct {
	ProcessedTotal int64      `json:"processed_total"`
	DeliveredTotal int64      `json:"delivered_total"`
	FailedTotal    int64      `json:"failed_total"`
	RetryTotal     int64      `json:"retry_total"`
	QueueStats     QueueStats `json:"queue_stats"`
}
