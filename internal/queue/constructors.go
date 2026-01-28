package queue

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// NewDeliveryManager creates a new delivery manager
func NewDeliveryManager(queueManager QueueManager, config QueueConfiguration) DeliveryManager {
	return &SimpleDeliveryManager{
		queueManager: queueManager,
		config:       config,
		logger:       slog.Default().With("component", "delivery"),
		hooks:        make([]DeliveryHook, 0),
		rateLimiters: make(map[string]*RateLimiter),
		running:      false,
	}
}

// NewProcessorManager creates a new processor manager
func NewProcessorManager(queueManager QueueManager, deliveryManager DeliveryManager, config QueueConfiguration) ProcessorManager {
	return &SimpleProcessorManager{
		queueManager:    queueManager,
		deliveryManager: deliveryManager,
		config:          config,
		logger:          slog.Default().With("component", "processor"),
		running:         false,
	}
}

// NewMonitoringBackend creates a new monitoring backend
func NewMonitoringBackend() MonitoringBackend {
	return &SimpleMonitoringBackend{
		stats:   DeliveryStats{},
		logger:  slog.Default().With("component", "monitoring"),
		healthy: true,
	}
}

// SimpleDeliveryManager implements DeliveryManager
type SimpleDeliveryManager struct {
	queueManager QueueManager
	config       QueueConfiguration
	logger       *slog.Logger
	hooks        []DeliveryHook
	rateLimiters map[string]*RateLimiter
	rateMutex    sync.RWMutex
	running      bool
	stopCh       chan struct{}
}

// ProcessQueue processes messages in a specific queue
func (dm *SimpleDeliveryManager) ProcessQueue(ctx context.Context, queueType QueueType) error {
	messages, err := dm.queueManager.ListMessages(queueType)
	if err != nil {
		return fmt.Errorf("failed to list messages: %w", err)
	}

	for _, msg := range messages {
		if err := dm.DeliverMessage(ctx, msg); err != nil {
			dm.logger.Error("Failed to deliver message", "id", msg.ID, "error", err)
		}
	}

	return nil
}

// DeliverMessage delivers a single message
func (dm *SimpleDeliveryManager) DeliverMessage(ctx context.Context, msg Message) error {
	// This is a simplified implementation
	// In a real implementation, this would handle SMTP delivery
	dm.logger.Info("Delivering message", "id", msg.ID, "from", msg.From, "to", msg.To)

	// Simulate delivery
	time.Sleep(100 * time.Millisecond)

	// Mark as delivered
	return dm.queueManager.MoveMessage(msg.ID, Failed, "Delivered successfully")
}

// SetMaxConcurrent sets the maximum concurrent deliveries
func (dm *SimpleDeliveryManager) SetMaxConcurrent(count int) {
	dm.config.MaxConcurrent = count
}

// SetRetrySchedule sets the retry schedule
func (dm *SimpleDeliveryManager) SetRetrySchedule(schedule []int) {
	dm.config.RetrySchedule = schedule
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (dm *SimpleDeliveryManager) GetFailedQueueRetentionHours() int {
	// Default to 0 (immediate deletion) if not set
	if dm.config.FailedQueueRetentionHours < 0 {
		return 0
	}
	return dm.config.FailedQueueRetentionHours
}

// AddDeliveryHook adds a delivery hook
func (dm *SimpleDeliveryManager) AddDeliveryHook(hook DeliveryHook) {
	dm.hooks = append(dm.hooks, hook)
}

// AcquireRateLimit attempts to acquire a rate limit token
func (dm *SimpleDeliveryManager) AcquireRateLimit(domain string) bool {
	if !dm.config.RateLimitEnabled {
		return true
	}

	dm.rateMutex.Lock()
	defer dm.rateMutex.Unlock()

	limiter, exists := dm.rateLimiters[domain]
	if !exists {
		limiter = &RateLimiter{
			Limit:     dm.config.RateLimitPerDomain,
			Tokens:    dm.config.RateLimitPerDomain,
			LastReset: time.Now(),
			Interval:  time.Duration(dm.config.RateLimitWindow) * time.Second,
		}
		dm.rateLimiters[domain] = limiter
	}

	// Reset tokens if interval has passed
	if time.Since(limiter.LastReset) > limiter.Interval {
		limiter.Tokens = limiter.Limit
		limiter.LastReset = time.Now()
	}

	if limiter.Tokens > 0 {
		limiter.Tokens--
		return true
	}

	return false
}

// ReleaseRateLimit releases a rate limit token
func (dm *SimpleDeliveryManager) ReleaseRateLimit(domain string) {
	// In this simple implementation, tokens are automatically restored
	// by the interval reset mechanism
}

// Start starts the delivery manager
func (dm *SimpleDeliveryManager) Start() error {
	dm.running = true
	dm.stopCh = make(chan struct{})
	dm.logger.Info("Delivery manager started")
	return nil
}

// Stop stops the delivery manager
func (dm *SimpleDeliveryManager) Stop() error {
	dm.running = false
	if dm.stopCh != nil {
		close(dm.stopCh)
	}
	dm.logger.Info("Delivery manager stopped")
	return nil
}

// RateLimiter represents a rate limiter for a domain
type RateLimiter struct {
	Limit     int
	Tokens    int
	LastReset time.Time
	Interval  time.Duration
}

// SimpleProcessorManager implements ProcessorManager
type SimpleProcessorManager struct {
	queueManager    QueueManager
	deliveryManager DeliveryManager
	config          QueueConfiguration
	logger          *slog.Logger
	running         bool
	stopCh          chan struct{}
}

// Start starts the processor manager
func (pm *SimpleProcessorManager) Start() error {
	pm.running = true
	pm.stopCh = make(chan struct{})

	// Start processing goroutines
	go pm.processLoop()

	pm.logger.Info("Processor manager started")
	return nil
}

// Stop stops the processor manager
func (pm *SimpleProcessorManager) Stop() error {
	pm.running = false
	if pm.stopCh != nil {
		close(pm.stopCh)
	}
	pm.logger.Info("Processor manager stopped")
	return nil
}

// processLoop is the main processing loop
func (pm *SimpleProcessorManager) processLoop() {
	ticker := time.NewTicker(time.Duration(pm.config.ProcessInterval) * time.Second)
	defer ticker.Stop()

	for pm.running {
		select {
		case <-ticker.C:
			ctx := context.Background()
			if err := pm.ProcessAllQueues(ctx); err != nil {
				pm.logger.Error("Failed to process queues", "error", err)
			}
		case <-pm.stopCh:
			return
		}
	}
}

// SetEnabled enables or disables processing
func (pm *SimpleProcessorManager) SetEnabled(enabled bool) {
	pm.config.Enabled = enabled
}

// SetInterval sets the processing interval
func (pm *SimpleProcessorManager) SetInterval(interval time.Duration) {
	pm.config.ProcessInterval = int(interval.Seconds())
}

// SetMaxWorkers sets the maximum number of workers
func (pm *SimpleProcessorManager) SetMaxWorkers(count int) {
	pm.config.MaxWorkers = count
}

// ProcessAllQueues processes all queue types
func (pm *SimpleProcessorManager) ProcessAllQueues(ctx context.Context) error {
	if !pm.config.Enabled {
		return nil
	}

	// Process active queue first
	if err := pm.ProcessActiveQueue(ctx); err != nil {
		pm.logger.Error("Failed to process active queue", "error", err)
	}

	// Then process deferred queue
	if err := pm.ProcessDeferredQueue(ctx); err != nil {
		pm.logger.Error("Failed to process deferred queue", "error", err)
	}

	return nil
}

// ProcessActiveQueue processes the active queue
func (pm *SimpleProcessorManager) ProcessActiveQueue(ctx context.Context) error {
	return pm.deliveryManager.ProcessQueue(ctx, Active)
}

// ProcessDeferredQueue processes the deferred queue
func (pm *SimpleProcessorManager) ProcessDeferredQueue(ctx context.Context) error {
	// Check for messages ready for retry
	messages, err := pm.queueManager.ListMessages(Deferred)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, msg := range messages {
		// Check if message is ready for retry
		if !msg.NextRetry.IsZero() && msg.NextRetry.Before(now) {
			// Move back to active queue
			if err := pm.queueManager.MoveMessage(msg.ID, Active, "Retry attempt"); err != nil {
				pm.logger.Error("Failed to move message for retry", "id", msg.ID, "error", err)
			}
		}
	}

	return nil
}

// RunCleanup runs cleanup operations
func (pm *SimpleProcessorManager) RunCleanup() error {
	if pm.config.RetentionHours > 0 {
		deleted, err := pm.queueManager.CleanupExpiredMessages(pm.config.RetentionHours)
		if err != nil {
			return err
		}
		pm.logger.Info("Cleanup completed", "deleted", deleted)
	}
	return nil
}

// SimpleMonitoringBackend implements MonitoringBackend
type SimpleMonitoringBackend struct {
	stats   DeliveryStats
	logger  *slog.Logger
	healthy bool
	mutex   sync.RWMutex
}

// RecordMessageEnqueued records a message being enqueued
func (mb *SimpleMonitoringBackend) RecordMessageEnqueued(queueType QueueType, priority Priority) {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()
	mb.stats.TotalProcessed++
}

// RecordMessageDelivered records a successful delivery
func (mb *SimpleMonitoringBackend) RecordMessageDelivered(messageID string, duration time.Duration) {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()
	mb.stats.TotalDelivered++
	mb.stats.LastProcessed = time.Now()
}

// RecordMessageFailed records a failed delivery
func (mb *SimpleMonitoringBackend) RecordMessageFailed(messageID string, reason string) {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()
	mb.stats.TotalFailed++
}

// RecordMessageDeferred records a deferred delivery
func (mb *SimpleMonitoringBackend) RecordMessageDeferred(messageID string, retryCount int) {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()
	mb.stats.TotalDeferred++
}

// GetDeliveryStats returns current delivery statistics
func (mb *SimpleMonitoringBackend) GetDeliveryStats() DeliveryStats {
	mb.mutex.RLock()
	defer mb.mutex.RUnlock()
	return mb.stats
}

// GetQueueDepth returns the depth of a specific queue
func (mb *SimpleMonitoringBackend) GetQueueDepth(queueType QueueType) int {
	// This would require access to the queue manager
	// For now, return 0
	return 0
}

// GetProcessingRate returns the processing rate
func (mb *SimpleMonitoringBackend) GetProcessingRate() float64 {
	mb.mutex.RLock()
	defer mb.mutex.RUnlock()
	// Simple calculation - messages per minute
	return float64(mb.stats.TotalProcessed)
}

// IsHealthy returns whether the monitoring system is healthy
func (mb *SimpleMonitoringBackend) IsHealthy() bool {
	mb.mutex.RLock()
	defer mb.mutex.RUnlock()
	return mb.healthy
}

// GetLastError returns the last error encountered
func (mb *SimpleMonitoringBackend) GetLastError() error {
	// For this simple implementation, return nil
	return nil
}
