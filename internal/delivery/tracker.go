package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// DeliveryTracker tracks delivery attempts and collects metrics
type DeliveryTracker struct {
	config     *Config
	logger     *slog.Logger
	deliveries map[string]*TrackedDelivery
	mu         sync.RWMutex
	metrics    *TrackerMetrics
}

// TrackedDelivery represents a delivery being tracked
type TrackedDelivery struct {
	ID           string             `json:"id"`
	MessageID    string             `json:"message_id"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      time.Time          `json:"end_time"`
	Status       DeliveryStatus     `json:"status"`
	Attempts     []*DeliveryAttempt `json:"attempts"`
	CurrentRoute *Route             `json:"current_route,omitempty"`
	Result       *DeliveryResult    `json:"result,omitempty"`
	Recipients   []string           `json:"recipients"`
	From         string             `json:"from"`
	Priority     int                `json:"priority"`

	// Progress tracking
	TotalRecipients      int `json:"total_recipients"`
	ProcessedRecipients  int `json:"processed_recipients"`
	SuccessfulRecipients int `json:"successful_recipients"`
	FailedRecipients     int `json:"failed_recipients"`

	// Error tracking
	LastError           error `json:"last_error,omitempty"`
	ErrorCount          int   `json:"error_count"`
	ConsecutiveFailures int   `json:"consecutive_failures"`

	// Timing
	QueueTime      time.Duration `json:"queue_time"`
	ProcessingTime time.Duration `json:"processing_time"`
	DeliveryTime   time.Duration `json:"delivery_time"`
	TotalTime      time.Duration `json:"total_time"`

	// Connection details
	ConnectionInfo *ConnectionInfo `json:"connection_info,omitempty"`

	// Metadata
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// TrackerMetrics tracks overall delivery statistics
type TrackerMetrics struct {
	mu                  sync.RWMutex
	TotalDeliveries     int64 `json:"total_deliveries"`
	ActiveDeliveries    int64 `json:"active_deliveries"`
	CompletedDeliveries int64 `json:"completed_deliveries"`
	FailedDeliveries    int64 `json:"failed_deliveries"`
	RetryingDeliveries  int64 `json:"retrying_deliveries"`
	CancelledDeliveries int64 `json:"cancelled_deliveries"`

	// Timing statistics
	AverageDeliveryTime time.Duration `json:"average_delivery_time"`
	MinDeliveryTime     time.Duration `json:"min_delivery_time"`
	MaxDeliveryTime     time.Duration `json:"max_delivery_time"`
	AverageQueueTime    time.Duration `json:"average_queue_time"`

	// Success rates
	SuccessRate float64 `json:"success_rate"`
	RetryRate   float64 `json:"retry_rate"`

	// Error statistics
	TotalErrors      int64 `json:"total_errors"`
	ConnectionErrors int64 `json:"connection_errors"`
	DNSErrors        int64 `json:"dns_errors"`
	SMTPErrors       int64 `json:"smtp_errors"`
	TLSErrors        int64 `json:"tls_errors"`
	TimeoutErrors    int64 `json:"timeout_errors"`

	// Recipients statistics
	TotalRecipients      int64 `json:"total_recipients"`
	SuccessfulRecipients int64 `json:"successful_recipients"`
	FailedRecipients     int64 `json:"failed_recipients"`

	// By priority
	CriticalDeliveries int64 `json:"critical_deliveries"`
	HighDeliveries     int64 `json:"high_deliveries"`
	NormalDeliveries   int64 `json:"normal_deliveries"`
	LowDeliveries      int64 `json:"low_deliveries"`
	BulkDeliveries     int64 `json:"bulk_deliveries"`

	// Hourly statistics
	HourlyStats map[int]*HourlyMetrics   `json:"hourly_stats"`
	DailyStats  map[string]*DailyMetrics `json:"daily_stats"`
}

// HourlyMetrics tracks metrics for each hour
type HourlyMetrics struct {
	Hour                int           `json:"hour"`
	Deliveries          int64         `json:"deliveries"`
	Successes           int64         `json:"successes"`
	Failures            int64         `json:"failures"`
	AverageDeliveryTime time.Duration `json:"average_delivery_time"`
}

// DailyMetrics tracks metrics for each day
type DailyMetrics struct {
	Date                string        `json:"date"`
	Deliveries          int64         `json:"deliveries"`
	Successes           int64         `json:"successes"`
	Failures            int64         `json:"failures"`
	AverageDeliveryTime time.Duration `json:"average_delivery_time"`
	UniqueRecipients    int64         `json:"unique_recipients"`
	UniqueFromAddresses int64         `json:"unique_from_addresses"`
}

// NewDeliveryTracker creates a new delivery tracker
func NewDeliveryTracker(config *Config) *DeliveryTracker {
	return &DeliveryTracker{
		config:     config,
		logger:     slog.Default().With("component", "delivery-tracker"),
		deliveries: make(map[string]*TrackedDelivery),
		metrics: &TrackerMetrics{
			HourlyStats: make(map[int]*HourlyMetrics),
			DailyStats:  make(map[string]*DailyMetrics),
		},
	}
}

// StartDelivery begins tracking a new delivery
func (dt *DeliveryTracker) StartDelivery(msg *Message) string {
	deliveryID := fmt.Sprintf("del_%d", time.Now().UnixNano())

	tracked := &TrackedDelivery{
		ID:              deliveryID,
		MessageID:       msg.ID,
		StartTime:       time.Now(),
		Status:          StatusPending,
		Attempts:        make([]*DeliveryAttempt, 0),
		Recipients:      msg.To,
		From:            msg.From,
		Priority:        msg.Priority,
		TotalRecipients: len(msg.To),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	dt.mu.Lock()
	dt.deliveries[deliveryID] = tracked
	dt.metrics.TotalDeliveries++
	dt.metrics.ActiveDeliveries++

	// Update priority statistics
	switch msg.Priority {
	case PriorityCritical:
		dt.metrics.CriticalDeliveries++
	case PriorityHigh:
		dt.metrics.HighDeliveries++
	case PriorityNormal:
		dt.metrics.NormalDeliveries++
	case PriorityLow:
		dt.metrics.LowDeliveries++
	default:
		dt.metrics.BulkDeliveries++
	}

	dt.metrics.TotalRecipients += int64(len(msg.To))
	dt.mu.Unlock()

	dt.logger.Info("Started tracking delivery",
		"delivery_id", deliveryID,
		"message_id", msg.ID,
		"recipients", len(msg.To),
		"priority", msg.Priority)

	return deliveryID
}

// UpdateDelivery updates the tracking information for a delivery
func (dt *DeliveryTracker) UpdateDelivery(deliveryID string, result *DeliveryResult) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	tracked, exists := dt.deliveries[deliveryID]
	if !exists {
		dt.logger.Warn("Attempted to update non-existent delivery", "delivery_id", deliveryID)
		return
	}

	tracked.Result = result
	tracked.UpdatedAt = time.Now()
	tracked.SuccessfulRecipients = result.SuccessfulRecipients
	tracked.FailedRecipients = result.FailedRecipients
	tracked.ProcessedRecipients = result.SuccessfulRecipients + result.FailedRecipients
	tracked.DeliveryTime = result.Duration
	tracked.TotalTime = time.Since(tracked.StartTime)

	if result.Success {
		tracked.Status = StatusCompleted
		tracked.CompletedAt = time.Now()
		dt.metrics.CompletedDeliveries++
		dt.metrics.SuccessfulRecipients += int64(result.SuccessfulRecipients)
	} else {
		tracked.Status = StatusFailed
		tracked.LastError = result.Error
		tracked.ErrorCount++
		dt.metrics.FailedDeliveries++
		dt.metrics.FailedRecipients += int64(result.FailedRecipients)

		if result.Error != nil {
			dt.updateErrorStatistics(result.Error)
		}
	}

	dt.metrics.ActiveDeliveries--

	// Update timing statistics
	dt.updateTimingStatistics(tracked.DeliveryTime)
	dt.updateHourlyStatistics(tracked, result.Success)
	dt.updateDailyStatistics(tracked, result.Success)

	// Update success rate
	if dt.metrics.CompletedDeliveries+dt.metrics.FailedDeliveries > 0 {
		dt.metrics.SuccessRate = float64(dt.metrics.CompletedDeliveries) /
			float64(dt.metrics.CompletedDeliveries+dt.metrics.FailedDeliveries) * 100
	}

	dt.logger.Info("Updated delivery tracking",
		"delivery_id", deliveryID,
		"status", tracked.Status,
		"successful_recipients", result.SuccessfulRecipients,
		"failed_recipients", result.FailedRecipients,
		"duration", result.Duration)
}

// AddAttempt records a delivery attempt
func (dt *DeliveryTracker) AddAttempt(deliveryID string, attempt *DeliveryAttempt) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	tracked, exists := dt.deliveries[deliveryID]
	if !exists {
		dt.logger.Warn("Attempted to add attempt to non-existent delivery", "delivery_id", deliveryID)
		return
	}

	tracked.Attempts = append(tracked.Attempts, attempt)
	tracked.UpdatedAt = time.Now()

	switch attempt.Status {
	case StatusFailed:
		tracked.ConsecutiveFailures++
		tracked.LastError = attempt.Error
	case StatusCompleted:
		tracked.ConsecutiveFailures = 0
	}

	if attempt.Status == StatusRetrying {
		dt.metrics.RetryingDeliveries++
	}

	dt.logger.Debug("Added delivery attempt",
		"delivery_id", deliveryID,
		"attempt_number", attempt.AttemptNumber,
		"status", attempt.Status)
}

// FinishDelivery marks a delivery as finished
func (dt *DeliveryTracker) FinishDelivery(deliveryID string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	tracked, exists := dt.deliveries[deliveryID]
	if !exists {
		return
	}

	tracked.EndTime = time.Now()
	tracked.TotalTime = tracked.EndTime.Sub(tracked.StartTime)
	tracked.UpdatedAt = time.Now()

	if tracked.Status == StatusInProgress {
		tracked.Status = StatusCompleted
		tracked.CompletedAt = time.Now()
	}

	dt.logger.Debug("Finished tracking delivery",
		"delivery_id", deliveryID,
		"status", tracked.Status,
		"total_time", tracked.TotalTime)
}

// GetDelivery returns tracking information for a specific delivery
func (dt *DeliveryTracker) GetDelivery(deliveryID string) (*TrackedDelivery, bool) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	delivery, exists := dt.deliveries[deliveryID]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid race conditions
	copy := *delivery
	return &copy, true
}

// GetActiveDeliveries returns all currently active deliveries
func (dt *DeliveryTracker) GetActiveDeliveries() []*TrackedDelivery {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	active := make([]*TrackedDelivery, 0)
	for _, delivery := range dt.deliveries {
		if delivery.Status == StatusInProgress || delivery.Status == StatusRetrying {
			copy := *delivery
			active = append(active, &copy)
		}
	}

	return active
}

// GetRecentDeliveries returns recent deliveries within the specified duration
func (dt *DeliveryTracker) GetRecentDeliveries(since time.Duration) []*TrackedDelivery {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	cutoff := time.Now().Add(-since)
	recent := make([]*TrackedDelivery, 0)

	for _, delivery := range dt.deliveries {
		if delivery.StartTime.After(cutoff) {
			copy := *delivery
			recent = append(recent, &copy)
		}
	}

	return recent
}

// GetFailedDeliveries returns deliveries that failed
func (dt *DeliveryTracker) GetFailedDeliveries(limit int) []*TrackedDelivery {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	failed := make([]*TrackedDelivery, 0)
	count := 0

	for _, delivery := range dt.deliveries {
		if delivery.Status == StatusFailed && count < limit {
			copy := *delivery
			failed = append(failed, &copy)
			count++
		}
	}

	return failed
}

// updateErrorStatistics updates error statistics based on the error type
func (dt *DeliveryTracker) updateErrorStatistics(err error) {
	dt.metrics.TotalErrors++

	// Categorize error by type (this is a simplified categorization)
	errorStr := err.Error()
	switch {
	case strings.Contains(errorStr, "connection"):
		dt.metrics.ConnectionErrors++
	case strings.Contains(errorStr, "dns") || strings.Contains(errorStr, "lookup"):
		dt.metrics.DNSErrors++
	case strings.Contains(errorStr, "smtp"):
		dt.metrics.SMTPErrors++
	case strings.Contains(errorStr, "tls"):
		dt.metrics.TLSErrors++
	case strings.Contains(errorStr, "timeout"):
		dt.metrics.TimeoutErrors++
	}
}

// updateTimingStatistics updates timing-related statistics
func (dt *DeliveryTracker) updateTimingStatistics(duration time.Duration) {
	if dt.metrics.CompletedDeliveries == 1 {
		dt.metrics.AverageDeliveryTime = duration
		dt.metrics.MinDeliveryTime = duration
		dt.metrics.MaxDeliveryTime = duration
	} else {
		dt.metrics.AverageDeliveryTime = (dt.metrics.AverageDeliveryTime + duration) / 2

		if duration < dt.metrics.MinDeliveryTime {
			dt.metrics.MinDeliveryTime = duration
		}
		if duration > dt.metrics.MaxDeliveryTime {
			dt.metrics.MaxDeliveryTime = duration
		}
	}
}

// updateHourlyStatistics updates hourly delivery statistics
func (dt *DeliveryTracker) updateHourlyStatistics(delivery *TrackedDelivery, success bool) {
	hour := delivery.StartTime.Hour()

	stats, exists := dt.metrics.HourlyStats[hour]
	if !exists {
		stats = &HourlyMetrics{Hour: hour}
		dt.metrics.HourlyStats[hour] = stats
	}

	stats.Deliveries++
	if success {
		stats.Successes++
	} else {
		stats.Failures++
	}

	// Update average delivery time
	if stats.Deliveries == 1 {
		stats.AverageDeliveryTime = delivery.DeliveryTime
	} else {
		stats.AverageDeliveryTime = (stats.AverageDeliveryTime + delivery.DeliveryTime) / 2
	}
}

// updateDailyStatistics updates daily delivery statistics
func (dt *DeliveryTracker) updateDailyStatistics(delivery *TrackedDelivery, success bool) {
	date := delivery.StartTime.Format("2006-01-02")

	stats, exists := dt.metrics.DailyStats[date]
	if !exists {
		stats = &DailyMetrics{Date: date}
		dt.metrics.DailyStats[date] = stats
	}

	stats.Deliveries++
	if success {
		stats.Successes++
	} else {
		stats.Failures++
	}

	// Update average delivery time
	if stats.Deliveries == 1 {
		stats.AverageDeliveryTime = delivery.DeliveryTime
	} else {
		stats.AverageDeliveryTime = (stats.AverageDeliveryTime + delivery.DeliveryTime) / 2
	}
}

// cleanup runs periodic cleanup of old delivery records
func (dt *DeliveryTracker) cleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour) // Cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dt.performCleanup()
		}
	}
}

// performCleanup removes old delivery records to prevent memory leaks
func (dt *DeliveryTracker) performCleanup() {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour) // Keep records for 24 hours
	cleaned := 0

	for id, delivery := range dt.deliveries {
		if delivery.EndTime.Before(cutoff) &&
			(delivery.Status == StatusCompleted || delivery.Status == StatusFailed) {
			delete(dt.deliveries, id)
			cleaned++
		}
	}

	if cleaned > 0 {
		dt.logger.Debug("Cleaned up old delivery records", "count", cleaned)
	}

	// Also cleanup old daily stats (keep last 30 days)
	cutoffDate := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	for date := range dt.metrics.DailyStats {
		if date < cutoffDate {
			delete(dt.metrics.DailyStats, date)
		}
	}
}

// GetStats returns current delivery tracking statistics
func (dt *DeliveryTracker) GetStats() map[string]interface{} {
	dt.metrics.mu.RLock()
	defer dt.metrics.mu.RUnlock()

	return map[string]interface{}{
		"total_deliveries":      dt.metrics.TotalDeliveries,
		"active_deliveries":     dt.metrics.ActiveDeliveries,
		"completed_deliveries":  dt.metrics.CompletedDeliveries,
		"failed_deliveries":     dt.metrics.FailedDeliveries,
		"retrying_deliveries":   dt.metrics.RetryingDeliveries,
		"cancelled_deliveries":  dt.metrics.CancelledDeliveries,
		"average_delivery_time": dt.metrics.AverageDeliveryTime,
		"min_delivery_time":     dt.metrics.MinDeliveryTime,
		"max_delivery_time":     dt.metrics.MaxDeliveryTime,
		"average_queue_time":    dt.metrics.AverageQueueTime,
		"success_rate":          dt.metrics.SuccessRate,
		"retry_rate":            dt.metrics.RetryRate,
		"total_errors":          dt.metrics.TotalErrors,
		"connection_errors":     dt.metrics.ConnectionErrors,
		"dns_errors":            dt.metrics.DNSErrors,
		"smtp_errors":           dt.metrics.SMTPErrors,
		"tls_errors":            dt.metrics.TLSErrors,
		"timeout_errors":        dt.metrics.TimeoutErrors,
		"total_recipients":      dt.metrics.TotalRecipients,
		"successful_recipients": dt.metrics.SuccessfulRecipients,
		"failed_recipients":     dt.metrics.FailedRecipients,
		"critical_deliveries":   dt.metrics.CriticalDeliveries,
		"high_deliveries":       dt.metrics.HighDeliveries,
		"normal_deliveries":     dt.metrics.NormalDeliveries,
		"low_deliveries":        dt.metrics.LowDeliveries,
		"bulk_deliveries":       dt.metrics.BulkDeliveries,
		"tracked_deliveries":    len(dt.deliveries),
	}
}

// GetDetailedStats returns detailed statistics including hourly and daily breakdowns
func (dt *DeliveryTracker) GetDetailedStats() map[string]interface{} {
	dt.metrics.mu.RLock()
	defer dt.metrics.mu.RUnlock()

	stats := dt.GetStats()
	stats["hourly_stats"] = dt.metrics.HourlyStats
	stats["daily_stats"] = dt.metrics.DailyStats

	return stats
}

// ResetStats resets all statistics (useful for testing or after maintenance)
func (dt *DeliveryTracker) ResetStats() {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.metrics = &TrackerMetrics{
		HourlyStats: make(map[int]*HourlyMetrics),
		DailyStats:  make(map[string]*DailyMetrics),
	}

	dt.logger.Info("Delivery tracking statistics reset")
}
