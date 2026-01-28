package api

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/busybox42/elemta/internal/queue"
)

// HealthStats represents server health statistics
type HealthStats struct {
	Status          string         `json:"status"`
	Uptime          int64          `json:"uptime"`           // seconds
	UptimeFormatted string         `json:"uptime_formatted"` // human readable
	StartedAt       time.Time      `json:"started_at"`
	GoVersion       string         `json:"go_version"`
	NumGoroutines   int            `json:"num_goroutines"`
	NumCPU          int            `json:"num_cpu"`
	Memory          MemoryStats    `json:"memory"`
	Queue           QueueHealth    `json:"queue"`
	SMTP            SMTPHealth     `json:"smtp"`
	Throughput      ThroughputInfo `json:"throughput"`
	ServerVersion   string         `json:"server_version"`
	ConfiguredAddr  string         `json:"configured_addr"`
	AuthEnabled     bool           `json:"auth_enabled"`
}

// MemoryStats represents memory usage statistics
type MemoryStats struct {
	Alloc        uint64  `json:"alloc"`          // bytes allocated and in use
	TotalAlloc   uint64  `json:"total_alloc"`    // bytes allocated total
	Sys          uint64  `json:"sys"`            // bytes obtained from system
	HeapAlloc    uint64  `json:"heap_alloc"`     // heap bytes allocated
	HeapSys      uint64  `json:"heap_sys"`       // heap bytes from system
	HeapInuse    uint64  `json:"heap_inuse"`     // heap bytes in use
	HeapIdle     uint64  `json:"heap_idle"`      // heap bytes idle
	HeapReleased uint64  `json:"heap_released"`  // heap bytes released
	StackInuse   uint64  `json:"stack_inuse"`    // stack bytes in use
	NumGC        uint32  `json:"num_gc"`         // number of GC cycles
	LastGC       int64   `json:"last_gc"`        // last GC time (unix nano)
	GCPauseTotal uint64  `json:"gc_pause_total"` // total GC pause time (ns)
	AllocMB      float64 `json:"alloc_mb"`       // allocated in MB
	SysMB        float64 `json:"sys_mb"`         // system memory in MB
}

// QueueHealth represents queue health information
type QueueHealth struct {
	TotalMessages   int  `json:"total_messages"`
	ActiveCount     int  `json:"active_count"`
	DeferredCount   int  `json:"deferred_count"`
	HoldCount       int  `json:"hold_count"`
	FailedCount     int  `json:"failed_count"`
	ProcessorActive bool `json:"processor_active"`
}

// SMTPHealth represents SMTP server health
type SMTPHealth struct {
	Listening         bool   `json:"listening"`
	ListenAddr        string `json:"listen_addr"`
	TLSEnabled        bool   `json:"tls_enabled"`
	StartTLSEnabled   bool   `json:"starttls_enabled"`
	AuthEnabled       bool   `json:"auth_enabled"`
	ActiveConnections int    `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
}

// ThroughputInfo represents throughput statistics
type ThroughputInfo struct {
	MessagesPerMinute float64 `json:"messages_per_minute"`
	MessagesPerHour   float64 `json:"messages_per_hour"`
	BytesPerMinute    float64 `json:"bytes_per_minute"`
	TotalProcessed    int64   `json:"total_processed"`
	TotalBytes        int64   `json:"total_bytes"`
}

// DeliveryStats represents delivery statistics
type DeliveryStats struct {
	TotalDelivered      int64            `json:"total_delivered"`
	TotalFailed         int64            `json:"total_failed"`
	TotalBounced        int64            `json:"total_bounced"`
	TotalDeferred       int64            `json:"total_deferred"`
	SuccessRate         float64          `json:"success_rate"`
	AverageDeliveryTime float64          `json:"average_delivery_time"` // milliseconds
	ByDomain            map[string]int64 `json:"by_domain"`
	ByHour              []HourlyStats    `json:"by_hour"`
	TopSenders          []SenderStats    `json:"top_senders"`
	TopRecipients       []RecipientStats `json:"top_recipients"`
	RecentErrors        []DeliveryError  `json:"recent_errors"`
}

// HourlyStats represents hourly delivery statistics
type HourlyStats struct {
	Hour      string `json:"hour"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// TimeScaleStats represents generic time-scale delivery statistics
type TimeScaleStats struct {
	Label     string `json:"label"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Deferred  int64  `json:"deferred"`
}

// SenderStats represents sender statistics
type SenderStats struct {
	Sender string `json:"sender"`
	Count  int64  `json:"count"`
}

// RecipientStats represents recipient statistics
type RecipientStats struct {
	Recipient string `json:"recipient"`
	Count     int64  `json:"count"`
}

// DeliveryError represents a delivery error
type DeliveryError struct {
	MessageID string    `json:"message_id"`
	Recipient string    `json:"recipient"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// Server-level stats tracking
var (
	serverStartTime   = time.Now()
	totalConnections  atomic.Int64
	activeConnections atomic.Int32
	messagesProcessed atomic.Int64
	bytesProcessed    atomic.Int64
)

// handleHealthStats returns server health statistics
func (s *Server) handleHealthStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(serverStartTime)
	uptimeFormatted := formatDuration(uptime)

	// Get queue stats
	queueStats := s.queueMgr.GetStats()

	// Get metrics from Valkey store for throughput calculation
	var totalProcessed int64
	var totalBytes int64
	if s.metricsStore != nil {
		metricsData, err := s.metricsStore.GetMetrics(ctx)
		if err == nil && metricsData != nil {
			totalProcessed = metricsData.TotalDelivered + metricsData.TotalFailed + metricsData.TotalDeferred
			// Note: bytes data may not be available in metrics store, using 0 for now
			totalBytes = 0
		}
	}

	health := HealthStats{
		Status:          "healthy",
		Uptime:          int64(uptime.Seconds()),
		UptimeFormatted: uptimeFormatted,
		StartedAt:       serverStartTime,
		GoVersion:       runtime.Version(),
		NumGoroutines:   runtime.NumGoroutine(),
		NumCPU:          runtime.NumCPU(),
		Memory: MemoryStats{
			Alloc:        memStats.Alloc,
			TotalAlloc:   memStats.TotalAlloc,
			Sys:          memStats.Sys,
			HeapAlloc:    memStats.HeapAlloc,
			HeapSys:      memStats.HeapSys,
			HeapInuse:    memStats.HeapInuse,
			HeapIdle:     memStats.HeapIdle,
			HeapReleased: memStats.HeapReleased,
			StackInuse:   memStats.StackInuse,
			NumGC:        memStats.NumGC,
			LastGC:       int64(memStats.LastGC),
			GCPauseTotal: memStats.PauseTotalNs,
			AllocMB:      float64(memStats.Alloc) / 1024 / 1024,
			SysMB:        float64(memStats.Sys) / 1024 / 1024,
		},
		Queue: QueueHealth{
			TotalMessages:   queueStats.ActiveCount + queueStats.DeferredCount + queueStats.HoldCount + queueStats.FailedCount,
			ActiveCount:     queueStats.ActiveCount,
			DeferredCount:   queueStats.DeferredCount,
			HoldCount:       queueStats.HoldCount,
			FailedCount:     queueStats.FailedCount,
			ProcessorActive: true,
		},
		SMTP: SMTPHealth{
			Listening:         true,
			ListenAddr:        s.listenAddr,
			TLSEnabled:        false, // Will be set from config
			StartTLSEnabled:   false,
			AuthEnabled:       s.authSystem != nil,
			ActiveConnections: int(activeConnections.Load()),
			TotalConnections:  totalConnections.Load(),
		},
		Throughput: ThroughputInfo{
			MessagesPerMinute: calculateRate(totalProcessed, uptime, time.Minute),
			MessagesPerHour:   calculateRate(totalProcessed, uptime, time.Hour),
			BytesPerMinute:    calculateRate(totalBytes, uptime, time.Minute),
			TotalProcessed:    totalProcessed,
			TotalBytes:        totalBytes,
		},
		ServerVersion:  "1.0.0",
		ConfiguredAddr: s.listenAddr,
		AuthEnabled:    s.authSystem != nil,
	}

	writeJSON(w, health)
}

// handleDeliveryStats returns delivery statistics
func (s *Server) handleDeliveryStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get time scale parameter (default: hour)
	timeScale := r.URL.Query().Get("timeScale")
	if timeScale == "" {
		timeScale = "hour"
	}

	// Get queue stats for current queue state
	queueStats := s.queueMgr.GetStats()

	var totalDelivered, totalFailed, totalDeferred int64
	var byHour []HourlyStats
	var data []TimeScaleStats
	var recentErrors []DeliveryError

	// Try to get metrics from Valkey store
	if s.metricsStore != nil {
		metricsData, err := s.metricsStore.GetMetrics(ctx)
		if err == nil && metricsData != nil {
			totalDelivered = metricsData.TotalDelivered
			totalFailed = metricsData.TotalFailed
			totalDeferred = metricsData.TotalDeferred
		}

		// Get stats based on time scale
		switch timeScale {
		case "hour":
			hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
			if err == nil {
				byHour = make([]HourlyStats, len(hourlyData))
				data = make([]TimeScaleStats, len(hourlyData))
				for i, h := range hourlyData {
					byHour[i] = HourlyStats(h)
					data[i] = TimeScaleStats{
						Label:     h.Hour,
						Delivered: h.Delivered,
						Failed:    h.Failed,
						Deferred:  h.Deferred,
					}
				}
			}
		case "day":
			data = s.getDailyStats(ctx)
		case "week":
			data = s.getWeeklyStats(ctx)
		case "month":
			data = s.getMonthlyStats(ctx)
		default:
			// Default to hourly for invalid scales
			hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
			if err == nil {
				byHour = make([]HourlyStats, len(hourlyData))
				data = make([]TimeScaleStats, len(hourlyData))
				for i, h := range hourlyData {
					byHour[i] = HourlyStats(h)
					data[i] = TimeScaleStats{
						Label:     h.Hour,
						Delivered: h.Delivered,
						Failed:    h.Failed,
						Deferred:  h.Deferred,
					}
				}
			}
		}

		// Get recent errors from Valkey
		errorsData, err := s.metricsStore.GetRecentErrors(ctx, 10)
		if err == nil {
			for _, e := range errorsData {
				ts, _ := time.Parse(time.RFC3339, e["timestamp"])
				recentErrors = append(recentErrors, DeliveryError{
					MessageID: e["message_id"],
					Recipient: e["recipient"],
					Error:     e["error"],
					Timestamp: ts,
				})
			}
		}
	}

	// If no Valkey data, generate empty hourly stats
	if byHour == nil {
		byHour = make([]HourlyStats, 24)
		now := time.Now()
		for i := 0; i < 24; i++ {
			hour := now.Add(-time.Duration(23-i) * time.Hour)
			byHour[i] = HourlyStats{
				Hour:      hour.Format("15:00"),
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			}
		}
	}

	// Fallback to failed queue for recent errors if Valkey has none
	if len(recentErrors) == 0 {
		failedMsgs, err := s.queueMgr.ListMessages(queue.Failed)
		if err == nil && len(failedMsgs) > 0 {
			limit := 10
			if len(failedMsgs) < limit {
				limit = len(failedMsgs)
			}
			for i := 0; i < limit; i++ {
				msg := failedMsgs[len(failedMsgs)-1-i]
				errorMsg := "Delivery failed"
				if msg.LastError != "" {
					errorMsg = msg.LastError
				}
				recipient := strings.Join(msg.To, ", ")
				recentErrors = append(recentErrors, DeliveryError{
					MessageID: msg.ID,
					Recipient: recipient,
					Error:     errorMsg,
					Timestamp: msg.UpdatedAt,
				})
			}
		}
		// Add current failed queue count to totalFailed
		totalFailed += int64(queueStats.FailedCount)
	}

	// Calculate success rate
	total := totalDelivered + totalFailed
	successRate := 100.0
	if total > 0 {
		successRate = float64(totalDelivered) / float64(total) * 100
	}

	// Build domain stats from current queue
	byDomain := make(map[string]int64)
	allMsgs, err := s.queueMgr.GetAllMessages()
	if err == nil {
		for _, msg := range allMsgs {
			for _, to := range msg.To {
				domain := extractDomain(to)
				byDomain[domain]++
			}
		}
	}

	writeJSON(w, map[string]interface{}{
		"total_delivered": totalDelivered,
		"total_failed":    totalFailed,
		"total_deferred":  totalDeferred,
		"success_rate":    successRate,
		"data":            data,
		"by_hour":         byHour, // Keep for backward compatibility
		"recent_errors":   recentErrors,
	})
}

// extractDomain extracts domain from email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return "unknown"
}

// handleSendTestEmail sends a test email
func (s *Server) handleSendTestEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.From == "" || req.To == "" {
		http.Error(w, "from and to are required", http.StatusBadRequest)
		return
	}

	if req.Subject == "" {
		req.Subject = "Test Email from Elemta"
	}
	if req.Body == "" {
		req.Body = "This is a test email sent from the Elemta web interface."
	}

	// Create email content
	content := "From: " + req.From + "\r\n" +
		"To: " + req.To + "\r\n" +
		"Subject: " + req.Subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"X-Mailer: Elemta-WebUI/1.0\r\n" +
		"\r\n" +
		req.Body

	// Queue the message
	msgID, err := s.queueMgr.EnqueueMessage(req.From, []string{req.To}, req.Subject, []byte(content), 2, time.Now())
	if err != nil {
		http.Error(w, "Failed to queue message: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":     "success",
		"message_id": msgID,
		"message":    "Test email queued successfully",
	})
}

// formatDuration formats a duration as human readable
func formatDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

// getDailyStats aggregates hourly data into daily statistics
func (s *Server) getDailyStats(ctx context.Context) []TimeScaleStats {
	var dailyStats []TimeScaleStats

	if s.metricsStore == nil {
		return dailyStats
	}

	// Get last 30 days of hourly data
	hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
	if err != nil || len(hourlyData) == 0 {
		return dailyStats
	}

	// Group by day
	dailyMap := make(map[string]TimeScaleStats)
	now := time.Now()

	for _, hour := range hourlyData {
		// Parse hour label (assuming format like "2023-01-01T15")
		if len(hour.Hour) < 10 {
			continue
		}
		dayKey := hour.Hour[:10] // Extract YYYY-MM-DD

		stat, exists := dailyMap[dayKey]
		if !exists {
			stat = TimeScaleStats{
				Label:     dayKey,
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			}
		}

		stat.Delivered += hour.Delivered
		stat.Failed += hour.Failed
		stat.Deferred += hour.Deferred
		dailyMap[dayKey] = stat
	}

	// Convert to slice and sort by date (last 30 days)
	for i := 0; i < 30; i++ {
		day := now.AddDate(0, 0, -29+i).Format("2006-01-02")
		if stat, exists := dailyMap[day]; exists {
			dailyStats = append(dailyStats, stat)
		} else {
			dailyStats = append(dailyStats, TimeScaleStats{
				Label:     day,
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			})
		}
	}

	return dailyStats
}

// getWeeklyStats aggregates hourly data into weekly statistics
func (s *Server) getWeeklyStats(ctx context.Context) []TimeScaleStats {
	var weeklyStats []TimeScaleStats

	if s.metricsStore == nil {
		return weeklyStats
	}

	// Get last 12 weeks of hourly data
	hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
	if err != nil || len(hourlyData) == 0 {
		return weeklyStats
	}

	// Group by week
	weeklyMap := make(map[string]TimeScaleStats)
	now := time.Now()

	for _, hour := range hourlyData {
		// Parse hour label
		if len(hour.Hour) < 10 {
			continue
		}

		// Parse date and get week start (Monday)
		date, err := time.Parse("2006-01-02T15", hour.Hour)
		if err != nil {
			continue
		}

		// Get Monday of this week
		weekday := int(date.Weekday())
		if weekday == 0 { // Sunday
			weekday = 7
		}
		weekStart := date.AddDate(0, 0, -weekday+1)
		weekKey := weekStart.Format("2006-01-02")

		stat, exists := weeklyMap[weekKey]
		if !exists {
			stat = TimeScaleStats{
				Label:     "Week of " + weekStart.Format("Jan 02"),
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			}
		}

		stat.Delivered += hour.Delivered
		stat.Failed += hour.Failed
		stat.Deferred += hour.Deferred
		weeklyMap[weekKey] = stat
	}

	// Convert to slice and sort by week (last 12 weeks)
	for i := 0; i < 12; i++ {
		weekStart := now.AddDate(0, 0, -7*11+7*i)
		// Adjust to Monday
		for weekStart.Weekday() != time.Monday {
			weekStart = weekStart.AddDate(0, 0, -1)
		}
		weekKey := weekStart.Format("2006-01-02")

		if stat, exists := weeklyMap[weekKey]; exists {
			weeklyStats = append(weeklyStats, stat)
		} else {
			weeklyStats = append(weeklyStats, TimeScaleStats{
				Label:     "Week of " + weekStart.Format("Jan 02"),
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			})
		}
	}

	return weeklyStats
}

// getMonthlyStats aggregates hourly data into monthly statistics
func (s *Server) getMonthlyStats(ctx context.Context) []TimeScaleStats {
	var monthlyStats []TimeScaleStats

	if s.metricsStore == nil {
		return monthlyStats
	}

	// Get last 12 months of hourly data
	hourlyData, err := s.metricsStore.GetHourlyStats(ctx)
	if err != nil || len(hourlyData) == 0 {
		return monthlyStats
	}

	// Group by month
	monthlyMap := make(map[string]TimeScaleStats)
	now := time.Now()

	for _, hour := range hourlyData {
		// Parse hour label
		if len(hour.Hour) < 7 {
			continue
		}

		// Extract month key (YYYY-MM)
		monthKey := hour.Hour[:7]

		stat, exists := monthlyMap[monthKey]
		if !exists {
			// Parse month for nice label
			date, err := time.Parse("2006-01", monthKey)
			if err != nil {
				continue
			}
			stat = TimeScaleStats{
				Label:     date.Format("Jan 2006"),
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			}
		}

		stat.Delivered += hour.Delivered
		stat.Failed += hour.Failed
		stat.Deferred += hour.Deferred
		monthlyMap[monthKey] = stat
	}

	// Convert to slice and sort by month (last 12 months)
	for i := 0; i < 12; i++ {
		month := now.AddDate(0, -11+i, 0)
		monthKey := month.Format("2006-01")

		if stat, exists := monthlyMap[monthKey]; exists {
			monthlyStats = append(monthlyStats, stat)
		} else {
			monthlyStats = append(monthlyStats, TimeScaleStats{
				Label:     month.Format("Jan 2006"),
				Delivered: 0,
				Failed:    0,
				Deferred:  0,
			})
		}
	}

	return monthlyStats
}

// calculateRate calculates a rate per period
func calculateRate(total int64, elapsed time.Duration, period time.Duration) float64 {
	if elapsed == 0 {
		return 0
	}
	return float64(total) / elapsed.Seconds() * period.Seconds()
}
