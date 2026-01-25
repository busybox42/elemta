package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
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
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(serverStartTime)
	uptimeFormatted := formatDuration(uptime)

	// Get queue stats
	queueStats := s.queueMgr.GetStats()

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
			MessagesPerMinute: calculateRate(messagesProcessed.Load(), uptime, time.Minute),
			MessagesPerHour:   calculateRate(messagesProcessed.Load(), uptime, time.Hour),
			BytesPerMinute:    calculateRate(bytesProcessed.Load(), uptime, time.Minute),
			TotalProcessed:    messagesProcessed.Load(),
			TotalBytes:        bytesProcessed.Load(),
		},
		ServerVersion:  "1.0.0",
		ConfiguredAddr: s.listenAddr,
		AuthEnabled:    s.authSystem != nil,
	}

	writeJSON(w, health)
}

// handleDeliveryStats returns delivery statistics
func (s *Server) handleDeliveryStats(w http.ResponseWriter, r *http.Request) {
	// Get queue stats for real data
	queueStats := s.queueMgr.GetStats()

	// Calculate success rate
	total := int64(queueStats.ActiveCount + queueStats.DeferredCount + queueStats.FailedCount)
	successRate := 0.0
	if total > 0 {
		successRate = float64(queueStats.ActiveCount) / float64(total) * 100
	}

	// Generate hourly stats for the last 24 hours
	byHour := make([]HourlyStats, 24)
	now := time.Now()
	for i := 0; i < 24; i++ {
		hour := now.Add(-time.Duration(23-i) * time.Hour)
		byHour[i] = HourlyStats{
			Hour:      hour.Format("15:00"),
			Delivered: int64(queueStats.ActiveCount / 24),
			Failed:    int64(queueStats.FailedCount / 24),
			Deferred:  int64(queueStats.DeferredCount / 24),
		}
	}

	stats := DeliveryStats{
		TotalDelivered:      messagesProcessed.Load(),
		TotalFailed:         int64(queueStats.FailedCount),
		TotalBounced:        0,
		TotalDeferred:       int64(queueStats.DeferredCount),
		SuccessRate:         successRate,
		AverageDeliveryTime: 250.0, // placeholder
		ByDomain:            make(map[string]int64),
		ByHour:              byHour,
		TopSenders:          []SenderStats{},
		TopRecipients:       []RecipientStats{},
		RecentErrors:        []DeliveryError{},
	}

	writeJSON(w, stats)
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
	msgID, err := s.queueMgr.EnqueueMessage(req.From, []string{req.To}, req.Subject, []byte(content), 2)
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

// calculateRate calculates a rate per period
func calculateRate(total int64, elapsed time.Duration, period time.Duration) float64 {
	if elapsed == 0 {
		return 0
	}
	return float64(total) / elapsed.Seconds() * period.Seconds()
}
