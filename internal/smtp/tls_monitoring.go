package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// TLSSecurityEvent represents a TLS security event
type TLSSecurityEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	RemoteAddr  string                 `json:"remote_addr,omitempty"`
	TLSVersion  string                 `json:"tls_version,omitempty"`
	CipherSuite string                 `json:"cipher_suite,omitempty"`
	Certificate string                 `json:"certificate,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Message     string                 `json:"message"`
}

// TLSConnectionMetrics holds metrics about TLS connections
type TLSConnectionMetrics struct {
	TotalConnections      int64            `json:"total_connections"`
	TLSConnections        int64            `json:"tls_connections"`
	TLS12Connections      int64            `json:"tls12_connections"`
	TLS13Connections      int64            `json:"tls13_connections"`
	FailedHandshakes      int64            `json:"failed_handshakes"`
	CertificateErrors     int64            `json:"certificate_errors"`
	WeakCipherConnections int64            `json:"weak_cipher_connections"`
	CipherSuiteUsage      map[string]int64 `json:"cipher_suite_usage"`
	TLSVersionUsage       map[string]int64 `json:"tls_version_usage"`
	LastUpdated           time.Time        `json:"last_updated"`
}

// TLSMonitor monitors TLS security events and connections
type TLSMonitor struct {
	logger           *slog.Logger
	events           []TLSSecurityEvent
	metrics          TLSConnectionMetrics
	eventsMutex      sync.RWMutex
	metricsMutex     sync.RWMutex
	maxEventsHistory int
	alertThresholds  TLSAlertThresholds
	enabled          bool
}

// TLSAlertThresholds defines thresholds for TLS security alerts
type TLSAlertThresholds struct {
	FailedHandshakeRate  float64 // Failed handshakes per minute
	WeakCipherRate       float64 // Weak cipher usage rate (%)
	CertificateErrorRate float64 // Certificate errors per minute
	OldTLSVersionRate    float64 // Old TLS version usage rate (%)
	MaxEventsPerMinute   int     // Maximum security events per minute
}

// DefaultTLSAlertThresholds returns sensible default alert thresholds
func DefaultTLSAlertThresholds() TLSAlertThresholds {
	return TLSAlertThresholds{
		FailedHandshakeRate:  10.0, // 10 failed handshakes per minute
		WeakCipherRate:       5.0,  // 5% weak cipher usage
		CertificateErrorRate: 5.0,  // 5 certificate errors per minute
		OldTLSVersionRate:    10.0, // 10% old TLS version usage
		MaxEventsPerMinute:   50,   // 50 security events per minute
	}
}

// NewTLSMonitor creates a new TLS security monitor
func NewTLSMonitor(logger *slog.Logger) *TLSMonitor {
	return &TLSMonitor{
		logger: logger.With("component", "tls-monitor"),
		events: make([]TLSSecurityEvent, 0),
		metrics: TLSConnectionMetrics{
			CipherSuiteUsage: make(map[string]int64),
			TLSVersionUsage:  make(map[string]int64),
			LastUpdated:      time.Now(),
		},
		maxEventsHistory: 1000, // Keep last 1000 events
		alertThresholds:  DefaultTLSAlertThresholds(),
		enabled:          true,
	}
}

// Enable enables TLS monitoring
func (tm *TLSMonitor) Enable() {
	tm.enabled = true
	tm.logger.Info("TLS monitoring enabled")
}

// Disable disables TLS monitoring
func (tm *TLSMonitor) Disable() {
	tm.enabled = false
	tm.logger.Info("TLS monitoring disabled")
}

// RecordTLSConnection records a successful TLS connection
func (tm *TLSMonitor) RecordTLSConnection(remoteAddr string, connState *tls.ConnectionState) {
	if !tm.enabled {
		return
	}

	tm.metricsMutex.Lock()
	defer tm.metricsMutex.Unlock()

	tm.metrics.TotalConnections++
	tm.metrics.TLSConnections++
	tm.metrics.LastUpdated = time.Now()

	// Record TLS version usage
	tlsVersion := tm.getTLSVersionName(connState.Version)
	tm.metrics.TLSVersionUsage[tlsVersion]++

	switch connState.Version {
	case tls.VersionTLS12:
		tm.metrics.TLS12Connections++
	case tls.VersionTLS13:
		tm.metrics.TLS13Connections++
	}

	// Record cipher suite usage
	cipherSuite := tm.getCipherSuiteName(connState.CipherSuite)
	tm.metrics.CipherSuiteUsage[cipherSuite]++

	// Check for weak ciphers
	if tm.isWeakCipherSuite(connState.CipherSuite) {
		tm.metrics.WeakCipherConnections++
		tm.recordSecurityEvent(TLSSecurityEvent{
			Timestamp:   time.Now(),
			EventType:   "weak_cipher",
			Severity:    "medium",
			RemoteAddr:  remoteAddr,
			TLSVersion:  tlsVersion,
			CipherSuite: cipherSuite,
			Message:     "Connection using weak cipher suite",
		})
	}

	// Check for old TLS versions
	if connState.Version < tls.VersionTLS12 {
		tm.recordSecurityEvent(TLSSecurityEvent{
			Timestamp:  time.Now(),
			EventType:  "old_tls_version",
			Severity:   "high",
			RemoteAddr: remoteAddr,
			TLSVersion: tlsVersion,
			Message:    "Connection using deprecated TLS version",
		})
	}

	tm.logger.Debug("TLS connection recorded",
		"remote_addr", remoteAddr,
		"tls_version", tlsVersion,
		"cipher_suite", cipherSuite,
		"handshake_complete", connState.HandshakeComplete)
}

// RecordTLSHandshakeFailure records a TLS handshake failure
func (tm *TLSMonitor) RecordTLSHandshakeFailure(remoteAddr string, err error) {
	if !tm.enabled {
		return
	}

	tm.metricsMutex.Lock()
	tm.metrics.FailedHandshakes++
	tm.metrics.LastUpdated = time.Now()
	tm.metricsMutex.Unlock()

	tm.recordSecurityEvent(TLSSecurityEvent{
		Timestamp:  time.Now(),
		EventType:  "handshake_failure",
		Severity:   "medium",
		RemoteAddr: remoteAddr,
		Message:    fmt.Sprintf("TLS handshake failed: %v", err),
		Details: map[string]interface{}{
			"error": err.Error(),
		},
	})

	tm.logger.Warn("TLS handshake failure",
		"remote_addr", remoteAddr,
		"error", err)
}

// RecordCertificateError records a certificate validation error
func (tm *TLSMonitor) RecordCertificateError(remoteAddr string, certificate string, err error) {
	if !tm.enabled {
		return
	}

	tm.metricsMutex.Lock()
	tm.metrics.CertificateErrors++
	tm.metrics.LastUpdated = time.Now()
	tm.metricsMutex.Unlock()

	tm.recordSecurityEvent(TLSSecurityEvent{
		Timestamp:   time.Now(),
		EventType:   "certificate_error",
		Severity:    "high",
		RemoteAddr:  remoteAddr,
		Certificate: certificate,
		Message:     fmt.Sprintf("Certificate validation error: %v", err),
		Details: map[string]interface{}{
			"error": err.Error(),
		},
	})

	tm.logger.Error("Certificate validation error",
		"remote_addr", remoteAddr,
		"certificate", certificate,
		"error", err)
}

// RecordSecurityViolation records a security policy violation
func (tm *TLSMonitor) RecordSecurityViolation(remoteAddr string, violation string, details map[string]interface{}) {
	if !tm.enabled {
		return
	}

	tm.recordSecurityEvent(TLSSecurityEvent{
		Timestamp:  time.Now(),
		EventType:  "security_violation",
		Severity:   "high",
		RemoteAddr: remoteAddr,
		Message:    fmt.Sprintf("Security policy violation: %s", violation),
		Details:    details,
	})

	tm.logger.Error("TLS security violation",
		"remote_addr", remoteAddr,
		"violation", violation,
		"details", details)
}

// recordSecurityEvent adds a security event to the history
func (tm *TLSMonitor) recordSecurityEvent(event TLSSecurityEvent) {
	tm.eventsMutex.Lock()
	defer tm.eventsMutex.Unlock()

	tm.events = append(tm.events, event)

	// Trim events if we exceed max history
	if len(tm.events) > tm.maxEventsHistory {
		// Keep the most recent events
		copy(tm.events, tm.events[len(tm.events)-tm.maxEventsHistory:])
		tm.events = tm.events[:tm.maxEventsHistory]
	}
}

// GetMetrics returns current TLS connection metrics
func (tm *TLSMonitor) GetMetrics() TLSConnectionMetrics {
	tm.metricsMutex.RLock()
	defer tm.metricsMutex.RUnlock()

	// Return a copy to avoid data races
	metrics := tm.metrics

	// Copy maps
	metrics.CipherSuiteUsage = make(map[string]int64)
	for k, v := range tm.metrics.CipherSuiteUsage {
		metrics.CipherSuiteUsage[k] = v
	}

	metrics.TLSVersionUsage = make(map[string]int64)
	for k, v := range tm.metrics.TLSVersionUsage {
		metrics.TLSVersionUsage[k] = v
	}

	return metrics
}

// GetRecentEvents returns security events from the last specified duration
func (tm *TLSMonitor) GetRecentEvents(duration time.Duration) []TLSSecurityEvent {
	tm.eventsMutex.RLock()
	defer tm.eventsMutex.RUnlock()

	cutoff := time.Now().Add(-duration)
	var recentEvents []TLSSecurityEvent

	for _, event := range tm.events {
		if event.Timestamp.After(cutoff) {
			recentEvents = append(recentEvents, event)
		}
	}

	return recentEvents
}

// CheckAlertThresholds checks if any alert thresholds have been exceeded
func (tm *TLSMonitor) CheckAlertThresholds() []TLSSecurityEvent {
	if !tm.enabled {
		return nil
	}

	var alerts []TLSSecurityEvent
	recentEvents := tm.GetRecentEvents(time.Minute)
	metrics := tm.GetMetrics()

	// Check failed handshake rate
	failedHandshakes := 0
	for _, event := range recentEvents {
		if event.EventType == "handshake_failure" {
			failedHandshakes++
		}
	}

	if float64(failedHandshakes) > tm.alertThresholds.FailedHandshakeRate {
		alerts = append(alerts, TLSSecurityEvent{
			Timestamp: time.Now(),
			EventType: "threshold_exceeded",
			Severity:  "high",
			Message:   fmt.Sprintf("Failed handshake rate exceeded: %d/min (threshold: %.1f/min)", failedHandshakes, tm.alertThresholds.FailedHandshakeRate),
			Details: map[string]interface{}{
				"threshold": "failed_handshake_rate",
				"current":   failedHandshakes,
				"limit":     tm.alertThresholds.FailedHandshakeRate,
			},
		})
	}

	// Check weak cipher usage rate
	if metrics.TLSConnections > 0 {
		weakCipherRate := float64(metrics.WeakCipherConnections) / float64(metrics.TLSConnections) * 100
		if weakCipherRate > tm.alertThresholds.WeakCipherRate {
			alerts = append(alerts, TLSSecurityEvent{
				Timestamp: time.Now(),
				EventType: "threshold_exceeded",
				Severity:  "medium",
				Message:   fmt.Sprintf("Weak cipher usage rate exceeded: %.1f%% (threshold: %.1f%%)", weakCipherRate, tm.alertThresholds.WeakCipherRate),
				Details: map[string]interface{}{
					"threshold": "weak_cipher_rate",
					"current":   weakCipherRate,
					"limit":     tm.alertThresholds.WeakCipherRate,
				},
			})
		}

		// Check old TLS version usage rate
		oldTLSConnections := metrics.TLSConnections - metrics.TLS12Connections - metrics.TLS13Connections
		if oldTLSConnections > 0 {
			oldTLSRate := float64(oldTLSConnections) / float64(metrics.TLSConnections) * 100
			if oldTLSRate > tm.alertThresholds.OldTLSVersionRate {
				alerts = append(alerts, TLSSecurityEvent{
					Timestamp: time.Now(),
					EventType: "threshold_exceeded",
					Severity:  "high",
					Message:   fmt.Sprintf("Old TLS version usage rate exceeded: %.1f%% (threshold: %.1f%%)", oldTLSRate, tm.alertThresholds.OldTLSVersionRate),
					Details: map[string]interface{}{
						"threshold": "old_tls_version_rate",
						"current":   oldTLSRate,
						"limit":     tm.alertThresholds.OldTLSVersionRate,
					},
				})
			}
		}
	}

	// Check certificate error rate
	certErrors := 0
	for _, event := range recentEvents {
		if event.EventType == "certificate_error" {
			certErrors++
		}
	}

	if float64(certErrors) > tm.alertThresholds.CertificateErrorRate {
		alerts = append(alerts, TLSSecurityEvent{
			Timestamp: time.Now(),
			EventType: "threshold_exceeded",
			Severity:  "high",
			Message:   fmt.Sprintf("Certificate error rate exceeded: %d/min (threshold: %.1f/min)", certErrors, tm.alertThresholds.CertificateErrorRate),
			Details: map[string]interface{}{
				"threshold": "certificate_error_rate",
				"current":   certErrors,
				"limit":     tm.alertThresholds.CertificateErrorRate,
			},
		})
	}

	// Check maximum events per minute
	if len(recentEvents) > tm.alertThresholds.MaxEventsPerMinute {
		alerts = append(alerts, TLSSecurityEvent{
			Timestamp: time.Now(),
			EventType: "threshold_exceeded",
			Severity:  "medium",
			Message:   fmt.Sprintf("Maximum security events per minute exceeded: %d (threshold: %d)", len(recentEvents), tm.alertThresholds.MaxEventsPerMinute),
			Details: map[string]interface{}{
				"threshold": "max_events_per_minute",
				"current":   len(recentEvents),
				"limit":     tm.alertThresholds.MaxEventsPerMinute,
			},
		})
	}

	// Record alerts as events
	for _, alert := range alerts {
		tm.recordSecurityEvent(alert)
		tm.logger.Error("TLS security alert", "message", alert.Message, "details", alert.Details)
	}

	return alerts
}

// GenerateSecurityReport generates a comprehensive security report
func (tm *TLSMonitor) GenerateSecurityReport(ctx context.Context, duration time.Duration) map[string]interface{} {
	metrics := tm.GetMetrics()
	recentEvents := tm.GetRecentEvents(duration)

	// Count events by type and severity
	eventTypes := make(map[string]int)
	eventSeverities := make(map[string]int)
	for _, event := range recentEvents {
		eventTypes[event.EventType]++
		eventSeverities[event.Severity]++
	}

	// Calculate rates and percentages
	var tlsUsageRate float64
	var tls13UsageRate float64
	var weakCipherRate float64

	if metrics.TotalConnections > 0 {
		tlsUsageRate = float64(metrics.TLSConnections) / float64(metrics.TotalConnections) * 100
	}

	if metrics.TLSConnections > 0 {
		tls13UsageRate = float64(metrics.TLS13Connections) / float64(metrics.TLSConnections) * 100
		weakCipherRate = float64(metrics.WeakCipherConnections) / float64(metrics.TLSConnections) * 100
	}

	report := map[string]interface{}{
		"report_period": duration.String(),
		"generated_at":  time.Now(),
		"metrics":       metrics,
		"summary": map[string]interface{}{
			"total_connections":     metrics.TotalConnections,
			"tls_connections":       metrics.TLSConnections,
			"tls_usage_rate":        tlsUsageRate,
			"tls13_usage_rate":      tls13UsageRate,
			"weak_cipher_rate":      weakCipherRate,
			"failed_handshakes":     metrics.FailedHandshakes,
			"certificate_errors":    metrics.CertificateErrors,
			"security_events_count": len(recentEvents),
		},
		"event_breakdown": map[string]interface{}{
			"by_type":     eventTypes,
			"by_severity": eventSeverities,
		},
		"top_cipher_suites": tm.getTopCipherSuites(metrics.CipherSuiteUsage, 5),
		"top_tls_versions":  tm.getTopTLSVersions(metrics.TLSVersionUsage, 5),
		"recent_events":     recentEvents,
	}

	return report
}

// SetAlertThresholds updates the alert thresholds
func (tm *TLSMonitor) SetAlertThresholds(thresholds TLSAlertThresholds) {
	tm.alertThresholds = thresholds
	tm.logger.Info("TLS alert thresholds updated", "thresholds", thresholds)
}

// Helper methods

func (tm *TLSMonitor) isWeakCipherSuite(cipher uint16) bool {
	// Define weak cipher suites
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		// Add more weak ciphers as needed
	}

	for _, weak := range weakCiphers {
		if cipher == weak {
			return true
		}
	}

	return false
}

func (tm *TLSMonitor) getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func (tm *TLSMonitor) getCipherSuiteName(cipher uint16) string {
	// Simplified cipher suite names
	cipherNames := map[uint16]string{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE-ECDSA-AES256-GCM-SHA384",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "ECDHE-RSA-AES256-GCM-SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE-RSA-AES128-GCM-SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "ECDHE-ECDSA-CHACHA20-POLY1305",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "ECDHE-RSA-CHACHA20-POLY1305",
		tls.TLS_RSA_WITH_RC4_128_SHA:                "RSA-RC4-SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "RSA-3DES-SHA",
	}

	if name, ok := cipherNames[cipher]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04x)", cipher)
}

func (tm *TLSMonitor) getTopCipherSuites(usage map[string]int64, limit int) []map[string]interface{} {
	type cipherEntry struct {
		name  string
		count int64
	}

	var entries []cipherEntry
	for name, count := range usage {
		entries = append(entries, cipherEntry{name, count})
	}

	// Sort by count (descending)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[i].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Take top entries
	if len(entries) > limit {
		entries = entries[:limit]
	}

	var result []map[string]interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"cipher_suite": entry.name,
			"count":        entry.count,
		})
	}

	return result
}

func (tm *TLSMonitor) getTopTLSVersions(usage map[string]int64, limit int) []map[string]interface{} {
	type versionEntry struct {
		name  string
		count int64
	}

	var entries []versionEntry
	for name, count := range usage {
		entries = append(entries, versionEntry{name, count})
	}

	// Sort by count (descending)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[i].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Take top entries
	if len(entries) > limit {
		entries = entries[:limit]
	}

	var result []map[string]interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"tls_version": entry.name,
			"count":       entry.count,
		})
	}

	return result
}
