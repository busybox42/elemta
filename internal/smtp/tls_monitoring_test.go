package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestNewTLSMonitor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewTLSMonitor(logger)

	if monitor == nil {
		t.Fatal("Expected TLSMonitor instance, got nil")
	}

	if !monitor.enabled {
		t.Error("Expected monitor to be enabled by default")
	}

	if monitor.maxEventsHistory != 1000 {
		t.Error("Expected default max events history to be 1000")
	}

	// Check default alert thresholds
	expected := DefaultTLSAlertThresholds()
	if monitor.alertThresholds.FailedHandshakeRate != expected.FailedHandshakeRate {
		t.Error("Expected default failed handshake rate threshold to match")
	}
}

func TestTLSConnectionRecording(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Test TLS 1.2 connection
	connState12 := &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		HandshakeComplete: true,
	}

	monitor.RecordTLSConnection("192.168.1.100:12345", connState12)

	metrics := monitor.GetMetrics()
	if metrics.TotalConnections != 1 {
		t.Error("Expected total connections to be 1")
	}
	if metrics.TLSConnections != 1 {
		t.Error("Expected TLS connections to be 1")
	}
	if metrics.TLS12Connections != 1 {
		t.Error("Expected TLS 1.2 connections to be 1")
	}
	if metrics.TLS13Connections != 0 {
		t.Error("Expected TLS 1.3 connections to be 0")
	}

	// Test TLS 1.3 connection
	connState13 := &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		HandshakeComplete: true,
	}

	monitor.RecordTLSConnection("192.168.1.101:12345", connState13)

	metrics = monitor.GetMetrics()
	if metrics.TotalConnections != 2 {
		t.Error("Expected total connections to be 2")
	}
	if metrics.TLS13Connections != 1 {
		t.Error("Expected TLS 1.3 connections to be 1")
	}

	// Check cipher suite usage tracking
	if len(metrics.CipherSuiteUsage) != 2 {
		t.Error("Expected 2 cipher suites to be tracked")
	}

	// Check TLS version usage tracking
	if len(metrics.TLSVersionUsage) != 2 {
		t.Error("Expected 2 TLS versions to be tracked")
	}
}

func TestHandshakeFailureRecording(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Record handshake failures
	monitor.RecordTLSHandshakeFailure("192.168.1.100:12345", fmt.Errorf("certificate expired"))
	monitor.RecordTLSHandshakeFailure("192.168.1.101:12345", fmt.Errorf("unknown cipher"))

	metrics := monitor.GetMetrics()
	if metrics.FailedHandshakes != 2 {
		t.Error("Expected 2 failed handshakes")
	}

	// Check that events were recorded
	events := monitor.GetRecentEvents(time.Minute)
	handshakeFailures := 0
	for _, event := range events {
		if event.EventType == "handshake_failure" {
			handshakeFailures++
		}
	}

	if handshakeFailures != 2 {
		t.Error("Expected 2 handshake failure events")
	}
}

func TestCertificateErrorRecording(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Record certificate errors
	monitor.RecordCertificateError("192.168.1.100:12345", "example.com", fmt.Errorf("certificate has expired"))

	metrics := monitor.GetMetrics()
	if metrics.CertificateErrors != 1 {
		t.Error("Expected 1 certificate error")
	}

	// Check that event was recorded
	events := monitor.GetRecentEvents(time.Minute)
	certErrors := 0
	for _, event := range events {
		if event.EventType == "certificate_error" {
			certErrors++
		}
	}

	if certErrors != 1 {
		t.Error("Expected 1 certificate error event")
	}
}

func TestWeakCipherDetection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Test weak cipher detection
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}

	for _, cipher := range weakCiphers {
		if !monitor.isWeakCipherSuite(cipher) {
			t.Errorf("Expected cipher %x to be detected as weak", cipher)
		}
	}

	// Test strong cipher (should not be detected as weak)
	strongCipher := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	if monitor.isWeakCipherSuite(strongCipher) {
		t.Errorf("Expected cipher %x to not be detected as weak", strongCipher)
	}

	// Test recording connection with weak cipher
	connState := &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		CipherSuite:       tls.TLS_RSA_WITH_RC4_128_SHA,
		HandshakeComplete: true,
	}

	monitor.RecordTLSConnection("192.168.1.100:12345", connState)

	metrics := monitor.GetMetrics()
	if metrics.WeakCipherConnections != 1 {
		t.Error("Expected 1 weak cipher connection")
	}

	// Check that weak cipher event was recorded
	events := monitor.GetRecentEvents(time.Minute)
	weakCipherEvents := 0
	for _, event := range events {
		if event.EventType == "weak_cipher" {
			weakCipherEvents++
		}
	}

	if weakCipherEvents != 1 {
		t.Error("Expected 1 weak cipher event")
	}
}

func TestAlertThresholds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Set low thresholds for testing
	thresholds := TLSAlertThresholds{
		FailedHandshakeRate:  1.0,  // 1 failure per minute
		WeakCipherRate:       10.0, // 10% weak ciphers
		CertificateErrorRate: 1.0,  // 1 cert error per minute
		OldTLSVersionRate:    10.0, // 10% old TLS versions
		MaxEventsPerMinute:   5,    // 5 events per minute
	}
	monitor.SetAlertThresholds(thresholds)

	// Generate failed handshakes to trigger threshold
	monitor.RecordTLSHandshakeFailure("192.168.1.100:12345", fmt.Errorf("test error 1"))
	monitor.RecordTLSHandshakeFailure("192.168.1.101:12345", fmt.Errorf("test error 2"))

	// Check alert thresholds
	alerts := monitor.CheckAlertThresholds()

	// Should have at least one alert for exceeded failed handshake rate
	hasFailedHandshakeAlert := false
	for _, alert := range alerts {
		if alert.EventType == "threshold_exceeded" {
			if details, ok := alert.Details["threshold"].(string); ok && details == "failed_handshake_rate" {
				hasFailedHandshakeAlert = true
			}
		}
	}

	if !hasFailedHandshakeAlert {
		t.Error("Expected failed handshake rate alert to be triggered")
	}
}

func TestTLSMonitoringSecurityReport(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Record some activity
	connState := &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		HandshakeComplete: true,
	}
	monitor.RecordTLSConnection("192.168.1.100:12345", connState)
	monitor.RecordTLSHandshakeFailure("192.168.1.101:12345", fmt.Errorf("test error"))

	// Generate security report
	ctx := context.Background()
	report := monitor.GenerateSecurityReport(ctx, time.Hour)

	if report == nil {
		t.Fatal("Expected security report, got nil")
	}

	// Check required fields
	requiredFields := []string{
		"report_period",
		"generated_at",
		"metrics",
		"summary",
		"event_breakdown",
		"top_cipher_suites",
		"top_tls_versions",
		"recent_events",
	}

	for _, field := range requiredFields {
		if _, exists := report[field]; !exists {
			t.Errorf("Expected field %s in security report", field)
		}
	}

	// Check summary fields
	summary, ok := report["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected summary to be a map")
	}

	expectedSummaryFields := []string{
		"total_connections",
		"tls_connections",
		"tls_usage_rate",
		"tls13_usage_rate",
		"weak_cipher_rate",
		"failed_handshakes",
		"certificate_errors",
		"security_events_count",
	}

	for _, field := range expectedSummaryFields {
		if _, exists := summary[field]; !exists {
			t.Errorf("Expected summary field %s in report", field)
		}
	}
}

func TestMonitorEnableDisable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Monitor should be enabled by default
	if !monitor.enabled {
		t.Error("Expected monitor to be enabled by default")
	}

	// Disable monitor
	monitor.Disable()
	if monitor.enabled {
		t.Error("Expected monitor to be disabled")
	}

	// Test that recording doesn't work when disabled
	monitor.RecordTLSHandshakeFailure("192.168.1.100:12345", fmt.Errorf("test error"))
	metrics := monitor.GetMetrics()
	if metrics.FailedHandshakes != 0 {
		t.Error("Expected no failed handshakes to be recorded when monitor is disabled")
	}

	// Re-enable monitor
	monitor.Enable()
	if !monitor.enabled {
		t.Error("Expected monitor to be enabled")
	}

	// Test that recording works again
	monitor.RecordTLSHandshakeFailure("192.168.1.100:12345", fmt.Errorf("test error"))
	metrics = monitor.GetMetrics()
	if metrics.FailedHandshakes != 1 {
		t.Error("Expected 1 failed handshake to be recorded when monitor is enabled")
	}
}

func TestEventHistoryLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	// Set a low history limit for testing
	monitor.maxEventsHistory = 3

	// Record more events than the limit
	monitor.RecordTLSHandshakeFailure("192.168.1.100:12345", fmt.Errorf("error 1"))
	monitor.RecordTLSHandshakeFailure("192.168.1.101:12345", fmt.Errorf("error 2"))
	monitor.RecordTLSHandshakeFailure("192.168.1.102:12345", fmt.Errorf("error 3"))
	monitor.RecordTLSHandshakeFailure("192.168.1.103:12345", fmt.Errorf("error 4"))
	monitor.RecordTLSHandshakeFailure("192.168.1.104:12345", fmt.Errorf("error 5"))

	// Should only keep the last 3 events
	events := monitor.GetRecentEvents(time.Hour)
	if len(events) > 3 {
		t.Errorf("Expected at most 3 events, got %d", len(events))
	}
}

func TestTLSVersionNames(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	monitor := NewTLSMonitor(logger)

	tests := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x9999, "Unknown (0x9999)"}, // Unknown version
	}

	for _, tt := range tests {
		name := monitor.getTLSVersionName(tt.version)
		if name != tt.name {
			t.Errorf("Expected TLS version name %s, got %s", tt.name, name)
		}
	}
}
