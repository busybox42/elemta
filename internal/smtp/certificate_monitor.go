package smtp

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CertificateMonitor provides enhanced certificate monitoring
type CertificateMonitor struct {
	certificates map[string]*CertificateStatus
	mutex        sync.RWMutex
	logger       *slog.Logger
	alerter      CertificateAlerter
}

// CertificateStatus tracks the status of a certificate
type CertificateStatus struct {
	Certificate     *x509.Certificate
	Hostname        string
	ExpiresAt       time.Time
	DaysUntilExpiry int
	LastChecked     time.Time
	Status          string // "valid", "expiring_soon", "expired", "invalid"
	Alerts          []CertificateAlert
}

// CertificateAlert represents an alert about a certificate
type CertificateAlert struct {
	Type         string // "expiration", "invalid", "weak_algorithm"
	Severity     string // "low", "medium", "high", "critical"
	Message      string
	CreatedAt    time.Time
	Acknowledged bool
}

// CertificateAlerter interface for sending certificate alerts
type CertificateAlerter interface {
	SendAlert(alert CertificateAlert) error
}

// NewCertificateMonitor creates a new certificate monitor
func NewCertificateMonitor(logger *slog.Logger, alerter CertificateAlerter) *CertificateMonitor {
	monitor := &CertificateMonitor{
		certificates: make(map[string]*CertificateStatus),
		logger:       logger,
		alerter:      alerter,
	}

	// Start background monitoring
	go monitor.startBackgroundMonitoring()

	return monitor
}

// startBackgroundMonitoring starts the background certificate monitoring
func (cm *CertificateMonitor) startBackgroundMonitoring() {
	ticker := time.NewTicker(time.Hour) // Check every hour
	defer ticker.Stop()

	for range ticker.C {
		cm.CheckAllCertificates()
	}
}

// MonitorCertificate adds a certificate to monitoring
func (cm *CertificateMonitor) MonitorCertificate(hostname string, cert *x509.Certificate) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	status := &CertificateStatus{
		Certificate:     cert,
		Hostname:        hostname,
		ExpiresAt:       cert.NotAfter,
		DaysUntilExpiry: daysUntilExpiry,
		LastChecked:     now,
		Status:          cm.determineCertificateStatus(cert, now),
		Alerts:          []CertificateAlert{},
	}

	cm.certificates[hostname] = status

	// Check for immediate alerts
	cm.checkCertificateAlerts(status)

	cm.logger.Info("Certificate added to monitoring",
		"hostname", hostname,
		"expires_at", cert.NotAfter,
		"days_until_expiry", daysUntilExpiry,
		"status", status.Status,
	)
}

// determineCertificateStatus determines the current status of a certificate
func (cm *CertificateMonitor) determineCertificateStatus(cert *x509.Certificate, now time.Time) string {
	if now.After(cert.NotAfter) {
		return "expired"
	}

	if now.Before(cert.NotBefore) {
		return "invalid"
	}

	daysUntilExpiry := cert.NotAfter.Sub(now).Hours() / 24
	if daysUntilExpiry <= 7 {
		return "expiring_soon"
	}

	return "valid"
}

// checkCertificateAlerts checks for certificate alerts and sends them
func (cm *CertificateMonitor) checkCertificateAlerts(status *CertificateStatus) {
	now := time.Now()

	// Expiration alerts with different thresholds
	thresholds := []struct {
		days     int
		severity string
	}{
		{1, "critical"},
		{7, "high"},
		{30, "medium"},
		{90, "low"},
	}

	for _, threshold := range thresholds {
		if status.DaysUntilExpiry <= threshold.days && status.DaysUntilExpiry > 0 {
			// Check if we've already sent this alert recently
			if !cm.hasRecentAlert(status, "expiration", threshold.severity) {
				alert := CertificateAlert{
					Type:      "expiration",
					Severity:  threshold.severity,
					Message:   fmt.Sprintf("Certificate for %s expires in %d days", status.Hostname, status.DaysUntilExpiry),
					CreatedAt: now,
				}
				status.Alerts = append(status.Alerts, alert)
				cm.sendAlert(alert)
			}
			break // Only send one alert per check
		}
	}

	// Check for expired certificates
	if status.Status == "expired" && !cm.hasRecentAlert(status, "expiration", "critical") {
		alert := CertificateAlert{
			Type:      "expiration",
			Severity:  "critical",
			Message:   fmt.Sprintf("Certificate for %s has EXPIRED", status.Hostname),
			CreatedAt: now,
		}
		status.Alerts = append(status.Alerts, alert)
		cm.sendAlert(alert)
	}

	// Check for invalid certificates (not yet valid)
	if status.Status == "invalid" && !cm.hasRecentAlert(status, "invalid", "high") {
		alert := CertificateAlert{
			Type:      "invalid",
			Severity:  "high",
			Message:   fmt.Sprintf("Certificate for %s is not yet valid", status.Hostname),
			CreatedAt: now,
		}
		status.Alerts = append(status.Alerts, alert)
		cm.sendAlert(alert)
	}
}

// hasRecentAlert checks if a similar alert was sent recently (within 24 hours)
func (cm *CertificateMonitor) hasRecentAlert(status *CertificateStatus, alertType, severity string) bool {
	now := time.Now()
	for _, alert := range status.Alerts {
		if alert.Type == alertType && alert.Severity == severity {
			if now.Sub(alert.CreatedAt) < 24*time.Hour {
				return true
			}
		}
	}
	return false
}

// sendAlert sends a certificate alert
func (cm *CertificateMonitor) sendAlert(alert CertificateAlert) {
	if cm.alerter != nil {
		if err := cm.alerter.SendAlert(alert); err != nil {
			cm.logger.Error("Failed to send certificate alert",
				"type", alert.Type,
				"severity", alert.Severity,
				"message", alert.Message,
				"error", err,
			)
		}
	}

	// Always log the alert
	cm.logger.Warn("Certificate Alert",
		"type", alert.Type,
		"severity", alert.Severity,
		"message", alert.Message,
	)
}

// CheckAllCertificates performs a check of all monitored certificates
func (cm *CertificateMonitor) CheckAllCertificates() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()

	for hostname, status := range cm.certificates {
		oldStatus := status.Status
		status.Status = cm.determineCertificateStatus(status.Certificate, now)
		status.DaysUntilExpiry = int(status.ExpiresAt.Sub(now).Hours() / 24)
		status.LastChecked = now

		// Check for status changes
		if oldStatus != status.Status {
			cm.logger.Info("Certificate status changed",
				"hostname", hostname,
				"old_status", oldStatus,
				"new_status", status.Status,
				"days_until_expiry", status.DaysUntilExpiry,
			)
		}

		// Check for new alerts
		cm.checkCertificateAlerts(status)
	}

	cm.logger.Debug("Certificate monitoring check completed",
		"certificates_checked", len(cm.certificates),
	)
}

// GetCertificateStatus returns the status of a monitored certificate
func (cm *CertificateMonitor) GetCertificateStatus(hostname string) (*CertificateStatus, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	status, exists := cm.certificates[hostname]
	return status, exists
}

// GetAllCertificateStatuses returns all monitored certificate statuses
func (cm *CertificateMonitor) GetAllCertificateStatuses() map[string]*CertificateStatus {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]*CertificateStatus)
	for k, v := range cm.certificates {
		result[k] = v
	}
	return result
}

// GetCertificateHealthReport generates a comprehensive health report
func (cm *CertificateMonitor) GetCertificateHealthReport() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	report := make(map[string]interface{})

	statusCounts := map[string]int{
		"valid":         0,
		"expiring_soon": 0,
		"expired":       0,
		"invalid":       0,
	}

	alertCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, status := range cm.certificates {
		statusCounts[status.Status]++

		// Count recent alerts (within 24 hours)
		now := time.Now()
		for _, alert := range status.Alerts {
			if now.Sub(alert.CreatedAt) < 24*time.Hour {
				alertCounts[alert.Severity]++
			}
		}
	}

	report["total_certificates"] = len(cm.certificates)
	report["status_counts"] = statusCounts
	report["alert_counts"] = alertCounts
	report["last_check"] = time.Now()

	return report
}

// RemoveCertificate removes a certificate from monitoring
func (cm *CertificateMonitor) RemoveCertificate(hostname string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	delete(cm.certificates, hostname)

	cm.logger.Info("Certificate removed from monitoring",
		"hostname", hostname,
	)
}

// DefaultCertificateAlerter provides basic alert functionality
type DefaultCertificateAlerter struct {
	logger *slog.Logger
}

// NewDefaultCertificateAlerter creates a default certificate alerter
func NewDefaultCertificateAlerter(logger *slog.Logger) *DefaultCertificateAlerter {
	return &DefaultCertificateAlerter{logger: logger}
}

// SendAlert sends an alert (default implementation just logs)
func (dca *DefaultCertificateAlerter) SendAlert(alert CertificateAlert) error {
	dca.logger.Warn("CERTIFICATE ALERT",
		"type", alert.Type,
		"severity", alert.Severity,
		"message", alert.Message,
		"created_at", alert.CreatedAt,
	)

	// In production, this would send emails, Slack notifications, etc.
	// Example implementation:
	// - Send email alerts for critical/high severity
	// - Send Slack notifications for medium/low severity
	// - Create monitoring system tickets for expired certificates

	return nil
}
