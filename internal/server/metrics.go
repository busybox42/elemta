package server

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// TLS Certificate metrics
	tlsCertificateExpiryGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "elemta_tls_certificate_expiry_seconds",
			Help: "Time in seconds until TLS certificate expiry",
		},
		[]string{"domain", "issuer"},
	)

	tlsCertificateValidGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "elemta_tls_certificate_valid",
			Help: "Whether the TLS certificate is valid (1) or not (0)",
		},
		[]string{"domain", "issuer"},
	)

	letsEncryptRenewalGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "elemta_letsencrypt_renewal_status",
			Help: "Status of Let's Encrypt certificate renewal (1 = success, 0 = failed)",
		},
		[]string{"domain"},
	)

	letsEncryptRenewalAttemptsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "elemta_letsencrypt_renewal_attempts_total",
			Help: "Total number of Let's Encrypt certificate renewal attempts",
		},
		[]string{"domain", "status"},
	)

	letsEncryptRenewalTimestampGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "elemta_letsencrypt_last_renewal_timestamp",
			Help: "Timestamp of the last Let's Encrypt certificate renewal attempt",
		},
		[]string{"domain", "status"},
	)
)

// GetCertificateMetrics collects and exposes TLS certificate metrics
func GetCertificateMetrics(certPath string, domain string) error {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Printf("Failed to read certificate file: %v, path: %s", err, certPath)
		return err
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Printf("Failed to parse certificate PEM, path: %s", certPath)
		return err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse certificate: %v, path: %s", err, certPath)
		return err
	}

	// Extract the domain if not provided
	if domain == "" {
		if len(cert.DNSNames) > 0 {
			domain = cert.DNSNames[0]
		} else {
			domain = cert.Subject.CommonName
		}
	}

	issuer := cert.Issuer.CommonName
	now := time.Now()
	expiryTime := cert.NotAfter
	secondsUntilExpiry := expiryTime.Sub(now).Seconds()

	// Set metrics
	tlsCertificateExpiryGauge.WithLabelValues(domain, issuer).Set(secondsUntilExpiry)

	// Check if certificate is valid (not expired and not yet to be valid)
	isValid := float64(0)
	if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
		isValid = 1
	}
	tlsCertificateValidGauge.WithLabelValues(domain, issuer).Set(isValid)

	log.Printf("Updated certificate metrics for domain: %s, issuer: %s, expiry: %s, days until expiry: %.2f, valid: %t",
		domain, issuer, expiryTime.Format(time.RFC3339), secondsUntilExpiry/86400, isValid == 1)

	return nil
}

// RecordCertificateRenewal records a certificate renewal attempt in metrics
func RecordCertificateRenewal(domain string, success bool) {
	status := "success"
	statusValue := float64(1)
	if !success {
		status = "failed"
		statusValue = 0
	}

	// Update metrics
	letsEncryptRenewalGauge.WithLabelValues(domain).Set(statusValue)
	letsEncryptRenewalAttemptsCounter.WithLabelValues(domain, status).Inc()
	letsEncryptRenewalTimestampGauge.WithLabelValues(domain, status).Set(float64(time.Now().Unix()))

	log.Printf("Recorded certificate renewal attempt for domain: %s, status: %s", domain, status)
}

// MonitorCertificates periodically checks certificate status and updates metrics
func MonitorCertificates(certDir string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Starting certificate monitoring for directory: %s, interval: %s",
		certDir, interval.String())

	// Run immediately on startup
	checkCertificates(certDir)

	for range ticker.C {
		checkCertificates(certDir)
	}
}

// checkCertificates scans the certificate directory and updates metrics
func checkCertificates(certDir string) {
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		log.Printf("Certificate directory does not exist: %s", certDir)
		return
	}

	// Look for .pem, .crt, and .cert files
	certFiles, err := filepath.Glob(filepath.Join(certDir, "*.pem"))
	if err == nil {
		crtFiles, err := filepath.Glob(filepath.Join(certDir, "*.crt"))
		if err == nil {
			certFiles = append(certFiles, crtFiles...)
		}

		certExtFiles, err := filepath.Glob(filepath.Join(certDir, "*.cert"))
		if err == nil {
			certFiles = append(certFiles, certExtFiles...)
		}
	}

	if len(certFiles) == 0 {
		log.Printf("No certificate files found in directory: %s", certDir)
		return
	}

	for _, certFile := range certFiles {
		// Skip private key files
		if filepath.Base(certFile) == "privkey.pem" {
			continue
		}

		err := GetCertificateMetrics(certFile, "")
		if err != nil {
			log.Printf("Failed to get certificate metrics: %v, file: %s", err, certFile)
		}
	}
}
