package main

import (
	"log"
	"time"

	"github.com/busybox42/elemta/cmd/elemta/commands"
	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/server"
	"github.com/busybox42/elemta/internal/smtp"
)

func main() {
	commands.Execute()
}

// initializeMetrics sets up metrics collection and monitoring
func initializeMetrics(config *config.Config, logger *log.Logger) {
	// Initialize core metrics
	smtp.GetMetrics()
	logger.Println("Core metrics initialized")

	// Start metrics server if enabled
	if config.TLS.Enabled {
		logger.Printf("Starting metrics monitoring")

		// Get certificate directory
		certDir := "/var/elemta/certs" // Default location
		if config.TLS.LetsEncrypt.Enabled && config.TLS.LetsEncrypt.CacheDir != "" {
			certDir = config.TLS.LetsEncrypt.CacheDir
		}

		// Start certificate metrics monitoring in a goroutine
		go server.MonitorCertificates(certDir, 12*time.Hour)
		logger.Printf("TLS certificate monitoring started for directory: %s", certDir)
	}
}
