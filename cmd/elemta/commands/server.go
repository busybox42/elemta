package commands

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/busybox42/elemta/internal/server"
	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Elemta MTA server",
	Long:  `Start the Elemta Mail Transfer Agent server`,
	Run: func(cmd *cobra.Command, args []string) {
		startServer()
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

func startServer() {
	fmt.Println("Starting Elemta MTA server...")

	// Load configuration
	if cfg == nil {
		fmt.Fprintf(os.Stderr, "Error: Configuration not loaded\n")
		os.Exit(1)
	}

	// Create SMTP server configuration
	smtpConfig := &smtp.Config{
		Hostname:   cfg.Server.Hostname,
		ListenAddr: cfg.Server.Listen,
		QueueDir:   cfg.QueueDir,
		MaxSize:    10 * 1024 * 1024, // Use 10MB default if not specified
	}

	// Configure TLS if enabled
	certDir := "/var/elemta/certs" // Default certificate directory
	if cfg.Server.TLS {
		smtpConfig.TLS = &smtp.TLSConfig{
			Enabled:  true,
			CertFile: cfg.Server.CertFile,
			KeyFile:  cfg.Server.KeyFile,
		}

		// Get certificate directory from configuration if available
		if cfg.TLS.LetsEncrypt.Enabled && cfg.TLS.LetsEncrypt.CacheDir != "" {
			certDir = cfg.TLS.LetsEncrypt.CacheDir
		} else if cfg.Server.CertFile != "" {
			// Extract directory from cert file path
			certDir = getDirectoryFromPath(cfg.Server.CertFile)
		}
	}

	// Configure Queue Processor from config
	smtpConfig.QueueProcessorEnabled = cfg.QueueProcessor.Enabled
	smtpConfig.QueueProcessInterval = cfg.QueueProcessor.Interval
	smtpConfig.QueueWorkers = cfg.QueueProcessor.Workers
	fmt.Printf("Queue processor config: enabled=%v, interval=%d, workers=%d\n",
		cfg.QueueProcessor.Enabled,
		cfg.QueueProcessor.Interval,
		cfg.QueueProcessor.Workers)

	// Create SMTP server
	fmt.Println("Creating SMTP server...")
	server, err := smtp.NewServer(smtpConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		os.Exit(1)
	}

	// Start SMTP server
	fmt.Println("Starting SMTP server...")
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

	// Initialize certificate monitoring if TLS is enabled
	if cfg.Server.TLS {
		// Start certificate metrics monitoring in a goroutine
		go initializeCertificateMonitoring(certDir)
	}

	// Log server configuration details
	fmt.Printf("Server configuration details:\n")
	fmt.Printf("  Server hostname: %s\n", cfg.Server.Hostname)
	fmt.Printf("  Server listening on: %s\n", cfg.Server.Listen)
	fmt.Printf("  Queue directory: %s\n", cfg.QueueDir)
	fmt.Printf("  Max message size: %d bytes\n", smtpConfig.MaxSize)
	fmt.Printf("  Queue processor: %v\n", smtpConfig.QueueProcessorEnabled)
	if cfg.Server.TLS {
		fmt.Printf("  TLS enabled: Yes\n")
		fmt.Printf("  Certificate directory: %s\n", certDir)
	}

	log.Printf("Elemta MTA starting on %s", cfg.Server.Listen)
	fmt.Println("SMTP server started successfully!")

	// Wait for signal to quit
	fmt.Println("Server running. Press Ctrl+C to stop.")

	// Set up signal channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan

	// Perform graceful shutdown
	fmt.Println("Shutting down server...")
	server.Close()
}

// initializeCertificateMonitoring starts monitoring TLS certificates
func initializeCertificateMonitoring(certDir string) {
	logger := log.New(os.Stdout, "[CertMonitor] ", log.LstdFlags)
	logger.Printf("Starting TLS certificate monitoring for directory: %s", certDir)

	// Initial scan of certificates
	if err := server.GetCertificateMetrics(certDir+"/fullchain.pem", ""); err != nil {
		logger.Printf("Initial certificate metrics collection failed: %v", err)
	}

	// Start periodic monitoring
	server.MonitorCertificates(certDir, 12*time.Hour)
}

// getDirectoryFromPath extracts the directory part from a file path
func getDirectoryFromPath(path string) string {
	if path == "" {
		return "/var/elemta/certs"
	}

	// Find the last separator
	lastSep := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			lastSep = i
			break
		}
	}

	if lastSep == -1 {
		return "."
	}

	return path[:lastSep]
}
