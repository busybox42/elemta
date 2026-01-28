package commands

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/busybox42/elemta/internal/logging"
	"github.com/busybox42/elemta/internal/server"
	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

// Define flags for server command
var (
	devMode        bool
	noAuthRequired bool
	portFlag       int

	// ServerRunFunc allows mocking the server run function for testing
	ServerRunFunc = func(cmd *cobra.Command, args []string) error {
		startServer()
		return nil
	}
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Elemta MTA server",
	Long:  `Start the Elemta Mail Transfer Agent server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ServerRunFunc(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Add flags to the server command
	serverCmd.Flags().BoolVar(&devMode, "dev", false, "Run server in development mode with simplified settings")
	serverCmd.Flags().BoolVar(&noAuthRequired, "no-auth-required", false, "Disable authentication requirement for server")
	serverCmd.Flags().IntVar(&portFlag, "port", 0, "Override the port to listen on (e.g. --port 2525)")
}

func startServer() {
	slog.Info("Starting Elemta MTA server")

	// Load configuration
	if cfg == nil {
		slog.Error("Configuration not loaded")
		os.Exit(1)
	}

	// Initialize logging with configured level
	logLevel := "INFO" // Default to INFO for production
	if cfg.Logging.Level != "" {
		logLevel = cfg.Logging.Level
	}
	if devMode {
		logLevel = "DEBUG" // Override to DEBUG in dev mode
	}
	logging.InitializeLogging(logLevel)

	slog.Info("Elemta MTA server starting", "event_type", "system",
		"hostname", cfg.Hostname,
		"listen_addr", cfg.ListenAddr,
		"log_level", logLevel,
		"dev_mode", devMode)

	// Apply flag overrides
	if devMode {
		slog.Info("Running in DEVELOPMENT mode - using simplified settings")
		cfg.Server.TLS = false // Disable TLS in dev mode

		// Set other dev mode settings here if needed
		if cfg.Queue.Dir == "" {
			cfg.Queue.Dir = "./queue" // Use local queue directory in dev mode
		}

		// Change to non-privileged port in dev mode if using default port 25
		if cfg.Server.Listen == ":25" {
			// Try various development ports (2525-2528) to find one that works
			devPorts := []string{":2525", ":2526", ":2527", ":2528"}
			originalPort := cfg.Server.Listen

			for _, port := range devPorts {
				// Try to listen on the port to see if it's available
				listener, err := net.Listen("tcp", port)
				if err == nil {
					// Close the listener, we'll reopen it in the server
					listener.Close()
					cfg.Server.Listen = port
					slog.Info("DEV MODE: Changed listen port (non-privileged)", "original_port", originalPort, "new_port", port)
					break
				}
			}

			if cfg.Server.Listen == ":25" {
				slog.Warn("Could not find an available development port. Will try to use port 25, but this may fail without privileges.")
			}
		}
	}

	// Override port if specified via command line
	if portFlag > 0 {
		// Extract host part from current listen address
		host := ""
		parts := strings.Split(cfg.Server.Listen, ":")
		if len(parts) > 1 && parts[0] != "" {
			host = parts[0]
		}

		// Create new listen address with specified port
		cfg.Server.Listen = fmt.Sprintf("%s:%d", host, portFlag)
		slog.Info("Overriding listen port", "address", cfg.Server.Listen)
	}

	if noAuthRequired && cfg.Auth != nil {
		slog.Info("Authentication requirement disabled via command line flag")
		cfg.Auth.Required = false
	}

	// Create SMTP server configuration
	slog.Debug("queue configuration",
		"queue_dir_flat", cfg.QueueDir,
		"queue_dir_nested", cfg.Queue.Dir)

	// Use Queue.Dir if QueueDir is empty (handle both config formats)
	queueDir := cfg.QueueDir
	if queueDir == "" && cfg.Queue.Dir != "" {
		slog.Debug("using nested queue directory configuration")
		queueDir = cfg.Queue.Dir
	}
	if queueDir == "" {
		queueDir = "/app/queue" // Fallback default
		slog.Debug("using fallback queue directory", "queue_dir", queueDir)
	}

	smtpConfig := &smtp.Config{
		Hostname:     cfg.Hostname,     // Use top-level hostname
		ListenAddr:   cfg.ListenAddr,   // Use top-level listen_addr
		QueueDir:     queueDir,         // Use queue directory (prioritize flat, fallback to nested)
		MaxSize:      cfg.MaxSize,      // Use top-level max_size
		LocalDomains: cfg.LocalDomains, // Use top-level local_domains
		TLS:          cfg.TLS,
		DevMode:      devMode || cfg.Server.DevMode,
	}

	slog.Info("SMTP Config", "hostname", smtpConfig.Hostname, "queue_dir", smtpConfig.QueueDir, "local_domains", smtpConfig.LocalDomains)

	// Map authentication config
	smtpConfig.Auth = cfg.Auth

	// Map delivery config
	smtpConfig.Delivery = cfg.Delivery

	// Map resources config (for Valkey integration)
	smtpConfig.Resources = cfg.Resources

	// Map metrics config
	smtpConfig.Metrics = cfg.Metrics
	if cfg.Metrics != nil {
		slog.Debug("metrics configuration mapped",
			"enabled", cfg.Metrics.Enabled,
			"listen_addr", cfg.Metrics.ListenAddr)
	} else {
		slog.Debug("metrics configuration not present")
	}

	if cfg.TLS != nil {
		slog.Debug("TLS configuration present",
			"enabled", cfg.TLS.Enabled,
			"cert_file", cfg.TLS.CertFile,
			"key_file", cfg.TLS.KeyFile)
	} else {
		slog.Debug("TLS configuration not present")
	}
	if smtpConfig.TLS != nil {
		slog.Debug("SMTP TLS configuration mapped",
			"enabled", smtpConfig.TLS.Enabled)
	} else {
		slog.Debug("SMTP TLS configuration not present")
	}

	// Map plugins config
	if len(cfg.Plugins.Enabled) > 0 {
		smtpConfig.Plugins = &smtp.PluginConfig{
			Enabled:    true,
			PluginPath: cfg.Plugins.Directory,
			Plugins:    cfg.Plugins.Enabled,
		}
	}

	// Restore certDir logic for certificate monitoring
	certDir := "/var/elemta/certs" // Default certificate directory
	if cfg.TLS != nil {
		if cfg.TLS.LetsEncrypt.Enabled && cfg.TLS.LetsEncrypt.CacheDir != "" {
			certDir = cfg.TLS.LetsEncrypt.CacheDir
		} else if cfg.TLS.CertFile != "" {
			certDir = getDirectoryFromPath(cfg.TLS.CertFile)
		}
	}

	// Configure Queue Processor from config
	smtpConfig.QueueProcessorEnabled = cfg.QueueProcessor.Enabled
	smtpConfig.QueueProcessInterval = cfg.QueueProcessor.Interval
	smtpConfig.QueueWorkers = cfg.QueueProcessor.Workers
	slog.Info("Queue processor config",
		"enabled", cfg.QueueProcessor.Enabled,
		"interval", cfg.QueueProcessor.Interval,
		"workers", cfg.QueueProcessor.Workers)

	// Create SMTP server
	slog.Info("Creating SMTP server")
	server, err := smtp.NewServer(smtpConfig)
	if err != nil {
		slog.Error("Error creating server", "error", err)
		os.Exit(1)
	}

	// Start SMTP server
	slog.Info("Starting SMTP server")
	if err := server.Start(); err != nil {
		slog.Error("Error starting server", "error", err)
		os.Exit(1)
	}

	// Initialize certificate monitoring if TLS is enabled
	if cfg.Server.TLS {
		// Start certificate metrics monitoring in a goroutine
		go initializeCertificateMonitoring(certDir)
	}

	// Log server configuration details
	slog.Info("Server configuration details",
		"hostname", cfg.Server.Hostname,
		"listen_addr", cfg.Server.Listen,
		"queue_dir", cfg.Queue.Dir,
		"max_size", smtpConfig.MaxSize,
		"queue_processor", smtpConfig.QueueProcessorEnabled,
		"tls_enabled", cfg.Server.TLS,
		"cert_dir", certDir,
		"dev_mode", devMode,
		"auth_required", func() bool {
			if cfg.Auth != nil {
				return cfg.Auth.Required
			}
			return false
		}())

	slog.Info("Elemta MTA starting", "event_type", "system", "listen_addr", cfg.Server.Listen)
	slog.Info("SMTP server started successfully")

	// Wait for signal to quit
	slog.Info("Server running. Press Ctrl+C to stop")

	// Set up signal channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Wait()
	}()

	select {
	case <-sigChan:
		slog.Info("Shutdown signal received, stopping server")
	case err := <-errChan:
		if err != nil {
			slog.Error("Server error occurred", "error", err)
		} else {
			slog.Info("Server stopped normally")
		}
	}

	// Perform graceful shutdown
	slog.Info("Shutting down server")
	server.Close()
}

// initializeCertificateMonitoring starts monitoring TLS certificates
func initializeCertificateMonitoring(certDir string) {
	slog.Info("Starting TLS certificate monitoring", "directory", certDir)

	// Initial scan of certificates
	if err := server.GetCertificateMetrics(certDir+"/fullchain.pem", ""); err != nil {
		slog.Warn("Initial certificate metrics collection failed", "error", err)
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
