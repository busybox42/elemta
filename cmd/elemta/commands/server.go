package commands

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	Run: func(cmd *cobra.Command, args []string) {
		ServerRunFunc(cmd, args)
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
	fmt.Println("Starting Elemta MTA server...")

	// Load configuration
	if cfg == nil {
		fmt.Fprintf(os.Stderr, "Error: Configuration not loaded\n")
		os.Exit(1)
	}

	// Apply flag overrides
	if devMode {
		fmt.Println("Running in DEVELOPMENT mode - using simplified settings")
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
					fmt.Printf("DEV MODE: Changed listen port from %s to %s (non-privileged)\n", originalPort, port)
					break
				}
			}

			if cfg.Server.Listen == ":25" {
				fmt.Println("WARNING: Could not find an available development port. Will try to use port 25, but this may fail without privileges.")
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
		fmt.Printf("Overriding listen port to: %s\n", cfg.Server.Listen)
	}

	if noAuthRequired && cfg.Auth != nil {
		fmt.Println("Authentication requirement disabled via command line flag")
		cfg.Auth.Required = false
	}

	// Create SMTP server configuration
	smtpConfig := &smtp.Config{
		Hostname:     cfg.Server.Hostname,
		ListenAddr:   cfg.Server.Listen,
		QueueDir:     cfg.Queue.Dir,
		MaxSize:      10 * 1024 * 1024, // Use 10MB default if not specified
		LocalDomains: cfg.Server.LocalDomains, // Map local domains from main config
		TLS:          cfg.TLS,
		DevMode:      devMode, // Pass dev mode flag to SMTP server
	}

	// Map authentication config
	smtpConfig.Auth = cfg.Auth

	// Map delivery config
	smtpConfig.Delivery = cfg.Delivery

	fmt.Printf("[DEBUG] cfg.TLS: %+v\n", *cfg.TLS)
	fmt.Printf("[DEBUG] smtpConfig.TLS: %+v\n", *smtpConfig.TLS)

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
	if cfg.TLS.LetsEncrypt.Enabled && cfg.TLS.LetsEncrypt.CacheDir != "" {
		certDir = cfg.TLS.LetsEncrypt.CacheDir
	} else if cfg.TLS.CertFile != "" {
		certDir = getDirectoryFromPath(cfg.TLS.CertFile)
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
	fmt.Printf("  Queue directory: %s\n", cfg.Queue.Dir)
	fmt.Printf("  Max message size: %d bytes\n", smtpConfig.MaxSize)
	fmt.Printf("  Queue processor: %v\n", smtpConfig.QueueProcessorEnabled)
	if cfg.Server.TLS {
		fmt.Printf("  TLS enabled: Yes\n")
		fmt.Printf("  Certificate directory: %s\n", certDir)
	}
	fmt.Printf("  Development mode: %v\n", devMode)
	if cfg.Auth != nil {
		fmt.Printf("  Authentication required: %v\n", cfg.Auth.Required)
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
