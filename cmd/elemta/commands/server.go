package commands

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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
	if cfg.Server.TLS {
		smtpConfig.TLS = &smtp.TLSConfig{
			Enabled:  true,
			CertFile: cfg.Server.CertFile,
			KeyFile:  cfg.Server.KeyFile,
		}
	}

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

	// Log server configuration details
	fmt.Printf("Server configuration details:\n")
	fmt.Printf("  Server hostname: %s\n", cfg.Server.Hostname)
	fmt.Printf("  Server listening on: %s\n", cfg.Server.Listen)
	fmt.Printf("  Queue directory: %s\n", cfg.QueueDir)
	fmt.Printf("  Max message size: %d bytes\n", smtpConfig.MaxSize)

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
