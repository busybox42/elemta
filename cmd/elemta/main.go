package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/busybox42/elemta/internal/api"
	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

var (
	configPath string
	version    = "dev"
	commit     = "unknown"
	date       = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "elemta",
		Short: "Elemta - High-performance SMTP server",
		Long: `Elemta is a high-performance, carrier-grade Mail Transfer Agent (MTA) 
written in Go with a modular plugin architecture for enterprise email processing.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to configuration file")

	// Add subcommands
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the SMTP server",
	Long:  "Start the Elemta SMTP server with optional API and web interface",
	RunE:  runServer,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Elemta %s\n", cmd.Root().Version)
		fmt.Printf("Commit: %s\n", commit)
		fmt.Printf("Built: %s\n", date)
	},
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web interface server",
	Long:  "Start the web interface server for managing Elemta via browser",
	RunE:  runWebServer,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long:  "Commands for generating, validating, and managing Elemta configuration",
}

func init() {
	// Server command flags
	serverCmd.Flags().Bool("api", false, "enable API server")
	serverCmd.Flags().Bool("web", false, "enable web interface")
	serverCmd.Flags().String("listen", "", "SMTP server listen address (overrides config)")
	serverCmd.Flags().String("hostname", "", "server hostname (overrides config)")

	// Web command flags
	webCmd.Flags().String("listen", "0.0.0.0:8025", "web server listen address")
	webCmd.Flags().Bool("auth-enabled", true, "enable authentication")
	webCmd.Flags().String("queue-dir", "/app/queue", "queue directory path")
	webCmd.Flags().String("web-root", "/app/web/static", "web static files root directory")

	// Config subcommands
	configCmd.AddCommand(&cobra.Command{
		Use:   "generate",
		Short: "Generate default configuration file",
		RunE:  generateConfig,
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE:  validateConfig,
	})
}

func runServer(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override config with command line flags
	if hostname, _ := cmd.Flags().GetString("hostname"); hostname != "" {
		cfg.Server.Hostname = hostname
	}
	if listen, _ := cmd.Flags().GetString("listen"); listen != "" {
		cfg.Server.Listen = listen
	}	// Ensure queue directories exist
	if err := cfg.EnsureQueueDirectory(); err != nil {
		return fmt.Errorf("failed to setup queue directories: %w", err)
	}

	// Create SMTP configuration
	smtpConfig := &smtp.Config{
		Hostname:   cfg.Server.Hostname,
		ListenAddr: cfg.Server.Listen,
		QueueDir:   cfg.Queue.Dir,
		TLS:        cfg.TLS,
		Auth:       cfg.Auth,
		Delivery:   cfg.Delivery,
		Plugins: &smtp.PluginConfig{
			Enabled:    len(cfg.Plugins.Enabled) > 0,
			PluginPath: cfg.Plugins.Directory,
			Plugins:    cfg.Plugins.Enabled,
		},
	}

	// Create and start SMTP server
	log.Printf("Starting Elemta SMTP server...")
	smtpServer, err := smtp.NewServer(smtpConfig)
	if err != nil {
		return fmt.Errorf("failed to create SMTP server: %w", err)
	}

	// Start SMTP server in goroutine
	serverErrors := make(chan error, 2)
	go func() {
		log.Printf("SMTP server listening on %s", smtpConfig.ListenAddr)
		if err := smtpServer.Start(); err != nil {
			serverErrors <- fmt.Errorf("SMTP server error: %w", err)
		}
	}()	// Start API server if enabled
	var apiServer *api.Server
	if apiEnabled, _ := cmd.Flags().GetBool("api"); apiEnabled {
		apiConfig := &api.Config{
			Enabled:     true,
			ListenAddr:  "127.0.0.1:8025", // Default API port
			WebRoot:     "./web/static",
			AuthEnabled: true,
		}

		apiServer, err = api.NewServer(apiConfig, cfg.Queue.Dir)
		if err != nil {
			log.Printf("Warning: failed to create API server: %v", err)
		} else {
			go func() {
				log.Printf("API server listening on %s", apiConfig.ListenAddr)
				if err := apiServer.Start(); err != nil {
					serverErrors <- fmt.Errorf("API server error: %w", err)
				}
			}()
		}
	}

	// Start queue processor if enabled
	if cfg.QueueProcessor.Enabled {
		queueMgr := queue.NewManager(cfg.Queue.Dir)
		deliveryHandler := queue.NewSMTPDeliveryHandler()
		processorConfig := queue.ProcessorConfig{
			Enabled:       cfg.QueueProcessor.Enabled,
			Interval:      time.Duration(cfg.QueueProcessor.Interval) * time.Second,
			MaxConcurrent: cfg.QueueProcessor.Workers,
		}
		processor := queue.NewProcessor(queueMgr, processorConfig, deliveryHandler)

		go func() {
			log.Printf("Queue processor starting with %d workers", cfg.QueueProcessor.Workers)
			if err := processor.Start(); err != nil {
				serverErrors <- fmt.Errorf("Queue processor error: %w", err)
			}
		}()
	}	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Elemta server started successfully. Press Ctrl+C to stop.")

	// Wait for shutdown signal or server error
	select {
	case sig := <-signalChan:
		log.Printf("Received signal %v, shutting down gracefully...", sig)
	case err := <-serverErrors:
		log.Printf("Server error: %v", err)
		return err
	}

	// Graceful shutdown
	log.Println("Shutting down servers...")
	
	if err := smtpServer.Close(); err != nil {
		log.Printf("Error stopping SMTP server: %v", err)
	}

	if apiServer != nil {
		if err := apiServer.Stop(); err != nil {
			log.Printf("Error stopping API server: %v", err)
		}
	}

	log.Println("Shutdown complete")
	return nil
}

func runWebServer(cmd *cobra.Command, args []string) error {
	// Get command flags
	listenAddr, _ := cmd.Flags().GetString("listen")
	authEnabled, _ := cmd.Flags().GetBool("auth-enabled")
	queueDir, _ := cmd.Flags().GetString("queue-dir")
	webRoot, _ := cmd.Flags().GetString("web-root")

	log.Printf("Starting Elemta Web Interface...")
	log.Printf("Listen Address: %s", listenAddr)
	log.Printf("Web Root: %s", webRoot)
	log.Printf("Queue Directory: %s", queueDir)
	log.Printf("Authentication: %t", authEnabled)

	// Create API server configuration for web interface
	apiConfig := &api.Config{
		Enabled:     true,
		ListenAddr:  listenAddr,
		WebRoot:     webRoot,
		AuthEnabled: authEnabled,
	}

	// Create API server (which also serves web interface)
	apiServer, err := api.NewServer(apiConfig, queueDir)
	if err != nil {
		return fmt.Errorf("failed to create web server: %w", err)
	}

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in background
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Web interface listening on %s", listenAddr)
		if err := apiServer.Start(); err != nil {
			serverErrors <- fmt.Errorf("web server error: %w", err)
		}
	}()

	log.Println("Elemta Web Interface started successfully. Press Ctrl+C to stop.")

	// Wait for shutdown signal or server error
	select {
	case sig := <-signalChan:
		log.Printf("Received signal %v, shutting down gracefully...", sig)
	case err := <-serverErrors:
		log.Printf("Server error: %v", err)
		return err
	}

	// Graceful shutdown
	log.Println("Shutting down web server...")
	if err := apiServer.Stop(); err != nil {
		log.Printf("Error stopping web server: %v", err)
	}

	log.Println("Shutdown complete")
	return nil
}

func generateConfig(cmd *cobra.Command, args []string) error {
	outputPath := "elemta.toml"
	if len(args) > 0 {
		outputPath = args[0]
	}

	if err := config.CreateDefaultConfig(outputPath); err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	fmt.Printf("Default configuration generated at: %s\n", outputPath)
	return nil
}

func validateConfig(cmd *cobra.Command, args []string) error {
	configFile := configPath
	if len(args) > 0 {
		configFile = args[0]
	}

	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Perform comprehensive validation
	result := cfg.Validate()

	// Print validation results
	fmt.Printf("=== Configuration Validation Report ===\n\n")
	
	if result.Valid {
		fmt.Printf("✅ Configuration is VALID\n\n")
	} else {
		fmt.Printf("❌ Configuration has ERRORS\n\n")
	}

	// Print errors
	if len(result.Errors) > 0 {
		fmt.Printf("🚨 ERRORS (%d):\n", len(result.Errors))
		for i, err := range result.Errors {
			fmt.Printf("  %d. %s\n", i+1, err.Error())
		}
		fmt.Println()
	}

	// Print warnings
	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  WARNINGS (%d):\n", len(result.Warnings))
		for i, warning := range result.Warnings {
			fmt.Printf("  %d. %s\n", i+1, warning.Error())
		}
		fmt.Println()
	}

	// Print configuration summary if valid
	if result.Valid {
		fmt.Printf("📋 Configuration Summary:\n")
		fmt.Printf("  Server: %s:%s\n", cfg.Server.Hostname, cfg.Server.Listen)
		fmt.Printf("  Queue Directory: %s\n", cfg.Queue.Dir)
		
		if cfg.TLS != nil && cfg.TLS.Enabled {
			fmt.Printf("  TLS: Enabled")
			if cfg.TLS.LetsEncrypt != nil && cfg.TLS.LetsEncrypt.Enabled {
				fmt.Printf(" (Let's Encrypt)")
			}
			fmt.Println()
		} else {
			fmt.Printf("  TLS: Disabled\n")
		}

		if cfg.Auth != nil && cfg.Auth.Enabled {
			fmt.Printf("  Authentication: Enabled (%s)\n", cfg.Auth.DataSourceType)
		} else {
			fmt.Printf("  Authentication: Disabled\n")
		}

		fmt.Printf("  Queue Processor: %d workers, %ds interval\n", 
			cfg.QueueProcessor.Workers, cfg.QueueProcessor.Interval)
		
		if len(cfg.Plugins.Enabled) > 0 {
			fmt.Printf("  Plugins: %d enabled\n", len(cfg.Plugins.Enabled))
		} else {
			fmt.Printf("  Plugins: None enabled\n")
		}
	}

	// Return error if validation failed
	if !result.Valid {
		return fmt.Errorf("configuration validation failed with %d errors", len(result.Errors))
	}

	return nil
}