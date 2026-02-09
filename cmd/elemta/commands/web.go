package commands

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/busybox42/elemta/internal/api"
	"github.com/busybox42/elemta/internal/config"
	"github.com/spf13/cobra"
)

// convertToAPIMainConfig converts config.Config to api.MainConfig
func convertToAPIMainConfig(cfg *config.Config) *api.MainConfig {
	// Use Server struct fields for primary config, fallback to top-level fields
	hostname := cfg.Server.Hostname
	if hostname == "" {
		hostname = cfg.Hostname // fallback
	}

	listenAddr := cfg.Server.Listen
	if listenAddr == "" {
		listenAddr = cfg.ListenAddr // fallback
	}

	maxSize := cfg.Server.MaxSize
	if maxSize == 0 {
		maxSize = cfg.MaxSize // fallback
	}

	localDomains := cfg.Server.LocalDomains
	if len(localDomains) == 0 {
		localDomains = cfg.LocalDomains // fallback
	}

	return &api.MainConfig{
		Hostname:                  hostname,
		ListenAddr:                listenAddr,
		QueueDir:                  cfg.QueueDir,
		MaxSize:                   maxSize,
		MaxWorkers:                cfg.MaxWorkers,
		MaxRetries:                cfg.MaxRetries,
		MaxQueueTime:              cfg.MaxQueueTime,
		RetrySchedule:             cfg.RetrySchedule,
		SessionTimeout:            cfg.SessionTimeout,
		LocalDomains:              localDomains,
		FailedQueueRetentionHours: cfg.FailedQueueRetentionHours,
		RateLimiterPluginConfig:   cfg.RateLimiter,
		TLS:                       cfg.TLS,
		API:                       nil, // API config not available in main config
	}
}

var (
	webListenAddr string
	webRoot       string
	webQueueDir   string
	authEnabled   bool
	authFile      string
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web interface",
	Long: `Start the Elemta web dashboard interface.
This provides a web-based UI for monitoring and managing mail queues.`,
	Run: runWeb,
}

func init() {
	rootCmd.AddCommand(webCmd)

	// Web-specific flags
	webCmd.Flags().StringVarP(&webListenAddr, "listen", "l", "127.0.0.1:8025", "Address to listen on")
	webCmd.Flags().StringVar(&webRoot, "web-root", "./web/static", "Path to web static files")
	webCmd.Flags().StringVar(&webQueueDir, "queue-dir", "./queue", "Path to queue directory")
	webCmd.Flags().BoolVar(&authEnabled, "auth-enabled", false, "Enable authentication and authorization")
	webCmd.Flags().StringVar(&authFile, "auth-file", "", "Path to users file for authentication")
}

func runWeb(cmd *cobra.Command, args []string) {
	// Load main config to get failed queue retention setting
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Printf("Warning: failed to load config, using defaults: %v", err)
		cfg = config.DefaultConfig()
	}

	// Find config file path for persistence
	configPath, _ := config.FindConfigFile("")

	// Create API config
	apiConfig := &api.Config{
		Enabled:     true,
		ListenAddr:  webListenAddr,
		WebRoot:     webRoot,
		AuthEnabled: authEnabled,
		AuthFile:    authFile,
	}

	// Create and start API server
	server, err := api.NewServer(apiConfig, convertToAPIMainConfig(cfg), webQueueDir, cfg.FailedQueueRetentionHours, configPath)
	if err != nil {
		log.Fatalf("Failed to create API server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}

	fmt.Printf("Elemta web interface started on http://%s\n", webListenAddr)
	fmt.Println("Press Ctrl+C to stop")

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down web interface...")
	if err := server.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
}
