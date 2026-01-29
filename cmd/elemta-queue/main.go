package main

import (
	"log/slog"
	"os"

	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/queue"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "queue-cli",
	)

	// Load configuration
	configPath := os.Getenv("ELEMTA_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config/elemta.conf"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create queue manager
	queueManager := queue.NewManager(cfg.Queue.Dir, cfg.FailedQueueRetentionHours)

	// Show queue stats
	logger.Info("Queue directory", "path", cfg.Queue.Dir)
	stats := queueManager.GetStats()
	logger.Info("Queue stats",
		"active_count", stats.ActiveCount,
		"deferred_count", stats.DeferredCount,
		"failed_count", stats.FailedCount,
		"hold_count", stats.HoldCount,
	)

	logger.Info("Queue status check completed")
}
