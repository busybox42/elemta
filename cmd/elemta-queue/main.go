package main

import (
	"log"
	"os"

	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/queue"
)

func main() {
	// Load configuration
	configPath := os.Getenv("ELEMTA_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config/elemta.conf"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create queue manager
	queueManager := queue.NewManager(cfg.Queue.Dir)

	// Show queue stats
	log.Printf("Queue directory: %s", cfg.Queue.Dir)
	stats := queueManager.GetStats()
	log.Printf("Queue stats: Active=%d, Deferred=%d, Failed=%d, Hold=%d", 
		stats.ActiveCount, stats.DeferredCount, stats.FailedCount, stats.HoldCount)

	log.Println("Queue status check completed")
}