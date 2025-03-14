package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/busybox42/elemta/internal/smtp"
)

func main() {
	config, err := smtp.LoadConfig("") // Change this line
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize SMTP server
	server, err := smtp.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	// Initialize queue manager
	queueManager := smtp.NewQueueManager(config)
	queueManager.Start()
	defer queueManager.Stop()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down...")
}
