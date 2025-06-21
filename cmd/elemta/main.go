package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/busybox42/elemta/internal/config"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/busybox42/elemta/internal/smtp"
)

func main() {
	// Check for web command
	if len(os.Args) > 1 && os.Args[1] == "web" {
		startWebServer()
		return
	}

	// Load configuration
	configPath := os.Getenv("ELEMTA_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config/elemta.conf"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if result := cfg.Validate(); !result.Valid {
		for _, err := range result.Errors {
			log.Printf("Config error: %s", err.Error())
		}
		log.Fatalf("Configuration validation failed")
	}

	// Ensure queue directory exists
	if err := cfg.EnsureQueueDirectory(); err != nil {
		log.Fatalf("Failed to create queue directory: %v", err)
	}

	// Create SMTP configuration from main config
	smtpConfig := &smtp.Config{
		Hostname:              cfg.Server.Hostname,
		ListenAddr:            cfg.Server.Listen,
		MaxSize:               cfg.Server.MaxSize,
		QueueDir:              cfg.Queue.Dir,
		QueueProcessorEnabled: cfg.QueueProcessor.Enabled,
		QueueProcessInterval:  cfg.QueueProcessor.Interval,
		QueueWorkers:          cfg.QueueProcessor.Workers,
		TLS:                   cfg.TLS,
		Auth:                  cfg.Auth,
		Delivery:              cfg.Delivery,
	}

	// Set defaults if not specified
	if smtpConfig.MaxWorkers == 0 {
		smtpConfig.MaxWorkers = 10
	}
	if smtpConfig.MaxRetries == 0 {
		smtpConfig.MaxRetries = 10
	}

	log.Printf("Starting Elemta SMTP server on %s", smtpConfig.ListenAddr)
	log.Printf("Queue directory: %s", smtpConfig.QueueDir)

	// Log delivery configuration
	if cfg.Delivery != nil {
		log.Printf("Delivery configuration: mode=%s, host=%s, port=%d",
			cfg.Delivery.Mode, cfg.Delivery.Host, cfg.Delivery.Port)
	} else {
		log.Printf("No delivery configuration found - using SMTP delivery")
	}

	// Create SMTP server
	server, err := smtp.NewServer(smtpConfig)
	if err != nil {
		log.Fatalf("Failed to create SMTP server: %v", err)
	}

	// Start the server in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Start(); err != nil {
			log.Fatalf("Failed to start SMTP server: %v", err)
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, stopping server...")

	// Stop the server
	if err := server.Close(); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	// Wait for server to finish
	wg.Wait()
	log.Println("Server stopped")
}

func startWebServer() {
	// Parse command line arguments for web server
	var listenAddr string = "0.0.0.0:8025"
	var queueDir string = "/app/queue"
	var webRoot string = "/app/web/static"

	// Parse flags
	for i, arg := range os.Args {
		if arg == "--listen" && i+1 < len(os.Args) {
			listenAddr = os.Args[i+1]
		}
		if arg == "--queue-dir" && i+1 < len(os.Args) {
			queueDir = os.Args[i+1]
		}
		if arg == "--web-root" && i+1 < len(os.Args) {
			webRoot = os.Args[i+1]
		}
	}

	log.Printf("Starting Elemta Web Server on %s", listenAddr)
	log.Printf("Queue directory: %s", queueDir)
	log.Printf("Web root: %s", webRoot)

	// Create HTTP server
	mux := http.NewServeMux()

	// Serve static files
	fs := http.FileServer(http.Dir(webRoot))
	mux.Handle("/", fs)

	// Create queue manager for reading queue data
	queueManager := queue.NewManager(queueDir)

	// API endpoints
	mux.HandleFunc("/api/queue/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := queueManager.GetStats()
		response := map[string]interface{}{
			"active_count":   stats.ActiveCount,
			"deferred_count": stats.DeferredCount,
			"failed_count":   stats.FailedCount,
			"hold_count":     stats.HoldCount,
			"status":         "running",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/api/queue/", func(w http.ResponseWriter, r *http.Request) {
		// Handle queue requests like /api/queue/active, /api/queue/failed, etc.
		path := strings.TrimPrefix(r.URL.Path, "/api/queue/")
		queueType := strings.Split(path, "/")[0]

		messages, err := getQueueMessages(queueDir, queueType)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to load %s queue: %v", queueType, err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(messages)
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Start server
	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}

func getQueueMessages(queueDir, queueType string) ([]map[string]interface{}, error) {
	queuePath := filepath.Join(queueDir, queueType)

	// Always return empty slice instead of nil
	messages := []map[string]interface{}{}

	// Check if directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return messages, nil
	}

	// Read directory contents
	files, err := ioutil.ReadDir(queuePath)
	if err != nil {
		return messages, fmt.Errorf("failed to read queue directory: %w", err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		// Read message metadata
		messagePath := filepath.Join(queuePath, file.Name())
		data, err := ioutil.ReadFile(messagePath)
		if err != nil {
			log.Printf("Failed to read message file %s: %v", messagePath, err)
			continue
		}

		var message map[string]interface{}
		if err := json.Unmarshal(data, &message); err != nil {
			log.Printf("Failed to parse message file %s: %v", messagePath, err)
			continue
		}

		// Add file info
		message["id"] = strings.TrimSuffix(file.Name(), ".json")
		message["created_at"] = file.ModTime().Format("2006-01-02T15:04:05Z")
		message["size"] = file.Size()

		messages = append(messages, message)
	}

	return messages, nil
}
