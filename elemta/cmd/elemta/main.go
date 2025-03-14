package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/elemta/elemta/internal/config"
	"github.com/elemta/elemta/internal/rule"
	"github.com/elemta/elemta/internal/smtp"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		// If config file not found, create a default config
		log.Printf("Warning: Failed to load config file: %v. Using default configuration.", err)
		cfg = &config.Config{
			SMTP: config.SMTPConfig{
				ListenAddress:     "0.0.0.0",
				Port:              2525, // Use a non-privileged port for testing
				Hostname:          "localhost",
				MaxConnections:    100,
				MaxMessageSize:    52428800, // 50MB
				AllowInsecureAuth: true,
				Timeouts: config.SMTPTimeouts{
					Connection: 60,
					Command:    30,
					Data:       300,
					Idle:       300,
				},
			},
			Queue: config.QueueConfig{
				Path:            "queue",
				MaxSize:         1073741824, // 1GB
				RetryInterval:   300,        // 5 minutes
				MaxRetries:      10,
				CleanupInterval: 3600, // 1 hour
			},
			Rules: config.RulesConfig{
				Path:       "rules",
				ScriptPath: "scripts",
			},
		}
	}

	// Create rule engine
	ruleEngine, err := rule.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to create rule engine: %v", err)
	}

	// Create SMTP server
	server, err := smtp.NewServer(cfg, ruleEngine)
	if err != nil {
		log.Fatalf("Failed to create SMTP server: %v", err)
	}

	// Start SMTP server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start SMTP server: %v", err)
	}

	log.Printf("ElemTA SMTP server started on %s:%d", cfg.SMTP.ListenAddress, cfg.SMTP.Port)
	log.Printf("Use telnet or netcat to connect and test the XDEBUG command")
	log.Printf("Example: nc %s %d", cfg.SMTP.ListenAddress, cfg.SMTP.Port)

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	server.Stop()
}
