package smtp

import (
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"
)

// QueueProcessorConfig represents the queue processor configuration section
type QueueProcessorConfig struct {
	Enabled       bool `toml:"enabled" json:"enabled"`
	Interval      int  `toml:"interval" json:"interval"`
	MaxConcurrent int  `toml:"max_concurrent" json:"max_concurrent"`
	MaxRetries    int  `toml:"max_retries" json:"max_retries"`
}

// StartQueueProcessor starts the queue processor if enabled
func (s *Server) StartQueueProcessor() {
	if s.queueManager == nil {
		log.Printf("Error: No queue manager initialized")
		return
	}

	// Check both possible configuration locations
	var enabled bool
	var interval int

	// Check if we have a queue_processor section
	if s.config.QueueProcessorEnabled {
		enabled = true
		interval = s.config.QueueProcessInterval
		log.Printf("Queue processor enabled via top-level config: %v, interval: %d seconds",
			enabled, interval)
	} else {
		enabled = false
		interval = 0
		log.Printf("Queue processor disabled via config")
	}

	if enabled {
		log.Printf("Starting queue processor with interval %d seconds", interval)

		// Set queue processing parameters
		s.queueManager.config.QueueProcessorEnabled = true
		s.queueManager.config.QueueProcessInterval = interval

		// Start the queue processor
		s.queueManager.Start()
	} else {
		log.Printf("Queue processor disabled, not starting")
	}
}

// ProcessQueueNow forces an immediate queue processing cycle
func (s *Server) ProcessQueueNow() {
	if s.queueManager == nil {
		log.Printf("Error: No queue manager initialized")
		return
	}

	log.Printf("Forcing immediate queue processing cycle")
	go func() {
		// Process active queue immediately
		log.Printf("Processing active queue...")
		activeQueue := filepath.Join(s.queueManager.config.QueueDir, string(QueueTypeActive))
		messages, err := s.queueManager.getQueuedMessagesFromDir(activeQueue)
		if err != nil {
			log.Printf("Failed to get active queue messages: %v", err)
			return
		}

		var wg sync.WaitGroup
		for _, msg := range messages {
			// Skip messages being processed already
			s.queueManager.activeMu.Lock()
			if s.queueManager.activeJobs[msg.ID] {
				s.queueManager.activeMu.Unlock()
				continue
			}

			// Mark message as being processed
			s.queueManager.activeJobs[msg.ID] = true
			s.queueManager.activeMu.Unlock()

			wg.Add(1)
			go func(message *QueuedMessage) {
				defer wg.Done()
				defer func() {
					s.queueManager.activeMu.Lock()
					delete(s.queueManager.activeJobs, message.ID)
					s.queueManager.activeMu.Unlock()
				}()

				// Process message
				log.Printf("Processing message %s...", message.ID)
				s.queueManager.processMessage(message)
			}(msg)
		}

		// Wait for all messages to be processed
		wg.Wait()
		log.Printf("Queue processing complete")
	}()
}

// HandleQueueCommand processes a queue-related admin command
func (s *Server) HandleQueueCommand(command string, args ...string) string {
	if s.queueManager == nil {
		return "Error: No queue manager initialized"
	}

	switch command {
	case "status":
		stats := s.queueManager.GetQueueStats()
		return fmt.Sprintf("Queue status: active=%d, deferred=%d, held=%d, failed=%d, processed=%d, delivered=%d, failed=%d, updated=%s",
			stats.ActiveCount, stats.DeferredCount, stats.HeldCount, stats.FailedCount,
			stats.TotalProcessed, stats.TotalDelivered, stats.TotalFailed,
			stats.LastUpdated.Format(time.RFC3339))

	case "process":
		s.ProcessQueueNow()
		return "Queue processing triggered"

	case "enable":
		s.queueManager.config.QueueProcessorEnabled = true
		s.queueManager.Start()
		return "Queue processor enabled and started"

	case "disable":
		s.queueManager.config.QueueProcessorEnabled = false
		s.queueManager.Stop()
		return "Queue processor disabled and stopped"

	default:
		return fmt.Sprintf("Unknown queue command: %s", command)
	}
}
