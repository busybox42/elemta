package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/busybox42/elemta/internal/queue"
)

func main() {
	// Create queue directory
	queueDir := "./queue_example"
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		log.Fatalf("Failed to create queue directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(queueDir) }()

	// Initialize queue manager
	manager := queue.NewManager(queueDir)
	defer manager.Stop()

	// Create delivery handler (use mock for example)
	deliveryHandler := queue.NewMockDeliveryHandler()

	// Configure processor
	config := queue.ProcessorConfig{
		Enabled:       true,
		Interval:      5 * time.Second,                  // Check every 5 seconds
		MaxConcurrent: 3,                                // Max 3 concurrent deliveries
		MaxRetries:    5,                                // Retry up to 5 times
		RetrySchedule: []int{60, 300, 900, 3600, 10800}, // 1m, 5m, 15m, 1h, 3h
		CleanupAge:    24 * time.Hour,                   // Clean up messages older than 24h
	}

	// Create and start processor
	processor := queue.NewProcessor(manager, config, deliveryHandler)
	if err := processor.Start(); err != nil {
		log.Fatalf("Failed to start processor: %v", err)
	}
	defer processor.Stop()

	log.Println("Queue system started successfully")

	// Example: Enqueue some messages
	exampleMessages := []struct {
		from     string
		to       []string
		subject  string
		content  string
		priority queue.Priority
	}{
		{
			from:     "user@example.com",
			to:       []string{"recipient1@example.com"},
			subject:  "High Priority Alert",
			content:  "From: user@example.com\r\nTo: recipient1@example.com\r\nSubject: High Priority Alert\r\n\r\nThis is a high priority message.",
			priority: queue.PriorityHigh,
		},
		{
			from:     "newsletter@example.com",
			to:       []string{"subscriber@example.com"},
			subject:  "Weekly Newsletter",
			content:  "From: newsletter@example.com\r\nTo: subscriber@example.com\r\nSubject: Weekly Newsletter\r\n\r\nThis is a normal priority newsletter.",
			priority: queue.PriorityNormal,
		},
		{
			from:     "system@example.com",
			to:       []string{"admin@example.com"},
			subject:  "Critical System Alert",
			content:  "From: system@example.com\r\nTo: admin@example.com\r\nSubject: Critical System Alert\r\n\r\nThis is a critical system alert.",
			priority: queue.PriorityCritical,
		},
	}

	// Enqueue messages
	for i, msg := range exampleMessages {
		msgID, err := manager.EnqueueMessage(
			msg.from,
			msg.to,
			msg.subject,
			[]byte(msg.content),
			msg.priority,
			time.Now(),
		)
		if err != nil {
			log.Printf("Failed to enqueue message %d: %v", i+1, err)
			continue
		}
		log.Printf("Enqueued message %d with ID: %s", i+1, msgID)
	}

	// Monitor queue statistics
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				stats := manager.GetStats()
				metrics := processor.GetMetrics()

				log.Printf("Queue Stats - Active: %d, Deferred: %d, Hold: %d, Failed: %d, Total Size: %d bytes",
					stats.ActiveCount, stats.DeferredCount, stats.HoldCount, stats.FailedCount, stats.TotalSize)

				log.Printf("Processor Metrics - Processed: %d, Delivered: %d, Failed: %d, Retries: %d",
					metrics.ProcessedTotal, metrics.DeliveredTotal, metrics.FailedTotal, metrics.RetryTotal)

				// Show delivered messages
				delivered := deliveryHandler.GetDeliveries()
				log.Printf("Total delivered messages: %d", len(delivered))
			}
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	log.Println("Shutting down queue system...")
}

// Example of how to integrate with your SMTP server:
//
// type SMTPServer struct {
//     queueManager *queue.Manager
//     processor    *queue.Processor
//     // ... other fields
// }
//
// func (s *SMTPServer) StartQueueSystem() error {
//     // Initialize queue manager
//     s.queueManager = queue.NewManager(s.config.QueueDir)
//
//     // Create SMTP delivery handler
//     deliveryHandler := queue.NewSMTPDeliveryHandler()
//
//     // Configure processor from your SMTP config
//     config := queue.ProcessorConfig{
//         Enabled:       s.config.QueueEnabled,
//         Interval:      time.Duration(s.config.QueueInterval) * time.Second,
//         MaxConcurrent: s.config.QueueWorkers,
//         MaxRetries:    s.config.MaxRetries,
//         RetrySchedule: s.config.RetrySchedule,
//         CleanupAge:    time.Duration(s.config.RetentionHours) * time.Hour,
//     }
//
//     // Create and start processor
//     s.processor = queue.NewProcessor(s.queueManager, config, deliveryHandler)
//     return s.processor.Start()
// }
//
// func (s *SMTPServer) HandleIncomingMessage(from string, to []string, data []byte) error {
//     // Extract subject from message data for better logging
//     subject := extractSubject(data)
//
//     // Determine priority based on sender, content, or headers
//     priority := queue.PriorityNormal
//     if isHighPriorityMessage(data) {
//         priority = queue.PriorityHigh
//     }
//
//     // Enqueue the message
//     msgID, err := s.queueManager.EnqueueMessage(from, to, subject, data, priority, time.Now())
//     if err != nil {
//         return fmt.Errorf("failed to enqueue message: %w", err)
//     }
//
//     log.Printf("Message queued with ID: %s", msgID)
//     return nil
// }
