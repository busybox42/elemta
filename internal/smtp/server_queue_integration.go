package smtp

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/queue"
)

// QueueProcessorIntegration bridges the old SMTP server with the new queue system
type QueueProcessorIntegration struct {
	manager         *queue.Manager
	processor       *queue.Processor
	deliveryHandler queue.DeliveryHandler
	config          *Config
	logger          *slog.Logger
	running         bool
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewQueueProcessorIntegration creates a new integration
func NewQueueProcessorIntegration(config *Config) (*QueueProcessorIntegration, error) {
	// Create queue manager
	manager := queue.NewManager(config.QueueDir)

	// Create delivery handler based on configuration
	var deliveryHandler queue.DeliveryHandler

	// Debug delivery configuration
	if config.Delivery != nil {
		slog.Info("Delivery config found", "mode", config.Delivery.Mode, "host", config.Delivery.Host, "port", config.Delivery.Port)
		if strings.ToLower(config.Delivery.Mode) == "lmtp" && config.Delivery.Host != "" {
			// Use LMTP delivery for local delivery (e.g., to Dovecot)
			port := config.Delivery.Port
			if port == 0 {
				port = 2424 // Default LMTP port
			}
			deliveryHandler = queue.NewLMTPDeliveryHandler(config.Delivery.Host, port)
			slog.Info("Configured LMTP delivery handler", "host", config.Delivery.Host, "port", port)
		} else {
			// Use SMTP delivery for external delivery
			deliveryHandler = queue.NewSMTPDeliveryHandler()
			slog.Info("Configured SMTP delivery handler - mode not LMTP or missing host", "mode", config.Delivery.Mode, "host", config.Delivery.Host)
		}
	} else {
		// Use SMTP delivery for external delivery
		deliveryHandler = queue.NewSMTPDeliveryHandler()
		slog.Info("Configured SMTP delivery handler - no delivery config")
	}

	// Configure processor
	processorConfig := queue.ProcessorConfig{
		Enabled:       config.QueueProcessorEnabled,
		Interval:      time.Duration(config.QueueProcessInterval) * time.Second,
		MaxConcurrent: config.QueueWorkers,
		MaxRetries:    config.MaxRetries,
		RetrySchedule: config.RetrySchedule,
		CleanupAge:    time.Duration(config.MessageRetentionHours) * time.Hour,
	}

	// Create processor
	processor := queue.NewProcessor(manager, processorConfig, deliveryHandler)

	return &QueueProcessorIntegration{
		manager:         manager,
		processor:       processor,
		deliveryHandler: deliveryHandler,
		config:          config,
		logger:          slog.Default().With("component", "queue-integration"),
		stopCh:          make(chan struct{}),
	}, nil
}

// Start starts the queue processor integration
func (q *QueueProcessorIntegration) Start() error {
	if q.running {
		return fmt.Errorf("queue processor integration already running")
	}

	q.logger.Info("Starting queue processor integration")

	// Start the processor
	if err := q.processor.Start(); err != nil {
		return fmt.Errorf("failed to start queue processor: %w", err)
	}

	q.running = true

	// Start integration loop to bridge old messages to new system
	q.wg.Add(1)
	go q.bridgeOldMessages()

	q.logger.Info("Queue processor integration started")
	return nil
}

// Stop stops the queue processor integration
func (q *QueueProcessorIntegration) Stop() error {
	if !q.running {
		return nil
	}

	q.logger.Info("Stopping queue processor integration")

	q.running = false
	close(q.stopCh)

	// Stop the processor
	if err := q.processor.Stop(); err != nil {
		q.logger.Error("Error stopping queue processor", "error", err)
	}

	// Wait for goroutines to finish
	q.wg.Wait()

	q.logger.Info("Queue processor integration stopped")
	return nil
}

// EnqueueMessage converts old SMTP message to new queue message format and enqueues it
func (q *QueueProcessorIntegration) EnqueueMessage(msg *Message, priority queue.Priority) error {
	// Convert SMTP message to queue message format
	queueMsg := q.convertSMTPToQueueMessage(msg, priority)

	// Enqueue in the new queue system
	msgID, err := q.manager.EnqueueMessage(
		queueMsg.From,
		queueMsg.To,
		queueMsg.Subject,
		msg.data,
		priority,
	)
	if err != nil {
		return fmt.Errorf("failed to enqueue message: %w", err)
	}

	q.logger.Info("Message enqueued in new queue system",
		"message_id", msgID,
		"from", queueMsg.From,
		"to", queueMsg.To,
		"priority", priority)

	return nil
}

// convertSMTPToQueueMessage converts old SMTP message format to new queue message format
func (q *QueueProcessorIntegration) convertSMTPToQueueMessage(msg *Message, priority queue.Priority) queue.Message {
	// Extract subject from message data (basic parsing)
	subject := q.extractSubject(msg.data)

	return queue.Message{
		ID:        msg.id,
		From:      msg.from,
		To:        msg.to,
		Subject:   subject,
		Priority:  priority,
		CreatedAt: msg.created,
		UpdatedAt: time.Now(),
	}
}

// extractSubject extracts the subject line from message data
func (q *QueueProcessorIntegration) extractSubject(data []byte) string {
	// Simple subject extraction - parse basic email headers
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "subject:") {
			subject := strings.TrimSpace(line[8:]) // Remove "Subject:" prefix
			return subject
		}
	}
	return "No Subject"
}

// bridgeOldMessages periodically checks for old queue messages and bridges them to new system
func (q *QueueProcessorIntegration) bridgeOldMessages() {
	defer q.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			if err := q.processOldQueueMessages(); err != nil {
				q.logger.Error("Failed to process old queue messages", "error", err)
			}
		}
	}
}

// processOldQueueMessages processes any messages still in the old queue format
func (q *QueueProcessorIntegration) processOldQueueMessages() error {
	// This would check for old format messages and convert them
	// For now, we'll just log that we're checking
	q.logger.Debug("Checking for old format messages to bridge")
	return nil
}

// GetStats returns queue statistics from the new system
func (q *QueueProcessorIntegration) GetStats() queue.QueueStats {
	return q.manager.GetStats()
}

// GetProcessor returns the queue processor for advanced usage
func (q *QueueProcessorIntegration) GetProcessor() *queue.Processor {
	return q.processor
}

// GetManager returns the queue manager for advanced usage
func (q *QueueProcessorIntegration) GetManager() *queue.Manager {
	return q.manager
}
