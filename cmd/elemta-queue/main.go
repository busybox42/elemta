package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
)

func main() {
	// Define command-line flags
	configPath := flag.String("config", "", "Path to configuration file")
	queueType := flag.String("queue", "all", "Queue type to operate on (active, deferred, held, failed, all)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] command [args]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  list                List messages in the queue\n")
		fmt.Fprintf(os.Stderr, "  view <message-id>   View details of a specific message\n")
		fmt.Fprintf(os.Stderr, "  retry <message-id>  Move a message to the active queue for immediate retry\n")
		fmt.Fprintf(os.Stderr, "  delete <message-id> Delete a message from the queue\n")
		fmt.Fprintf(os.Stderr, "  flush               Delete all messages from the queue\n")
		fmt.Fprintf(os.Stderr, "  hold <message-id> [reason]  Hold a message for manual review\n")
		fmt.Fprintf(os.Stderr, "  release <message-id>        Release a held message back to the active queue\n")
		fmt.Fprintf(os.Stderr, "  stats               Show queue statistics\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Load configuration
	config, err := smtp.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Check if queue directory exists
	if _, err := os.Stat(config.QueueDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Queue directory does not exist: %s\n", config.QueueDir)
		os.Exit(1)
	}

	// Parse command
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Validate queue type
	validQueueTypes := map[string]bool{
		"active":   true,
		"deferred": true,
		"held":     true,
		"failed":   true,
		"all":      true,
	}
	if !validQueueTypes[*queueType] {
		fmt.Fprintf(os.Stderr, "Error: invalid queue type: %s\n", *queueType)
		os.Exit(1)
	}

	command := args[0]
	switch command {
	case "list":
		listMessages(config, *queueType)
	case "view":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: message ID required\n")
			os.Exit(1)
		}
		viewMessage(config, args[1])
	case "retry":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: message ID required\n")
			os.Exit(1)
		}
		retryMessage(config, args[1])
	case "delete":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: message ID required\n")
			os.Exit(1)
		}
		deleteMessage(config, args[1])
	case "flush":
		flushQueue(config, *queueType)
	case "hold":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: message ID required\n")
			os.Exit(1)
		}
		reason := ""
		if len(args) > 2 {
			reason = strings.Join(args[2:], " ")
		}
		holdMessage(config, args[1], reason)
	case "release":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: message ID required\n")
			os.Exit(1)
		}
		releaseMessage(config, args[1])
	case "stats":
		showQueueStats(config)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

func listMessages(config *smtp.Config, queueType string) {
	var files []string
	var err error

	if queueType == "all" {
		// Get messages from all queues
		for _, qt := range []string{"active", "deferred", "held", "failed"} {
			qDir := filepath.Join(config.QueueDir, qt)
			pattern := filepath.Join(qDir, "*.json")
			qFiles, err := filepath.Glob(pattern)
			if err == nil {
				files = append(files, qFiles...)
			}
		}
	} else {
		// Get messages from specific queue
		qDir := filepath.Join(config.QueueDir, queueType)
		pattern := filepath.Join(qDir, "*.json")
		files, err = filepath.Glob(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing queue: %v\n", err)
			os.Exit(1)
		}
	}

	if len(files) == 0 {
		fmt.Println("Queue is empty")
		return
	}

	// Create a tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tQueue\tFrom\tTo\tStatus\tPriority\tRetries\tCreated\tNext Retry")

	// Load and sort messages
	var messages []*smtp.QueuedMessage
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var msg smtp.QueuedMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		messages = append(messages, &msg)
	}

	// Sort messages by priority (highest first) and then by creation time (oldest first)
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].Priority != messages[j].Priority {
			return messages[i].Priority > messages[j].Priority
		}
		return messages[i].CreatedAt.Before(messages[j].CreatedAt)
	})

	// Display messages
	for _, msg := range messages {
		// Format recipients
		recipients := strings.Join(msg.To, ", ")
		if len(recipients) > 30 {
			recipients = recipients[:27] + "..."
		}

		// Format priority
		priority := "Normal"
		switch msg.Priority {
		case smtp.PriorityLow:
			priority = "Low"
		case smtp.PriorityHigh:
			priority = "High"
		case smtp.PriorityCritical:
			priority = "Critical"
		}

		// Format next retry time
		nextRetry := "-"
		if !msg.NextRetry.IsZero() && msg.NextRetry.After(time.Now()) {
			nextRetry = msg.NextRetry.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			msg.ID,
			string(msg.QueueType),
			msg.From,
			recipients,
			msg.Status,
			priority,
			msg.RetryCount,
			msg.CreatedAt.Format("2006-01-02 15:04:05"),
			nextRetry)
	}

	w.Flush()
}

func viewMessage(config *smtp.Config, id string) {
	// Find message in any queue
	var msgFile string
	var msgData []byte
	var err error

	for _, qType := range []string{"active", "deferred", "held", "failed"} {
		path := filepath.Join(config.QueueDir, qType, id+".json")
		if _, err := os.Stat(path); err == nil {
			msgFile = path
			msgData, err = os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading message metadata: %v\n", err)
				os.Exit(1)
			}
			break
		}
	}

	if msgFile == "" {
		fmt.Fprintf(os.Stderr, "Message not found: %s\n", id)
		os.Exit(1)
	}

	var msg smtp.QueuedMessage
	if err := json.Unmarshal(msgData, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Display message details
	fmt.Println("Message ID:", msg.ID)
	fmt.Println("Queue:", msg.QueueType)
	fmt.Println("From:", msg.From)
	fmt.Println("To:", strings.Join(msg.To, ", "))
	fmt.Println("Status:", msg.Status)

	// Format priority
	priority := "Normal"
	switch msg.Priority {
	case smtp.PriorityLow:
		priority = "Low"
	case smtp.PriorityHigh:
		priority = "High"
	case smtp.PriorityCritical:
		priority = "Critical"
	}
	fmt.Println("Priority:", priority)

	fmt.Println("Created:", msg.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println("Updated:", msg.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println("Retry Count:", msg.RetryCount)

	if !msg.NextRetry.IsZero() {
		fmt.Println("Next Retry:", msg.NextRetry.Format("2006-01-02 15:04:05"))
	}

	if msg.LastError != "" {
		fmt.Println("Last Error:", msg.LastError)
	}

	if msg.HoldReason != "" {
		fmt.Println("Hold Reason:", msg.HoldReason)
	}

	if msg.FailReason != "" {
		fmt.Println("Failure Reason:", msg.FailReason)
	}

	if len(msg.Attempts) > 0 {
		fmt.Println("Delivery Attempts:")
		for i, attempt := range msg.Attempts {
			fmt.Printf("  %d. %s\n", i+1, attempt.Timestamp.Format("2006-01-02 15:04:05"))
		}
	}

	if len(msg.Annotations) > 0 {
		fmt.Println("Annotations:")
		for k, v := range msg.Annotations {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Try to read message content
	dataPath := filepath.Join(config.QueueDir, "data", id)
	content, err := os.ReadFile(dataPath)
	if err == nil {
		fmt.Println("\nMessage Content:")
		fmt.Println(string(content))
	}
}

func retryMessage(config *smtp.Config, id string) {
	// Find message in any queue
	var sourceQueue string
	var msgPath string

	for _, qType := range []string{"deferred", "failed", "held"} {
		path := filepath.Join(config.QueueDir, qType, id+".json")
		if _, err := os.Stat(path); err == nil {
			sourceQueue = qType
			msgPath = path
			break
		}
	}

	if msgPath == "" {
		fmt.Fprintf(os.Stderr, "Message not found or already in active queue: %s\n", id)
		os.Exit(1)
	}

	// Read message data
	data, err := os.ReadFile(msgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading message metadata: %v\n", err)
		os.Exit(1)
	}

	var msg smtp.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Update message for retry
	msg.QueueType = smtp.QueueTypeActive
	msg.Status = smtp.StatusQueued
	msg.NextRetry = time.Now()
	msg.UpdatedAt = time.Now()

	// Clear hold or failure reason if present
	msg.HoldReason = ""
	msg.FailReason = ""

	// Save to active queue
	activeQueueDir := filepath.Join(config.QueueDir, "active")
	if err := os.MkdirAll(activeQueueDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating active queue directory: %v\n", err)
		os.Exit(1)
	}

	activeFilePath := filepath.Join(activeQueueDir, id+".json")
	updatedData, err := json.Marshal(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing message metadata: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(activeFilePath, updatedData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Remove from source queue
	if err := os.Remove(msgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to remove message from source queue: %v\n", err)
	}

	fmt.Printf("Message %s moved from %s queue to active queue for immediate retry\n", id, sourceQueue)
}

func deleteMessage(config *smtp.Config, id string) {
	// Find message in any queue
	var found bool

	for _, qType := range []string{"active", "deferred", "held", "failed"} {
		path := filepath.Join(config.QueueDir, qType, id+".json")
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				fmt.Fprintf(os.Stderr, "Error removing message metadata: %v\n", err)
				os.Exit(1)
			}
			found = true
			break
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "Message not found: %s\n", id)
		os.Exit(1)
	}

	// Try to remove message data
	dataPath := filepath.Join(config.QueueDir, "data", id)
	if _, err := os.Stat(dataPath); err == nil {
		if err := os.Remove(dataPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove message data: %v\n", err)
		}
	}

	fmt.Printf("Message %s deleted from queue\n", id)
}

func flushQueue(config *smtp.Config, queueType string) {
	var count int

	if queueType == "all" {
		// Flush all queues
		for _, qt := range []string{"active", "deferred", "held", "failed"} {
			qDir := filepath.Join(config.QueueDir, qt)
			pattern := filepath.Join(qDir, "*.json")
			files, err := filepath.Glob(pattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listing %s queue: %v\n", qt, err)
				continue
			}

			for _, file := range files {
				if err := os.Remove(file); err != nil {
					fmt.Fprintf(os.Stderr, "Error removing %s: %v\n", file, err)
					continue
				}
				count++
			}
		}

		// Also remove message data
		dataDir := filepath.Join(config.QueueDir, "data")
		if _, err := os.Stat(dataDir); err == nil {
			files, err := os.ReadDir(dataDir)
			if err == nil {
				for _, file := range files {
					if !file.IsDir() {
						path := filepath.Join(dataDir, file.Name())
						os.Remove(path)
					}
				}
			}
		}
	} else {
		// Flush specific queue
		qDir := filepath.Join(config.QueueDir, queueType)
		pattern := filepath.Join(qDir, "*.json")
		files, err := filepath.Glob(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing queue: %v\n", err)
			os.Exit(1)
		}

		for _, file := range files {
			// Extract message ID from filename
			base := filepath.Base(file)
			id := strings.TrimSuffix(base, ".json")

			// Remove metadata file
			if err := os.Remove(file); err != nil {
				fmt.Fprintf(os.Stderr, "Error removing %s: %v\n", file, err)
				continue
			}

			// Try to remove message data if flushing all queues
			dataPath := filepath.Join(config.QueueDir, "data", id)
			if _, err := os.Stat(dataPath); err == nil {
				os.Remove(dataPath)
			}

			count++
		}
	}

	fmt.Printf("Flushed %d messages from %s queue(s)\n", count, queueType)
}

func holdMessage(config *smtp.Config, id string, reason string) {
	// Find message in active or deferred queue
	var sourceQueue string
	var msgPath string

	for _, qType := range []string{"active", "deferred"} {
		path := filepath.Join(config.QueueDir, qType, id+".json")
		if _, err := os.Stat(path); err == nil {
			sourceQueue = qType
			msgPath = path
			break
		}
	}

	if msgPath == "" {
		fmt.Fprintf(os.Stderr, "Message not found in active or deferred queue: %s\n", id)
		os.Exit(1)
	}

	// Read message data
	data, err := os.ReadFile(msgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading message metadata: %v\n", err)
		os.Exit(1)
	}

	var msg smtp.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Update message for hold
	msg.QueueType = smtp.QueueTypeHeld
	msg.Status = smtp.StatusHeld
	msg.UpdatedAt = time.Now()
	msg.HoldReason = reason

	// Save to held queue
	heldQueueDir := filepath.Join(config.QueueDir, "held")
	if err := os.MkdirAll(heldQueueDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating held queue directory: %v\n", err)
		os.Exit(1)
	}

	heldFilePath := filepath.Join(heldQueueDir, id+".json")
	updatedData, err := json.Marshal(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing message metadata: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(heldFilePath, updatedData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Remove from source queue
	if err := os.Remove(msgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to remove message from source queue: %v\n", err)
	}

	fmt.Printf("Message %s moved from %s queue to held queue\n", id, sourceQueue)
	if reason != "" {
		fmt.Printf("Hold reason: %s\n", reason)
	}
}

func releaseMessage(config *smtp.Config, id string) {
	// Find message in held queue
	heldPath := filepath.Join(config.QueueDir, "held", id+".json")
	if _, err := os.Stat(heldPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Message not found in held queue: %s\n", id)
		os.Exit(1)
	}

	// Read message data
	data, err := os.ReadFile(heldPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading message metadata: %v\n", err)
		os.Exit(1)
	}

	var msg smtp.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Update message for release
	msg.QueueType = smtp.QueueTypeActive
	msg.Status = smtp.StatusQueued
	msg.UpdatedAt = time.Now()
	msg.HoldReason = ""

	// Save to active queue
	activeQueueDir := filepath.Join(config.QueueDir, "active")
	if err := os.MkdirAll(activeQueueDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating active queue directory: %v\n", err)
		os.Exit(1)
	}

	activeFilePath := filepath.Join(activeQueueDir, id+".json")
	updatedData, err := json.Marshal(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing message metadata: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(activeFilePath, updatedData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing message metadata: %v\n", err)
		os.Exit(1)
	}

	// Remove from held queue
	if err := os.Remove(heldPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to remove message from held queue: %v\n", err)
	}

	fmt.Printf("Message %s released from held queue to active queue\n", id)
}

func showQueueStats(config *smtp.Config) {
	// Count messages in each queue
	stats := struct {
		Active   int
		Deferred int
		Held     int
		Failed   int
		Total    int
		DataSize int64
	}{}

	// Count active queue
	activeDir := filepath.Join(config.QueueDir, "active")
	if files, err := filepath.Glob(filepath.Join(activeDir, "*.json")); err == nil {
		stats.Active = len(files)
		stats.Total += len(files)
	}

	// Count deferred queue
	deferredDir := filepath.Join(config.QueueDir, "deferred")
	if files, err := filepath.Glob(filepath.Join(deferredDir, "*.json")); err == nil {
		stats.Deferred = len(files)
		stats.Total += len(files)
	}

	// Count held queue
	heldDir := filepath.Join(config.QueueDir, "held")
	if files, err := filepath.Glob(filepath.Join(heldDir, "*.json")); err == nil {
		stats.Held = len(files)
		stats.Total += len(files)
	}

	// Count failed queue
	failedDir := filepath.Join(config.QueueDir, "failed")
	if files, err := filepath.Glob(filepath.Join(failedDir, "*.json")); err == nil {
		stats.Failed = len(files)
		stats.Total += len(files)
	}

	// Calculate data size
	dataDir := filepath.Join(config.QueueDir, "data")
	if _, err := os.Stat(dataDir); err == nil {
		filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				stats.DataSize += info.Size()
			}
			return nil
		})
	}

	// Display stats
	fmt.Println("Queue Statistics:")
	fmt.Printf("Active Messages:   %d\n", stats.Active)
	fmt.Printf("Deferred Messages: %d\n", stats.Deferred)
	fmt.Printf("Held Messages:     %d\n", stats.Held)
	fmt.Printf("Failed Messages:   %d\n", stats.Failed)
	fmt.Printf("Total Messages:    %d\n", stats.Total)
	fmt.Printf("Data Size:         %.2f MB\n", float64(stats.DataSize)/(1024*1024))
}
