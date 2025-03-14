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
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] command [args]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  list                List all queued messages\n")
		fmt.Fprintf(os.Stderr, "  view <message-id>   View details of a specific message\n")
		fmt.Fprintf(os.Stderr, "  retry <message-id>  Force retry of a failed message\n")
		fmt.Fprintf(os.Stderr, "  delete <message-id> Delete a message from the queue\n")
		fmt.Fprintf(os.Stderr, "  flush               Delete all messages from the queue\n\n")
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

	command := args[0]
	switch command {
	case "list":
		listMessages(config)
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
		flushQueue(config)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

func listMessages(config *smtp.Config) {
	// Get all message metadata files
	pattern := filepath.Join(config.QueueDir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing queue: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Println("Queue is empty")
		return
	}

	// Create a tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tFrom\tTo\tStatus\tPriority\tRetries\tCreated\tNext Retry")

	// Load and display each message
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

	// Sort messages by priority (highest first) and then by next retry time
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].Priority != messages[j].Priority {
			return messages[i].Priority > messages[j].Priority
		}
		return messages[i].NextRetry.Before(messages[j].NextRetry)
	})

	// Display messages
	for _, msg := range messages {
		to := strings.Join(msg.To, ", ")
		if len(to) > 30 {
			to = to[:27] + "..."
		}

		nextRetry := ""
		if msg.Status == smtp.StatusFailed {
			nextRetry = msg.NextRetry.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			msg.ID,
			msg.From,
			to,
			msg.Status,
			msg.Priority,
			msg.RetryCount,
			msg.CreatedAt.Format("2006-01-02 15:04:05"),
			nextRetry,
		)
	}
	w.Flush()

	fmt.Printf("\nTotal messages: %d\n", len(messages))
}

func viewMessage(config *smtp.Config, id string) {
	// Check if message exists
	metaPath := filepath.Join(config.QueueDir, id+".json")
	msgPath := filepath.Join(config.QueueDir, id)

	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Message not found: %s\n", id)
		os.Exit(1)
	}

	// Load metadata
	data, err := os.ReadFile(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading metadata: %v\n", err)
		os.Exit(1)
	}

	var msg smtp.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing metadata: %v\n", err)
		os.Exit(1)
	}

	// Display metadata
	fmt.Println("Message ID:", msg.ID)
	fmt.Println("From:", msg.From)
	fmt.Println("To:", strings.Join(msg.To, ", "))
	fmt.Println("Status:", msg.Status)
	fmt.Println("Priority:", msg.Priority)
	fmt.Println("Created:", msg.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println("Updated:", msg.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println("Retry Count:", msg.RetryCount)

	if msg.NextRetry.After(time.Time{}) {
		fmt.Println("Next Retry:", msg.NextRetry.Format("2006-01-02 15:04:05"))
	}

	if msg.LastError != "" {
		fmt.Println("Last Error:", msg.LastError)
	}

	if len(msg.Attempts) > 0 {
		fmt.Println("Delivery Attempts:")
		for i, attempt := range msg.Attempts {
			fmt.Printf("  %d. %s\n", i+1, attempt.Format("2006-01-02 15:04:05"))
		}
	}

	// Check if message data exists
	if _, err := os.Stat(msgPath); !os.IsNotExist(err) {
		// Display message size
		info, err := os.Stat(msgPath)
		if err == nil {
			fmt.Printf("Message Size: %d bytes\n", info.Size())
		}

		// Ask if user wants to view message content
		fmt.Print("\nView message content? (y/n): ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(answer) == "y" {
			// Read and display message content
			content, err := os.ReadFile(msgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading message: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("\n--- Message Content ---")
			fmt.Println(string(content))
		}
	} else {
		fmt.Println("Message data not found")
	}
}

func retryMessage(config *smtp.Config, id string) {
	// Check if message exists
	metaPath := filepath.Join(config.QueueDir, id+".json")
	msgPath := filepath.Join(config.QueueDir, id)

	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Message not found: %s\n", id)
		os.Exit(1)
	}

	if _, err := os.Stat(msgPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Message data not found: %s\n", id)
		os.Exit(1)
	}

	// Load metadata
	data, err := os.ReadFile(metaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading metadata: %v\n", err)
		os.Exit(1)
	}

	var msg smtp.QueuedMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing metadata: %v\n", err)
		os.Exit(1)
	}

	// Update metadata for immediate retry
	msg.Status = smtp.StatusQueued
	msg.NextRetry = time.Now()
	msg.UpdatedAt = time.Now()

	// Save updated metadata
	updatedData, err := json.Marshal(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding metadata: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(metaPath, updatedData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing metadata: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Message %s scheduled for immediate retry\n", id)
}

func deleteMessage(config *smtp.Config, id string) {
	// Check if message exists
	metaPath := filepath.Join(config.QueueDir, id+".json")
	msgPath := filepath.Join(config.QueueDir, id)

	metaExists := false
	msgExists := false

	if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
		metaExists = true
	}

	if _, err := os.Stat(msgPath); !os.IsNotExist(err) {
		msgExists = true
	}

	if !metaExists && !msgExists {
		fmt.Fprintf(os.Stderr, "Message not found: %s\n", id)
		os.Exit(1)
	}

	// Delete files
	if metaExists {
		if err := os.Remove(metaPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting metadata: %v\n", err)
			os.Exit(1)
		}
	}

	if msgExists {
		if err := os.Remove(msgPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting message data: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Message %s deleted from queue\n", id)
}

func flushQueue(config *smtp.Config) {
	// Ask for confirmation
	fmt.Print("Are you sure you want to delete all messages from the queue? (y/n): ")
	var answer string
	fmt.Scanln(&answer)
	if strings.ToLower(answer) != "y" {
		fmt.Println("Operation cancelled")
		return
	}

	// Get all files in queue directory
	files, err := os.ReadDir(config.QueueDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading queue directory: %v\n", err)
		os.Exit(1)
	}

	count := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		path := filepath.Join(config.QueueDir, file.Name())
		if err := os.Remove(path); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting %s: %v\n", file.Name(), err)
			continue
		}
		count++
	}

	fmt.Printf("Deleted %d files from queue\n", count)
}
