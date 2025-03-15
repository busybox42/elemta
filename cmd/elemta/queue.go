package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

type queueOperations struct {
	config *smtp.Config
	out    io.Writer
}

func newQueueOperations(config *smtp.Config) *queueOperations {
	return &queueOperations{
		config: config,
		out:    os.Stdout,
	}
}

func (qo *queueOperations) listQueue(cmd *cobra.Command, args []string) error {
	messages, err := qo.getAllMessages()
	if err != nil {
		return err
	}

	if len(messages) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No messages in queue")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tFrom\tTo\tStatus\tQueue\tNext Retry\tAttempts")
	fmt.Fprintln(w, "--\t----\t--\t------\t-----\t----------\t--------")

	for _, msg := range messages {
		nextRetry := "-"
		if !msg.NextRetry.IsZero() {
			nextRetry = msg.NextRetry.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n",
			msg.ID,
			msg.From,
			msg.To[0], // Show first recipient
			msg.Status,
			msg.QueueType,
			nextRetry,
			msg.RetryCount,
		)
	}
	return w.Flush()
}

func (qo *queueOperations) showMessage(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("message ID required")
	}

	msg, err := qo.findMessage(args[0])
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func (qo *queueOperations) deleteMessage(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("message ID required")
	}

	msg, err := qo.findMessage(args[0])
	if err != nil {
		return err
	}

	path := filepath.Join(qo.config.QueueDir, string(msg.QueueType), args[0]+".json")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Message %s deleted successfully\n", args[0])
	return nil
}

func (qo *queueOperations) flushQueue(cmd *cobra.Command, args []string) error {
	queueTypes := []smtp.QueueType{
		smtp.QueueTypeActive,
		smtp.QueueTypeDeferred,
		smtp.QueueTypeHeld,
		smtp.QueueTypeFailed,
	}

	var totalDeleted int
	for _, qType := range queueTypes {
		dir := filepath.Join(qo.config.QueueDir, string(qType))
		files, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("failed to read directory %s: %w", dir, err)
		}

		for _, file := range files {
			if filepath.Ext(file.Name()) != ".json" {
				continue
			}

			path := filepath.Join(dir, file.Name())
			if err := os.Remove(path); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Warning: failed to delete %s: %v\n", path, err)
				continue
			}
			totalDeleted++
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Successfully flushed queue: %d messages deleted\n", totalDeleted)
	return nil
}

func (qo *queueOperations) showStats(cmd *cobra.Command, args []string) error {
	messages, err := qo.getAllMessages()
	if err != nil {
		return err
	}

	stats := struct {
		Total     int
		Active    int
		Deferred  int
		Held      int
		Failed    int
		Attempts  int
		AvgRetry  float64
		OldestMsg time.Time
		NewestMsg time.Time
	}{
		OldestMsg: time.Now(),
		NewestMsg: time.Time{},
	}

	for _, msg := range messages {
		stats.Total++
		stats.Attempts += msg.RetryCount

		switch msg.QueueType {
		case smtp.QueueTypeActive:
			stats.Active++
		case smtp.QueueTypeDeferred:
			stats.Deferred++
		case smtp.QueueTypeHeld:
			stats.Held++
		case smtp.QueueTypeFailed:
			stats.Failed++
		}

		if msg.CreatedAt.Before(stats.OldestMsg) {
			stats.OldestMsg = msg.CreatedAt
		}
		if msg.CreatedAt.After(stats.NewestMsg) {
			stats.NewestMsg = msg.CreatedAt
		}
	}

	if stats.Total > 0 {
		stats.AvgRetry = float64(stats.Attempts) / float64(stats.Total)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Queue Statistics")
	fmt.Fprintln(w, "---------------")
	fmt.Fprintf(w, "Total Messages:\t%d\n", stats.Total)
	fmt.Fprintf(w, "Active:\t%d\n", stats.Active)
	fmt.Fprintf(w, "Deferred:\t%d\n", stats.Deferred)
	fmt.Fprintf(w, "Held:\t%d\n", stats.Held)
	fmt.Fprintf(w, "Failed:\t%d\n", stats.Failed)
	fmt.Fprintf(w, "Average Retries:\t%.2f\n", stats.AvgRetry)

	if !stats.NewestMsg.IsZero() {
		fmt.Fprintf(w, "Newest Message:\t%s\n", stats.NewestMsg.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "Oldest Message:\t%s\n", stats.OldestMsg.Format("2006-01-02 15:04:05"))
	}

	return w.Flush()
}

func (qo *queueOperations) getAllMessages() ([]*smtp.QueuedMessage, error) {
	var messages []*smtp.QueuedMessage
	queueTypes := []smtp.QueueType{
		smtp.QueueTypeActive,
		smtp.QueueTypeDeferred,
		smtp.QueueTypeHeld,
		smtp.QueueTypeFailed,
	}

	for _, qType := range queueTypes {
		dir := filepath.Join(qo.config.QueueDir, string(qType))
		files, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
		}

		for _, file := range files {
			if filepath.Ext(file.Name()) != ".json" {
				continue
			}

			path := filepath.Join(dir, file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(qo.out, "Warning: failed to read %s: %v\n", path, err)
				continue
			}

			var msg smtp.QueuedMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				fmt.Fprintf(qo.out, "Warning: failed to parse %s: %v\n", path, err)
				continue
			}

			messages = append(messages, &msg)
		}
	}

	// Sort by creation time, newest first
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].CreatedAt.After(messages[j].CreatedAt)
	})

	return messages, nil
}

func (qo *queueOperations) findMessage(id string) (*smtp.QueuedMessage, error) {
	messages, err := qo.getAllMessages()
	if err != nil {
		return nil, err
	}

	for _, msg := range messages {
		if msg.ID == id {
			return msg, nil
		}
	}

	return nil, fmt.Errorf("message %s not found", id)
}
