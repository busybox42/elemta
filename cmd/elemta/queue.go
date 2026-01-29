package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

type queueOperations struct {
	config       *smtp.Config
	queueManager queue.QueueManager
	out          io.Writer
}

func newQueueOperations(config *smtp.Config) *queueOperations {
	return &queueOperations{
		config:       config,
		queueManager: queue.NewManager(config.QueueDir, config.FailedQueueRetentionHours),
		out:          os.Stdout,
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
			msg.QueueType,
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
	queueTypes := []queue.QueueType{
		queue.Active,
		queue.Deferred,
		queue.Hold,
		queue.Failed,
	}

	for _, qType := range queueTypes {
		err := qo.queueManager.FlushQueue(qType)
		if err != nil {
			return fmt.Errorf("failed to flush queue %s: %w", qType, err)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Successfully flushed all queues\n")
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
		case queue.Active:
			stats.Active++
		case queue.Deferred:
			stats.Deferred++
		case queue.Hold:
			stats.Held++
		case queue.Failed:
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

func (qo *queueOperations) getAllMessages() ([]queue.Message, error) {
	return qo.queueManager.GetAllMessages()
}

func (qo *queueOperations) findMessage(id string) (queue.Message, error) {
	msg, err := qo.queueManager.GetMessage(id)
	if err != nil {
		return queue.Message{}, fmt.Errorf("message %s not found: %w", id, err)
	}
	return msg, nil
}
