package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/spf13/cobra"
)

var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage the mail queue",
	Long:  `Manage the mail queue`,
}

func init() {
	rootCmd.AddCommand(queueCmd)

	// List command
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all messages in the queue",
		Run: func(cmd *cobra.Command, args []string) {
			queueDir := getQueueDir()
			manager := queue.NewManager(queueDir, 0) // CLI tools use immediate deletion
			defer manager.Stop()

			// Get messages from all queues
			messages, err := manager.GetAllMessages()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if len(messages) == 0 {
				fmt.Println("No messages in queue")
				return
			}

			// Print messages in a nice table
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tFrom\tTo\tSubject\tQueue\tSize")
			_, _ = fmt.Fprintln(w, "------\t------\t------\t------\t------\t------")

			for _, msg := range messages {
				to := ""
				if len(msg.To) > 0 {
					to = msg.To[0]
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
					msg.ID,
					msg.From,
					to,
					msg.Subject,
					msg.QueueType,
					msg.Size)
			}
			_ = w.Flush()
		},
	}

	// Show command
	var showCmd = &cobra.Command{
		Use:   "show [message ID]",
		Short: "Show details of a specific message",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			queueDir := getQueueDir()
			manager := queue.NewManager(queueDir, 0) // CLI tools use immediate deletion
			defer manager.Stop()

			id := args[0]
			content, err := manager.GetMessageContent(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(string(content))
		},
	}

	// Delete command
	var deleteCmd = &cobra.Command{
		Use:   "delete [message ID]",
		Short: "Delete a message from the queue",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			queueDir := getQueueDir()
			manager := queue.NewManager(queueDir, 0) // CLI tools use immediate deletion
			defer manager.Stop()

			id := args[0]
			if err := manager.DeleteMessage(id); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Message %s deleted from queue\n", id)
		},
	}

	// Flush command
	var flushCmd = &cobra.Command{
		Use:   "flush",
		Short: "Delete all messages from the queue",
		Run: func(cmd *cobra.Command, args []string) {
			queueDir := getQueueDir()
			manager := queue.NewManager(queueDir, 0) // CLI tools use immediate deletion
			defer manager.Stop()

			if err := manager.FlushAllQueues(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("All queues flushed successfully")
		},
	}

	// Stats command
	var statsCmd = &cobra.Command{
		Use:   "stats",
		Short: "Show queue statistics",
		Run: func(cmd *cobra.Command, args []string) {
			queueDir := getQueueDir()
			manager := queue.NewManager(queueDir, 0) // CLI tools use immediate deletion
			defer manager.Stop()

			stats := manager.GetStats()

			// Print stats in a nice table
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "Queue\tCount")
			_, _ = fmt.Fprintln(w, "------\t------")

			_, _ = fmt.Fprintf(w, "Active\t%d\n", stats.ActiveCount)
			_, _ = fmt.Fprintf(w, "Deferred\t%d\n", stats.DeferredCount)
			_, _ = fmt.Fprintf(w, "Hold\t%d\n", stats.HoldCount)
			_, _ = fmt.Fprintf(w, "Failed\t%d\n", stats.FailedCount)

			_, _ = fmt.Fprintf(w, "------\t------\n")
			total := stats.ActiveCount + stats.DeferredCount + stats.HoldCount + stats.FailedCount
			_, _ = fmt.Fprintf(w, "Total\t%d\n", total)
			_, _ = fmt.Fprintf(w, "Total Size\t%d bytes\n", stats.TotalSize)
			_ = w.Flush()
		},
	}

	queueCmd.AddCommand(listCmd)
	queueCmd.AddCommand(showCmd)
	queueCmd.AddCommand(deleteCmd)
	queueCmd.AddCommand(flushCmd)
	queueCmd.AddCommand(statsCmd)
}

func getQueueDir() string {
	if cfg != nil && cfg.Queue.Dir != "" {
		return cfg.Queue.Dir
	}

	// Check for test mode environment variable
	if testQueue := os.Getenv("ELEMTA_TEST_QUEUE_DIR"); testQueue != "" {
		return testQueue
	}

	// Default queue directory
	return "/app/queue"
}
