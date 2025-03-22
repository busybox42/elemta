package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/busybox42/elemta/cmd/elemta-cli/client"
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
	var listQueueCmd = &cobra.Command{
		Use:   "list [queue_type]",
		Short: "List messages in the queue",
		Long: `List all messages in the specified queue.
If no queue type is specified, lists messages from all queues.
Valid queue types: active, deferred, hold, failed`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			apiClient := client.NewClient(apiURL, apiKey)

			var messages []client.Message
			var err error

			if len(args) > 0 {
				queueType := args[0]
				messages, err = apiClient.GetQueueMessages(queueType)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			} else {
				messages, err = apiClient.GetAllMessages()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			}

			if len(messages) == 0 {
				fmt.Println("No messages in queue")
				return
			}

			printMessages(messages)
		},
	}

	// Show command
	var showQueueCmd = &cobra.Command{
		Use:   "show [message_id]",
		Short: "Show a specific message",
		Long:  `Show details of a specific message in the queue`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			apiClient := client.NewClient(apiURL, apiKey)

			id := args[0]

			// If raw flag is set, print raw message
			if cmd.Flags().Changed("raw") {
				content, err := apiClient.GetMessageRaw(id)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				fmt.Println(content)
				return
			}

			// Otherwise, print message with metadata
			message, err := apiClient.GetMessage(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Message ID: %s\n", message.ID)
			fmt.Printf("Queue: %s\n", message.QueueType)
			fmt.Printf("From: %s\n", message.From)
			fmt.Printf("To: %v\n", message.To)
			fmt.Printf("Subject: %s\n", message.Subject)
			fmt.Printf("Size: %d bytes\n", message.Size)
			fmt.Println("\nContent:")
			fmt.Println("--------")
			fmt.Println(message.Content)
		},
	}
	showQueueCmd.Flags().Bool("raw", false, "Display raw message content")

	// Delete command
	var deleteQueueCmd = &cobra.Command{
		Use:   "delete [message_id]",
		Short: "Delete a message from the queue",
		Long:  `Delete a specific message from the queue`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			apiClient := client.NewClient(apiURL, apiKey)

			id := args[0]
			if err := apiClient.DeleteMessage(id); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Message %s deleted from queue\n", id)
		},
	}

	// Flush command
	var flushQueueCmd = &cobra.Command{
		Use:   "flush [queue_type]",
		Short: "Flush messages from the queue",
		Long: `Flush all messages from the specified queue.
If no queue type is specified, flushes all queues.
Valid queue types: active, deferred, hold, failed, all`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			apiClient := client.NewClient(apiURL, apiKey)

			queueType := "all"
			if len(args) > 0 {
				queueType = args[0]
			}

			if err := apiClient.FlushQueue(queueType); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Queue %s flushed\n", queueType)
		},
	}

	// Stats command
	var statsQueueCmd = &cobra.Command{
		Use:   "stats",
		Short: "Show queue statistics",
		Long:  `Display statistics about the mail queues`,
		Run: func(cmd *cobra.Command, args []string) {
			apiClient := client.NewClient(apiURL, apiKey)

			stats, err := apiClient.GetQueueStats()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Print stats in a nice table
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Queue\tCount")
			fmt.Fprintln(w, "------\t------")

			total := 0
			for queue, count := range stats {
				fmt.Fprintf(w, "%s\t%d\n", queue, count)
				total += count
			}

			fmt.Fprintf(w, "------\t------\n")
			fmt.Fprintf(w, "Total\t%d\n", total)
			w.Flush()
		},
	}

	queueCmd.AddCommand(listQueueCmd)
	queueCmd.AddCommand(showQueueCmd)
	queueCmd.AddCommand(deleteQueueCmd)
	queueCmd.AddCommand(flushQueueCmd)
	queueCmd.AddCommand(statsQueueCmd)
}

// printMessages prints message information in a table
func printMessages(messages []client.Message) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tFrom\tTo\tSubject\tQueue\tSize")
	fmt.Fprintln(w, "------\t------\t------\t------\t------\t------")

	for _, msg := range messages {
		to := ""
		if len(msg.To) > 0 {
			to = msg.To[0]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
			msg.ID,
			msg.From,
			to,
			msg.Subject,
			msg.QueueType,
			msg.Size)
	}
	w.Flush()
}
