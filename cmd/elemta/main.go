package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "elemta",
	Short: "Command line interface for managing Elemta Mail Transfer Agent",
	Long:  `A command line tool for managing and monitoring the Elemta Mail Transfer Agent.`,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Elemta MTA server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting Elemta MTA server...")

		// Load configuration
		configPath := os.Getenv("ELEMTA_CONFIG_PATH")
		fmt.Printf("Using config path: %s\n", configPath)

		config, err := smtp.LoadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Configuration loaded successfully. Hostname: %s, Listen: %s\n",
			config.Hostname, config.ListenAddr)

		// Create and start the server
		fmt.Println("Creating SMTP server...")
		server, err := smtp.NewServer(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Starting SMTP server...")
		if err := server.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("SMTP server started successfully!")

		// Set up signal handling for graceful shutdown
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		// Block until we receive a signal
		fmt.Println("Server running. Press Ctrl+C to stop.")
		<-c

		fmt.Println("Shutting down server...")
		if err := server.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing server: %v\n", err)
		}
	},
}

var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage the mail queue",
}

var queueListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all messages in the queue",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := smtp.LoadConfig("")
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error loading config: %v\n", err)
			os.Exit(1)
		}
		qo := newQueueOperations(config)
		if err := qo.listQueue(cmd, args); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var queueShowCmd = &cobra.Command{
	Use:   "show [message-id]",
	Short: "Show details of a specific message",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := smtp.LoadConfig("")
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error loading config: %v\n", err)
			os.Exit(1)
		}
		qo := newQueueOperations(config)
		if err := qo.showMessage(cmd, args); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var queueDeleteCmd = &cobra.Command{
	Use:   "delete [message-id]",
	Short: "Delete a message from the queue",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := smtp.LoadConfig("")
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error loading config: %v\n", err)
			os.Exit(1)
		}
		qo := newQueueOperations(config)
		if err := qo.deleteMessage(cmd, args); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var queueFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Delete all messages from the queue",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := smtp.LoadConfig("")
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error loading config: %v\n", err)
			os.Exit(1)
		}
		qo := newQueueOperations(config)
		if err := qo.flushQueue(cmd, args); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var queueStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show queue statistics",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := smtp.LoadConfig("")
		if err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error loading config: %v\n", err)
			os.Exit(1)
		}
		qo := newQueueOperations(config)
		if err := qo.showStats(cmd, args); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(queueCmd)

	queueCmd.AddCommand(queueListCmd)
	queueCmd.AddCommand(queueShowCmd)
	queueCmd.AddCommand(queueDeleteCmd)
	queueCmd.AddCommand(queueFlushCmd)
	queueCmd.AddCommand(queueStatsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
