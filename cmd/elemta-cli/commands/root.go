package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global configuration
	apiURL    string
	apiKey    string
	verbose   bool
	formatter string

	// Root command
	rootCmd = &cobra.Command{
		Use:   "elemta-cli",
		Short: "Elemta CLI - Command Line Interface for Elemta MTA",
		Long: `A command-line tool for interacting with and managing the Elemta Mail Transfer Agent.
Elemta CLI provides commands for queue management, server status, and more.`,
	}
)

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Add global flags
	rootCmd.PersistentFlags().StringVarP(&apiURL, "api-url", "a", "http://localhost:8081", "API server URL")
	rootCmd.PersistentFlags().StringVarP(&apiKey, "api-key", "k", "", "API key for authentication")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&formatter, "formatter", "f", "table", "Output format (table, json, csv)")
}
