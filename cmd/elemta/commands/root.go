package commands

import (
	"fmt"
	"os"

	"github.com/busybox42/elemta/internal/config"
	"github.com/spf13/cobra"
)

var (
	// Global configuration
	configPath string
	cfg        *config.Config

	// Root command
	rootCmd = &cobra.Command{
		Use:   "elemta",
		Short: "Elemta Mail Transfer Agent",
		Long: `A command line tool for managing and monitoring the Elemta Mail Transfer Agent.
Elemta is a high-performance, carrier-grade MTA with modular architecture and plugin system.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Skip config loading for some commands
			if cmd.Name() == "help" || cmd.Name() == "version" || cmd.Name() == "completion" {
				return
			}

			// Load configuration
			var err error
			cfg, err = config.LoadConfig(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			// For server command, ensure queue directory exists
			if cmd.Name() == "server" {
				if err := cfg.EnsureQueueDirectory(); err != nil {
					fmt.Fprintf(os.Stderr, "Error creating queue directories: %v\n", err)
					os.Exit(1)
				}
			}
		},
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
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Path to configuration file")
}

// GetConfig returns the global configuration
func GetConfig() *config.Config {
	return cfg
}

// GetRootCmd returns the root command for testing purposes
func GetRootCmd() *cobra.Command {
	return rootCmd
}
