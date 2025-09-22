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
			if cmd.Name() == "help" || cmd.Name() == "version" || cmd.Name() == "completion" || cmd.Name() == "secure" {
				return
			}

			// Load configuration
			var err error
			cfg, err = config.LoadConfig(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "FATAL ERROR: Failed to load configuration: %v\n", err)
				fmt.Fprintf(os.Stderr, "\nTroubleshooting:\n")
				fmt.Fprintf(os.Stderr, "  - Check if the config file exists and is readable\n")
				fmt.Fprintf(os.Stderr, "  - Verify the config file format (should be TOML)\n")
				fmt.Fprintf(os.Stderr, "  - Try specifying a config file with: --config /path/to/config.toml\n")
				fmt.Fprintf(os.Stderr, "  - Check file permissions on the config file\n")
				os.Exit(1)
			}

			// For server command, ensure queue directory exists
			if cmd.Name() == "server" {
				if err := cfg.EnsureQueueDirectory(); err != nil {
					fmt.Fprintf(os.Stderr, "FATAL ERROR: Failed to create queue directories: %v\n", err)
					fmt.Fprintf(os.Stderr, "\nTroubleshooting:\n")
					fmt.Fprintf(os.Stderr, "  - Check if you have write permissions to the queue directory: %s\n", cfg.Queue.Dir)
					fmt.Fprintf(os.Stderr, "  - Try running with a different queue directory in your config\n")
					fmt.Fprintf(os.Stderr, "  - Ensure the parent directory exists and is writable\n")
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
