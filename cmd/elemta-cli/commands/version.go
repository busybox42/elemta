package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version is the version of the CLI
	Version = "0.1.0"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display version information for the Elemta CLI`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Elemta CLI version %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
