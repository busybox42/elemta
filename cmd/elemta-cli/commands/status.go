package commands

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/busybox42/elemta/cmd/elemta-cli/client"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show server status",
	Long:  `Show the current status of the Elemta MTA server`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create a client with a timeout
		httpClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		// Try to connect to the API server
		resp, err := httpClient.Get(apiURL + "/api/queue/stats")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Could not connect to Elemta server: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Println("Status: Running")
			fmt.Printf("API Server: %s\n", apiURL)

			if verbose {
				// Get queue stats to show more info
				apiClient := client.NewClient(apiURL, apiKey)
				stats, err := apiClient.GetQueueStats()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Could not get queue statistics: %v\n", err)
				} else {
					fmt.Println("\nQueue Statistics:")
					for qType, count := range stats {
						fmt.Printf("  %s: %d messages\n", qType, count)
					}
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Status: Error (HTTP %d)\n", resp.StatusCode)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
