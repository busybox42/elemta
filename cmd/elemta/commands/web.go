package commands

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/busybox42/elemta/internal/api"
	"github.com/spf13/cobra"
)

var (
	webListenAddr string
	webRoot       string
	webQueueDir   string
	authEnabled   bool
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web interface",
	Long: `Start the Elemta web dashboard interface.
This provides a web-based UI for monitoring and managing mail queues.`,
	Run: runWeb,
}

func init() {
	rootCmd.AddCommand(webCmd)

	// Web-specific flags
	webCmd.Flags().StringVarP(&webListenAddr, "listen", "l", "127.0.0.1:8025", "Address to listen on")
	webCmd.Flags().StringVar(&webRoot, "web-root", "./web/static", "Path to web static files")
	webCmd.Flags().StringVar(&webQueueDir, "queue-dir", "./queue", "Path to queue directory")
	webCmd.Flags().BoolVar(&authEnabled, "auth-enabled", false, "Enable authentication and authorization")
}

func runWeb(cmd *cobra.Command, args []string) {
	// Create API config
	apiConfig := &api.Config{
		Enabled:     true,
		ListenAddr:  webListenAddr,
		WebRoot:     webRoot,
		AuthEnabled: authEnabled,
	}

	// Create and start API server
	server, err := api.NewServer(apiConfig, webQueueDir)
	if err != nil {
		log.Fatalf("Failed to create API server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}

	fmt.Printf("Elemta web interface started on http://%s\n", webListenAddr)
	fmt.Println("Press Ctrl+C to stop")

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down web interface...")
	if err := server.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
}
