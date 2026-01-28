package main

import (
"os"

"github.com/busybox42/elemta/cmd/elemta/commands"
"github.com/busybox42/elemta/internal/logging"
)

func main() {
// Initialize logging very early to ensure all components write to both stdout and file
logLevel := os.Getenv("LOG_LEVEL")
if logLevel == "" {
logLevel = "INFO"
}
logging.InitializeLogging(logLevel)

commands.Execute()
}
