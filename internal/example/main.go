package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/busybox42/elemta/internal/cache"
	"github.com/busybox42/elemta/internal/logging"
)

func main() {
	// Initialize the logger
	fmt.Println("Initializing loggers...")

	// Create a console logger
	consoleLogger, err := logging.Factory(logging.Config{
		Type:      "console",
		Name:      "console",
		Level:     logging.Debug,
		Formatter: "text",
	})
	if err != nil {
		fmt.Printf("Failed to create console logger: %v\n", err)
		os.Exit(1)
	}

	// Register the console logger
	if err := logging.Register(consoleLogger, "console"); err != nil {
		fmt.Printf("Failed to register console logger: %v\n", err)
		os.Exit(1)
	}

	// Set as default logger
	if err := logging.SetDefault("console"); err != nil {
		fmt.Printf("Failed to set default logger: %v\n", err)
		os.Exit(1)
	}

	// Create a file logger
	fileLogger, err := logging.Factory(logging.Config{
		Type:      "file",
		Name:      "file",
		Level:     logging.Info,
		Output:    "./logs/example.log",
		Formatter: "json",
		Options: map[string]interface{}{
			"maxSize":  int64(1024 * 1024), // 1MB
			"maxFiles": 5,
		},
	})
	if err != nil {
		logging.Default().Error("Failed to create file logger", logging.F("error", err))
	} else {
		// Register the file logger
		if err := logging.Register(fileLogger, "file"); err != nil {
			logging.Default().Error("Failed to register file logger", logging.F("error", err))
		}
	}

	// Initialize the cache
	fmt.Println("Initializing caches...")

	// Create a memory cache
	memoryCache, err := cache.Factory(cache.Config{
		Type: "memory",
		Name: "memory",
	})
	if err != nil {
		logging.Default().Error("Failed to create memory cache", logging.F("error", err))
		os.Exit(1)
	}

	// Connect to the memory cache
	if err := memoryCache.Connect(); err != nil {
		logging.Default().Error("Failed to connect to memory cache", logging.F("error", err))
		os.Exit(1)
	}

	// Create a cache manager
	cacheManager := cache.NewManager()

	// Register the memory cache
	if err := cacheManager.Register(memoryCache); err != nil {
		logging.Default().Error("Failed to register memory cache", logging.F("error", err))
		os.Exit(1)
	}

	// Log success
	logging.Default().Info("Cache and logging systems initialized successfully")

	// Demonstrate logging with different levels and fields
	demoLogging()

	// Demonstrate cache operations
	demoCache(memoryCache)

	// Clean up
	if err := logging.CloseAll(); err != nil {
		fmt.Printf("Error closing loggers: %v\n", err)
	}

	if err := cacheManager.CloseAll(); err != nil {
		fmt.Printf("Error closing caches: %v\n", err)
	}

	fmt.Println("Example completed successfully")
}

func demoLogging() {
	logger := logging.Default()

	logger.Debug("This is a debug message")
	logger.Info("This is an info message")
	logger.Warn("This is a warning message")
	logger.Error("This is an error message")

	// Logging with fields
	logger.Info("User logged in",
		logging.F("user_id", "12345"),
		logging.F("ip", "192.168.1.1"),
	)

	// Using WithFields
	userLogger := logger.WithFields(
		logging.F("user_id", "12345"),
		logging.F("session_id", "abc123"),
	)
	userLogger.Info("User performed an action")
	userLogger.Warn("User attempted a restricted operation")

	// Get file logger if available
	if fileLogger, ok := logging.Get("file"); ok {
		fileLogger.Info("This message goes to the file logger")
	}
}

func demoCache(c cache.Cache) {
	ctx := context.Background()

	// Set a value
	err := c.Set(ctx, "greeting", "Hello, World!", 1*time.Minute)
	if err != nil {
		logging.Default().Error("Failed to set cache value", logging.F("error", err))
		return
	}
	logging.Default().Info("Set value in cache", logging.F("key", "greeting"))

	// Get a value
	value, err := c.Get(ctx, "greeting")
	if err != nil {
		logging.Default().Error("Failed to get cache value", logging.F("error", err))
		return
	}
	logging.Default().Info("Got value from cache",
		logging.F("key", "greeting"),
		logging.F("value", value),
	)

	// Set a value only if it doesn't exist
	success, err := c.SetNX(ctx, "counter", 1, 1*time.Minute)
	if err != nil {
		logging.Default().Error("Failed to SetNX cache value", logging.F("error", err))
		return
	}
	logging.Default().Info("SetNX result",
		logging.F("key", "counter"),
		logging.F("success", success),
	)

	// Increment a counter
	newValue, err := c.Increment(ctx, "counter", 1)
	if err != nil {
		logging.Default().Error("Failed to increment counter", logging.F("error", err))
		return
	}
	logging.Default().Info("Incremented counter",
		logging.F("key", "counter"),
		logging.F("new_value", newValue),
	)

	// Check if a key exists
	exists, err := c.Exists(ctx, "greeting")
	if err != nil {
		logging.Default().Error("Failed to check if key exists", logging.F("error", err))
		return
	}
	logging.Default().Info("Key exists check",
		logging.F("key", "greeting"),
		logging.F("exists", exists),
	)

	// Delete a key
	err = c.Delete(ctx, "greeting")
	if err != nil {
		logging.Default().Error("Failed to delete key", logging.F("error", err))
		return
	}
	logging.Default().Info("Deleted key", logging.F("key", "greeting"))

	// Verify key is gone
	exists, err = c.Exists(ctx, "greeting")
	if err != nil {
		logging.Default().Error("Failed to check if key exists", logging.F("error", err))
		return
	}
	logging.Default().Info("Key exists check after deletion",
		logging.F("key", "greeting"),
		logging.F("exists", exists),
	)
}
