# Elemta Internal Packages

This directory contains internal packages used by the Elemta application.

## Cache System

The cache system provides a distributed cache that can be shared across multiple nodes. It supports various backends such as Redis and in-memory caching.

### Features

- Common interface for different cache backends
- Support for Redis and in-memory caching
- Key-value operations with expiration
- Atomic operations (increment, decrement, SetNX)
- Cache manager for handling multiple cache instances

### Usage

```go
import "github.com/busybox42/elemta/internal/cache"

// Create a cache instance
redisCache, err := cache.Factory(cache.Config{
    Type:     "redis",
    Name:     "session-cache",
    Host:     "localhost",
    Port:     6379,
    Password: "",
    Database: 0,
})
if err != nil {
    // Handle error
}

// Connect to the cache
if err := redisCache.Connect(); err != nil {
    // Handle error
}

// Use the cache
ctx := context.Background()
err = redisCache.Set(ctx, "user:123:session", sessionData, 30*time.Minute)
```

### Cache Manager

The cache manager allows you to register and manage multiple cache instances:

```go
// Create a cache manager
manager := cache.NewManager()

// Register caches
manager.Register(redisCache)
manager.Register(memoryCache)

// Get a cache by name
if sessionCache, exists := manager.Get("session-cache"); exists {
    // Use the cache
}

// Close all caches when shutting down
manager.CloseAll()
```

## Logging System

The logging system provides a flexible and pluggable logging framework with support for various backends such as console, file, and Elasticsearch.

### Features

- Common interface for different logging backends
- Support for console, file, and Elasticsearch logging
- Structured logging with fields
- Multiple log levels (Debug, Info, Warn, Error, Fatal)
- Log formatting in text or JSON
- File rotation for file logger
- Buffered logging for Elasticsearch

### Usage

```go
import "github.com/busybox42/elemta/internal/logging"

// Create a logger
consoleLogger, err := logging.Factory(logging.Config{
    Type:      "console",
    Name:      "app-logger",
    Level:     logging.Info,
    Formatter: "text",
})
if err != nil {
    // Handle error
}

// Register the logger
logging.Register(consoleLogger, "app-logger")

// Set as default logger
logging.SetDefault("app-logger")

// Use the logger
logging.Default().Info("Application started", 
    logging.F("version", "1.0.0"),
    logging.F("environment", "production"),
)

// Create a logger with context
userLogger := logging.Default().WithFields(
    logging.F("user_id", "123"),
    logging.F("session_id", "abc123"),
)
userLogger.Info("User logged in")
```

### Logger Manager

The logging system includes a manager for handling multiple logger instances:

```go
// Get the logger manager
manager := logging.GetManager()

// Register loggers
manager.Register(consoleLogger, "console")
manager.Register(fileLogger, "file")

// Get a logger by name
if appLogger, exists := manager.Get("app-logger"); exists {
    // Use the logger
}

// Close all loggers when shutting down
manager.CloseAll()
```

## Example

See the `internal/example/main.go` file for a complete example of using both the cache and logging systems. 