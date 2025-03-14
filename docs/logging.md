# Logging System

Elemta includes a flexible logging system that supports multiple outputs. This document explains how to configure and use the logging system.

## Supported Log Outputs

Elemta currently supports the following log outputs:

- **Console**: Logs to standard output, ideal for development and debugging
- **File**: Logs to a file, ideal for production and long-term storage
- **Elasticsearch**: Logs to Elasticsearch, ideal for centralized logging and analysis

## Configuration

The logging system is configured using the `logging.Config` struct:

```go
import "github.com/yourusername/elemta/internal/logging"

// Create a logger with console and file outputs
logger := logging.NewLogger(&logging.Config{
    Console: &logging.ConsoleConfig{
        Enabled: true,
        Level:   "info",
    },
    File: &logging.FileConfig{
        Enabled: true,
        Path:    "./logs/elemta.log",
        Level:   "debug",
    },
})

// Create a logger with Elasticsearch output
esLogger := logging.NewLogger(&logging.Config{
    Elasticsearch: &logging.ElasticsearchConfig{
        Enabled:  true,
        URL:      "http://localhost:9200",
        Index:    "elemta-logs",
        Username: "elastic",
        Password: "password",
        Level:    "info",
    },
})
```

### Configuration Options

#### Console Output

- `Enabled`: Whether console logging is enabled
- `Level`: The minimum log level to output (`debug`, `info`, `warn`, `error`, `fatal`)

#### File Output

- `Enabled`: Whether file logging is enabled
- `Path`: The path to the log file
- `Level`: The minimum log level to output
- `MaxSize`: The maximum size of the log file in megabytes before rotation
- `MaxBackups`: The maximum number of old log files to retain
- `MaxAge`: The maximum number of days to retain old log files
- `Compress`: Whether to compress rotated log files

#### Elasticsearch Output

- `Enabled`: Whether Elasticsearch logging is enabled
- `URL`: The URL of the Elasticsearch server
- `Index`: The Elasticsearch index to use
- `Username`: The username for Elasticsearch authentication
- `Password`: The password for Elasticsearch authentication
- `Level`: The minimum log level to output

## Usage

Once you have created a logger, you can use it to log messages at different levels:

```go
// Log at different levels
logger.Debug("This is a debug message")
logger.Info("This is an info message")
logger.Warn("This is a warning message")
logger.Error("This is an error message", errors.New("error details"))
logger.Fatal("This is a fatal message", errors.New("fatal error"))

// Log with context
logger.WithFields(map[string]interface{}{
    "user_id": 123,
    "action":  "login",
}).Info("User logged in")

// Log with a single field
logger.WithField("request_id", "abc123").Info("Processing request")
```

## Log Levels

Elemta uses the following log levels, in order of increasing severity:

1. **Debug**: Detailed information, typically useful only for diagnosing problems
2. **Info**: Confirmation that things are working as expected
3. **Warn**: Indication that something unexpected happened, but the application can continue
4. **Error**: An error occurred, but the application can still function
5. **Fatal**: A severe error occurred, and the application cannot continue

## Structured Logging

Elemta's logging system supports structured logging, which allows you to include additional context with your log messages:

```go
// Log with structured data
logger.WithFields(map[string]interface{}{
    "user_id":    123,
    "email":      "user@example.com",
    "ip_address": "192.168.1.1",
    "action":     "login",
    "status":     "success",
}).Info("User authentication")
```

This makes it easier to filter and analyze logs, especially when using Elasticsearch.

## Log Rotation

When using file logging, Elemta supports log rotation to manage log file size and retention:

```go
logger := logging.NewLogger(&logging.Config{
    File: &logging.FileConfig{
        Enabled:    true,
        Path:       "./logs/elemta.log",
        Level:      "info",
        MaxSize:    100,    // 100 MB
        MaxBackups: 5,      // Keep 5 old files
        MaxAge:     30,     // 30 days
        Compress:   true,   // Compress old files
    },
})
```

## Best Practices

- **Use appropriate log levels**: Reserve `Error` and `Fatal` for actual errors
- **Include context in logs**: Add relevant information to help with debugging
- **Be consistent with log messages**: Use a consistent format for similar events
- **Don't log sensitive information**: Avoid logging passwords, tokens, or personal data
- **Use structured logging**: Include structured data for better filtering and analysis

## Troubleshooting

### High Log Volume

If you're generating too many logs:

1. Increase the minimum log level (e.g., from `debug` to `info`)
2. Be more selective about what you log
3. Configure log rotation to manage file size

### Missing Logs

If logs are not appearing as expected:

1. Check that the logger is properly configured
2. Verify that the log level is appropriate (e.g., `debug` logs won't appear if the level is set to `info`)
3. Ensure that the log file is writable
4. Check Elasticsearch connectivity if using Elasticsearch output

### Performance Issues

If logging is causing performance issues:

1. Reduce the log level in production
2. Use asynchronous logging if available
3. Optimize the information included in log messages 