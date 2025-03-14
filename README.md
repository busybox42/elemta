# Elemta

Elemta is a lightweight, high-performance SMTP server with advanced filtering capabilities, designed for modern email infrastructure.

## Features

- **Lightweight SMTP Server**: Fast and efficient email handling
- **Pluggable Caching System**: Supports Redis and in-memory caching
- **Flexible Logging**: Console, file, and Elasticsearch logging options
- **Multiple Data Sources**: SQLite, MySQL, and PostgreSQL support
- **Development Mode**: Test email functionality without sending actual emails
- **Docker Support**: Easy deployment with Docker and Docker Compose
- **Configurable Rules**: Create custom rules for email filtering

## Quick Start

### Using Docker

The easiest way to get started with Elemta is using Docker:

```bash
# Clone the repository
git clone https://github.com/yourusername/elemta.git
cd elemta

# Start the container
docker-compose up -d

# Check the logs
docker-compose logs -f
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/elemta.git
cd elemta

# Build the application
go build -o bin/elemta ./cmd/elemta

# Run the server
./bin/elemta
```

## Configuration

Elemta is configured using a JSON configuration file located at `config/elemta.conf`:

```json
{
    "hostname": "mail.example.com",
    "listen_addr": ":2525",
    "queue_dir": "./queue",
    "max_size": 26214400,
    "dev_mode": false,
    "allowed_relays": ["127.0.0.1", "::1"]
}
```

### Configuration Options

- `hostname`: The hostname to use in SMTP responses
- `listen_addr`: The address and port to listen on
- `queue_dir`: Directory to store the email queue
- `max_size`: Maximum message size in bytes
- `dev_mode`: Enable development mode (emails are not actually sent)
- `allowed_relays`: IP addresses allowed to relay emails

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test ./... -v

# Run tests with coverage
go test ./... -cover
```

### Integration Tests

For integration tests with MySQL and PostgreSQL, you need to set up the appropriate environment variables:

```bash
# MySQL integration tests
export MYSQL_TEST_DSN="user:password@tcp(localhost:3306)/elemta_test?parseTime=true"
go test ./internal/datasource -run TestMySQLDataSource

# PostgreSQL integration tests
export POSTGRES_TEST_DSN="postgres://user:password@localhost:5432/elemta_test?sslmode=disable"
go test ./internal/datasource -run TestPostgreSQLDataSource
```

### Testing SMTP Functionality

You can test the SMTP functionality using the provided scripts:

```bash
# Make the scripts executable
chmod +x test_smtp.sh test_gmail.sh

# Test local SMTP
./test_smtp.sh

# Test sending to Gmail (update with your email)
./test_gmail.sh
```

## Documentation

Detailed documentation is available in the `docs` directory:

- [SMTP Server](docs/smtp_server.md): Configuration and usage of the SMTP server
- [Caching System](docs/caching.md): Using the pluggable caching system
- [Logging System](docs/logging.md): Configuring and using the logging system
- [Datasource System](docs/datasource.md): Working with different database backends
- [Docker Deployment](docs/docker_deployment.md): Deploying Elemta with Docker

## Caching System

Elemta includes a flexible caching system with support for:

- In-memory cache
- Redis cache

Configure the cache in your application code:

```go
import "github.com/yourusername/elemta/internal/cache"

// Create a cache manager
manager := cache.NewManager(&cache.Config{
    Type:     "redis",
    Address:  "localhost:6379",
    Password: "",
    DB:       0,
})

// Get a cache instance
c := manager.GetCache()

// Use the cache
c.Set("key", "value", 60)
value, found := c.Get("key")
```

## Logging System

The logging system supports multiple outputs:

- Console logging
- File logging
- Elasticsearch logging

Configure logging in your application:

```go
import "github.com/yourusername/elemta/internal/logging"

// Create a logger
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

// Use the logger
logger.Info("Server started")
logger.Error("Something went wrong", errors.New("error details"))
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
