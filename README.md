# Elemta SMTP Server

Elemta is a high-performance SMTP server written in Go, designed to be extensible and secure.

## Features

- **Lightweight**: Elemta is designed to be lightweight and efficient, making it suitable for both small and large deployments.
- **Flexible**: Supports various storage backends, including file system, MySQL, PostgreSQL, and SQLite.
- **Secure**: Implements modern security practices to protect your email infrastructure.
- **Extensible**: Provides a plugin system for adding custom functionality.
- **Authentication**: Supports PLAIN and LOGIN authentication methods with configurable backends.
- **TLS Support**: Secure your SMTP connections with TLS, including Let's Encrypt integration.
- **Advanced Queue Management**: Prioritized message queue with configurable retry logic and worker pools.
- **Development Mode**: Test your email functionality without sending actual emails.

## Code Structure

The codebase is organized into several packages:

### `/cmd`

Contains the main application entry points.

### `/internal`

Contains packages that are specific to this application and not meant to be imported by other applications.

- `/internal/datasource`: Database access (SQLite, MySQL, PostgreSQL)
- `/internal/queue`: Email queue management
- `/internal/smtp`: SMTP server implementation

### `/docs`

Contains detailed documentation for various components of the system.

## Configuration

Elemta is configured using a JSON configuration file. The server will look for a configuration file in the following locations:

1. The path specified by the `-config` command-line flag
2. `./elemta.conf`
3. `./config/elemta.conf`
4. `../config/elemta.conf`
5. `$HOME/.elemta.conf`
6. `/etc/elemta/elemta.conf`

If no configuration file is found, default values will be used.

### Example Configuration

```json
{
  "hostname": "mail.example.com",
  "listen_addr": ":2525",
  "queue_dir": "./queue",
  "max_size": 26214400,
  "dev_mode": true,
  "allowed_relays": ["127.0.0.1", "::1", "192.168.65.1"],
  "max_workers": 5,
  "max_retries": 3,
  "max_queue_time": 3600,
  "retry_schedule": [60, 300, 900],
  "auth": {
    "enabled": true,
    "required": false,
    "datasource_type": "sqlite",
    "datasource_path": "./auth.db"
  },
  "tls": {
    "enabled": true,
    "listen_addr": ":465",
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem"
  }
}
```

## Building and Running

### Prerequisites

- Go 1.21 or later
- Docker (optional, for containerized deployment)

### Building

```bash
go build -o elemta ./cmd/elemta
```

### Running with Docker

```bash
# Build and start the container
docker-compose up -d

# Check the logs
docker logs elemta
```

## Testing

You can test the SMTP server using the provided Python scripts:

```bash
# Test basic SMTP functionality
python3 test_smtp.py

# Test SMTP authentication
python3 test_smtp_auth.py
```

## Queue Management System

Elemta includes a robust queue management system for reliable email delivery:

- **Message Prioritization**: Messages can be assigned different priority levels (Low, Normal, High, Critical)
- **Configurable Retry Logic**: Customize retry intervals and maximum attempts
- **Worker Pool**: Limit concurrent deliveries to prevent resource exhaustion
- **Automatic Cleanup**: Old messages are automatically removed from the queue
- **Delivery Tracking**: Track delivery attempts and errors for each message

For more details, see the [Queue Management Documentation](docs/queue_management.md).

## Docker Deployment

For detailed instructions on deploying Elemta with Docker, see the [Docker Deployment Documentation](docs/docker_deployment.md).

## SMTP Server

For detailed information about the SMTP server functionality, see the [SMTP Server Documentation](docs/smtp_server.md).