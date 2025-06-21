# SMTP Module Documentation

**Location**: `internal/smtp/`
**Purpose**: Core SMTP server implementation for handling email protocol

## Overview
The SMTP module provides the core email server functionality, implementing the Simple Mail Transfer Protocol (SMTP) with support for modern extensions and security features.

## Key Components

### Server (`server.go`)
**Responsibilities**:
- SMTP server lifecycle management (start/stop)
- Client connection handling
- Plugin integration coordination
- Metrics collection
- Queue system integration

**Key Functions**:
- `NewServer(config *Config)` - Creates new SMTP server instance
- `Start()` - Starts the server and begins accepting connections
- `Close()` - Gracefully shuts down the server

### Session (`session.go`)
**Responsibilities**:
- Individual SMTP session handling
- Protocol command processing
- Message reception and validation
- Authentication enforcement

**Key Functions**:
- `NewSession(conn net.Conn, config *Config)` - Creates new session
- `Handle()` - Main session processing loop
- `processCommand(cmd string)` - Processes individual SMTP commands

### Authentication (`auth.go`)
**Responsibilities**:
- SMTP AUTH command implementation
- Multiple authentication mechanism support
- Integration with datasource providers

**Supported Mechanisms**:
- PLAIN
- LOGIN
- CRAM-MD5 (future)

### TLS (`tls.go`)
**Responsibilities**:
- TLS/SSL connection handling
- STARTTLS command implementation
- Certificate management
- Let's Encrypt integration

**Key Functions**:
- `NewTLSManager(config *Config)` - Sets up TLS configuration
- `HandleStartTLS(session *Session)` - Processes STARTTLS command

### Queue Integration (`queue.go`)
**Responsibilities**:
- Message queuing for delivery
- Queue management operations
- Integration with queue system

## Inputs
- **Network Connections**: TCP connections on SMTP ports (25, 587, etc.)
- **Configuration**: Server settings, TLS certificates, authentication config
- **Email Messages**: Raw email data from clients

## Outputs
- **Queued Messages**: Messages accepted for delivery
- **SMTP Responses**: Protocol responses to clients
- **Metrics**: Performance and operational metrics
- **Logs**: Structured logging for monitoring

## Dependencies
- `internal/plugin` - Plugin system for message processing
- `internal/auth` - Authentication system
- `internal/queue` - Message queuing
- `internal/config` - Configuration management
- Standard library: `net`, `crypto/tls`, `context`

## Configuration
```toml
[smtp]
hostname = "mail.example.com"
listen_addr = ":25"
max_message_size = 10485760  # 10MB
timeout = 300

[tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
enable_starttls = true

[auth]
enabled = true
required = false
mechanisms = ["PLAIN", "LOGIN"]
```

## Example Usage

### Basic Server Setup
```go
// Load configuration
config, err := config.LoadConfig("elemta.toml")
if err != nil {
    log.Fatal(err)
}

// Create SMTP server
server, err := smtp.NewServer(config.SMTP)
if err != nil {
    log.Fatal(err)
}

// Start server
if err := server.Start(); err != nil {
    log.Fatal(err)
}

// Graceful shutdown
defer server.Close()
```

### Session Handling
```go
// Accept connection
conn, err := listener.Accept()
if err != nil {
    return err
}

// Create session
session := smtp.NewSession(conn, config)

// Handle session
go session.Handle()
```

## Security Considerations
- **TLS Encryption**: All passwords transmitted over encrypted connections
- **Input Validation**: All SMTP commands and data validated
- **Rate Limiting**: Connection and command rate limiting
- **Authentication**: Configurable authentication requirements

## Performance Notes
- **Concurrent Sessions**: Each session handled in separate goroutine
- **Connection Pooling**: Reuses connections for delivery
- **Memory Management**: Streaming message processing for large emails
- **Metrics Collection**: Low-overhead metrics for monitoring

## Testing
- Unit tests cover individual components
- Integration tests verify SMTP protocol compliance
- Load tests validate performance under high load
- Security tests check for common vulnerabilities

## Common Issues
1. **Port Binding**: Ensure SMTP ports are available and accessible
2. **TLS Certificates**: Verify certificate paths and permissions
3. **Authentication**: Check datasource connectivity
4. **Queue Integration**: Ensure queue directories are writable

## Future Enhancements
- Support for SMTP-over-HTTP (future protocol)
- Enhanced DKIM signing integration
- Advanced rate limiting features
- Cluster-aware session management 