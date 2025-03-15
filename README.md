# Elemta - High-Performance SMTP Server

Elemta is a high-performance, carrier-grade Mail Transfer Agent (MTA) written in Go. It's designed to be a modern, pluggable, and secure alternative to traditional MTAs like Postfix, Sendmail, and Exim.

## Features

- **High Performance**: Built with Go for excellent concurrency and performance
- **Pluggable Architecture**: Easily extend functionality with plugins
- **Security-First Design**: Built-in SPF, DKIM, and DMARC validation
- **Modern Queue Management**: Sophisticated queue system with priority, retry, and status tracking
- **Comprehensive Monitoring**: Detailed metrics and logging
- **Containerized Deployment**: Ready for Docker and Kubernetes
- **Horizontal Scalability**: Designed to scale out across multiple nodes
- **API-Driven**: RESTful API for management and monitoring

## Architecture

Elemta is built with a modular architecture:

- **Core SMTP Server**: Handles SMTP protocol and message processing
- **Plugin System**: Allows for extending functionality at various processing stages
- **Queue Manager**: Manages message queues, retries, and delivery
- **Delivery Manager**: Handles message delivery to remote servers
- **Configuration Manager**: Manages configuration and runtime settings
- **Monitoring System**: Provides metrics and monitoring capabilities

## Plugin Types

Elemta supports various plugin types:

- **Connection Plugins**: Run during the SMTP connection phase
- **Authentication Plugins**: Handle SMTP authentication
- **HELO/EHLO Plugins**: Process HELO/EHLO commands
- **MAIL FROM Plugins**: Process MAIL FROM commands
- **RCPT TO Plugins**: Process RCPT TO commands
- **DATA Plugins**: Process message data
- **Queue Plugins**: Interact with the queue system
- **Delivery Plugins**: Modify delivery behavior
- **Security Plugins**: Implement security features (SPF, DKIM, DMARC)
- **Routing Plugins**: Control message routing
- **Storage Plugins**: Customize message storage

## Getting Started

### Prerequisites

- Go 1.20 or higher
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/elemta.git
cd elemta

# Build the binary
go build -o elemta cmd/elemta/main.go

# Run the server
./elemta serve
```

### Configuration

Elemta uses a YAML configuration file. A sample configuration is provided in `config/elemta.yaml.example`.

```bash
# Copy the example configuration
cp config/elemta.yaml.example config/elemta.yaml

# Edit the configuration
vim config/elemta.yaml
```

### Docker

Elemta can be run in Docker:

```bash
# Build the Docker image
docker build -t elemta .

# Run the container
docker run -p 25:25 -p 587:587 -v /path/to/config:/etc/elemta elemta
```

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/elemta.git
cd elemta

# Install dependencies
go mod download

# Build
go build -o elemta cmd/elemta/main.go
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...
```

### Creating Plugins

Elemta's plugin system makes it easy to extend functionality. Here's a simple example of a plugin:

```go
package myplugin

import (
    "github.com/yourusername/elemta/internal/plugin"
)

type MyPlugin struct {
    plugin.BasePlugin
}

func (p *MyPlugin) Init() error {
    // Initialize the plugin
    return nil
}

func (p *MyPlugin) Close() error {
    // Clean up resources
    return nil
}

func (p *MyPlugin) Execute(ctx *plugin.Context) (*plugin.Result, error) {
    // Plugin logic here
    return &plugin.Result{
        Action:  plugin.ActionContinue,
        Message: "Plugin executed successfully",
    }, nil
}

// Register the plugin
func init() {
    plugin.Register("my-plugin", &MyPlugin{})
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The Go team for creating an excellent language for building high-performance servers
- The open-source community for inspiration and tools