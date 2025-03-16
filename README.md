# Elemta - High-Performance SMTP Server

Elemta is a high-performance, carrier-grade Mail Transfer Agent (MTA) written in Go. It's designed to be a modern, pluggable, and secure alternative to traditional MTAs like Postfix, Sendmail, and Exim.

## Features

- **High Performance**: Built with Go for excellent concurrency and performance
- **Pluggable Architecture**: Easily extend functionality with plugins
- **Security-First Design**: Built-in SPF, DKIM, and DMARC validation
- **Modern Queue Management**: Sophisticated queue system with priority, retry, and status tracking
- **Comprehensive Monitoring**: Detailed metrics and logging with Prometheus and Grafana integration
- **Containerized Deployment**: Ready for Docker and Kubernetes
- **Horizontal Scalability**: Designed to scale out across multiple nodes
- **API-Driven**: RESTful API for management and monitoring
- **Native Packages**: Support for RHEL/CentOS 8/9, Debian 11, and Ubuntu 22.04

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
- **Greylisting Plugins**: Implement greylisting for spam reduction

## Getting Started

### Prerequisites

- Go 1.20 or higher
- Git

### Installation

#### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/elemta.git
cd elemta

# Build the binary
go build -o elemta cmd/elemta/main.go

# Run the server
./elemta serve
```

#### Using Native Packages

Elemta provides native packages for various Linux distributions:

##### RHEL/CentOS 8
```bash
sudo rpm -i elemta-0.0.1-1.el8.x86_64.rpm
```

##### RHEL/CentOS 9
```bash
sudo rpm -i elemta-0.0.1-1.el9.x86_64.rpm
```

##### Debian 11
```bash
sudo dpkg -i elemta_0.0.1_amd64.deb
```

##### Ubuntu 22.04
```bash
sudo dpkg -i elemta_0.0.1_amd64.deb
```

After installation, the Elemta service can be managed using systemd:

```bash
# Start the service
sudo systemctl start elemta

# Enable the service to start at boot
sudo systemctl enable elemta

# Check the service status
sudo systemctl status elemta
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

### Monitoring

Elemta provides comprehensive monitoring capabilities using Prometheus and Grafana.

#### Setting Up Monitoring

```bash
# Set up the monitoring environment
./scripts/setup-monitoring.sh

# Start the monitoring stack
docker-compose -f docker-compose-monitoring.yml up -d

# Test the monitoring setup
./scripts/test-monitoring.sh

# Generate test load to see metrics in action
./scripts/generate-test-load.sh
```

#### Accessing Dashboards

- **Grafana**: http://localhost:3000 (default credentials: admin/admin)
- **Prometheus**: http://localhost:9090

#### Available Metrics

Elemta exposes various metrics for monitoring:

- SMTP server metrics (connections, messages)
- Queue metrics (size, processing time)
- Delivery metrics (attempts, successes, failures)
- Security metrics (authentication, TLS)
- Plugin-specific metrics (e.g., greylisting statistics)

For more information about monitoring, see [docs/monitoring/README.md](docs/monitoring/README.md).

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

### Building Native Packages

Elemta includes a package builder for creating native packages for various Linux distributions:

```bash
# Navigate to the package builder directory
cd linux-package-builder

# Build all packages
./build_all.sh

# Or build a specific package type
./build_rpm.sh      # RHEL/CentOS 8
./build_rhel9.sh    # RHEL/CentOS 9
./build_debian.sh   # Debian 11
./build_ubuntu.sh   # Ubuntu 22.04
```

For more information about the package builder, see [linux-package-builder/README.md](linux-package-builder/README.md).

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

For an example of a more complex plugin, see the [Greylisting Plugin](docs/plugins/greylisting.md).

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