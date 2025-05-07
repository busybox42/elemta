# Elemta - High-Performance SMTP Server

Elemta is a high-performance, carrier-grade Mail Transfer Agent (MTA) written in Go. It's designed to be a modern, pluggable, and secure alternative to traditional MTAs like Postfix, Sendmail, and Exim.

## Features

- **High Performance**: Built with Go for excellent concurrency and performance
- **Pluggable Architecture**: Easily extend functionality with plugins
- **Security-First Design**: Built-in SPF, DKIM, DMARC, and ARC validation
- **Modern Queue Management**: Sophisticated queue system with priority, retry, and status tracking
- **Comprehensive Monitoring**: Detailed metrics and logging with Prometheus and Grafana integration
- **Containerized Deployment**: Ready for Docker and Kubernetes
- **Horizontal Scalability**: Designed to scale out across multiple nodes
- **API-Driven**: RESTful API for management and monitoring
- **Native Packages**: Support for RHEL/CentOS 8/9, Debian 11, and Ubuntu 22.04
- **Flexible Configuration**: Support for both YAML and TOML configuration formats
- **TLS Encryption**: Built-in support for Let's Encrypt integration

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
- **Security Plugins**: Implement security features (SPF, DKIM, DMARC, ARC)
- **Routing Plugins**: Control message routing
- **Storage Plugins**: Customize message storage
- **Greylisting Plugins**: Implement greylisting for spam reduction

## Email Authentication

Elemta provides comprehensive email authentication support:

### SPF (Sender Policy Framework)

SPF validation helps prevent email spoofing by verifying that incoming mail from a domain comes from a host authorized by that domain's administrators.

```yaml
plugins:
  spf:
    enabled: true
    enforce: false  # Set to true to reject emails that fail SPF validation
```

### DKIM (DomainKeys Identified Mail)

DKIM adds a digital signature to outgoing messages and validates incoming messages, allowing the receiver to verify that the message was not altered in transit.

```yaml
plugins:
  dkim:
    enabled: true
    verify: true    # Verify DKIM signatures on incoming messages
    sign: true      # Sign outgoing messages
    domain: "example.com"
    selector: "mail"
    key_file: "/etc/elemta/dkim/example.com.private"
```

### DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC builds on SPF and DKIM to provide domain-level authentication and reporting.

```yaml
plugins:
  dmarc:
    enabled: true
    enforce: false  # Set to true to enforce DMARC policies
```

### ARC (Authenticated Received Chain)

ARC preserves email authentication results across forwarding services, solving the email forwarding problem that affects SPF, DKIM, and DMARC.

```yaml
plugins:
  arc:
    enabled: true
    verify: true    # Verify ARC chains on incoming messages
    seal: true      # Add ARC seals to outgoing messages
    domain: "example.com"
    selector: "arc"
    key_file: "/etc/elemta/arc/example.com.private"
```

For more information about email authentication, see [Email Authentication Documentation](docs/email_authentication.md).

## Getting Started

### Prerequisites

- Go 1.20 or higher
- Git

### Installation

#### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/elemta/elemta.git
   cd elemta
   ```

2. Build the binary:
   ```bash
   go build -o elemta cmd/elemta/main.go
   ```

3. Run the server:
   ```bash
   ./elemta -config config/elemta.yaml
   ```

#### Using Native Packages

We provide native packages for various Linux distributions:

#### RHEL/CentOS 8
```bash
sudo dnf install -y https://github.com/elemta/elemta/releases/download/v0.1.0/elemta-0.1.0-1.el8.x86_64.rpm
```

#### RHEL/CentOS 9
```bash
sudo dnf install -y https://github.com/elemta/elemta/releases/download/v0.1.0/elemta-0.1.0-1.el9.x86_64.rpm
```

#### Debian 11
```bash
wget https://github.com/elemta/elemta/releases/download/v0.1.0/elemta_0.1.0-1_amd64.deb
sudo dpkg -i elemta_0.1.0-1_amd64.deb
```

#### Ubuntu 22.04
```bash
wget https://github.com/elemta/elemta/releases/download/v0.1.0/elemta_0.1.0-1_amd64.deb
sudo dpkg -i elemta_0.1.0-1_amd64.deb
```

After installation, you can manage the service using systemd:
```bash
sudo systemctl start elemta
sudo systemctl enable elemta
```

### Using Docker

For a quick deployment with all components (including ClamAV and Rspamd), you can use Docker:

1. Clone the repository:
   ```bash
   git clone https://github.com/elemta/elemta.git
   cd elemta
   ```

2. Build and start the containers:
   ```bash
   docker-compose up -d
   ```

3. Verify the deployment:
   ```bash
   ./tests/test-elemta.sh
   ```

The Docker deployment exposes the following ports:
- SMTP service: 2525
- Metrics endpoint: 8080
- Rspamd web interface: 11334

For more details, see [Docker Deployment Documentation](docs/docker/README.md).

### Configuration

Elemta supports both YAML and TOML configuration formats. Sample configurations are provided in `config/elemta.yaml.example` and `config/elemta.toml.example`.

For detailed configuration information, see [Configuration Documentation](docs/configuration.md).

#### Quick Start with YAML

```bash
# Copy the example YAML configuration
cp config/elemta.yaml.example config/elemta.yaml

# Edit the configuration
vim config/elemta.yaml
```

#### Quick Start with TOML

```bash
# Copy the example TOML configuration
cp config/elemta.toml.example config/elemta.toml

# Edit the configuration
vim config/elemta.toml
```

To specify which configuration file to use:

```bash
# Run with YAML configuration
./elemta -config config/elemta.yaml

# Run with TOML configuration
./elemta -config config/elemta.toml
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
# Set up the basic monitoring environment
./scripts/setup-monitoring.sh

# Set up security monitoring with ClamAV and Rspamd
./scripts/setup-security-monitoring.sh

# Start the monitoring stack
docker-compose -f docker-compose-monitoring.yml up -d

# Verify the monitoring setup
./scripts/verify-monitoring-stack.sh

# Generate test load to see metrics in action
./scripts/generate-test-load.sh
```

#### TLS and Let's Encrypt Monitoring

Elemta provides specialized monitoring for TLS certificates, with a focus on Let's Encrypt certificate management. This includes:

- Certificate expiration monitoring
- Automatic renewal tracking
- Certificate validity checks
- Grafana dashboards for certificate visibility
- Prometheus alerts for certificate issues

To set up Let's Encrypt certificate monitoring:

```bash
# Start the certificate monitoring service
sudo ./scripts/letsencrypt-monitor.sh

# Access the certificate dashboard
# Open http://localhost:9090/ in your browser
```

For more details, see [Let's Encrypt Monitoring Documentation](docs/letsencrypt-monitoring.md).

#### Monitoring Stack

Elemta's monitoring stack includes:

- **Prometheus**: Time-series database for storing metrics
- **Grafana**: Visualization and dashboarding platform
- **AlertManager**: Handles alerts from Prometheus
- **Node Exporter**: Collects system metrics
- **CAdvisor**: Collects container metrics
- **Loki**: Log aggregation system
- **Promtail**: Log collector for Loki

#### Grafana Dashboards

Elemta comes with pre-configured Grafana dashboards:

- **Elemta Overview**: High-level view of SMTP server performance
- **Queue Dashboard**: Detailed queue metrics and performance
- **Security Dashboard**: Email authentication and security metrics
- **System Dashboard**: Host and container resource usage
- **Logs Dashboard**: Centralized log viewing and analysis

#### Accessing Dashboards

- **Grafana**: http://localhost:3000 (default credentials: admin/elemta123)
- **Prometheus**: http://localhost:9090
- **AlertManager**: http://localhost:9093
- **Rspamd Web Interface**: http://localhost:11334
- **Loki**: http://localhost:3100 (accessed through Grafana)

#### Available Metrics

Elemta exposes various metrics for monitoring:

- **SMTP Server Metrics**:
  - Connection rates and states
  - Message throughput
  - Command success/failure rates
  - TLS usage statistics

- **Queue Metrics**:
  - Queue sizes by type (active, deferred, held, failed)
  - Message processing times
  - Retry statistics
  - Delivery success/failure rates

- **Security Metrics**:
  - Authentication success/failure rates
  - SPF, DKIM, DMARC, and ARC validation results
  - TLS connection statistics
  - Rate limiting metrics

- **Antivirus/Antispam Metrics**:
  - ClamAV scan results and performance
  - Rspamd spam scores and actions
  - Greylisting statistics
  - Blocklist hits

- **System Metrics**:
  - CPU, memory, disk, and network usage
  - Container resource utilization
  - Go runtime metrics

#### Alerting

Elemta includes pre-configured alerts for:

- High queue sizes
- Delivery failures
- Authentication failures
- Resource constraints
- Security issues

Alerts can be sent via email, Slack, PagerDuty, or other notification channels configured in AlertManager.

For more information about monitoring, see [docs/monitoring/README.md](docs/monitoring/README.md).
For details on security monitoring, see [docs/monitoring/security-monitoring.md](docs/monitoring/security-monitoring.md).
For information on log management, see [docs/monitoring/logging.md](docs/monitoring/logging.md).

## CLI Tools

Elemta provides command-line tools for managing the server and queue. For detailed information, see [CLI Documentation](docs/cli.md).

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

For an example of a custom policy plugin, see the [Policy Plugin](docs/plugins/policy.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

> **Note**: AI assistant configuration files (in the `.cursor/` directory) are intentionally excluded from version control. These files contain project guidance for AI coding assistants and are maintained separately.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Testing

Elemta provides comprehensive testing capabilities, including test mode, queue testing, and SMTP testing. For detailed information, see [Testing Documentation](docs/testing.md).

### Quick Testing

```bash
# Run a comprehensive test (deployment, SMTP, queue, test mode)
./scripts/deploy-and-test.sh

# Test only the queue functionality
make test-queue-only

# Test only SMTP functionality
./scripts/test-smtp.sh

# Run in test mode
./scripts/test-mode.sh
```

## Development Roadmap

Elemta is currently in active development, focusing on Phase 1 (Core Infrastructure Stabilization). 

Our development is guided by a detailed roadmap that outlines:
- Current state assessment
- Development phases and timelines
- Key features for each phase
- Immediate next steps

For developers interested in contributing, please refer to the roadmap in `.cursor/rules/elemta_roadmap.mdc` 
for a comprehensive view of our development plan.

## Let's Encrypt Integration

Elemta includes built-in support for automatic TLS certificate provisioning via Let's Encrypt:

- **Quick Setup**: Use our setup script: `tools/letsencrypt-setup.sh`
- **Troubleshooting**: Use our troubleshooter: `tools/letsencrypt-troubleshooter.sh`
- **Monitoring**: Ongoing certificate monitoring: `tools/letsencrypt-monitor.sh`

See `docs/letsencrypt-guide.md` for complete documentation.

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Plugin Development](docs/plugins.md)
- [Let's Encrypt Guide](docs/letsencrypt-guide.md)