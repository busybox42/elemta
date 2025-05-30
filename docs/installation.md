# Elemta Installation Guide

This guide covers all installation and deployment methods for Elemta.

## Prerequisites

- **Docker & Docker Compose** (for containerized deployment)
- **Kubernetes cluster** (for Kubernetes deployment)
- **Go 1.23+** (for source builds)
- **Git**

## Deployment Methods

### Docker Deployment (Recommended)

Docker is the recommended deployment method for both development and production environments.

#### Quick Start

```bash
git clone https://github.com/busybox42/elemta.git
cd elemta
docker-compose up -d
```

#### Service Access

After deployment, access these services:

- **Web UI**: http://localhost:8025 (admin:password)
- **SMTP Server**: localhost:2525
- **API Server**: http://localhost:8081
- **Grafana Monitoring**: http://localhost:3000 (admin:elemta123)
- **Prometheus**: http://localhost:9090
- **RSpamd Web UI**: http://localhost:11334

#### Testing the Setup

```bash
# Send a test email via SMTP
telnet localhost 2525

# Or use the test script
./scripts/test/test-smtp.sh
```

#### Advanced Docker Configuration

For production deployments, see [Docker Deployment Guide](docker_deployment.md).

### Kubernetes Deployment

Deploy Elemta on Kubernetes using the provided manifests:

```bash
# Deploy all components
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=elemta

# Access services via port forwarding
kubectl port-forward service/elemta-web 8025:8025
kubectl port-forward service/elemta-smtp 2525:25
```

#### Kubernetes Configuration

The Kubernetes deployment includes:
- Elemta SMTP server
- Web interface
- Monitoring stack (Prometheus/Grafana)
- Persistent volumes for queues and logs

For advanced Kubernetes configuration, see `k8s/README.md`.

### From Source (Development)

Building from source is recommended for development and testing.

#### Prerequisites

- Go 1.23 or higher
- Git

#### Build Steps

```bash
# Clone repository
git clone https://github.com/busybox42/elemta.git
cd elemta

# Install dependencies
go mod download

# Build binaries
go build -o bin/elemta ./cmd/elemta
go build -o bin/elemta-queue ./cmd/elemta-queue
go build -o bin/elemta-cli ./cmd/elemta-cli

# Run with example configuration
./bin/elemta -config config/elemta.yaml.example
```

#### Development Mode

For development, use the provided development script:

```bash
# Run with development settings
./scripts/dev/run-dev.sh

# Run with custom port
./scripts/dev/run-dev.sh --port 3000
```

Development mode automatically:
- Uses non-privileged ports (2525-2528)
- Disables TLS requirements
- Uses local directories for data
- Provides verbose logging

#### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test suites
./scripts/test/test-queue-only.sh
./scripts/test/test-smtp.sh
```

## Configuration

### Configuration Files

Elemta supports both YAML and TOML configuration formats:

#### YAML Configuration

```bash
# Copy example configuration
cp config/elemta.yaml.example config/elemta.yaml

# Edit configuration
vim config/elemta.yaml

# Run with YAML config
./elemta -config config/elemta.yaml
```

#### TOML Configuration

```bash
# Copy example configuration
cp config/elemta.toml.example config/elemta.toml

# Edit configuration
vim config/elemta.toml

# Run with TOML config
./elemta -config config/elemta.toml
```

### Basic Configuration

Minimum configuration for getting started:

```yaml
# Basic server configuration
hostname: "mail.example.com"
listen_addr: "0.0.0.0:25"
queue_dir: "/var/spool/elemta/queue"
log_level: "info"
max_message_size: 10485760  # 10MB

# TLS configuration
tls:
  enabled: true
  cert_file: "/etc/elemta/certs/cert.pem"
  key_file: "/etc/elemta/certs/key.pem"

# Authentication
auth:
  enabled: true
  methods: ["plain", "login"]
```

For complete configuration options, see [Configuration Reference](configuration.md).

## Distribution Packages (Future)

While currently focused on cloud-native deployment, we plan to provide native packages:

### Planned Support

- **RHEL/CentOS 8/9**: RPM packages via `dnf`
- **Debian 11**: DEB packages via `apt`
- **Ubuntu 22.04 LTS**: DEB packages via `apt`
- **Alpine Linux**: APK packages
- **Arch Linux**: AUR packages

### Experimental Package Builder

```bash
cd linux-package-builder

# Build all package types (experimental)
./build_all.sh

# Or build specific types
./build_rpm.sh      # RHEL/CentOS 8
./build_debian.sh   # Debian 11
./build_ubuntu.sh   # Ubuntu 22.04
```

**Note**: These packages are experimental and not production-ready. Use Docker/Kubernetes for production.

## Next Steps

After installation:

1. **Configure Email Authentication**: [Email Authentication Guide](email_authentication.md)
2. **Set Up Monitoring**: [Monitoring Setup](monitoring/README.md)
3. **Configure Let's Encrypt**: [Let's Encrypt Guide](letsencrypt-guide.md)
4. **Develop Plugins**: [Plugin Development](plugins.md)

## Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check if ports are in use
netstat -tlnp | grep :25
netstat -tlnp | grep :2525

# Use alternative ports
./elemta -config config/elemta.yaml --port 2526
```

#### Permission Issues
```bash
# Ensure correct ownership
sudo chown -R elemta:elemta /var/spool/elemta
sudo chmod 755 /var/spool/elemta

# For Docker
docker-compose logs elemta
```

#### TLS Certificate Issues
```bash
# Test certificate
openssl x509 -in /etc/elemta/certs/cert.pem -text -noout

# Use Let's Encrypt setup
./scripts/ssl/letsencrypt-setup.sh
```

For more troubleshooting, see [Testing Documentation](testing.md). 