![Elemta Logo](images/elemta.png?v=2)

# Elemta - High-Performance SMTP Server

Elemta: A high-performance SMTP server written in Go with comprehensive email authentication (SPF, DKIM, DMARC, ARC), advanced queue management, and extensive monitoring capabilities. Features a pluggable architecture, containerized deployment, and security-first design.

## Key Features

- **High Performance**: Built with Go for excellent concurrency and performance
- **Pluggable Architecture**: Easily extend functionality with plugins
- **Security-First**: Built-in SPF, DKIM, DMARC, and ARC validation
- **Container Security**: Non-root execution with hardened Docker and Kubernetes configurations
- **Cloud-Native**: Ready for Docker and Kubernetes deployment
- **Comprehensive Monitoring**: Prometheus/Grafana integration with pre-built dashboards
- **API-Driven**: RESTful API for management and monitoring

## Quick Start

### Docker Deployment (Recommended)

```bash
git clone https://github.com/busybox42/elemta.git
cd elemta
docker-compose up -d
```

**Access Services:**
- **Web UI**: http://localhost:8025 (admin:password)
- **SMTP Server**: localhost:2525
- **Grafana Monitoring**: http://localhost:3000 (admin:elemta123)

### Kubernetes Deployment

```bash
kubectl apply -f k8s/
kubectl port-forward service/elemta-web 8025:8025
```

### From Source (Development)

```bash
git clone https://github.com/busybox42/elemta.git
cd elemta
go build -o elemta cmd/elemta/main.go
./elemta -config config/elemta.yaml
```

## Documentation

### Core Documentation
- **[Installation & Deployment](docs/installation.md)** - Detailed setup instructions
- **[Configuration Reference](docs/configuration.md)** - Complete configuration options
- **[Email Authentication](docs/email_authentication.md)** - SPF, DKIM, DMARC, ARC setup
- **[Plugin Development](docs/plugin-development.md)** - Creating custom plugins

### Production & Operations
- **[Production Deployment](docs/production-deployment.md)** - Enterprise deployment guide
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions
- **[Monitoring & Metrics](docs/monitoring/README.md)** - Prometheus/Grafana setup
- **[Queue Management](docs/queue_management.md)** - Queue operations and troubleshooting
- **[CLI Tools](docs/cli.md)** - Command-line utilities

### Development & Testing
- **[Testing](docs/testing.md)** - Testing procedures and tools
- **[Docker Deployment](docs/docker_deployment.md)** - Advanced Docker configuration
- **[Logging](docs/logging.md)** - Log management and analysis

### Advanced Topics
- **[Let's Encrypt Integration](docs/letsencrypt-guide.md)** - Automatic TLS certificate management
- **[Security Hardening](docs/production-deployment.md#security-hardening)** - Production security guide
- **[Performance Tuning](docs/production-deployment.md#performance-tuning)** - Optimization guide

## Architecture

Elemta uses a modular architecture with these core components:

- **SMTP Server**: Protocol handling and message processing
- **Plugin System**: Extensible processing pipeline
- **Queue Manager**: Message queuing, retries, and delivery tracking
- **Monitoring**: Metrics collection and alerting
- **API Server**: RESTful management interface

For detailed architecture information, see [Architecture Documentation](docs/smtp_server.md).

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)c
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [Development Workflow](docs/installation.md) for detailed contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Need Help?** Check our [documentation](docs/README.md) or open an issue on GitHub.
