# Elemta Scripts Directory

This directory contains various utility scripts organized by category for the Elemta MTA project.

## Directory Structure

```
scripts/
├── ssl/           # SSL/TLS certificate management scripts (comprehensive tools)
├── test/          # Testing and test runner scripts  
├── debug/         # Debugging and troubleshooting scripts
├── dev/           # Development utility scripts
├── monitoring/    # Monitoring and alerting scripts
├── docker/        # Docker deployment and container management
├── queue/         # Queue management and inspection tools
├── load-testing/  # Load testing and performance scripts
├── build/         # Build and packaging scripts
└── [root]         # General utility scripts
```

## SSL/TLS Certificate Management (`ssl/`)

**Comprehensive Let's Encrypt management tools:**

- **`letsencrypt-admin.sh`** - Advanced certificate management (784 lines)
  - Complete ACME workflow management
  - Certificate lifecycle operations
  - Multi-domain support
  - Staging/production environments
  - Backup and recovery operations

- **`letsencrypt-test.sh`** - Comprehensive testing suite (564 lines)
  - Pre-deployment validation
  - DNS resolution and propagation checks
  - Port accessibility testing
  - Certificate path validation
  - ACME connectivity verification

- **`letsencrypt-monitor.sh`** - Advanced monitoring system (471 lines)
  - Real-time certificate monitoring
  - Automated renewal triggers
  - Multi-channel alerting (email, Slack, webhooks)
  - Prometheus metrics integration

- **`letsencrypt-setup.sh`** - Initial setup and configuration (283 lines)
  - Environment preparation
  - Initial ACME registration
  - Configuration file generation

- **`letsencrypt-troubleshooter.sh`** - Diagnostic and repair tool (421 lines)
  - Certificate issue diagnosis
  - Common problem resolution
  - Automated repair workflows

## Testing Scripts (`test/`)

- **`run-all-tests.sh`** - Master test runner for the entire test suite
- **`run-datasource-tests.sh`** - Database-specific test runner  
- **`test-mode.sh`** - Test mode configuration and management
- **`test-monitoring.sh`** - Monitoring stack testing
- **`test-queue-only.sh`** - Queue-specific testing
- **`test-queue.sh`** - Queue functionality tests
- **`test-smtp.sh`** - SMTP protocol testing

## Debugging Scripts (`debug/`)

- **`debug-email.sh`** - Email debugging and testing utility

## Development Scripts (`dev/`)

- **`rebuild.sh`** - Development build and restart script
- **`run-dev.sh`** - Quick development server startup script

## Monitoring & Alerting (`monitoring/`)

- **`setup-monitoring.sh`** - Complete monitoring stack deployment
- **`setup-security-monitoring.sh`** - Security-focused monitoring setup
- **`start-monitoring.sh`** - Start monitoring services
- **`verify-monitoring-stack.sh`** - Monitoring system health checks

## Docker Management (`docker/`)

- **`docker-deploy.sh`** - Docker deployment automation
- **`docker-undeploy.sh`** - Docker cleanup and removal
- **`docker-entrypoint.sh`** - Container entry point script
- **`entrypoint.sh`** - Application entry point

## Queue Management (`queue/`)

- **`check-queue.sh`** - Queue inspection and status
- **`create-queue-entry.sh`** - Manual queue entry creation
- **`simulate-queue.sh`** - Queue simulation for testing

## Load Testing (`load-testing/`)

- **`generate-test-load.sh`** - Email load generation for performance testing
- **`generate-security-events.sh`** - Security event simulation

## Build & Packaging (`build/`)

- **`build_all.sh`** - Build all package types
- **`build_debian.sh`** - Debian package builder
- **`build_ubuntu.sh`** - Ubuntu package builder
- **`build_rhel9.sh`** - RHEL 9 package builder
- **`build_rpm.sh`** - RPM package builder
- **`check_files.sh`** - Package file validation

## General Utility Scripts (root level)

- **`elemta-api.sh`** - API client for Elemta management
- **`elemta-cli.sh`** - Command-line interface wrapper
- **`build_plugins.sh`** - Plugin compilation and management
- **`deploy-and-test.sh`** - Automated deployment and testing
- **`api_server.py`** - Python API server for testing
- **`metrics_server.py`** - Metrics collection server
- **`mock-queue.py`** - Queue mocking for development

## Usage Examples

### SSL Certificate Management
```bash
# Complete certificate setup
./scripts/ssl/letsencrypt-setup.sh -d mail.example.tld -e admin@example.tld

# Test configuration before deployment
./scripts/ssl/letsencrypt-test.sh -d mail.example.tld

# Advanced certificate management
./scripts/ssl/letsencrypt-admin.sh status
./scripts/ssl/letsencrypt-admin.sh renew --force

# Start monitoring
./scripts/ssl/letsencrypt-monitor.sh --daemon
```

### Testing & Development
```bash
# Run comprehensive test suite
./scripts/test/run-all-tests.sh --all

# Start development environment
./scripts/dev/run-dev.sh -p 2530

# Test specific components
./scripts/test/test-smtp.sh
./scripts/debug/debug-email.sh
```

### Deployment & Operations
```bash
# Deploy with Docker
./scripts/docker/docker-deploy.sh

# Set up monitoring
./scripts/monitoring/setup-monitoring.sh

# Generate test load
./scripts/load-testing/generate-test-load.sh 1000

# Check queue status
./scripts/queue/check-queue.sh
```

### Build & Package
```bash
# Build all packages
./scripts/build/build_all.sh

# Build specific platform
./scripts/build/build_debian.sh
./scripts/build/build_rpm.sh
```

## Prerequisites

Most scripts require:
- **Core:** Docker, Docker Compose, Go 1.19+, OpenSSL
- **SSL Tools:** certbot or acme.sh, DNS management access
- **Monitoring:** Prometheus, Grafana (auto-installed by setup scripts)
- **Testing:** Python 3.8+, pytest (for Python tests)
- **Building:** Platform-specific build tools (dpkg, rpm, etc.)

Specific requirements are documented in individual script headers.

## Security Considerations

- SSL scripts require appropriate DNS/domain control
- Monitoring scripts may need elevated privileges
- Build scripts should run in isolated environments
- All scripts validate inputs and provide secure defaults

## Contributing

When adding new scripts:
1. **Categorize properly** - Place in appropriate subdirectory
2. **Make executable** - `chmod +x script-name.sh`
3. **Document thoroughly** - Add header with usage, requirements
4. **Update README** - Add entry to this documentation
5. **Follow naming** - Use kebab-case with descriptive names
6. **Test extensively** - Ensure scripts work in clean environments