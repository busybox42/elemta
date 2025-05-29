# Elemta Scripts Directory

This directory contains various utility scripts organized by category for the Elemta MTA project.

## Directory Structure

```
scripts/
├── ssl/           # SSL/TLS certificate management scripts
├── test/          # Testing and test runner scripts  
├── debug/         # Debugging and troubleshooting scripts
├── dev/           # Development utility scripts
└── [root]         # General utility scripts
```

## SSL/TLS Certificate Management (`ssl/`)

- **`letsencrypt-admin.sh`** - Comprehensive Let's Encrypt certificate management tool
  - Check certificate status
  - Force certificate renewal
  - Revoke certificates
  - Backup/restore certificates
  - Toggle staging/production mode
  - Import existing certificates

- **`letsencrypt-test.sh`** - Tests Let's Encrypt/ACME configuration and readiness
  - DNS resolution checks
  - Port availability tests
  - Certificate path validation
  - ACME connectivity tests

- **`letsencrypt-metrics.sh`** - Prometheus metrics exporter for Let's Encrypt certificates
  - Certificate expiration metrics
  - Renewal status tracking
  - Can run as HTTP server or write to textfile

- **`letsencrypt-monitor.sh`** - Advanced monitoring and alerting for Let's Encrypt certificates
  - Continuous certificate monitoring
  - Email/Slack notifications
  - Automated renewal triggers

## Testing Scripts (`test/`)

- **`run-all-tests.sh`** - Master test runner for the entire test suite
  - Runs Go unit tests
  - Optionally runs database tests
  - Runs Python e2e tests
  - Usage: `./run-all-tests.sh [--all]`

- **`run-datasource-tests.sh`** - Database-specific test runner
  - MySQL tests
  - PostgreSQL tests
  - LDAP tests
  - Let's Encrypt tests
  - Usage: `./run-datasource-tests.sh [mysql|postgres|ldap|letsencrypt|all]`

## Debugging Scripts (`debug/`)

- **`debug-email.sh`** - Email debugging and testing utility
  - Sends test emails to Elemta SMTP server
  - Checks delivery status
  - Shows relevant logs
  - Verifies mailbox delivery

## Development Scripts (`dev/`)

- **`rebuild.sh`** - Development build and restart script
  - Rebuilds Go binary
  - Rebuilds Docker image
  - Restarts containers
  - Quick development iteration

## General Utility Scripts (root level)

- **`elemta-api.sh`** - API client for Elemta management
- **`elemta-cli.sh`** - Command-line interface wrapper
- **`setup-monitoring.sh`** - Sets up monitoring stack (Prometheus, Grafana)
- **`generate-test-load.sh`** - Generates test email load for performance testing
- **`check-queue.sh`** - Queue inspection and management
- **`deploy-and-test.sh`** - Automated deployment and testing
- **`docker-deploy.sh`** / **`docker-undeploy.sh`** - Docker deployment utilities

## Usage Examples

### SSL Certificate Management
```bash
# Check certificate status
./scripts/ssl/letsencrypt-admin.sh status

# Force certificate renewal
./scripts/ssl/letsencrypt-admin.sh renew

# Test Let's Encrypt configuration
./scripts/ssl/letsencrypt-test.sh -d mail.example.tld
```

### Running Tests
```bash
# Run all tests including database tests
./scripts/test/run-all-tests.sh --all

# Run only MySQL tests
./scripts/test/run-datasource-tests.sh mysql
```

### Development
```bash
# Quick rebuild and restart
./scripts/dev/rebuild.sh

# Debug email delivery
./scripts/debug/debug-email.sh
```

### Monitoring
```bash
# Set up monitoring stack
./scripts/setup-monitoring.sh

# Generate test load
./scripts/generate-test-load.sh 100
```

## Prerequisites

Most scripts require:
- Docker and Docker Compose
- Go 1.19+
- Python 3.8+ (for some scripts)
- OpenSSL (for SSL scripts)
- Standard Unix utilities (curl, grep, sed, etc.)

Specific requirements are documented in individual script headers.

## Contributing

When adding new scripts:
1. Place them in the appropriate category directory
2. Make them executable (`chmod +x`)
3. Add proper header comments with usage information
4. Update this README
5. Follow the existing naming conventions 