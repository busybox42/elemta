# Docker Compose Deployments

This directory contains various Docker Compose configurations for different deployment scenarios.

## Available Configurations

### `docker-compose.yml` (Main Development Stack)
Complete development environment including:
- Elemta SMTP server
- LDAP authentication server
- Dovecot IMAP/LMTP
- Roundcube webmail
- Rspamd spam filtering
- ClamAV antivirus
- Valkey distributed cache

**Usage:**
```bash
cd deployments/compose
docker compose up -d
```

### `docker-compose-monitoring.yml`
Monitoring stack with:
- Prometheus metrics collection
- Grafana dashboards
- Alertmanager

**Usage:**
```bash
docker compose -f docker-compose.yml -f docker-compose-monitoring.yml up -d
```

### `docker-compose-cli.yml`
CLI tools for testing and management

### `docker-compose-test.yml`
Test environment configuration

## Quick Start

From the project root:
```bash
# Start main stack
make docker-setup

# View logs
docker compose -f deployments/compose/docker-compose.yml logs -f

# Stop stack
make docker-down
```

## Network Architecture

All services run on the `elemta_network` bridge network with the following ports:
- **2525**: SMTP (Elemta)
- **8080**: Metrics (Prometheus format)
- **1389**: LDAP
- **14143**: IMAP (Dovecot)
- **8000**: Webmail (Roundcube)
- **6379**: Valkey (internal)

