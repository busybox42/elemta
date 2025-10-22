# Environment Configuration Guide

## Overview

Elemta uses a `.env` file for environment-specific configuration, making it easy to manage different deployments (development, staging, production) without changing code or Docker Compose files.

## Quick Start

### Development Environment

```bash
make install-dev    # Auto-configures development environment
make up             # Start services
make logs           # View logs
make down           # Stop services
```

### Production Environment

```bash
make install        # Interactive production setup
# ... answer prompts for hostname, ports, etc.
make up             # Start services
make status         # Check service health
```

## Environment File (.env)

### Location

The `.env` file is automatically loaded by Docker Compose and should be placed in the project root:

```
/home/alan/repos/elemta/.env
```

### Creating .env

**Method 1: Automatic (Development)**
```bash
make docker-setup   # Creates .env automatically with dev settings
```

**Method 2: Interactive (Production)**
```bash
make install        # Prompts for configuration
```

**Method 3: Manual**
```bash
cp .env.example .env
# Edit .env with your settings
```

## Make Commands

### Lifecycle Commands

| Command | Description |
|---------|-------------|
| `make up` | Start all services (requires .env) |
| `make down` | Stop services (keep volumes) |
| `make down-volumes` | Stop services and remove all data |
| `make restart` | Restart all services |
| `make rebuild` | Rebuild images and restart |

### Monitoring Commands

| Command | Description |
|---------|-------------|
| `make status` | Show service health status |
| `make logs` | Follow all service logs |
| `make logs-elemta` | Follow Elemta SMTP logs only |

### Installation Commands

| Command | Description |
|---------|-------------|
| `make install` | Production setup (interactive) |
| `make install-dev` | Development setup (automatic) |
| `make docker-setup` | Build and start dev environment |

## Configuration Variables

### Core Settings

```env
# Deployment type
ENVIRONMENT=production          # production, staging, development

# Server identification
HOSTNAME=mail.example.com
LISTEN_PORT=25                 # 25 for production, 2525 for dev
```

### TLS/SSL

```env
TLS_ENABLED=true
ENABLE_STARTTLS=true
CERT_FILE=/app/certs/cert.pem
KEY_FILE=/app/certs/key.pem

# Let's Encrypt (automatic certificates)
LETSENCRYPT_ENABLED=true
LETSENCRYPT_EMAIL=admin@example.com
LETSENCRYPT_DOMAIN=mail.example.com
```

### Authentication

```env
AUTH_ENABLED=true
AUTH_BACKEND=ldap               # ldap, file, database

# LDAP Configuration
LDAP_HOST=ldap.example.com
LDAP_PORT=389
LDAP_BASE_DN=dc=example,dc=com
LDAP_BIND_DN=cn=admin,dc=example,dc=com
LDAP_BIND_PASSWORD=secure_password
```

### Resources & Performance

```env
MAX_MEMORY_USAGE=2147483648     # 2GB
MAX_CONNECTIONS=1000
MAX_CONNECTIONS_PER_IP=50
MEMORY_CRITICAL_THRESHOLD=0.90  # 90%
```

### Logging

```env
LOG_LEVEL=INFO                  # DEBUG, INFO, WARN, ERROR
LOG_FORMAT=json
LOG_TYPE=console                # console, file, elastic
```

## Deployment Workflows

### Development Workflow

```bash
# Initial setup
make install-dev

# Daily workflow
make up              # Start
make logs            # Monitor
make restart         # Restart after code changes
make down            # Stop

# Testing
make test-load       # Run load tests
make status          # Check health
```

### Production Workflow

```bash
# Initial setup
make install
# ... configure via prompts
vi .env              # Review and adjust settings
make up

# Ongoing maintenance
make status          # Check health
make logs            # Monitor logs
make restart         # Restart services
make rebuild         # Rebuild after updates

# Updates
git pull
make rebuild         # Rebuild with new code
make test-load       # Verify
```

### Staging Workflow

```bash
# Copy production .env and modify
cp .env .env.staging
vi .env.staging      # Adjust for staging
ln -sf .env.staging .env

make rebuild
make test-load
```

## Environment-Specific Configurations

### Development (.env)

```env
ENVIRONMENT=development
HOSTNAME=mail.dev.example.com
LISTEN_PORT=2525              # Non-privileged port
LOG_LEVEL=DEBUG               # Verbose logging
DEV_MODE=true
TEST_MODE=true
AUTH_REQUIRED=false           # Optional auth for testing
MAX_CONNECTIONS_PER_IP=1000   # Permissive for load testing
```

### Production (.env)

```env
ENVIRONMENT=production
HOSTNAME=mail.example.com
LISTEN_PORT=25                # Standard SMTP port
LOG_LEVEL=INFO                # Normal logging
DEV_MODE=false
TEST_MODE=false
AUTH_REQUIRED=true            # Enforce authentication
MAX_CONNECTIONS_PER_IP=50     # Strict limits
LETSENCRYPT_ENABLED=true      # Auto SSL
```

## Security Considerations

### .env File Security

1. **Never commit .env** - Already in .gitignore
2. **Restrict permissions**: `chmod 600 .env`
3. **Use secrets management** in production
4. **Rotate passwords** regularly

### Secrets

Store sensitive values in `.env`:

```env
LDAP_BIND_PASSWORD=your_secure_password
LETSENCRYPT_EMAIL=admin@example.com
```

Consider using Docker secrets for production:

```bash
# Create secrets
echo "password" | docker secret create ldap_password -

# Reference in docker-compose.yml
secrets:
  - ldap_password
```

## Troubleshooting

### .env Not Loading

**Symptom**: Services start with default configuration

**Solution**:
```bash
# Verify .env exists
ls -la .env

# Check Docker Compose recognizes it
docker compose config | grep HOSTNAME
```

### Port Conflicts

**Symptom**: `port is already allocated`

**Solution**:
```env
# Change ports in .env
LISTEN_PORT=2525     # Instead of 25
METRICS_PORT=8081    # Instead of 8080
```

### Services Not Starting

**Symptom**: Containers exit immediately

**Solution**:
```bash
# Check logs
make logs-elemta

# Verify configuration
make status

# Rebuild
make rebuild
```

## Best Practices

1. **Use make commands** - Don't call docker compose directly
2. **Keep .env.example updated** - Document all variables
3. **Environment-specific files** - Use .env.dev, .env.prod, .env.staging
4. **Version control** - Commit .env.example, never commit .env
5. **Document changes** - Update this guide when adding variables

## Related Documentation

- [Production Deployment](production-deployment.md)
- [Docker Deployment](docker_deployment.md)
- [Configuration Reference](configuration.md)

