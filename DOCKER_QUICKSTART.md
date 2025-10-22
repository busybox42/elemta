# Elemta Docker Quick Start

## TL;DR

```bash
# Development
make install-dev    # One command setup
make status         # Check health
make logs          # View logs

# Production
make install        # Interactive setup
make up             # Start
make down          # Stop
```

## Development Workflow

### Initial Setup (Once)

```bash
make install-dev
```

This will:
- ✅ Create `.env` with development settings
- ✅ Build Docker images
- ✅ Start all 8 services
- ✅ Initialize LDAP users
- ✅ Show service URLs

### Daily Development

```bash
# Start services
make up

# Check status
make status

# View logs
make logs           # All services
make logs-elemta    # Elemta only

# Restart after code changes
make rebuild

# Stop services
make down
```

## Production Deployment

### Initial Setup

```bash
# Interactive configuration
make install
```

Answer prompts:
- Hostname: `mail.example.com`
- SMTP Port: `25`
- Admin Email: `admin@example.com`
- Enable Let's Encrypt: `y`
- LDAP Host: `ldap.example.com`
- LDAP Base DN: `dc=example,dc=com`

### Review Configuration

```bash
# Edit .env for your environment
vi .env

# Update:
# - LDAP credentials
# - TLS certificates
# - Memory limits
# - Domain names
```

### Start Production

```bash
make up
make status
make logs
```

## Make Commands Reference

### Essential Commands

| Command | Description |
|---------|-------------|
| `make up` | Start all services |
| `make down` | Stop services (keep data) |
| `make restart` | Restart all services |
| `make status` | Show service health |
| `make logs` | Follow all logs |

### Deployment Commands

| Command | Description |
|---------|-------------|
| `make install` | Production setup (interactive) |
| `make install-dev` | Development setup (automatic) |
| `make rebuild` | Rebuild images and restart |
| `make down-volumes` | Stop and delete all data |

### Monitoring Commands

| Command | Description |
|---------|-------------|
| `make logs-elemta` | Elemta SMTP logs only |
| `make status` | Service health check |
| `make test-load` | Run load tests |

## Service URLs

After `make up`, access services at:

- **SMTP**: `localhost:2525` (dev) or `localhost:25` (prod)
- **Metrics**: http://localhost:8080/metrics
- **Web UI**: http://localhost:8025
- **Roundcube**: http://localhost:8026
- **IMAP**: `localhost:14143`

## Configuration (.env)

The `.env` file controls all deployment settings:

```env
# Core
HOSTNAME=mail.example.com
LISTEN_PORT=25
LOG_LEVEL=INFO

# TLS
LETSENCRYPT_ENABLED=true
LETSENCRYPT_EMAIL=admin@example.com

# Resources
MAX_MEMORY_USAGE=2147483648  # 2GB
MAX_CONNECTIONS=1000
```

See `.env.example` for all available variables.

## Troubleshooting

### Services Won't Start

```bash
# Check logs
make logs-elemta

# Verify .env
cat .env

# Rebuild from scratch
make down-volumes
make install-dev
```

### Port Conflicts

Edit `.env`:
```env
LISTEN_PORT=2525    # Change from 25
METRICS_PORT=8081   # Change from 8080
```

Then:
```bash
make down
make up
```

### Reset Everything

```bash
make down-volumes   # Stops and deletes all data
rm .env             # Remove configuration
make install-dev    # Fresh start
```

## Next Steps

1. ✅ Run `make install-dev` or `make install`
2. ✅ Verify with `make status`
3. ✅ Test with `make test-load`
4. ✅ Monitor with `make logs`
5. ✅ Read full docs: `docs/environment_configuration.md`

## Support

- Full documentation: `docs/`
- Environment guide: `docs/environment_configuration.md`
- Production deployment: `docs/production-deployment.md`
- Troubleshooting: `docs/troubleshooting.md`

