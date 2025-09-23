# Elemta Installation and Update Guide

This guide explains how to install and update Elemta using the provided scripts.

## Installation

### Quick Start

#### Option 1: Interactive Installation
1. **Run the installer:**
   ```bash
   make install
   ```

2. **Follow the interactive prompts** to configure your Elemta instance

3. **Start the services:**
   ```bash
   docker-compose -f docker-compose.yml --env-file .env up -d
   ```

#### Option 2: Development Environment
For development and testing, use the pre-configured development environment:

```bash
make install-dev
```

This sets up:
- Development domain: `example.com`
- Demo users for testing
- Development configuration with debug logging
- All services pre-configured

**Demo Users Created:**
- `alan@example.com` (password: `password123`)
- `admin@example.com` (password: `admin123`)
- `test@example.com` (password: `test123`)
- `demo@example.com` (password: `demo123`)

## Uninstallation

To completely remove Elemta and all associated data:

```bash
make uninstall
```

This will:
- ✅ Stop and remove all Docker containers
- ✅ Remove all Docker images and volumes
- ✅ Clean up configuration files (.env, generated configs)
- ✅ Remove all logs and queue data
- ✅ Perform Docker system cleanup

**⚠️ Warning:** This will permanently delete all email data, logs, and configurations!

### Installation Process

The installer (`install.sh`) will:

- ✅ Prompt for server configuration (hostname, domain, email)
- ✅ Configure ports for SMTP, IMAP, webmail, etc.
- ✅ Set up database configuration (SQLite or PostgreSQL)
- ✅ Configure LDAP authentication (optional)
- ✅ Set up SSL/TLS with Let's Encrypt (optional)
- ✅ Create test user accounts
- ✅ Generate secure passwords automatically
- ✅ Create `.env` configuration file
- ✅ Generate Elemta configuration files
- ✅ Create authentication files

### Configuration Options

#### Server Configuration
- **Hostname**: Your mail server hostname (e.g., `mail.example.com`)
- **Domain**: Your domain name (e.g., `example.com`)
- **Admin Email**: Administrator email address

#### Port Configuration
- **SMTP**: Port 25 (standard) or custom
- **SMTPS**: Port 465 (SSL/TLS)
- **STARTTLS**: Port 587 (STARTTLS)
- **IMAP**: Port 143 (standard) or custom
- **Web UI**: Port 8025 (admin interface)
- **Webmail**: Port 8026 (Roundcube)
- **API**: Port 8081 (management API)

#### Database Options
- **SQLite**: Simple file-based database (default)
- **PostgreSQL**: Full-featured database server

#### Authentication
- **LDAP**: Optional LDAP/Active Directory integration
- **Local Users**: File-based user authentication

#### SSL/TLS
- **Let's Encrypt**: Automatic SSL certificate management
- **Staging**: Use Let's Encrypt staging environment for testing

## Updates

### Update Script

The update script allows you to update a running Elemta instance:

```bash
# Full update (configuration + restart)
make update

# Update with backup
make update-backup

# Restart services only
make update-restart
```

### Update Options

- `-e, --env-file FILE`: Use specific .env file
- `-c, --config-only`: Only update configuration
- `-r, --restart-only`: Only restart services
- `-b, --backup`: Create backup before updating
- `-f, --force`: Force update without confirmation
- `-h, --help`: Show help message

### Update Process

The update script will:

1. ✅ Validate current configuration
2. ✅ Create backup (if requested)
3. ✅ Update configuration files
4. ✅ Restart services (if not config-only)
5. ✅ Validate final configuration
6. ✅ Show service status and logs

## Configuration Files

### .env File

The `.env` file contains all environment variables for your Elemta instance:

```bash
# Server Configuration
ELEMTA_HOSTNAME=mail.example.com
ELEMTA_DOMAIN=example.com
ELEMTA_EMAIL=admin@example.com

# Port Configuration
SMTP_PORT=25
SMTPS_PORT=465
# ... more configuration
```

### Generated Configuration

- `config/elemta-generated.toml`: Main Elemta configuration
- `config/users.txt`: User authentication file

## Security Notes

### Important Security Considerations

- 🔐 **Never commit `.env` files to version control**
- 🔐 **Keep passwords secure and change default passwords**
- 🔐 **Use strong passwords for all services**
- 🔐 **Enable SSL/TLS in production**
- 🔐 **Regularly update Elemta and dependencies**

### Password Management

- Passwords are automatically generated for services
- Test user passwords are set during installation
- LDAP passwords are configured if LDAP is enabled
- Database passwords are set for PostgreSQL

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports are not in use by other services
2. **Permission issues**: Run with appropriate permissions
3. **Docker issues**: Ensure Docker and docker-compose are installed
4. **Configuration errors**: Check `.env` file syntax

### Useful Commands

```bash
# Check service status
docker-compose -f docker-compose.yml ps

# View logs
docker-compose -f docker-compose.yml logs -f elemta

# Stop services
docker-compose -f docker-compose.yml down

# Restart services
make update-restart

# Check configuration
cat .env
cat config/elemta-generated.toml
```

### Getting Help

- Check the logs: `docker-compose -f docker-compose.yml logs -f elemta`
- Validate configuration: `make update`
- Create backup: `make update-backup`
- Review documentation in `docs/` directory

## Examples

### Development Setup

```bash
# Install with development settings
./install.sh
# Use default values for most prompts
# Enable Let's Encrypt staging
# Use SQLite database
```

### Production Setup

```bash
# Install with production settings
./install.sh
# Use production domain
# Enable Let's Encrypt production
# Use PostgreSQL database
# Configure LDAP authentication
```

### Update Production

```bash
# Update with backup
make update-backup

# Only restart services
make update-restart
```

## Next Steps

After installation:

1. **Test email functionality** using the test user
2. **Configure DNS records** for your domain
3. **Set up monitoring** and logging
4. **Configure backup procedures**
5. **Review security settings**
6. **Set up SSL certificates** (if not using Let's Encrypt)

For more detailed configuration options, see the documentation in the `docs/` directory.
