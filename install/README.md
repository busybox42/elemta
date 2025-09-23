# Elemta Installation Scripts

This directory contains all the installation and management scripts for Elemta.

## Scripts

### `install.sh`
Interactive installer that generates a `.env` configuration file for Elemta.
- Prompts for server configuration (hostname, domain, email)
- Generates secure passwords
- Creates `.env` file with all necessary settings
- Can be run multiple times to update configuration

### `install-dev.sh`
Development environment setup script with pre-configured demo users.
- Creates a complete development environment
- Sets up demo users in LDAP
- Generates self-signed certificates
- Configures all services for local development
- Includes authentication testing

### `update.sh`
Update script for running Elemta environments.
- Regenerates configuration from `.env` file
- Restarts services
- Supports backup and force options
- Can update configuration only or restart services only

### `uninstall.sh`
Complete removal script for Elemta.
- Stops and removes all Docker containers
- Cleans up configuration files
- Removes logs and queue data
- Performs Docker system cleanup
- Preserves certificates by default

### `test-auth.sh`
Quick authentication test script.
- Tests SMTP connection
- Verifies PLAIN and LOGIN authentication
- Tests invalid authentication rejection
- Shows available demo users

## Usage

All scripts are designed to be run from the Elemta project root directory using the Makefile:

```bash
# Interactive installation
make install

# Development environment setup
make install-dev

# Update running environment
make update

# Complete removal
make uninstall

# Quick authentication test
make test-auth
```

## Development Environment

The `install-dev.sh` script sets up a complete development environment with:

- **Domain**: example.com
- **Hostname**: mail.example.com
- **Demo Users**:
  - demo@example.com / demo123
  - alan@example.com / password123
  - admin@example.com / admin123
  - test@example.com / test123

## Configuration

All scripts automatically change to the Elemta project root directory, so they can be run from anywhere within the project structure.

## Dependencies

- Docker and Docker Compose
- `nc` (netcat) for network testing
- `openssl` for certificate generation
- `ldapadd` for LDAP user creation
