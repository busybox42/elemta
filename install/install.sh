#!/bin/bash
# Elemta Installation Script
# This script creates a new .env file with user-provided configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Elemta Installation Script   ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to prompt for input with default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " input
        eval "$var_name=\"\${input:-$default}\""
    else
        read -p "$prompt: " input
        eval "$var_name=\"$input\""
    fi
}

# Function to prompt for password
prompt_password() {
    local prompt="$1"
    local var_name="$2"
    
    read -s -p "$prompt: " password
    echo ""
    eval "$var_name=\"$password\""
}

# Function to generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Function to validate domain
validate_domain() {
    local domain="$1"
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate email
validate_email() {
    local email="$1"
    if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

print_header

# Change to the parent directory (Elemta project root)
cd "$(dirname "$0")/.."

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ] || [ ! -f "generate-config-alt.sh" ]; then
    print_error "Not in Elemta directory. Please run this from the Elemta project root."
    exit 1
fi

# Check if .env already exists
if [ -f ".env" ]; then
    print_warning "A .env file already exists!"
    read -p "Do you want to overwrite it? (y/N): " overwrite
    if [[ ! $overwrite =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled."
        exit 0
    fi
fi

echo "This script will help you create a .env configuration file for Elemta."
echo "You can press Enter to use the default values shown in brackets."
echo ""

# Server Configuration
echo -e "${BLUE}📧 Server Configuration${NC}"
echo ""

prompt_with_default "Enter your mail server hostname" "mail.example.com" "ELEMTA_HOSTNAME"
prompt_with_default "Enter your domain name" "example.com" "ELEMTA_DOMAIN"

# Validate domain
while ! validate_domain "$ELEMTA_DOMAIN"; do
    print_error "Invalid domain format. Please enter a valid domain."
    prompt_with_default "Enter your domain name" "example.com" "ELEMTA_DOMAIN"
done

prompt_with_default "Enter admin email address" "admin@$ELEMTA_DOMAIN" "ELEMTA_EMAIL"

# Validate email
while ! validate_email "$ELEMTA_EMAIL"; do
    print_error "Invalid email format. Please enter a valid email address."
    prompt_with_default "Enter admin email address" "admin@$ELEMTA_DOMAIN" "ELEMTA_EMAIL"
done

echo ""

# Port Configuration
echo -e "${BLUE}🔌 Port Configuration${NC}"
echo ""

prompt_with_default "SMTP port" "25" "SMTP_PORT"
prompt_with_default "SMTPS port" "465" "SMTPS_PORT"
prompt_with_default "SMTP STARTTLS port" "587" "SMTP_STARTTLS_PORT"
prompt_with_default "IMAP port" "143" "IMAP_PORT"
prompt_with_default "Web UI port" "8025" "WEB_UI_PORT"
prompt_with_default "Webmail port" "8026" "WEBMAIL_PORT"
prompt_with_default "HTTP port" "8080" "HTTP_PORT"
prompt_with_default "API port" "8081" "API_PORT"

echo ""

# Database Configuration
echo -e "${BLUE}🗄️  Database Configuration${NC}"
echo ""

prompt_with_default "Database type (sqlite/postgres)" "sqlite" "DB_TYPE"

if [ "$DB_TYPE" = "postgres" ]; then
    prompt_with_default "PostgreSQL host" "postgres" "DB_HOST"
    prompt_with_default "PostgreSQL port" "5432" "DB_PORT"
    prompt_with_default "Database name" "elemta" "DB_NAME"
    prompt_with_default "Database user" "elemta" "DB_USER"
    prompt_password "Enter database password" "DB_PASSWORD"
else
    DB_HOST=""
    DB_PORT=""
    DB_NAME=""
    DB_USER=""
    DB_PASSWORD=""
fi

echo ""

# LDAP Configuration
echo -e "${BLUE}👥 LDAP Configuration${NC}"
echo ""

read -p "Do you want to configure LDAP authentication? (y/N): " configure_ldap

if [[ $configure_ldap =~ ^[Yy]$ ]]; then
    prompt_with_default "LDAP host" "ldap" "LDAP_HOST"
    prompt_with_default "LDAP port" "389" "LDAP_PORT"
    prompt_with_default "LDAP base DN" "dc=$ELEMTA_DOMAIN" "LDAP_BASE_DN"
    prompt_with_default "LDAP admin DN" "cn=admin,dc=$ELEMTA_DOMAIN" "LDAP_ADMIN_DN"
    prompt_password "Enter LDAP admin password" "LDAP_ADMIN_PASSWORD"
    prompt_with_default "LDAP organization" "Example Organization" "LDAP_ORGANISATION"
else
    LDAP_HOST="ldap"
    LDAP_PORT="389"
    LDAP_BASE_DN="dc=$ELEMTA_DOMAIN"
    LDAP_ADMIN_DN="cn=admin,dc=$ELEMTA_DOMAIN"
    LDAP_ADMIN_PASSWORD="admin123"
    LDAP_ORGANISATION="Example Organization"
fi

echo ""

# Let's Encrypt Configuration
echo -e "${BLUE}🔒 SSL/TLS Configuration${NC}"
echo ""

read -p "Do you want to enable Let's Encrypt SSL certificates? (y/N): " enable_letsencrypt

if [[ $enable_letsencrypt =~ ^[Yy]$ ]]; then
    LETSENCRYPT_ENABLED="true"
    prompt_with_default "Let's Encrypt email" "$ELEMTA_EMAIL" "LETSENCRYPT_EMAIL"
    read -p "Use Let's Encrypt staging environment? (y/N): " use_staging
    if [[ $use_staging =~ ^[Yy]$ ]]; then
        LETSENCRYPT_STAGING="true"
    else
        LETSENCRYPT_STAGING="false"
    fi
else
    LETSENCRYPT_ENABLED="false"
    LETSENCRYPT_EMAIL="$ELEMTA_EMAIL"
    LETSENCRYPT_STAGING="false"
fi

echo ""

# Test User Configuration
echo -e "${BLUE}🧪 Test User Configuration${NC}"
echo ""

prompt_with_default "Test username" "testuser" "TEST_USER"
prompt_password "Enter test user password" "TEST_PASSWORD"

echo ""

# Generate additional passwords
print_info "Generating secure passwords for services..."

DB_PASSWORD_GENERATED=$(generate_password)
LDAP_PASSWORD_GENERATED=$(generate_password)
TEST_PASSWORD_GENERATED=$(generate_password)

# Use generated passwords if user didn't provide them
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD="$DB_PASSWORD_GENERATED"
fi
if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
    LDAP_ADMIN_PASSWORD="$LDAP_PASSWORD_GENERATED"
fi
if [ -z "$TEST_PASSWORD" ]; then
    TEST_PASSWORD="$TEST_PASSWORD_GENERATED"
fi

# Create .env file
print_info "Creating .env configuration file..."

cat > .env << EOF
# Elemta Configuration File
# Generated by install.sh on $(date)

# Server Configuration
ELEMTA_HOSTNAME=$ELEMTA_HOSTNAME
ELEMTA_DOMAIN=$ELEMTA_DOMAIN
ELEMTA_EMAIL=$ELEMTA_EMAIL

# Environment Settings
TZ=UTC
DEBUG=false
TEST_MODE=false
NODE_ID=0

# Port Configuration
SMTP_PORT=$SMTP_PORT
SMTPS_PORT=$SMTPS_PORT
SMTP_STARTTLS_PORT=$SMTP_STARTTLS_PORT
IMAP_PORT=$IMAP_PORT
WEB_UI_PORT=$WEB_UI_PORT
WEBMAIL_PORT=$WEBMAIL_PORT
HTTP_PORT=$HTTP_PORT
METRICS_PORT=$HTTP_PORT
API_PORT=$API_PORT

# Database Configuration
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_TYPE=$DB_TYPE

# LDAP Configuration
LDAP_HOST=$LDAP_HOST
LDAP_PORT=$LDAP_PORT
LDAP_BASE_DN=$LDAP_BASE_DN
LDAP_ADMIN_DN=$LDAP_ADMIN_DN
LDAP_ADMIN_PASSWORD=$LDAP_ADMIN_PASSWORD
LDAP_ORGANISATION=$LDAP_ORGANISATION
LDAP_DOMAIN=$ELEMTA_DOMAIN

# Test User Configuration
TEST_USER=$TEST_USER
TEST_PASSWORD=$TEST_PASSWORD

# Let's Encrypt Configuration
LETSENCRYPT_ENABLED=$LETSENCRYPT_ENABLED
LETSENCRYPT_STAGING=$LETSENCRYPT_STAGING
LETSENCRYPT_EMAIL=$LETSENCRYPT_EMAIL

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=text
LOG_FILE=/app/logs/elemta.log

# Monitoring Configuration
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
ELASTICSEARCH_PORT=9200
KIBANA_PORT=5601

# Delivery Configuration
DELIVERY_HOST=elemta-dovecot
DELIVERY_PORT=2424
DELIVERY_MODE=lmtp
DELIVERY_TIMEOUT=30

# Docker Configuration
DOCKER_IMAGE=elemta_node
DOCKER_TAG=latest

# Rspamd Configuration
RSPAMD_PORT=11334

# Queue Configuration
QUEUE_INTERVAL=10
QUEUE_WORKERS=5

# Metrics and HTTP Configuration
METRICS_ENABLED=true
HTTP_ENABLED=true
ACME_CHALLENGE=true

# Check Interval (24 hours in nanoseconds)
CHECK_INTERVAL_NANOS=86400000000000
EOF

print_success "Configuration file created: .env"

# Create users.txt file for authentication
print_info "Creating users.txt for authentication..."
mkdir -p config
cat > config/users.txt << EOF
$TEST_USER@$ELEMTA_DOMAIN:$TEST_PASSWORD
$ELEMTA_EMAIL:$(generate_password)
EOF

print_success "Authentication file created: config/users.txt"

# Generate configuration
print_info "Generating Elemta configuration..."
./generate-config-alt.sh .env

if [ ! -f "config/elemta-generated.toml" ]; then
    print_error "Failed to generate Elemta configuration!"
    exit 1
fi

print_success "Elemta configuration generated: config/elemta-generated.toml"

echo ""
print_success "Installation complete!"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Review your configuration: cat .env"
echo "2. Start the services: docker-compose -f docker-compose.yml --env-file .env up -d"
echo "3. Check service status: docker-compose -f docker-compose.yml ps"
echo "4. View logs: docker-compose -f docker-compose.yml logs -f elemta"
echo ""
echo -e "${YELLOW}🔐 Important:${NC}"
echo "- Keep your .env file secure and never commit it to version control"
echo "- Your passwords are stored in .env and config/users.txt"
echo "- You can update your configuration using ./update.sh"
echo ""
echo -e "${GREEN}🎉 Elemta is ready to use!${NC}"
