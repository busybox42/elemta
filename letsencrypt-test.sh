#!/bin/bash

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions for logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Default values
CONFIG_FILE="/etc/elemta/elemta.toml"
DOMAIN=""

# Banner
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}  Elemta Let's Encrypt Test Script       ${NC}"
echo -e "${BLUE}  Tests ACME configuration and readiness ${NC}"
echo -e "${BLUE}==========================================${NC}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-c CONFIG_FILE] [-d DOMAIN]"
            echo "  -c, --config CONFIG_FILE  Path to Elemta config file (default: /etc/elemta/elemta.toml)"
            echo "  -d, --domain DOMAIN       Domain to test (default: from config file)"
            echo "  -h, --help                Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown parameter: $1"
            exit 1
            ;;
    esac
done

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Config file not found: $CONFIG_FILE"
    exit 1
fi

log_info "Using config file: $CONFIG_FILE"

# Check for required commands
REQUIRED_COMMANDS=("curl" "openssl" "grep" "dig" "nc")
MISSING_COMMANDS=0

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command_exists "$cmd"; then
        log_error "Required command not found: $cmd"
        MISSING_COMMANDS=1
    fi
done

if [[ $MISSING_COMMANDS -eq 1 ]]; then
    log_error "Please install the missing commands and try again"
    exit 1
fi

# Parse config file
if [[ -z "$DOMAIN" ]]; then
    if grep -q "domain =" "$CONFIG_FILE"; then
        DOMAIN=$(grep "domain =" "$CONFIG_FILE" | sed 's/.*"\(.*\)".*/\1/')
        log_info "Using domain from config: $DOMAIN"
    else
        log_error "Domain not found in config and not provided as argument"
        exit 1
    fi
fi

# Extract TLS settings
TLS_ENABLED=$(grep "enabled =" "$CONFIG_FILE" | grep -A3 "\[tls\]" | head -n1 | grep -o "true\|false")
STARTTLS_ENABLED=$(grep "starttls =" "$CONFIG_FILE" | grep -o "true\|false")
ACME_ENABLED=$(grep "enabled =" "$CONFIG_FILE" | grep -A3 "\[tls.acme\]" | head -n1 | grep -o "true\|false")

# Show current TLS configuration
echo -e "\n${BLUE}Current TLS Configuration:${NC}"
echo -e "TLS Enabled: ${TLS_ENABLED:-not set}"
echo -e "STARTTLS Enabled: ${STARTTLS_ENABLED:-not set}"
echo -e "ACME (Let's Encrypt) Enabled: ${ACME_ENABLED:-not set}"

# Check if ACME is enabled
if [[ "$ACME_ENABLED" != "true" ]]; then
    log_warning "ACME is not enabled in the configuration. Let's Encrypt certificates won't be obtained automatically."
fi

# Test 1: DNS resolution
echo -e "\n${BLUE}Running Test: DNS Resolution${NC}"
SERVER_IP=$(dig +short "$(hostname)")
DOMAIN_IP=$(dig +short "$DOMAIN")

if [[ -z "$DOMAIN_IP" ]]; then
    log_error "Domain $DOMAIN does not resolve to any IP address"
else
    if [[ "$SERVER_IP" == "$DOMAIN_IP" ]]; then
        log_success "Domain $DOMAIN resolves to this server's IP: $SERVER_IP"
    else
        log_error "Domain $DOMAIN resolves to $DOMAIN_IP, which is different from this server's IP: $SERVER_IP"
        log_error "Let's Encrypt verification will likely fail because the domain must point to this server"
    fi
fi

# Test 2: HTTP-01 challenge port availability (port 80)
echo -e "\n${BLUE}Running Test: HTTP-01 Challenge Port Availability${NC}"
if nc -z localhost 80 2>/dev/null; then
    # Check if elemta is listening on port 80
    if netstat -tlnp 2>/dev/null | grep -q ":80.*elemta"; then
        log_success "Port 80 is available and Elemta is listening on it"
    else
        log_warning "Port 80 is in use by another application. Let's Encrypt HTTP-01 challenge might fail"
        log_info "Process using port 80: $(netstat -tlnp 2>/dev/null | grep ":80" | awk '{print $7}')"
    fi
else
    log_warning "Port 80 is not in use. Make sure Elemta is configured to listen on port 80 for ACME challenges"
fi

# Test 3: SMTP ports check
echo -e "\n${BLUE}Running Test: SMTP Ports${NC}"
PORTS=(25 465 587)
for PORT in "${PORTS[@]}"; do
    if nc -z localhost $PORT 2>/dev/null; then
        if netstat -tlnp 2>/dev/null | grep -q ":$PORT.*elemta"; then
            log_success "Port $PORT is available and Elemta is listening on it"
        else
            log_warning "Port $PORT is in use by another application"
            log_info "Process using port $PORT: $(netstat -tlnp 2>/dev/null | grep ":$PORT" | awk '{print $7}')"
        fi
    else
        log_warning "Port $PORT is not in use. SMTP service might not be fully configured"
    fi
done

# Test 4: Certificate paths and permissions
echo -e "\n${BLUE}Running Test: Certificate Paths and Permissions${NC}"
CERT_DIR=$(grep "cert_dir" "$CONFIG_FILE" | sed 's/.*"\(.*\)".*/\1/' | head -n1)
if [[ -z "$CERT_DIR" ]]; then
    CERT_DIR="/var/elemta/certs"
    log_info "Certificate directory not specified in config, using default: $CERT_DIR"
else
    log_info "Certificate directory from config: $CERT_DIR"
fi

if [[ ! -d "$CERT_DIR" ]]; then
    log_warning "Certificate directory does not exist: $CERT_DIR"
    log_info "Directory will need to be created with proper permissions"
else
    if [[ -w "$CERT_DIR" ]]; then
        log_success "Certificate directory exists and is writable: $CERT_DIR"
    else
        log_error "Certificate directory exists but is not writable: $CERT_DIR"
        log_info "Please ensure the directory is writable by the Elemta service user"
    fi
fi

# Test 5: Attempt to connect to Let's Encrypt ACME directory
echo -e "\n${BLUE}Running Test: Let's Encrypt ACME Connectivity${NC}"
LE_PROD="https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING="https://acme-staging-v02.api.letsencrypt.org/directory"

# Check production
if curl --connect-timeout 5 -s -o /dev/null -w "%{http_code}" "$LE_PROD" | grep -q "200"; then
    log_success "Successfully connected to Let's Encrypt production ACME directory"
else
    log_error "Failed to connect to Let's Encrypt production ACME directory"
    log_info "Check your network connectivity and firewall settings"
fi

# Check staging
if curl --connect-timeout 5 -s -o /dev/null -w "%{http_code}" "$LE_STAGING" | grep -q "200"; then
    log_success "Successfully connected to Let's Encrypt staging ACME directory"
else
    log_error "Failed to connect to Let's Encrypt staging ACME directory"
    log_info "Check your network connectivity and firewall settings"
fi

# Test 6: Check rate limits
echo -e "\n${BLUE}Running Test: Rate Limit Status${NC}"
if command_exists "certbot"; then
    CERTBOT_CERTS=$(certbot certificates 2>/dev/null | grep -c "Certificate Name:")
    if [[ $CERTBOT_CERTS -gt 0 ]]; then
        log_info "Found $CERTBOT_CERTS certificates managed by Certbot"
        log_warning "Be aware of Let's Encrypt rate limits if you're also using Certbot for the same domains"
    fi
fi

log_info "Let's Encrypt has the following rate limits:"
log_info "- 50 certificates per registered domain per week"
log_info "- 5 duplicate certificates per week"
log_info "- 100 failed validations per account per hour"

# Final recommendations
echo -e "\n${BLUE}Recommendations:${NC}"
if [[ "$ACME_ENABLED" != "true" ]]; then
    echo "1. Enable ACME in your config file by adding the following:"
    echo -e "   [tls.acme]\n   enabled = true\n   email = \"your-email@example.com\"\n   domain = \"$DOMAIN\"\n   staging = false"
fi

if [[ "$TLS_ENABLED" != "true" ]]; then
    echo "2. Ensure TLS is enabled in your config file:"
    echo -e "   [tls]\n   enabled = true"
fi

echo "3. Make sure ports 80, 465, and 587 are open in your firewall"
echo "4. Ensure the certificate directory is writable by the Elemta service user"
echo "5. Consider testing with staging mode first to avoid rate limits"

# Finished
echo -e "\n${GREEN}Test completed! Review the output above for any issues.${NC}"
exit 0 