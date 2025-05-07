#!/bin/bash

# Let's Encrypt Troubleshooter for Elemta
# This script helps diagnose common issues with Let's Encrypt integration

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions for formatted output
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for domain argument
if [ -z "$1" ]; then
    error "Please provide a domain name as the first argument"
    echo "Usage: $0 <domain_name> [config_file]"
    exit 1
fi

DOMAIN=$1
CONFIG_FILE=${2:-/etc/elemta/elemta.toml}

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    error "Configuration file not found: $CONFIG_FILE"
    echo "Please provide the correct path to your elemta.toml file as the second argument"
    exit 1
fi

echo "============================================="
echo "    Let's Encrypt Troubleshooter for Elemta"
echo "============================================="
echo ""
info "Running diagnostics for domain: $DOMAIN"
info "Using configuration file: $CONFIG_FILE"
echo ""

# Check for required tools
for cmd in curl dig openssl nc grep; do
    if ! command -v $cmd &> /dev/null; then
        warning "$cmd is required but not installed. Some tests may fail."
    fi
done

# Check 1: DNS resolution
echo "============================================="
info "Checking DNS resolution for $DOMAIN..."
echo "============================================="

if ! host_ips=$(dig +short A $DOMAIN); then
    error "Failed to resolve DNS for $DOMAIN"
    echo "Make sure your domain has proper DNS A records set up."
else
    success "Domain resolves to the following IP(s):"
    echo "$host_ips"
    
    # Get server IP
    server_ip=$(curl -s ifconfig.me)
    echo "This server's IP address is: $server_ip"
    
    if echo "$host_ips" | grep -q "$server_ip"; then
        success "Domain correctly points to this server"
    else
        error "Domain does not point to this server's IP ($server_ip)"
        echo "Let's Encrypt verification will fail unless the domain points to this server."
    fi
fi
echo ""

# Check 2: Port 80 accessibility
echo "============================================="
info "Checking port 80 (HTTP) accessibility..."
echo "============================================="

# First check locally
if nc -z localhost 80; then
    success "Port 80 is open locally"
    
    # Check what's running on port 80
    if command -v lsof &> /dev/null; then
        echo "Process using port 80:"
        lsof -i :80 | grep LISTEN
    elif command -v netstat &> /dev/null; then
        echo "Process using port 80:"
        netstat -tlpn | grep ":80"
    fi
else
    error "Port 80 is not open locally"
    echo "Let's Encrypt needs port 80 for HTTP-01 challenge verification."
fi

# Check externally
echo ""
info "Checking external port 80 accessibility..."
echo "This will attempt to connect to your domain on port 80 from an external service."
echo "Press Enter to continue or Ctrl+C to skip this test."
read

external_check=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN/.well-known/acme-challenge/test)
if [ "$external_check" = "000" ]; then
    error "Could not connect to $DOMAIN on port 80 from outside"
    echo "Let's Encrypt will not be able to validate your domain."
    echo "Check your firewall settings and ensure port 80 is open to the internet."
else
    success "Port 80 is accessible from outside (HTTP status: $external_check)"
fi
echo ""

# Check 3: TLS Configuration
echo "============================================="
info "Checking TLS configuration in $CONFIG_FILE..."
echo "============================================="

if ! grep -q '^\[tls\]' "$CONFIG_FILE"; then
    error "No [tls] section found in the configuration file"
else
    success "Found [tls] section in configuration"
    
    # Extract key settings
    tls_enabled=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^enabled" | awk -F '=' '{print $2}' | tr -d ' "')
    acme_enabled=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_enabled" | awk -F '=' '{print $2}' | tr -d ' "')
    acme_domain=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_domain" | awk -F '=' '{print $2}' | tr -d ' "')
    endpoint_port=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^endpoint_port" | awk -F '=' '{print $2}' | tr -d ' "')
    
    echo "TLS enabled: ${tls_enabled:-not set}"
    echo "ACME enabled: ${acme_enabled:-not set}"
    echo "ACME domain: ${acme_domain:-not set}"
    echo "ACME endpoint port: ${endpoint_port:-not set}"
    
    if [ "$tls_enabled" != "true" ]; then
        error "TLS is not enabled (enabled = true is required)"
    fi
    
    if [ "$acme_enabled" != "true" ]; then
        error "ACME is not enabled (acme_enabled = true is required)"
    fi
    
    if [ -z "$acme_domain" ]; then
        error "ACME domain is not set"
    elif [ "$acme_domain" != "$DOMAIN" ]; then
        warning "ACME domain ($acme_domain) does not match the domain being tested ($DOMAIN)"
    fi
    
    if [ -z "$endpoint_port" ]; then
        warning "ACME endpoint port is not set (default is 80)"
    elif [ "$endpoint_port" != "80" ]; then
        warning "ACME endpoint port is not 80 (using $endpoint_port instead)"
        echo "Make sure this port is accessible from the internet."
    fi
fi
echo ""

# Check 4: Certificate Storage
echo "============================================="
info "Checking certificate storage configuration..."
echo "============================================="

acme_storage=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_storage_path" | awk -F '=' '{print $2}' | tr -d ' "')
if [ -z "$acme_storage" ]; then
    warning "ACME storage path not set in configuration"
    echo "Using default storage location"
    # Try to guess the default location
    if [ -d "/var/elemta/certs" ]; then
        acme_storage="/var/elemta/certs"
    elif [ -d "/etc/elemta/certs" ]; then
        acme_storage="/etc/elemta/certs"
    else
        acme_storage="/tmp" # Fallback, probably not correct
    fi
fi

echo "ACME storage path: $acme_storage"

# Check if the directory exists and is writable
if [ ! -d "$acme_storage" ]; then
    error "ACME storage directory does not exist: $acme_storage"
    echo "Create the directory and ensure Elemta has write permissions:"
    echo "  mkdir -p $acme_storage"
    echo "  chown <elemta_user>:<elemta_group> $acme_storage"
elif [ ! -w "$acme_storage" ]; then
    error "ACME storage directory is not writable: $acme_storage"
    echo "Make sure the directory is writable by the Elemta process."
else
    success "ACME storage directory exists and is writable"
fi

# Check if certificates exist
cert_file=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^cert_file" | awk -F '=' '{print $2}' | tr -d ' "')
key_file=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^key_file" | awk -F '=' '{print $2}' | tr -d ' "')

echo "Certificate file: ${cert_file:-not set}"
echo "Private key file: ${key_file:-not set}"

if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
    success "Certificate file exists"
    
    # Check certificate validity
    if command -v openssl &> /dev/null; then
        echo "Certificate details:"
        openssl x509 -in "$cert_file" -noout -subject -issuer -dates
        
        # Check if certificate matches domain
        cert_domain=$(openssl x509 -in "$cert_file" -noout -subject | grep -o "CN = [^ ,]*" | sed 's/CN = //')
        if [[ "$cert_domain" == "$DOMAIN" || "$cert_domain" == "*.$DOMAIN" ]]; then
            success "Certificate domain matches: $cert_domain"
        else
            warning "Certificate domain ($cert_domain) does not match $DOMAIN"
        fi
        
        # Check certificate validity dates
        not_after=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
        not_after_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$not_after" +%s)
        now_epoch=$(date +%s)
        days_left=$(( (not_after_epoch - now_epoch) / 86400 ))
        
        if [ $days_left -lt 0 ]; then
            error "Certificate has EXPIRED!"
        elif [ $days_left -lt 7 ]; then
            warning "Certificate will expire soon (${days_left} days left)"
        else
            success "Certificate is valid for ${days_left} more days"
        fi
    fi
elif [ -n "$cert_file" ]; then
    error "Certificate file does not exist: $cert_file"
fi

if [ -n "$key_file" ] && [ -f "$key_file" ]; then
    success "Private key file exists"
else
    error "Private key file does not exist: $key_file"
fi
echo ""

# Check 5: ACME Account
echo "============================================="
info "Checking ACME account configuration..."
echo "============================================="

acme_email=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_email" | awk -F '=' '{print $2}' | tr -d ' "')
acme_directory=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_directory" | awk -F '=' '{print $2}' | tr -d ' "')

echo "ACME email: ${acme_email:-not set}"
echo "ACME directory: ${acme_directory:-not set (will use default Let's Encrypt production)}"

if [ -z "$acme_email" ]; then
    error "ACME email is not set"
    echo "An email address is required for Let's Encrypt registration."
fi

if [ -n "$acme_directory" ] && [[ "$acme_directory" == *"staging"* ]]; then
    warning "Using Let's Encrypt staging environment"
    echo "Certificates issued from staging will not be trusted by browsers."
    echo "This is normal for testing. Switch to production when ready."
fi
echo ""

# Check 6: Elemta Service Status
echo "============================================="
info "Checking Elemta service status..."
echo "============================================="

elemta_running=false

# Check systemd
if command -v systemctl &> /dev/null && systemctl list-unit-files | grep -q elemta; then
    if systemctl is-active --quiet elemta; then
        success "Elemta systemd service is running"
        elemta_running=true
        echo "Service logs can be viewed with: journalctl -u elemta -f"
    else
        error "Elemta systemd service is not running"
        echo "Start the service with: sudo systemctl start elemta"
    fi
# Check init.d
elif [ -f /etc/init.d/elemta ]; then
    if /etc/init.d/elemta status | grep -q "running"; then
        success "Elemta init.d service is running"
        elemta_running=true
    else
        error "Elemta init.d service is not running"
        echo "Start the service with: sudo /etc/init.d/elemta start"
    fi
# Check Docker
elif command -v docker &> /dev/null; then
    if docker ps | grep -q elemta; then
        success "Elemta Docker container is running"
        elemta_running=true
        echo "Container logs can be viewed with: docker logs -f $(docker ps | grep elemta | awk '{print $1}')"
    elif docker ps -a | grep -q elemta; then
        error "Elemta Docker container exists but is not running"
        echo "Start the container with: docker start $(docker ps -a | grep elemta | awk '{print $1}')"
    else
        warning "No Elemta Docker container found"
    fi
else
    warning "Could not determine how Elemta is running"
    echo "Please check your process list for Elemta processes."
fi

# Check if SMTP ports are open
if $elemta_running; then
    echo ""
    info "Checking if SMTP ports are open..."
    
    # Check port 465 (SMTPS)
    if nc -z localhost 465 2>/dev/null; then
        success "Port 465 (SMTPS) is open"
        
        # Check if TLS is properly configured
        if command -v openssl &> /dev/null; then
            echo ""
            info "Testing TLS on port 465..."
            echo "This will attempt to connect to the SMTP server with TLS."
            echo "Press Enter to continue or Ctrl+C to skip this test."
            read
            
            echo "Q" | openssl s_client -connect localhost:465 -starttls smtp -servername $DOMAIN 2>/dev/null > /tmp/elemta_tls_test
            
            if grep -q "BEGIN CERTIFICATE" /tmp/elemta_tls_test; then
                success "TLS connection successful"
                certificate_info=$(openssl x509 -in /tmp/elemta_tls_test -noout -subject -issuer -dates 2>/dev/null)
                if [ -n "$certificate_info" ]; then
                    echo "Certificate details:"
                    echo "$certificate_info"
                else
                    warning "Could not extract certificate information"
                fi
            else
                error "TLS connection failed"
                echo "Check the Elemta logs for TLS-related errors."
            fi
            
            rm -f /tmp/elemta_tls_test
        fi
    else
        error "Port 465 (SMTPS) is not open"
        echo "Make sure Elemta is configured to listen on port 465 for TLS."
    fi
    
    # Check port 25 (SMTP)
    if nc -z localhost 25 2>/dev/null; then
        success "Port 25 (SMTP) is open"
    else
        warning "Port 25 (SMTP) is not open. This port is optional but commonly used."
    fi
    
    # Check port 587 (Submission)
    if nc -z localhost 587 2>/dev/null; then
        success "Port 587 (Submission) is open"
    else
        warning "Port 587 (Submission) is not open. This port is optional but commonly used for email submission."
    fi
fi
echo ""

# Final summary
echo "============================================="
info "Troubleshooting Summary"
echo "============================================="

echo "Key findings:"
if [ "$tls_enabled" != "true" ]; then
    echo "- TLS is not enabled in the configuration"
fi

if [ "$acme_enabled" != "true" ]; then
    echo "- ACME (Let's Encrypt) is not enabled in the configuration"
fi

if [ -z "$host_ips" ] || ! echo "$host_ips" | grep -q "$server_ip"; then
    echo "- Domain does not point to this server"
fi

if ! nc -z localhost 80 2>/dev/null; then
    echo "- Port 80 is not open locally"
fi

if [ -n "$cert_file" ] && [ ! -f "$cert_file" ]; then
    echo "- Certificate file does not exist"
fi

if [ -n "$key_file" ] && [ ! -f "$key_file" ]; then
    echo "- Private key file does not exist"
fi

if ! $elemta_running; then
    echo "- Elemta service is not running"
fi

echo ""
echo "For detailed Let's Encrypt troubleshooting, check the Elemta logs:"
if command -v journalctl &> /dev/null && systemctl list-unit-files | grep -q elemta; then
    echo "  journalctl -u elemta -f | grep -i 'tls\\|acme\\|certificate'"
elif command -v docker &> /dev/null && docker ps | grep -q elemta; then
    echo "  docker logs -f $(docker ps | grep elemta | awk '{print $1}') | grep -i 'tls\\|acme\\|certificate'"
else
    echo "  Check your system's log files or Elemta's configured log location"
fi

echo ""
echo "For more information, see the documentation at:"
echo "  https://github.com/elemta/elemta/blob/main/docs/letsencrypt-guide.md"
echo ""
