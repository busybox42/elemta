#!/bin/bash

# ANSI color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default values
CONFIG_FILE="/etc/elemta/elemta.toml"
DOMAIN=""
VERBOSE=false
DEBUG=false
TEST_CONNECTIVITY=true
VERIFY_CERTS=true
SKIP_PROMPTS=false
TLS_TEST_PORTS=("465" "587" "25")

# Usage function
function show_usage() {
    echo -e "${BOLD}Usage:${NC} $0 [OPTIONS]"
    echo -e ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  -c, --config FILE    Specify the Elemta configuration file path"
    echo -e "  -d, --domain DOMAIN  Specify the domain to test"
    echo -e "  -v, --verbose        Enable verbose output"
    echo -e "  --debug              Enable debug mode with extra details"
    echo -e "  --no-connectivity    Skip connectivity tests"
    echo -e "  --no-verify          Skip certificate verification"
    echo -e "  -y, --yes            Skip all prompts (non-interactive mode)"
    echo -e "  -h, --help           Show this help message"
    echo -e ""
    echo -e "${BOLD}Example:${NC}"
    echo -e "  $0 --domain mail.example.com --config /etc/elemta/elemta.toml --verbose"
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -c|--config) CONFIG_FILE="$2"; shift ;;
        -d|--domain) DOMAIN="$2"; shift ;;
        -v|--verbose) VERBOSE=true ;;
        --debug) DEBUG=true; VERBOSE=true ;;
        --no-connectivity) TEST_CONNECTIVITY=false ;;
        --no-verify) VERIFY_CERTS=false ;;
        -y|--yes) SKIP_PROMPTS=true ;;
        -h|--help) show_usage; exit 0 ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
    esac
    shift
done

# Helper functions for logging
function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function log_debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "${MAGENTA}[DEBUG]${NC} $1"
    fi
}

function log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Check if we're running as root
function check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_warning "Not running as root. Some tests may fail due to permission issues."
        if [ "$SKIP_PROMPTS" = false ]; then
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
        log_debug "Running as root."
    fi
}

# Check for required tools
function check_required_tools() {
    local missing_tools=()
    
    for tool in curl dig openssl nc grep sed jq timeout; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Required tools are missing: ${missing_tools[*]}"
        log_info "Please install the missing tools and try again."
        
        # Suggest installation commands for common distributions
        if command -v apt-get &> /dev/null; then
            echo -e "For Debian/Ubuntu, try: ${YELLOW}sudo apt-get install curl dnsutils openssl netcat grep sed jq${NC}"
        elif command -v yum &> /dev/null; then
            echo -e "For CentOS/RHEL, try: ${YELLOW}sudo yum install curl bind-utils openssl nc grep sed jq${NC}"
        elif command -v pacman &> /dev/null; then
            echo -e "For Arch Linux, try: ${YELLOW}sudo pacman -S curl bind openssl gnu-netcat grep sed jq${NC}"
        fi
        
        exit 1
    else
        log_debug "All required tools are available."
    fi
}

# Validate the configuration file
function validate_config_file() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        
        # Check for common locations
        local potential_configs=("/etc/elemta/elemta.toml" "/var/elemta/config/elemta.toml" "./elemta.toml")
        local found_configs=()
        
        for config in "${potential_configs[@]}"; do
            if [ -f "$config" ]; then
                found_configs+=("$config")
            fi
        done
        
        if [ ${#found_configs[@]} -gt 0 ]; then
            log_info "Found potential configuration files:"
            for config in "${found_configs[@]}"; do
                echo "  - $config"
            done
            
            if [ "$SKIP_PROMPTS" = false ]; then
                echo -n "Would you like to use one of these instead? (y/n) "
                read -r response
                if [[ "$response" =~ ^[Yy]$ ]]; then
                    echo "Enter the number of the configuration file to use:"
                    select config in "${found_configs[@]}"; do
                        if [ -n "$config" ]; then
                            CONFIG_FILE="$config"
                            log_info "Using configuration file: $CONFIG_FILE"
                            break
                        fi
                    done
                else
                    exit 1
                fi
            else
                CONFIG_FILE="${found_configs[0]}"
                log_info "Automatically selecting configuration file: $CONFIG_FILE"
            fi
        else
            exit 1
        fi
    fi
    
    if [ ! -r "$CONFIG_FILE" ]; then
        log_error "Cannot read configuration file: $CONFIG_FILE"
        exit 1
    fi
    
    log_success "Configuration file is valid and readable: $CONFIG_FILE"
}

# Extract domain from configuration if not provided
function extract_domain() {
    if [ -z "$DOMAIN" ]; then
        # Try to extract domain from configuration
        local acme_domain=$(grep -E "^[[:space:]]*domain[[:space:]]*=" "$CONFIG_FILE" | sed -E 's/^[[:space:]]*domain[[:space:]]*=[[:space:]]*"?([^"]*)"?/\1/')
        local hostname=$(grep -E "^[[:space:]]*hostname[[:space:]]*=" "$CONFIG_FILE" | sed -E 's/^[[:space:]]*hostname[[:space:]]*=[[:space:]]*"?([^"]*)"?/\1/')
        
        if [ -n "$acme_domain" ]; then
            DOMAIN="$acme_domain"
            log_info "Found domain in ACME configuration: $DOMAIN"
        elif [ -n "$hostname" ]; then
            DOMAIN="$hostname"
            log_info "Found hostname in configuration: $DOMAIN"
        else
            log_error "Domain not specified and couldn't be extracted from configuration"
            
            if [ "$SKIP_PROMPTS" = false ]; then
                echo -n "Please enter the domain name: "
                read -r DOMAIN
                if [ -z "$DOMAIN" ]; then
                    log_error "Domain is required."
                    exit 1
                fi
            else
                exit 1
            fi
        fi
    fi
    
    # Validate domain format
    if ! echo "$DOMAIN" | grep -qE '^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
        log_error "Invalid domain format: $DOMAIN"
        exit 1
    fi
    
    log_success "Using domain: $DOMAIN"
}

# Check DNS resolution
function check_dns() {
    log_step "Checking DNS resolution for $DOMAIN..."
    
    local ip_addresses=$(dig +short A "$DOMAIN")
    local server_ip=$(curl -s https://api.ipify.org || curl -s http://ifconfig.me)
    
    if [ -z "$ip_addresses" ]; then
        log_error "Domain $DOMAIN does not resolve to any IP address"
        log_info "Please check your DNS configuration and make sure the A record is properly set"
        return 1
    else
        log_info "Domain $DOMAIN resolves to the following IP address(es):"
        echo "$ip_addresses" | while read -r ip; do
            echo "  - $ip"
        done
        
        # Check if any of the resolved IPs match the server IP
        if echo "$ip_addresses" | grep -q "$server_ip"; then
            log_success "Domain correctly points to this server's IP address ($server_ip)"
        else
            log_warning "Domain does not point to this server's IP address ($server_ip)"
            log_info "This may cause issues with Let's Encrypt verification"
            
            if [ "$SKIP_PROMPTS" = false ]; then
                echo -n "Continue anyway? (y/n) "
                read -r response
                if [[ ! "$response" =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
        fi
    fi
    
    # Check CAA records
    log_info "Checking CAA records for $DOMAIN..."
    local caa_records=$(dig +short CAA "$DOMAIN")
    
    if [ -z "$caa_records" ]; then
        log_info "No CAA records found. This is not an issue."
    else
        log_info "CAA records found:"
        echo "$caa_records" | while read -r record; do
            echo "  - $record"
        done
        
        # Check if Let's Encrypt is allowed
        if ! echo "$caa_records" | grep -q "letsencrypt.org"; then
            log_warning "No CAA record allowing Let's Encrypt found"
            log_info "This may prevent Let's Encrypt from issuing certificates for your domain"
            log_info "Consider adding a CAA record: '0 issue \"letsencrypt.org\"'"
        else
            log_success "CAA records allow Let's Encrypt to issue certificates"
        fi
    fi
}

# Check ACME HTTP-01 challenge port (80)
function check_http_challenge_port() {
    log_step "Checking if HTTP challenge port (80) is accessible..."
    
    # Check if port 80 is open locally
    if nc -z localhost 80 2>/dev/null; then
        log_info "Port 80 is open locally"
        
        # Check what service is using port 80
        local service=$(sudo netstat -tlnp 2>/dev/null | grep ":80 " || echo "Unknown")
        log_info "Service using port 80: $service"
        
        # Check if it's Elemta or another web server
        if echo "$service" | grep -qi "elemta"; then
            log_success "Elemta is listening on port 80, which is correct for HTTP challenges"
        else
            log_warning "Another service is using port 80, which may interfere with HTTP challenges"
            log_info "Consider temporarily stopping the service during certificate renewal"
        fi
    else
        log_warning "Port 80 is not open locally"
        log_info "HTTP challenges will fail unless Elemta can bind to port 80 during verification"
    fi
    
    # Check if port 80 is reachable from the outside
    if [ "$TEST_CONNECTIVITY" = true ]; then
        log_info "Testing if port 80 is reachable from outside..."
        
        # Use an external service to check port 80
        local external_check=$(curl -s "https://check-host.net/check-http?host=$DOMAIN" -H "Accept: application/json")
        
        if [ -n "$external_check" ] && [ "$external_check" != "null" ]; then
            log_success "Port 80 appears to be reachable from outside"
        else
            log_warning "Port 80 may not be reachable from outside"
            log_info "This may cause Let's Encrypt verification to fail"
            log_info "Please check your firewall and router configurations"
        fi
    fi
}

# Check TLS configuration
function check_tls_config() {
    log_step "Checking TLS configuration in Elemta config..."
    
    # Check if TLS is enabled
    local tls_enabled=$(grep -E "^[[:space:]]*enabled[[:space:]]*=" "$CONFIG_FILE" | grep -A 3 -B 3 "\[tls\]" | sed -E 's/^[[:space:]]*enabled[[:space:]]*=[[:space:]]*([^[:space:]]*)[[:space:]]*/\1/')
    
    if [ "$tls_enabled" = "true" ]; then
        log_success "TLS is enabled in the configuration"
    else
        log_error "TLS is not enabled in the configuration"
        log_info "Add or modify the [tls] section in $CONFIG_FILE to include 'enabled = true'"
        return 1
    fi
    
    # Check certificate and key file paths
    local cert_file=$(grep -E "^[[:space:]]*cert_file[[:space:]]*=" "$CONFIG_FILE" | grep -A 10 -B 10 "\[tls\]" | sed -E 's/^[[:space:]]*cert_file[[:space:]]*=[[:space:]]*"?([^"]*)"?/\1/')
    local key_file=$(grep -E "^[[:space:]]*key_file[[:space:]]*=" "$CONFIG_FILE" | grep -A 10 -B 10 "\[tls\]" | sed -E 's/^[[:space:]]*key_file[[:space:]]*=[[:space:]]*"?([^"]*)"?/\1/')
    
    log_info "Certificate file: $cert_file"
    log_info "Key file: $key_file"
    
    # Check if the files exist
    if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
        log_success "Certificate file exists"
    else
        log_error "Certificate file does not exist: $cert_file"
    fi
    
    if [ -n "$key_file" ] && [ -f "$key_file" ]; then
        log_success "Key file exists"
    else
        log_error "Key file does not exist: $key_file"
    fi
    
    # Check ACME configuration
    local acme_enabled=$(grep -E "^[[:space:]]*auto_renew[[:space:]]*=" "$CONFIG_FILE" | grep -A 10 -B 10 "\[tls\]" | sed -E 's/^[[:space:]]*auto_renew[[:space:]]*=[[:space:]]*([^[:space:]]*)[[:space:]]*/\1/')
    
    if [ "$acme_enabled" = "true" ]; then
        log_success "Automatic certificate renewal is enabled"
        
        # Check ACME email
        local acme_email=$(grep -E "^[[:space:]]*email[[:space:]]*=" "$CONFIG_FILE" | grep -A 20 -B 10 "\[tls\]" | sed -E 's/^[[:space:]]*email[[:space:]]*=[[:space:]]*"?([^"]*)"?/\1/')
        
        if [ -n "$acme_email" ]; then
            log_success "ACME email is configured: $acme_email"
        else
            log_warning "ACME email is not configured"
            log_info "It's recommended to set an email address for important notifications"
        fi
    else
        log_warning "Automatic certificate renewal is not enabled"
        log_info "Consider enabling auto_renew in the [tls] section for automatic certificate management"
    fi
}

# Check certificate details
function check_certificate() {
    if [ "$VERIFY_CERTS" != true ]; then
        log_info "Skipping certificate verification as requested"
        return 0
    fi
    
    log_step "Checking certificate details..."
    
    # Get certificate file path from config
    local cert_file=$(grep -E "^[[:space:]]*cert_file[[:space:]]*=" "$CONFIG_FILE" | grep -A 10 -B 10 "\[tls\]" | sed -E 's/^[[:space:]]*cert_file[[:space:]]*=[[:space:]]*"?([^"]*)"?/\1/')
    
    if [ -z "$cert_file" ] || [ ! -f "$cert_file" ]; then
        log_error "Cannot find certificate file"
        return 1
    fi
    
    # Check certificate validity
    log_info "Certificate information:"
    openssl x509 -in "$cert_file" -noout -text | grep -E "Subject:|Issuer:|Not Before:|Not After :|DNS:" | while read -r line; do
        echo "  $line"
    done
    
    # Check expiration
    local expiry=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    local expiry_date=$(date -d "$expiry" +%s)
    local current_date=$(date +%s)
    local days_remaining=$(( (expiry_date - current_date) / 86400 ))
    
    log_info "Certificate expires on: $expiry ($days_remaining days remaining)"
    
    if [ $days_remaining -lt 0 ]; then
        log_error "Certificate has expired!"
    elif [ $days_remaining -lt 7 ]; then
        log_error "Certificate will expire very soon (less than 7 days)"
    elif [ $days_remaining -lt 30 ]; then
        log_warning "Certificate will expire in less than 30 days"
    else
        log_success "Certificate is valid for more than 30 days"
    fi
    
    # Check domain match
    local cert_domain=$(openssl x509 -in "$cert_file" -noout -text | grep -oP "DNS:[a-zA-Z0-9.-]*" | sed 's/DNS://g' | head -1)
    
    if [ "$cert_domain" = "$DOMAIN" ]; then
        log_success "Certificate domain matches the configured domain"
    else
        log_warning "Certificate domain ($cert_domain) does not match the configured domain ($DOMAIN)"
    fi
    
    # Check issuer
    local issuer=$(openssl x509 -in "$cert_file" -noout -issuer)
    
    if echo "$issuer" | grep -q "Let's Encrypt"; then
        log_success "Certificate was issued by Let's Encrypt"
        
        # Check if it's a staging certificate
        if echo "$issuer" | grep -q "Fake LE"; then
            log_warning "This is a staging (test) certificate from Let's Encrypt"
            log_info "For production use, you should obtain a real certificate"
        fi
    else
        log_info "Certificate was not issued by Let's Encrypt: $issuer"
    fi
}

# Check TLS connection
function check_tls_connection() {
    if [ "$TEST_CONNECTIVITY" != true ]; then
        log_info "Skipping connectivity tests as requested"
        return 0
    fi
    
    log_step "Testing TLS connections to SMTP ports..."
    
    for port in "${TLS_TEST_PORTS[@]}"; do
        log_info "Testing SMTP connection to $DOMAIN:$port..."
        
        # Try to establish a connection
        if timeout 5 nc -z "$DOMAIN" "$port" 2>/dev/null; then
            log_success "Port $port is open"
            
            # Test STARTTLS for port 25 and 587
            if [ "$port" = "25" ] || [ "$port" = "587" ]; then
                log_info "Testing STARTTLS capability on port $port..."
                
                local starttls_output=$(timeout 5 openssl s_client -connect "$DOMAIN:$port" -starttls smtp 2>/dev/null)
                
                if echo "$starttls_output" | grep -q "BEGIN CERTIFICATE"; then
                    log_success "STARTTLS is working on port $port"
                else
                    log_error "STARTTLS is not working properly on port $port"
                fi
            fi
            
            # Test direct TLS for port 465
            if [ "$port" = "465" ]; then
                log_info "Testing direct TLS on port 465..."
                
                local tls_output=$(timeout 5 openssl s_client -connect "$DOMAIN:465" 2>/dev/null)
                
                if echo "$tls_output" | grep -q "BEGIN CERTIFICATE"; then
                    log_success "Direct TLS is working on port 465"
                else
                    log_error "Direct TLS is not working properly on port 465"
                fi
            fi
        else
            log_warning "Port $port is not open or not reachable"
        fi
    done
}

# Recommend fixes for common issues
function provide_recommendations() {
    log_step "Recommendations and next steps:"
    
    # Check status file to see what issues were found
    local recommendations=()
    
    # DNS recommendations
    if ! dig +short A "$DOMAIN" | grep -q "$(curl -s https://api.ipify.org || curl -s http://ifconfig.me)"; then
        recommendations+=("Update your DNS A record for $DOMAIN to point to this server's IP address")
    fi
    
    # Port 80 recommendations
    if ! nc -z localhost 80 2>/dev/null; then
        recommendations+=("Configure your firewall to allow inbound traffic on port 80 for Let's Encrypt verification")
        recommendations+=("Ensure no other service is using port 80 during certificate issuance")
    fi
    
    # TLS config recommendations
    local tls_enabled=$(grep -E "^[[:space:]]*enabled[[:space:]]*=" "$CONFIG_FILE" | grep -A 3 -B 3 "\[tls\]" | sed -E 's/^[[:space:]]*enabled[[:space:]]*=[[:space:]]*([^[:space:]]*)[[:space:]]*/\1/')
    if [ "$tls_enabled" != "true" ]; then
        recommendations+=("Enable TLS in your Elemta configuration by setting 'enabled = true' in the [tls] section")
    fi
    
    local acme_enabled=$(grep -E "^[[:space:]]*auto_renew[[:space:]]*=" "$CONFIG_FILE" | grep -A 10 -B 10 "\[tls\]" | sed -E 's/^[[:space:]]*auto_renew[[:space:]]*=[[:space:]]*([^[:space:]]*)[[:space:]]*/\1/')
    if [ "$acme_enabled" != "true" ]; then
        recommendations+=("Enable automatic certificate renewal by setting 'auto_renew = true' in the [tls] section")
    fi
    
    # Display recommendations
    if [ ${#recommendations[@]} -eq 0 ]; then
        log_success "No critical issues found. Your Let's Encrypt setup appears to be working correctly."
    else
        log_info "Based on the tests, we recommend the following actions:"
        for i in "${!recommendations[@]}"; do
            echo -e "${YELLOW}$(($i+1))${NC}. ${recommendations[$i]}"
        done
    fi
    
    # Display helpful commands
    echo
    log_info "Helpful commands:"
    echo -e "  ${CYAN}View certificate details:${NC} openssl x509 -in <cert_file> -text -noout"
    echo -e "  ${CYAN}Test SMTP STARTTLS:${NC} openssl s_client -connect $DOMAIN:587 -starttls smtp"
    echo -e "  ${CYAN}Test direct TLS:${NC} openssl s_client -connect $DOMAIN:465"
    echo -e "  ${CYAN}Check port 80 status:${NC} curl -vI http://$DOMAIN"
    echo -e "  ${CYAN}Test DNS resolution:${NC} dig +short A $DOMAIN"
}

# Main function
function main() {
    echo -e "${BOLD}${CYAN}===== Elemta Let's Encrypt Configuration Tester =====${NC}"
    echo
    
    check_root
    check_required_tools
    validate_config_file
    extract_domain
    
    echo
    log_step "Running tests for $DOMAIN using config file $CONFIG_FILE"
    echo
    
    check_dns
    check_http_challenge_port
    check_tls_config
    check_certificate
    check_tls_connection
    
    echo
    provide_recommendations
    
    echo
    log_info "Test completed on $(date)"
}

# Execute main function
main
