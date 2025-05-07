#!/bin/bash
# Elemta Let's Encrypt Setup Script
# This script automates the setup of Let's Encrypt for Elemta SMTP server

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root or with sudo"
    exit 1
fi

echo "============================================="
echo "    Elemta Let's Encrypt Setup Script"
echo "============================================="
echo ""
info "This script will set up Let's Encrypt for your Elemta SMTP server."
echo ""

# Check for required tools
for cmd in curl dig openssl grep sed; do
    if ! command -v $cmd &> /dev/null; then
        error "$cmd is required but not installed. Please install it and try again."
        exit 1
    fi
done

# Find Elemta configuration file
config_file=""
possible_paths=(
    "/etc/elemta/elemta.toml"
    "/var/elemta/config/elemta.toml"
    "./elemta.toml"
)

for path in "${possible_paths[@]}"; do
    if [ -f "$path" ]; then
        config_file="$path"
        success "Found Elemta configuration at $config_file"
        break
    fi
done

if [ -z "$config_file" ]; then
    error "Could not find Elemta configuration file."
    read -p "Please enter the full path to your elemta.toml file: " config_file
    if [ ! -f "$config_file" ]; then
        error "Invalid file path. Exiting."
        exit 1
    fi
fi

# Check if config file is writable
if [ ! -w "$config_file" ]; then
    error "Configuration file $config_file is not writable."
    exit 1
fi

# Prompt for domain name
read -p "Enter your domain name (e.g., mail.example.com): " domain_name
if [ -z "$domain_name" ]; then
    error "Domain name cannot be empty"
    exit 1
fi

# Verify domain resolves to this server
info "Verifying DNS for $domain_name..."
server_ip=$(curl -s ifconfig.me)
domain_ip=$(dig +short $domain_name)

if [ -z "$domain_ip" ]; then
    warning "Could not resolve DNS for $domain_name"
    echo "Please ensure your domain is properly configured to point to this server."
    read -p "Do you want to continue anyway? (y/n): " continue_anyway
    if [ "$continue_anyway" != "y" ]; then
        exit 1
    fi
elif [ "$domain_ip" != "$server_ip" ]; then
    warning "Domain $domain_name resolves to $domain_ip, but this server's IP is $server_ip"
    echo "Let's Encrypt validation may fail if the domain doesn't point to this server."
    read -p "Do you want to continue anyway? (y/n): " continue_anyway
    if [ "$continue_anyway" != "y" ]; then
        exit 1
    fi
else
    success "Domain $domain_name correctly resolves to this server ($server_ip)"
fi

# Prompt for email address
read -p "Enter your email address (for Let's Encrypt notifications): " email_address
if [ -z "$email_address" ]; then
    error "Email address cannot be empty"
    exit 1
fi

# Check if email address is valid
if ! echo "$email_address" | grep -E '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' &> /dev/null; then
    warning "Email address $email_address doesn't appear to be valid"
    read -p "Do you want to continue anyway? (y/n): " continue_anyway
    if [ "$continue_anyway" != "y" ]; then
        exit 1
    fi
fi

# Check if port 80 is available
info "Checking if port 80 is available..."
if nc -z localhost 80 2>/dev/null; then
    warning "Port 80 is already in use by another service"
    echo "Let's Encrypt requires port 80 for domain validation."
    read -p "Do you want to continue anyway? (y/n): " continue_anyway
    if [ "$continue_anyway" != "y" ]; then
        exit 1
    fi
else
    success "Port 80 is available"
fi

# Create certificates directory
cert_dir="/var/elemta/certs"
info "Creating certificate storage directory at $cert_dir..."
mkdir -p "$cert_dir"
chmod 755 "$cert_dir"
success "Created certificate directory"

# Ask about staging environment
read -p "Do you want to use Let's Encrypt staging environment for testing? (y/n, default: n): " use_staging
use_staging=${use_staging:-n}

if [ "$use_staging" = "y" ]; then
    acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory"
    warning "Using Let's Encrypt staging environment - certificates won't be trusted by clients"
else
    acme_directory="https://acme-v02.api.letsencrypt.org/directory"
    info "Using Let's Encrypt production environment"
fi

# Update configuration file
info "Updating Elemta configuration..."

# Check if [tls] section exists
if ! grep -q '^\[tls\]' "$config_file"; then
    echo "" >> "$config_file"
    echo "[tls]" >> "$config_file"
    success "Added [tls] section to configuration"
fi

# Function to add or update a configuration entry
update_config() {
    local section=$1
    local key=$2
    local value=$3
    local config=$4
    
    # Escape any / characters in the value for sed
    value=$(echo "$value" | sed 's/\//\\\//g')
    
    # Check if key exists in section
    if grep -A 50 "^\[$section\]" "$config" | grep -m 1 -q "^$key[[:space:]]*="; then
        # Update existing key
        sed -i "/^\[$section\]/,/^\[.*\]/ s/^$key[[:space:]]*=.*/$key = \"$value\"/" "$config"
    else
        # Add new key at the end of the section
        # Find the line number of the section header
        section_line=$(grep -n "^\[$section\]" "$config" | cut -d: -f1)
        
        # Find the line number of the next section header or the end of file
        next_section_line=$(tail -n +$((section_line + 1)) "$config" | grep -n "^\[.*\]" | head -1 | cut -d: -f1)
        
        if [ -z "$next_section_line" ]; then
            # No next section, append to end of file
            echo "$key = \"$value\"" >> "$config"
        else
            # Calculate insertion point
            insertion_line=$((section_line + next_section_line - 1))
            # Insert the new key before the next section
            sed -i "$insertion_line i $key = \"$value\"" "$config"
        fi
    fi
}

# Update TLS settings
update_config "tls" "enabled" "true" "$config_file"
update_config "tls" "listen_addr" ":465" "$config_file"
update_config "tls" "starttls_enabled" "true" "$config_file"

# Update Let's Encrypt settings
update_config "tls" "acme_enabled" "true" "$config_file"
update_config "tls" "acme_email" "$email_address" "$config_file"
update_config "tls" "acme_domain" "$domain_name" "$config_file"
update_config "tls" "acme_directory" "$acme_directory" "$config_file"

# Update ACME challenge settings
update_config "tls" "endpoint_port" "80" "$config_file"
update_config "tls" "endpoint_path" "/.well-known/acme-challenge/" "$config_file"
update_config "tls" "acme_storage_path" "$cert_dir" "$config_file"

# Update renewal settings
update_config "tls" "auto_renew" "true" "$config_file"
update_config "tls" "renewal_days" "30" "$config_file"
update_config "tls" "check_interval" "24h" "$config_file"

success "Updated Elemta configuration with Let's Encrypt settings"

# Configure firewall if UFW or firewalld is available
if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    info "Configuring UFW firewall..."
    ufw allow 80/tcp
    ufw allow 465/tcp
    ufw allow 587/tcp
    success "Updated firewall rules"
elif command -v firewall-cmd &> /dev/null && firewall-cmd --state &> /dev/null; then
    info "Configuring firewalld..."
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=465/tcp
    firewall-cmd --permanent --add-port=587/tcp
    firewall-cmd --reload
    success "Updated firewall rules"
else
    warning "No supported firewall detected. Please ensure ports 80, 465, and 587 are open."
fi

# Ask to restart Elemta
read -p "Do you want to restart Elemta to apply the changes? (y/n): " restart_elemta
if [ "$restart_elemta" = "y" ]; then
    info "Restarting Elemta..."
    
    # Try different methods to restart
    if systemctl is-active --quiet elemta; then
        systemctl restart elemta
        success "Restarted Elemta using systemd"
    elif [ -f /etc/init.d/elemta ]; then
        /etc/init.d/elemta restart
        success "Restarted Elemta using init script"
    elif docker ps | grep -q elemta; then
        docker restart $(docker ps | grep elemta | awk '{print $1}')
        success "Restarted Elemta Docker container"
    else
        warning "Could not automatically restart Elemta. Please restart it manually."
    fi
fi

echo ""
echo "============================================="
echo "    Setup Complete"
echo "============================================="
echo ""
success "Let's Encrypt integration has been configured for Elemta"
echo ""
info "Your settings:"
echo "  Domain: $domain_name"
echo "  Email: $email_address"
echo "  Certificate storage: $cert_dir"
echo "  Using staging: $([ "$use_staging" = "y" ] && echo "Yes" || echo "No")"
echo ""
info "Next steps:"
echo "  1. Make sure port 80 is accessible from the internet"
echo "  2. Restart Elemta if you haven't already"
echo "  3. Check logs to verify certificate issuance"
echo ""
info "For more information, see the documentation at:"
echo "  https://github.com/elemta/elemta/blob/main/docs/letsencrypt-guide.md"
echo "" 