#!/bin/bash

# Let's Encrypt Admin Script for Elemta
# This script provides a unified interface for common Let's Encrypt certificate management operations

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default settings
CONFIG_FILE=""
DOMAIN=""
ACTION=""
BACKUP_DIR="/var/elemta/certs/backups"
CERT_DIR="/var/elemta/certs"
FORCE=false

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

# Show usage information
function show_usage {
    echo "Usage: $0 <action> [options]"
    echo ""
    echo "Actions:"
    echo "  issue            Request a new certificate for a domain"
    echo "  renew            Force renewal of an existing certificate"
    echo "  backup           Backup current certificates"
    echo "  restore          Restore certificates from backup"
    echo "  switch           Switch to a different domain"
    echo "  status           Show certificate status"
    echo "  revoke           Revoke a certificate"
    echo "  list-backups     List available backups"
    echo "  help             Show this help message"
    echo ""
    echo "Options:"
    echo "  -c, --config FILE       Path to elemta.toml configuration file"
    echo "  -d, --domain DOMAIN     Domain name for the certificate"
    echo "  -b, --backup-dir DIR    Backup directory (default: /var/elemta/certs/backups)"
    echo "  -f, --force             Force the operation without confirmation"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 issue -d mail.example.com"
    echo "  $0 renew -c /etc/elemta/elemta.toml"
    echo "  $0 backup -d mail.example.com"
    echo "  $0 restore -d mail.example.com -b /path/to/backup"
    echo "  $0 switch -d new.example.com -c /etc/elemta/elemta.toml"
    echo "  $0 status -d mail.example.com"
    exit 1
}

# Process command line arguments
if [ $# -eq 0 ]; then
    show_usage
fi

ACTION="$1"
shift

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
        -b|--backup-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        -*)
            error "Unknown option: $1"
            show_usage
            ;;
        *)
            error "Unknown argument: $1"
            show_usage
            ;;
    esac
done

# Find configuration file if not specified
if [ -z "$CONFIG_FILE" ]; then
    for path in "/etc/elemta/elemta.toml" "/var/elemta/config/elemta.toml" "./elemta.toml"; do
        if [ -f "$path" ]; then
            CONFIG_FILE="$path"
            info "Using configuration file: $CONFIG_FILE"
            break
        fi
    done
    
    if [ -z "$CONFIG_FILE" ]; then
        error "Could not find Elemta configuration file"
        echo "Please specify a configuration file with -c or --config"
        exit 1
    fi
fi

# Extract domain from config if not specified
if [ -z "$DOMAIN" ] && [ -f "$CONFIG_FILE" ]; then
    DOMAIN=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_domain" | awk -F '=' '{print $2}' | tr -d ' "')
    if [ -n "$DOMAIN" ]; then
        info "Using domain from config: $DOMAIN"
    else
        # Try to get hostname from server section
        DOMAIN=$(grep -A 50 '^\[server\]' "$CONFIG_FILE" | grep -m 1 "^hostname" | awk -F '=' '{print $2}' | tr -d ' "')
        if [ -n "$DOMAIN" ]; then
            info "Using hostname from config: $DOMAIN"
        fi
    fi
fi

# Create backup directory if it doesn't exist
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    if [ $? -ne 0 ]; then
        error "Failed to create backup directory: $BACKUP_DIR"
        exit 1
    fi
    success "Created backup directory: $BACKUP_DIR"
fi

# Extract certificate paths from configuration
cert_file=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^cert_file" | awk -F '=' '{print $2}' | tr -d ' "')
key_file=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^key_file" | awk -F '=' '{print $2}' | tr -d ' "')
acme_storage=$(grep -A 50 '^\[tls\]' "$CONFIG_FILE" | grep -m 1 "^acme_storage_path" | awk -F '=' '{print $2}' | tr -d ' "')

# Use default paths if not found in config
if [ -z "$cert_file" ]; then
    cert_file="$CERT_DIR/$DOMAIN.crt"
fi

if [ -z "$key_file" ]; then
    key_file="$CERT_DIR/$DOMAIN.key"
fi

if [ -z "$acme_storage" ]; then
    acme_storage="$CERT_DIR/acme"
fi

# Check if Elemta CLI is available
elemta_cli_available=false
if command -v elemta &> /dev/null; then
    elemta_cli_available=true
    info "Elemta CLI is available"
else
    warning "Elemta CLI is not available, some operations may be limited"
fi

# Function to backup certificates
function backup_certificates {
    local timestamp=$(date +%Y%m%d%H%M%S)
    local backup_path="$BACKUP_DIR/${DOMAIN}_$timestamp"
    
    info "Backing up certificates for $DOMAIN to $backup_path"
    
    # Create backup directory
    mkdir -p "$backup_path"
    if [ $? -ne 0 ]; then
        error "Failed to create backup directory: $backup_path"
        return 1
    fi
    
    # Copy certificate files
    if [ -f "$cert_file" ]; then
        cp "$cert_file" "$backup_path/"
        success "Backed up certificate: $cert_file"
    else
        warning "Certificate file not found: $cert_file"
    fi
    
    if [ -f "$key_file" ]; then
        cp "$key_file" "$backup_path/"
        success "Backed up private key: $key_file"
    else
        warning "Private key file not found: $key_file"
    fi
    
    # Backup ACME account data
    if [ -d "$acme_storage" ]; then
        mkdir -p "$backup_path/acme"
        cp -r "$acme_storage"/* "$backup_path/acme/" 2>/dev/null
        success "Backed up ACME account data: $acme_storage"
    else
        warning "ACME storage directory not found: $acme_storage"
    fi
    
    # Create metadata file
    cat > "$backup_path/metadata.txt" << EOF
Domain: $DOMAIN
Certificate: $cert_file
Private Key: $key_file
ACME Storage: $acme_storage
Date: $(date)
Configuration: $CONFIG_FILE
EOF
    
    success "Backup completed: $backup_path"
    return 0
}

# Function to restore certificates
function restore_certificates {
    local backup_path=""
    
    # Find the latest backup for the domain if not specified
    if [ -z "$1" ]; then
        backup_path=$(find "$BACKUP_DIR" -type d -name "${DOMAIN}_*" | sort -r | head -1)
        if [ -z "$backup_path" ]; then
            error "No backup found for domain: $DOMAIN"
            return 1
        fi
        info "Using latest backup: $backup_path"
    else
        backup_path="$1"
    fi
    
    # Check if backup exists
    if [ ! -d "$backup_path" ]; then
        error "Backup directory not found: $backup_path"
        return 1
    fi
    
    # Verify backup metadata
    if [ -f "$backup_path/metadata.txt" ]; then
        info "Backup metadata:"
        cat "$backup_path/metadata.txt"
    else
        warning "No metadata found in backup, this may not be a valid backup"
        if [ "$FORCE" != "true" ]; then
            read -p "Continue anyway? (y/n): " continue_restore
            if [ "$continue_restore" != "y" ]; then
                info "Restore cancelled"
                return 1
            fi
        fi
    fi
    
    # Create backup of current certificates
    if [ "$FORCE" != "true" ]; then
        info "Creating backup of current certificates before restoring"
        backup_certificates
    fi
    
    # Restore certificate files
    cert_basename=$(basename "$cert_file")
    key_basename=$(basename "$key_file")
    
    if [ -f "$backup_path/$cert_basename" ]; then
        mkdir -p "$(dirname "$cert_file")"
        cp "$backup_path/$cert_basename" "$cert_file"
        success "Restored certificate to: $cert_file"
    elif [ -f "$backup_path/$(basename "$cert_file")" ]; then
        mkdir -p "$(dirname "$cert_file")"
        cp "$backup_path/$(basename "$cert_file")" "$cert_file"
        success "Restored certificate to: $cert_file"
    else
        warning "Certificate file not found in backup"
    fi
    
    if [ -f "$backup_path/$key_basename" ]; then
        mkdir -p "$(dirname "$key_file")"
        cp "$backup_path/$key_basename" "$key_file"
        success "Restored private key to: $key_file"
    elif [ -f "$backup_path/$(basename "$key_file")" ]; then
        mkdir -p "$(dirname "$key_file")"
        cp "$backup_path/$(basename "$key_file")" "$key_file"
        success "Restored private key to: $key_file"
    else
        warning "Private key file not found in backup"
    fi
    
    # Restore ACME account data
    if [ -d "$backup_path/acme" ]; then
        mkdir -p "$acme_storage"
        cp -r "$backup_path/acme/"* "$acme_storage/" 2>/dev/null
        success "Restored ACME account data to: $acme_storage"
    else
        warning "ACME account data not found in backup"
    fi
    
    success "Restore completed from: $backup_path"
    
    # Ask to restart Elemta
    if [ "$FORCE" != "true" ]; then
        read -p "Restart Elemta to apply changes? (y/n): " restart_elemta
        if [ "$restart_elemta" = "y" ]; then
            restart_elemta_service
        fi
    fi
    
    return 0
}

# Function to restart Elemta
function restart_elemta_service {
    info "Attempting to restart Elemta"
    
    if command -v systemctl &> /dev/null && systemctl list-unit-files | grep -q elemta; then
        systemctl restart elemta
        if systemctl is-active --quiet elemta; then
            success "Successfully restarted Elemta systemd service"
            return 0
        else
            error "Failed to restart Elemta systemd service"
            return 1
        fi
    elif [ -f /etc/init.d/elemta ]; then
        /etc/init.d/elemta restart
        if /etc/init.d/elemta status | grep -q "running"; then
            success "Successfully restarted Elemta init.d service"
            return 0
        else
            error "Failed to restart Elemta init.d service"
            return 1
        fi
    elif command -v docker &> /dev/null && docker ps -a | grep -q elemta; then
        docker_id=$(docker ps -a | grep elemta | awk '{print $1}')
        docker restart $docker_id
        if docker ps | grep -q elemta; then
            success "Successfully restarted Elemta Docker container"
            return 0
        else
            error "Failed to restart Elemta Docker container"
            return 1
        fi
    else
        error "Could not determine how to restart Elemta"
        return 1
    fi
}

# Function to update configuration
function update_config {
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
        # Check if section exists
        if ! grep -q "^\[$section\]" "$config"; then
            # Add section
            echo "" >> "$config"
            echo "[$section]" >> "$config"
        fi
        
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

# Function to check certificate status
function check_certificate_status {
    info "Checking certificate status for domain: $DOMAIN"
    
    # Check if certificate file exists
    if [ ! -f "$cert_file" ]; then
        error "Certificate file not found: $cert_file"
        return 1
    fi
    
    # Check certificate details
    echo "Certificate details:"
    openssl x509 -in "$cert_file" -noout -subject -issuer -dates
    
    # Check if it's a Let's Encrypt certificate
    if openssl x509 -in "$cert_file" -noout -issuer | grep -q "Let's Encrypt"; then
        success "This is a Let's Encrypt certificate"
    else
        warning "This is not a Let's Encrypt certificate"
    fi
    
    # Check if certificate matches domain
    cert_domain=$(openssl x509 -in "$cert_file" -noout -subject | grep -o "CN = [^ ,]*" | sed 's/CN = //')
    if [[ "$cert_domain" == "$DOMAIN" || "$cert_domain" == "*.$DOMAIN" ]]; then
        success "Certificate domain matches: $cert_domain"
    else
        warning "Certificate domain ($cert_domain) does not match $DOMAIN"
    fi
    
    # Check certificate validity
    not_after=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    not_after_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$not_after" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    days_left=$(( (not_after_epoch - now_epoch) / 86400 ))
    
    if [ $days_left -lt 0 ]; then
        error "Certificate has EXPIRED!"
    elif [ $days_left -lt 7 ]; then
        warning "Certificate will expire soon (${days_left} days left)"
    else
        success "Certificate is valid for ${days_left} more days"
    fi
    
    # Check if private key matches certificate
    if [ -f "$key_file" ]; then
        cert_modulus=$(openssl x509 -in "$cert_file" -noout -modulus | md5sum)
        key_modulus=$(openssl rsa -in "$key_file" -noout -modulus 2>/dev/null | md5sum)
        
        if [ "$cert_modulus" = "$key_modulus" ]; then
            success "Private key matches certificate"
        else
            error "Private key does not match certificate!"
        fi
    else
        error "Private key file not found: $key_file"
    fi
    
    return 0
}

# Function to issue a new certificate
function issue_certificate {
    info "Issuing new certificate for domain: $DOMAIN"
    
    # Backup existing certificates
    if [ -f "$cert_file" ] || [ -f "$key_file" ]; then
        info "Backing up existing certificates"
        backup_certificates
    fi
    
    # Ensure ACME is enabled in config
    update_config "tls" "enabled" "true" "$CONFIG_FILE"
    update_config "tls" "acme_enabled" "true" "$CONFIG_FILE"
    update_config "tls" "acme_domain" "$DOMAIN" "$CONFIG_FILE"
    
    # Use Elemta CLI if available
    if [ "$elemta_cli_available" = true ]; then
        elemta cert issue --domain "$DOMAIN"
        if [ $? -eq 0 ]; then
            success "Successfully issued certificate for $DOMAIN using Elemta CLI"
            return 0
        else
            error "Failed to issue certificate using Elemta CLI"
        fi
    fi
    
    # Alternative: restart Elemta to trigger certificate issuance
    info "Restarting Elemta to trigger certificate issuance"
    restart_elemta_service
    
    # Wait for certificate to be issued
    info "Waiting for certificate issuance (this may take a minute)..."
    attempt=0
    max_attempts=60
    
    while [ $attempt -lt $max_attempts ]; do
        if [ -f "$cert_file" ]; then
            # Check if certificate is fresh (less than 5 minutes old)
            cert_time=$(stat -c %Y "$cert_file" 2>/dev/null || stat -f %m "$cert_file" 2>/dev/null)
            now=$(date +%s)
            age=$((now - cert_time))
            
            if [ $age -lt 300 ]; then
                success "Certificate has been issued successfully"
                check_certificate_status
                return 0
            fi
        fi
        
        sleep 5
        attempt=$((attempt + 1))
        echo -n "."
    done
    
    error "Timed out waiting for certificate issuance"
    echo "Check Elemta logs for more information"
    return 1
}

# Function to force certificate renewal
function renew_certificate {
    info "Forcing renewal of certificate for domain: $DOMAIN"
    
    # Backup existing certificates
    if [ -f "$cert_file" ] || [ -f "$key_file" ]; then
        info "Backing up existing certificates"
        backup_certificates
    fi
    
    # Use Elemta CLI if available
    if [ "$elemta_cli_available" = true ]; then
        elemta cert renew --force --domain "$DOMAIN"
        if [ $? -eq 0 ]; then
            success "Successfully renewed certificate for $DOMAIN using Elemta CLI"
            return 0
        else
            error "Failed to renew certificate using Elemta CLI"
        fi
    fi
    
    # Alternative: update config to force renewal
    info "Updating configuration to force certificate renewal"
    update_config "tls" "force_renewal" "true" "$CONFIG_FILE"
    
    # Restart Elemta to trigger renewal
    info "Restarting Elemta to trigger certificate renewal"
    restart_elemta_service
    
    # Wait for certificate to be renewed
    info "Waiting for certificate renewal (this may take a minute)..."
    attempt=0
    max_attempts=60
    
    while [ $attempt -lt $max_attempts ]; do
        if [ -f "$cert_file" ]; then
            # Check if certificate is fresh (less than 5 minutes old)
            cert_time=$(stat -c %Y "$cert_file" 2>/dev/null || stat -f %m "$cert_file" 2>/dev/null)
            now=$(date +%s)
            age=$((now - cert_time))
            
            if [ $age -lt 300 ]; then
                success "Certificate has been renewed successfully"
                # Revert force_renewal setting
                update_config "tls" "force_renewal" "false" "$CONFIG_FILE"
                check_certificate_status
                return 0
            fi
        fi
        
        sleep 5
        attempt=$((attempt + 1))
        echo -n "."
    done
    
    error "Timed out waiting for certificate renewal"
    # Revert force_renewal setting
    update_config "tls" "force_renewal" "false" "$CONFIG_FILE"
    echo "Check Elemta logs for more information"
    return 1
}

# Function to switch to a different domain
function switch_domain {
    if [ -z "$DOMAIN" ]; then
        error "Domain name is required for switch operation"
        return 1
    fi
    
    info "Switching to domain: $DOMAIN"
    
    # Backup existing certificates
    info "Backing up existing certificates"
    backup_certificates
    
    # Update configuration
    update_config "tls" "acme_domain" "$DOMAIN" "$CONFIG_FILE"
    
    # Update certificate paths if using domain-based paths
    old_cert_file="$cert_file"
    old_key_file="$key_file"
    
    # Update paths if they contain the domain name
    if echo "$cert_file" | grep -q "/[^/]*\.[^/]*\.crt$"; then
        new_cert_file=$(echo "$cert_file" | sed "s|/[^/]*\.[^/]*\.crt$|/$DOMAIN.crt|")
        update_config "tls" "cert_file" "$new_cert_file" "$CONFIG_FILE"
        cert_file="$new_cert_file"
        info "Updated certificate path: $cert_file"
    fi
    
    if echo "$key_file" | grep -q "/[^/]*\.[^/]*\.key$"; then
        new_key_file=$(echo "$key_file" | sed "s|/[^/]*\.[^/]*\.key$|/$DOMAIN.key|")
        update_config "tls" "key_file" "$new_key_file" "$CONFIG_FILE"
        key_file="$new_key_file"
        info "Updated private key path: $key_file"
    fi
    
    # Ask user if they want to issue a new certificate
    if [ "$FORCE" != "true" ]; then
        read -p "Issue a new certificate for $DOMAIN now? (y/n): " issue_new
        if [ "$issue_new" = "y" ]; then
            issue_certificate
        else
            info "Skipping certificate issuance"
            info "Don't forget to issue a certificate before restarting Elemta"
        fi
    fi
    
    success "Successfully switched to domain: $DOMAIN"
    return 0
}

# Function to revoke a certificate
function revoke_certificate {
    info "Revoking certificate for domain: $DOMAIN"
    
    # Check if certificate file exists
    if [ ! -f "$cert_file" ]; then
        error "Certificate file not found: $cert_file"
        return 1
    fi
    
    # Confirm revocation
    if [ "$FORCE" != "true" ]; then
        warning "WARNING: Revoking a certificate is irreversible!"
        read -p "Are you sure you want to revoke the certificate for $DOMAIN? (y/n): " confirm
        if [ "$confirm" != "y" ]; then
            info "Certificate revocation cancelled"
            return 1
        fi
    fi
    
    # Use Elemta CLI if available
    if [ "$elemta_cli_available" = true ]; then
        elemta cert revoke --domain "$DOMAIN"
        if [ $? -eq 0 ]; then
            success "Successfully revoked certificate for $DOMAIN using Elemta CLI"
            return 0
        else
            error "Failed to revoke certificate using Elemta CLI"
            return 1
        fi
    else
        error "Cannot revoke certificate without Elemta CLI"
        echo "Please install or use Elemta CLI to revoke certificates"
        return 1
    fi
}

# Function to list available backups
function list_backups {
    info "Listing backups for domain: $DOMAIN"
    
    # Find backups for the domain
    backups=$(find "$BACKUP_DIR" -type d -name "${DOMAIN}_*" | sort)
    
    if [ -z "$backups" ]; then
        warning "No backups found for domain: $DOMAIN"
        return 1
    fi
    
    echo "Available backups:"
    echo "------------------"
    
    for backup in $backups; do
        backup_date=$(echo "$backup" | grep -o "[0-9]\{14\}$" | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/\1-\2-\3 \4:\5:\6/')
        
        if [ -f "$backup/metadata.txt" ]; then
            echo -e "${GREEN}Backup:${NC} $(basename "$backup")"
            echo -e "${GREEN}Date:${NC} $backup_date"
            echo -e "${GREEN}Files:${NC}"
            
            # Show certificate details if available
            if [ -f "$backup/$(basename "$cert_file")" ]; then
                echo "  Certificate: $(basename "$cert_file")"
                cert_info=$(openssl x509 -in "$backup/$(basename "$cert_file")" -noout -subject -issuer -dates 2>/dev/null)
                if [ -n "$cert_info" ]; then
                    echo "$cert_info" | sed 's/^/    /'
                fi
            elif ls "$backup"/*.crt &>/dev/null; then
                cert_file_in_backup=$(ls "$backup"/*.crt | head -1)
                echo "  Certificate: $(basename "$cert_file_in_backup")"
                cert_info=$(openssl x509 -in "$cert_file_in_backup" -noout -subject -issuer -dates 2>/dev/null)
                if [ -n "$cert_info" ]; then
                    echo "$cert_info" | sed 's/^/    /'
                fi
            fi
            
            echo ""
        else
            echo -e "${YELLOW}Backup:${NC} $(basename "$backup") (${YELLOW}incomplete or invalid${NC})"
            echo -e "${YELLOW}Date:${NC} $backup_date"
            echo ""
        fi
    done
    
    success "Found $(echo "$backups" | wc -l) backup(s)"
    return 0
}

# Execute action
case "$ACTION" in
    issue)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for issue operation"
            exit 1
        fi
        issue_certificate
        ;;
    renew)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for renew operation"
            exit 1
        fi
        renew_certificate
        ;;
    backup)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for backup operation"
            exit 1
        fi
        backup_certificates
        ;;
    restore)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for restore operation"
            exit 1
        fi
        restore_certificates
        ;;
    switch)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for switch operation"
            exit 1
        fi
        switch_domain
        ;;
    status)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for status operation"
            exit 1
        fi
        check_certificate_status
        ;;
    revoke)
        if [ -z "$DOMAIN" ]; then
            error "Domain name is required for revoke operation"
            exit 1
        fi
        revoke_certificate
        ;;
    list-backups)
        list_backups
        ;;
    help)
        show_usage
        ;;
    *)
        error "Unknown action: $ACTION"
        show_usage
        ;;
esac

exit $?
