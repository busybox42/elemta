#!/bin/bash
# letsencrypt-admin.sh - Let's Encrypt Certificate Management Script for Elemta SMTP Server
# 
# This script provides utilities for managing Let's Encrypt certificates for Elemta SMTP server.
# Features:
# - Check certificate status
# - Force certificate renewal
# - Revoke certificates
# - Backup/restore certificates
# - Toggle staging/production mode
# - Import existing certificates

set -e

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default values
CONFIG_FILE=""
CERT_DIR=""
DOMAIN=""
EMAIL=""
STAGING=false
DEFAULT_CONFIG_PATHS=(
  "/etc/elemta/elemta.toml"
  "/var/elemta/config/elemta.toml"
  "./elemta.toml"
)

# Helper functions for colored output
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${MAGENTA}[STEP]${NC} $1"; }
log_header() { echo -e "\n${BOLD}${CYAN}$1${NC}\n"; }

# Function to check for required commands
check_command() {
  if ! command -v "$1" &> /dev/null; then
    log_error "Required command '$1' not found. Please install it and try again."
    exit 1
  fi
}

# Function to read config value from elemta.toml
get_config_value() {
  local section=$1
  local key=$2
  local result=$(grep -A20 "^\[$section\]" "$CONFIG_FILE" | grep "^$key\s*=" | head -1 | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^"//;s/"$//')
  echo "$result"
}

# Function to read TLS config from elemta.toml
read_tls_config() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    exit 1
  fi

  # Read TLS configuration
  local tls_enabled=$(get_config_value "tls" "enabled")
  if [[ "$tls_enabled" != "true" ]]; then
    log_warning "TLS is not enabled in the configuration file"
  fi

  # Read certificate paths
  CERT_DIR=$(dirname "$(get_config_value "tls" "cert_file")")
  if [[ -z "$CERT_DIR" || "$CERT_DIR" == "." ]]; then
    CERT_DIR="/var/elemta/certs"
    log_info "Using default certificate directory: $CERT_DIR"
  fi

  # Read ACME configuration
  local acme_enabled=$(get_config_value "tls.acme" "enabled")
  if [[ "$acme_enabled" != "true" ]]; then
    log_warning "ACME (Let's Encrypt) is not enabled in the configuration file"
  fi

  DOMAIN=$(get_config_value "tls.acme" "domains" | tr -d '[],"' | awk '{print $1}')
  EMAIL=$(get_config_value "tls.acme" "email")
  
  local staging=$(get_config_value "tls.acme" "staging")
  if [[ "$staging" == "true" ]]; then
    STAGING=true
  fi
}

# Function to find and set config file
find_config_file() {
  if [[ -n "$1" ]]; then
    CONFIG_FILE="$1"
    if [[ ! -f "$CONFIG_FILE" ]]; then
      log_error "Specified configuration file not found: $CONFIG_FILE"
      exit 1
    fi
  else
    for path in "${DEFAULT_CONFIG_PATHS[@]}"; do
      if [[ -f "$path" ]]; then
        CONFIG_FILE="$path"
        break
      fi
    done
    
    if [[ -z "$CONFIG_FILE" ]]; then
      log_error "Could not find Elemta configuration file. Please specify with -c option."
      exit 1
    fi
  fi
  log_info "Using configuration file: $CONFIG_FILE"
}

# Function to check certificate status
check_cert_status() {
  local cert_file=$(get_config_value "tls" "cert_file")
  local key_file=$(get_config_value "tls" "key_file")
  
  if [[ ! -f "$cert_file" ]]; then
    log_error "Certificate file not found: $cert_file"
    return 1
  fi
  
  if [[ ! -f "$key_file" ]]; then
    log_error "Private key file not found: $key_file"
    return 1
  }
  
  log_header "Certificate Information"
  
  # Check expiration
  local expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
  local expiry_epoch=$(date -d "$expiry_date" +%s)
  local current_epoch=$(date +%s)
  local seconds_left=$((expiry_epoch - current_epoch))
  local days_left=$((seconds_left / 86400))
  
  echo -e "Certificate: ${BOLD}$cert_file${NC}"
  echo -e "Private key: ${BOLD}$key_file${NC}"
  echo -e "Domain:      ${BOLD}$(openssl x509 -noout -subject -in "$cert_file" | sed -n 's/.*CN = \([^,]*\).*/\1/p')${NC}"
  echo -e "Issuer:      ${BOLD}$(openssl x509 -noout -issuer -in "$cert_file" | sed -n 's/.*CN = \([^,]*\).*/\1/p')${NC}"
  echo -e "Valid from:  ${BOLD}$(openssl x509 -noout -startdate -in "$cert_file" | cut -d= -f2)${NC}"
  echo -e "Valid until: ${BOLD}$expiry_date${NC}"
  
  if [[ $days_left -lt 0 ]]; then
    echo -e "Status:      ${RED}EXPIRED${NC} ($((days_left * -1)) days ago)"
  elif [[ $days_left -lt 7 ]]; then
    echo -e "Status:      ${RED}CRITICAL${NC} (expires in $days_left days)"
  elif [[ $days_left -lt 14 ]]; then
    echo -e "Status:      ${YELLOW}WARNING${NC} (expires in $days_left days)"
  else
    echo -e "Status:      ${GREEN}VALID${NC} (expires in $days_left days)"
  fi
  
  # Check certificate chain
  echo -e "\nCertificate chain:"
  openssl crl2pkcs7 -nocrl -certfile "$cert_file" | openssl pkcs7 -print_certs -noout
  
  # Check if private key matches certificate
  if openssl x509 -noout -modulus -in "$cert_file" | openssl md5 | grep -q "$(openssl rsa -noout -modulus -in "$key_file" | openssl md5)"; then
    echo -e "\nPrivate key: ${GREEN}Matches certificate${NC}"
  else
    echo -e "\nPrivate key: ${RED}DOES NOT MATCH CERTIFICATE${NC}"
  fi
  
  return 0
}

# Function to force certificate renewal
force_renewal() {
  log_header "Forcing Certificate Renewal"
  
  # Check if Elemta supports the force-renew directive
  log_info "Checking for Elemta's certificate renewal support..."
  
  if ! systemctl list-units --all | grep -q elemta; then
    log_warning "Elemta service not found in systemd. Will attempt to renew using direct command."
    
    if command -v elemta &> /dev/null; then
      log_step "Running 'elemta acme renew --force'..."
      if elemta acme renew --force; then
        log_success "Certificate renewal successfully triggered"
        log_info "Check the Elemta logs for the result of the renewal process"
      else
        log_error "Failed to trigger certificate renewal"
      fi
    else
      log_error "Cannot find the Elemta command. Please renew the certificate manually."
      log_info "You can try restarting the Elemta service to trigger automatic renewal."
    fi
  else
    log_step "Elemta service found. Attempting to restart service to trigger renewal..."
    if sudo systemctl restart elemta; then
      log_success "Elemta service restarted. Certificate renewal should be triggered."
      log_info "Check the service logs with 'sudo journalctl -u elemta' to verify renewal"
    else
      log_error "Failed to restart Elemta service"
    fi
  fi
}

# Function to revoke a certificate
revoke_certificate() {
  log_header "Revoking Certificate"
  
  if ! command -v elemta &> /dev/null; then
    log_error "Cannot find the Elemta command. Manual revocation required."
    log_info "To revoke a Let's Encrypt certificate manually, use certbot or acme.sh"
    return 1
  fi
  
  log_warning "This will revoke your current certificate. Are you sure? (y/N)"
  read -r confirmation
  if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
    log_info "Revocation cancelled"
    return 0
  fi
  
  log_step "Attempting to revoke certificate..."
  if elemta acme revoke; then
    log_success "Certificate successfully revoked"
  else
    log_error "Failed to revoke certificate"
    log_info "You may need to revoke manually using certbot or acme.sh"
  fi
}

# Function to backup certificates
backup_certificates() {
  local cert_file=$(get_config_value "tls" "cert_file")
  local key_file=$(get_config_value "tls" "key_file")
  local backup_dir="$HOME/elemta_cert_backup_$(date +%Y%m%d_%H%M%S)"
  
  if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
    log_error "Certificate files not found"
    return 1
  fi
  
  log_header "Backing Up Certificates"
  
  log_step "Creating backup directory: $backup_dir"
  mkdir -p "$backup_dir"
  
  log_step "Copying certificate files..."
  cp "$cert_file" "$backup_dir/$(basename "$cert_file")"
  cp "$key_file" "$backup_dir/$(basename "$key_file")"
  
  # Backup chain if it exists
  local chain_file="${cert_file%.*}.chain.pem"
  if [[ -f "$chain_file" ]]; then
    cp "$chain_file" "$backup_dir/$(basename "$chain_file")"
  fi
  
  # Backup ACME account
  local acme_dir="/var/elemta/acme"
  if [[ -d "$acme_dir" ]]; then
    log_step "Backing up ACME account data..."
    cp -r "$acme_dir" "$backup_dir/acme"
  fi
  
  log_success "Certificates backed up to $backup_dir"
  ls -la "$backup_dir"
}

# Function to restore certificates from backup
restore_certificates() {
  log_header "Restoring Certificates from Backup"
  
  log_step "Please enter the backup directory path:"
  read -r backup_dir
  
  if [[ ! -d "$backup_dir" ]]; then
    log_error "Backup directory not found: $backup_dir"
    return 1
  fi
  
  local cert_file=$(get_config_value "tls" "cert_file")
  local key_file=$(get_config_value "tls" "key_file")
  
  # Make sure destination directories exist
  mkdir -p "$(dirname "$cert_file")"
  mkdir -p "$(dirname "$key_file")"
  
  # Find certificate files in backup
  local backup_cert=$(find "$backup_dir" -name "*.crt" -o -name "*.pem" | grep -v "chain" | head -1)
  local backup_key=$(find "$backup_dir" -name "*.key" | head -1)
  
  if [[ -z "$backup_cert" || -z "$backup_key" ]]; then
    log_error "Could not find certificate files in backup directory"
    return 1
  fi
  
  log_step "Restoring certificate from $backup_cert to $cert_file"
  cp "$backup_cert" "$cert_file"
  
  log_step "Restoring private key from $backup_key to $key_file"
  cp "$backup_key" "$key_file"
  
  # Restore chain if it exists
  local backup_chain=$(find "$backup_dir" -name "*.chain.pem" | head -1)
  if [[ -n "$backup_chain" ]]; then
    local chain_file="${cert_file%.*}.chain.pem"
    log_step "Restoring certificate chain from $backup_chain to $chain_file"
    cp "$backup_chain" "$chain_file"
  fi
  
  # Restore ACME account if it exists
  if [[ -d "$backup_dir/acme" ]]; then
    log_step "Restoring ACME account data..."
    cp -r "$backup_dir/acme" "/var/elemta/"
  fi
  
  log_success "Certificates restored successfully"
  log_warning "You may need to restart the Elemta service to apply the restored certificates"
}

# Function to toggle staging/production mode
toggle_staging() {
  log_header "Toggling Staging/Production Mode"
  
  local current_mode=$(get_config_value "tls.acme" "staging")
  
  if [[ "$current_mode" == "true" ]]; then
    log_info "Currently using STAGING mode. Switching to PRODUCTION mode."
    new_mode="false"
    mode_name="PRODUCTION"
  else
    log_info "Currently using PRODUCTION mode. Switching to STAGING mode."
    new_mode="true"
    mode_name="STAGING"
  fi
  
  log_warning "This will change your ACME mode to $mode_name. Are you sure? (y/N)"
  read -r confirmation
  if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
    log_info "Mode change cancelled"
    return 0
  fi
  
  if sed -i "s/staging = $current_mode/staging = $new_mode/" "$CONFIG_FILE"; then
    log_success "Successfully changed to $mode_name mode"
    log_info "Please restart the Elemta service to apply changes"
  else
    log_error "Failed to update configuration file"
  fi
}

# Function to import existing certificates
import_certificates() {
  log_header "Importing Existing Certificates"
  
  log_step "Please enter the path to the certificate file (.crt or .pem):"
  read -r import_cert
  
  log_step "Please enter the path to the private key file (.key):"
  read -r import_key
  
  if [[ ! -f "$import_cert" || ! -f "$import_key" ]]; then
    log_error "Certificate or key file not found"
    return 1
  fi
  
  local cert_file=$(get_config_value "tls" "cert_file")
  local key_file=$(get_config_value "tls" "key_file")
  
  # Make sure destination directories exist
  mkdir -p "$(dirname "$cert_file")"
  mkdir -p "$(dirname "$key_file")"
  
  log_step "Importing certificate from $import_cert to $cert_file"
  cp "$import_cert" "$cert_file"
  
  log_step "Importing private key from $import_key to $key_file"
  cp "$import_key" "$key_file"
  
  # Check if there's a chain file to import
  log_step "Do you have a certificate chain file to import? (y/N)"
  read -r has_chain
  if [[ "$has_chain" =~ ^[Yy]$ ]]; then
    log_step "Please enter the path to the chain file:"
    read -r import_chain
    
    if [[ -f "$import_chain" ]]; then
      local chain_file="${cert_file%.*}.chain.pem"
      log_step "Importing certificate chain from $import_chain to $chain_file"
      cp "$import_chain" "$chain_file"
    else
      log_error "Chain file not found"
    fi
  fi
  
  log_success "Certificates imported successfully"
  log_info "Please check the imported certificate:"
  check_cert_status
  log_warning "You may need to restart the Elemta service to apply the imported certificates"
}

# Function to display script usage
show_help() {
  echo -e "${BOLD}Let's Encrypt Certificate Management Script for Elemta SMTP Server${NC}"
  echo
  echo "Usage: $0 [options] command"
  echo
  echo "Options:"
  echo "  -c, --config FILE     Path to Elemta configuration file"
  echo "  -h, --help            Display this help message"
  echo
  echo "Commands:"
  echo "  status                Check certificate status"
  echo "  renew                 Force certificate renewal"
  echo "  revoke                Revoke current certificate"
  echo "  backup                Backup certificates and ACME account"
  echo "  restore               Restore certificates from backup"
  echo "  toggle-staging        Toggle between staging and production mode"
  echo "  import                Import existing certificates"
  echo
  echo "Example:"
  echo "  $0 status                     # Check current certificate status"
  echo "  $0 -c /etc/elemta/custom.toml renew  # Force renewal with custom config"
}

# Parse command line arguments
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -c|--config)
      CONFIG_PARAM="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done
set -- "${POSITIONAL[@]}"

# Verify required commands are available
check_command openssl
check_command grep
check_command sed
check_command find

# Find configuration file
find_config_file "$CONFIG_PARAM"

# Read TLS configuration
read_tls_config

# Execute requested command
if [[ $# -eq 0 ]]; then
  show_help
  exit 0
fi

case "$1" in
  status)
    check_cert_status
    ;;
  renew)
    force_renewal
    ;;
  revoke)
    revoke_certificate
    ;;
  backup)
    backup_certificates
    ;;
  restore)
    restore_certificates
    ;;
  toggle-staging)
    toggle_staging
    ;;
  import)
    import_certificates
    ;;
  *)
    log_error "Unknown command: $1"
    show_help
    exit 1
    ;;
esac

exit 0 