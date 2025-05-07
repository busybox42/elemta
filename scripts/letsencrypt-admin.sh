#!/bin/bash
#
# Let's Encrypt Certificate Management Script for Elemta SMTP Server
# This script provides administrative functions for managing Let's Encrypt certificates

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

# Configuration
CONFIG_PATHS=(
  "/etc/elemta/elemta.toml"
  "/var/elemta/config/elemta.toml"
  "./elemta.toml"
)
DEFAULT_CERT_PATH="/var/elemta/certs"
ELEMTA_SERVICE="elemta"

# Print a formatted header
print_header() {
  echo -e "\n${BOLD}${BLUE}$1${NC}\n"
}

# Print success message
print_success() {
  echo -e "${GREEN}✓ $1${NC}"
}

# Print error message
print_error() {
  echo -e "${RED}✗ $1${NC}" >&2
}

# Print warning message
print_warning() {
  echo -e "${YELLOW}! $1${NC}"
}

# Print info message
print_info() {
  echo -e "${CYAN}i $1${NC}"
}

# Find the correct config file
find_config() {
  for config_path in "${CONFIG_PATHS[@]}"; do
    if [[ -f "$config_path" ]]; then
      echo "$config_path"
      return 0
    fi
  done
  return 1
}

# Check if Elemta service exists and is running
check_service() {
  if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet "$ELEMTA_SERVICE"; then
      return 0
    else
      return 1
    fi
  elif command -v docker &> /dev/null; then
    if docker ps | grep -q elemta; then
      ELEMTA_SERVICE="docker"
      return 0
    else
      return 1
    fi
  else
    return 2
  fi
}

# Restart Elemta service
restart_service() {
  print_info "Restarting Elemta service..."
  
  if [[ "$ELEMTA_SERVICE" == "docker" ]]; then
    docker restart elemta
  else
    systemctl restart "$ELEMTA_SERVICE"
  fi
  
  sleep 2
  
  if check_service; then
    print_success "Elemta service restarted successfully."
  else
    print_error "Failed to restart Elemta service."
    return 1
  fi
}

# Get certificate information
get_cert_info() {
  local cert_path="$1"
  
  if [[ ! -f "$cert_path" ]]; then
    print_error "Certificate not found at $cert_path"
    return 1
  fi
  
  print_header "Certificate Information"
  
  local subject
  subject=$(openssl x509 -in "$cert_path" -noout -subject | sed 's/subject=//g')
  echo -e "${BOLD}Subject:${NC} $subject"
  
  local issuer
  issuer=$(openssl x509 -in "$cert_path" -noout -issuer | sed 's/issuer=//g')
  echo -e "${BOLD}Issuer:${NC} $issuer"
  
  local valid_from
  valid_from=$(openssl x509 -in "$cert_path" -noout -startdate | sed 's/notBefore=//g')
  echo -e "${BOLD}Valid From:${NC} $valid_from"
  
  local valid_to
  valid_to=$(openssl x509 -in "$cert_path" -noout -enddate | sed 's/notAfter=//g')
  echo -e "${BOLD}Valid To:${NC} $valid_to"
  
  local expiry_date
  expiry_date=$(date -d "$(openssl x509 -in "$cert_path" -noout -enddate | cut -d= -f 2)" +%s)
  local now
  now=$(date +%s)
  local days_left
  days_left=$(( (expiry_date - now) / 86400 ))
  
  if [[ $days_left -lt 0 ]]; then
    echo -e "${BOLD}Status:${NC} ${RED}Expired (${days_left#-} days ago)${NC}"
  elif [[ $days_left -lt 7 ]]; then
    echo -e "${BOLD}Status:${NC} ${RED}Critical ($days_left days left)${NC}"
  elif [[ $days_left -lt 30 ]]; then
    echo -e "${BOLD}Status:${NC} ${YELLOW}Warning ($days_left days left)${NC}"
  else
    echo -e "${BOLD}Status:${NC} ${GREEN}Valid ($days_left days left)${NC}"
  fi
  
  local san
  san=$(openssl x509 -in "$cert_path" -noout -text | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/DNS://g; s/, /\n- /g; s/^/- /')
  echo -e "${BOLD}Subject Alternative Names:${NC}\n$san"
}

# Get TLS configuration from config file
get_tls_config() {
  local config_file="$1"
  local cert_path=""
  local key_path=""
  local tls_enabled=false
  
  if grep -q "\[tls\]" "$config_file"; then
    if grep -q "enabled.*=.*true" "$config_file"; then
      tls_enabled=true
    fi
    
    cert_path=$(grep -A10 "\[tls\]" "$config_file" | grep "cert_file" | cut -d= -f2 | tr -d ' "' || echo "")
    key_path=$(grep -A10 "\[tls\]" "$config_file" | grep "key_file" | cut -d= -f2 | tr -d ' "' || echo "")
  fi
  
  echo "$tls_enabled:$cert_path:$key_path"
}

# Get ACME configuration from config file
get_acme_config() {
  local config_file="$1"
  local acme_enabled=false
  local cert_storage=""
  
  if grep -q "\[acme\]" "$config_file"; then
    if grep -q -A20 "\[acme\]" "$config_file" | grep -q "enabled.*=.*true"; then
      acme_enabled=true
    fi
    
    cert_storage=$(grep -A20 "\[acme\]" "$config_file" | grep "cert_storage_path" | cut -d= -f2 | tr -d ' "' || echo "$DEFAULT_CERT_PATH")
  fi
  
  echo "$acme_enabled:$cert_storage"
}

# Force certificate renewal
force_renewal() {
  print_header "Forcing certificate renewal"
  
  local config_file
  config_file=$(find_config)
  
  if [[ $? -ne 0 ]]; then
    print_error "No Elemta configuration file found."
    return 1
  fi
  
  print_info "Using configuration file: $config_file"
  
  # Get ACME config
  IFS=':' read -r acme_enabled cert_storage <<< "$(get_acme_config "$config_file")"
  
  if [[ "$acme_enabled" != "true" ]]; then
    print_error "Let's Encrypt integration is not enabled in the configuration."
    return 1
  fi
  
  # If cert storage is empty, use default
  if [[ -z "$cert_storage" ]]; then
    cert_storage="$DEFAULT_CERT_PATH"
  fi
  
  print_info "Certificate storage path: $cert_storage"
  
  # Create marker file to force renewal
  local marker_file="$cert_storage/.force_renewal"
  touch "$marker_file"
  print_success "Created marker file for forced renewal."
  
  # Restart the service to trigger renewal
  if ! restart_service; then
    print_error "Failed to trigger certificate renewal."
    return 1
  fi
  
  print_success "Certificate renewal process initiated."
  print_info "Check service logs to monitor the renewal process:"
  
  if [[ "$ELEMTA_SERVICE" == "docker" ]]; then
    echo "  docker logs elemta -f"
  else
    echo "  journalctl -fu $ELEMTA_SERVICE"
  fi
}

# Backup certificates
backup_certificates() {
  print_header "Backing up certificates"
  
  local config_file
  config_file=$(find_config)
  
  if [[ $? -ne 0 ]]; then
    print_error "No Elemta configuration file found."
    return 1
  fi
  
  # Get ACME config
  IFS=':' read -r acme_enabled cert_storage <<< "$(get_acme_config "$config_file")"
  
  # Get TLS config
  IFS=':' read -r tls_enabled cert_path key_path <<< "$(get_tls_config "$config_file")"
  
  # Determine source directory
  local source_dir
  if [[ "$acme_enabled" == "true" && -n "$cert_storage" && -d "$cert_storage" ]]; then
    source_dir="$cert_storage"
  elif [[ "$tls_enabled" == "true" && -n "$cert_path" && -d "$(dirname "$cert_path")" ]]; then
    source_dir="$(dirname "$cert_path")"
  else
    print_error "Could not determine certificate location."
    return 1
  fi
  
  print_info "Source directory: $source_dir"
  
  # Create backup directory
  local backup_dir="/var/backups/elemta/certs/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup_dir"
  
  # Copy certificates
  if cp -r "$source_dir"/* "$backup_dir"/; then
    print_success "Backed up certificates to $backup_dir"
  else
    print_error "Failed to backup certificates."
    return 1
  fi
  
  # Create a symlink to the latest backup
  ln -sf "$backup_dir" "/var/backups/elemta/certs/latest"
  
  print_info "Backup complete. Certificate files are stored in:"
  echo "  $backup_dir"
  echo "  /var/backups/elemta/certs/latest (symlink to the latest backup)"
}

# Restore certificates from backup
restore_certificates() {
  print_header "Restoring certificates"
  
  local backup_dir="/var/backups/elemta/certs"
  
  # List available backups
  if [[ ! -d "$backup_dir" || $(find "$backup_dir" -maxdepth 1 -type d | wc -l) -le 1 ]]; then
    print_error "No backups found in $backup_dir"
    return 1
  fi
  
  echo "Available backups:"
  local i=1
  local backups=()
  
  while read -r dir; do
    if [[ "$dir" != "$backup_dir" && "$dir" != "$backup_dir/latest" ]]; then
      backups+=("$dir")
      echo "  $i) $(basename "$dir")"
      ((i++))
    fi
  done < <(find "$backup_dir" -maxdepth 1 -type d | sort -r)
  
  # Prompt for backup selection
  local selection
  echo
  read -rp "Select backup to restore [1]: " selection
  selection=${selection:-1}
  
  if ! [[ "$selection" =~ ^[0-9]+$ ]] || (( selection < 1 || selection > ${#backups[@]} )); then
    print_error "Invalid selection."
    return 1
  fi
  
  local selected_backup="${backups[$((selection-1))]}"
  print_info "Selected backup: $(basename "$selected_backup")"
  
  # Get config file and cert paths
  local config_file
  config_file=$(find_config)
  
  if [[ $? -ne 0 ]]; then
    print_error "No Elemta configuration file found."
    return 1
  fi
  
  # Get ACME config
  IFS=':' read -r acme_enabled cert_storage <<< "$(get_acme_config "$config_file")"
  
  # If cert storage is empty, use default
  if [[ -z "$cert_storage" ]]; then
    cert_storage="$DEFAULT_CERT_PATH"
  fi
  
  # Create target directory if it doesn't exist
  mkdir -p "$cert_storage"
  
  # Confirm
  read -rp "Are you sure you want to restore certificates to $cert_storage? [y/N] " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    print_info "Restore cancelled."
    return 0
  fi
  
  # Copy files
  if cp -r "$selected_backup"/* "$cert_storage"/; then
    print_success "Restored certificates from $(basename "$selected_backup") to $cert_storage"
  else
    print_error "Failed to restore certificates."
    return 1
  fi
  
  # Restart service
  if ! restart_service; then
    print_error "Failed to restart Elemta after restoring certificates."
    return 1
  fi
  
  print_success "Certificate restoration complete."
}

# Show status
show_status() {
  print_header "Let's Encrypt Status"
  
  local config_file
  config_file=$(find_config)
  
  if [[ $? -ne 0 ]]; then
    print_error "No Elemta configuration file found."
    return 1
  fi
  
  print_info "Using configuration file: $config_file"
  
  # Get TLS config
  IFS=':' read -r tls_enabled cert_path key_path <<< "$(get_tls_config "$config_file")"
  
  echo -e "${BOLD}TLS Status:${NC} $(if [[ "$tls_enabled" == "true" ]]; then echo -e "${GREEN}Enabled${NC}"; else echo -e "${RED}Disabled${NC}"; fi)"
  
  if [[ "$tls_enabled" == "true" ]]; then
    echo -e "${BOLD}Certificate File:${NC} ${cert_path:-Not specified}"
    echo -e "${BOLD}Key File:${NC} ${key_path:-Not specified}"
    
    if [[ -n "$cert_path" && -f "$cert_path" ]]; then
      get_cert_info "$cert_path"
    fi
  fi
  
  # Get ACME config
  IFS=':' read -r acme_enabled cert_storage <<< "$(get_acme_config "$config_file")"
  
  echo -e "\n${BOLD}Let's Encrypt Integration:${NC} $(if [[ "$acme_enabled" == "true" ]]; then echo -e "${GREEN}Enabled${NC}"; else echo -e "${RED}Disabled${NC}"; fi)"
  
  if [[ "$acme_enabled" == "true" ]]; then
    echo -e "${BOLD}Certificate Storage:${NC} ${cert_storage:-$DEFAULT_CERT_PATH}"
    
    # If not using custom cert path, check Let's Encrypt cert
    if [[ -z "$cert_path" || ! -f "$cert_path" ]]; then
      local le_cert="$cert_storage/certificate.pem"
      if [[ -f "$le_cert" ]]; then
        get_cert_info "$le_cert"
      else
        print_warning "No Let's Encrypt certificate found."
      fi
    fi
    
    # Check service status
    echo -e "\n${BOLD}Service Status:${NC}"
    if check_service; then
      echo -e "Elemta service: ${GREEN}Running${NC}"
    else
      echo -e "Elemta service: ${RED}Not running${NC}"
    fi
  fi
}

# Print usage information
usage() {
  cat <<EOT
${BOLD}Let's Encrypt Certificate Management Script for Elemta SMTP Server${NC}

${BOLD}Usage:${NC}
  $0 [command]

${BOLD}Commands:${NC}
  status        Show TLS and Let's Encrypt configuration status
  info          Display certificate information
  renew         Force certificate renewal
  backup        Backup certificates
  restore       Restore certificates from backup
  help          Show this help message

EOT
}

# Main script execution
case "$1" in
  status)
    show_status
    ;;
  info)
    config_file=$(find_config)
    if [[ $? -ne 0 ]]; then
      print_error "No Elemta configuration file found."
      exit 1
    fi
    
    # Get TLS config
    IFS=':' read -r tls_enabled cert_path key_path <<< "$(get_tls_config "$config_file")"
    
    # Get ACME config
    IFS=':' read -r acme_enabled cert_storage <<< "$(get_acme_config "$config_file")"
    
    # Determine certificate path
    if [[ -n "$cert_path" && -f "$cert_path" ]]; then
      get_cert_info "$cert_path"
    elif [[ "$acme_enabled" == "true" ]]; then
      local le_cert="$cert_storage/certificate.pem"
      if [[ -f "$le_cert" ]]; then
        get_cert_info "$le_cert"
      else
        print_error "No certificate found."
        exit 1
      fi
    else
      print_error "No certificate found."
      exit 1
    fi
    ;;
  renew)
    force_renewal
    ;;
  backup)
    backup_certificates
    ;;
  restore)
    restore_certificates
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac 