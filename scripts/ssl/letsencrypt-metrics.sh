#!/bin/bash
# letsencrypt-metrics.sh - Prometheus Metrics Exporter for Let's Encrypt Certificates
# 
# This script generates Prometheus metrics for Let's Encrypt certificates used by Elemta.
# It can be used with node_exporter's textfile collector or as a standalone HTTP endpoint.
# 
# Metrics provided:
# - letsencrypt_cert_expiry_seconds: Time remaining until certificate expiration
# - letsencrypt_cert_issued_time_seconds: Timestamp when certificate was issued
# - letsencrypt_cert_valid: 1 if certificate is valid, 0 otherwise
# - letsencrypt_renewal_success: 1 if last renewal was successful, 0 otherwise
# - letsencrypt_renewal_last_attempt_time_seconds: Timestamp of last renewal attempt

set -e

# Default values
CONFIG_FILE=""
METRICS_FILE="/var/lib/node_exporter/textfile_collector/letsencrypt.prom"
HTTP_PORT=9090
HTTP_MODE=false
DEFAULT_CONFIG_PATHS=(
  "/etc/elemta/elemta.toml"
  "/var/elemta/config/elemta.toml"
  "./elemta.toml"
)

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions for colored output
log_info() { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

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

# Function to get certificate metrics
get_certificate_metrics() {
  local cert_file=$(get_config_value "tls" "cert_file")
  
  if [[ ! -f "$cert_file" ]]; then
    log_error "Certificate file not found: $cert_file"
    echo "# HELP letsencrypt_cert_exists Indicates if certificate file exists"
    echo "# TYPE letsencrypt_cert_exists gauge"
    echo "letsencrypt_cert_exists 0"
    return 1
  fi
  
  # Get certificate info
  local subject=$(openssl x509 -noout -subject -in "$cert_file" | sed -n 's/.*CN = \([^,]*\).*/\1/p')
  local issuer=$(openssl x509 -noout -issuer -in "$cert_file" | sed -n 's/.*CN = \([^,]*\).*/\1/p')
  local not_before=$(openssl x509 -noout -startdate -in "$cert_file" | cut -d= -f2)
  local not_after=$(openssl x509 -noout -enddate -in "$cert_file" | cut -d= -f2)
  local not_before_epoch=$(date -d "$not_before" +%s)
  local not_after_epoch=$(date -d "$not_after" +%s)
  local current_epoch=$(date +%s)
  local seconds_left=$((not_after_epoch - current_epoch))
  
  # Check if TLS is enabled
  local tls_enabled=$(get_config_value "tls" "enabled")
  local tls_status=0
  if [[ "$tls_enabled" == "true" ]]; then
    tls_status=1
  fi
  
  # Check if ACME is enabled
  local acme_enabled=$(get_config_value "tls.acme" "enabled")
  local acme_status=0
  if [[ "$acme_enabled" == "true" ]]; then
    acme_status=1
  fi
  
  # Check for acme logs to determine last renewal attempt
  local renewal_log="/var/log/elemta/acme.log"
  local last_renewal_attempt=0
  local renewal_success=0
  
  if [[ -f "$renewal_log" ]]; then
    # Get timestamp of last renewal attempt
    local last_log_entry=$(tail -1 "$renewal_log")
    if [[ "$last_log_entry" =~ ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
      last_renewal_attempt=$(date -d "${BASH_REMATCH[1]}" +%s)
    fi
    
    # Check if last renewal was successful
    if grep -q "Certificate successfully renewed" "$renewal_log"; then
      renewal_success=1
    fi
  fi
  
  # Generate Prometheus metrics
  echo "# HELP letsencrypt_cert_exists Indicates if certificate file exists"
  echo "# TYPE letsencrypt_cert_exists gauge"
  echo "letsencrypt_cert_exists 1"
  
  echo "# HELP letsencrypt_cert_expiry_seconds Time remaining until certificate expiration in seconds"
  echo "# TYPE letsencrypt_cert_expiry_seconds gauge"
  echo "letsencrypt_cert_expiry_seconds{domain=\"$subject\",issuer=\"$issuer\"} $seconds_left"
  
  echo "# HELP letsencrypt_cert_issued_time_seconds Timestamp when certificate was issued"
  echo "# TYPE letsencrypt_cert_issued_time_seconds gauge"
  echo "letsencrypt_cert_issued_time_seconds{domain=\"$subject\",issuer=\"$issuer\"} $not_before_epoch"
  
  echo "# HELP letsencrypt_cert_valid Certificate validity (1 = valid, 0 = expired)"
  echo "# TYPE letsencrypt_cert_valid gauge"
  local valid=1
  if [[ $seconds_left -lt 0 ]]; then
    valid=0
  fi
  echo "letsencrypt_cert_valid{domain=\"$subject\",issuer=\"$issuer\"} $valid"
  
  echo "# HELP letsencrypt_tls_enabled TLS configuration enabled status"
  echo "# TYPE letsencrypt_tls_enabled gauge"
  echo "letsencrypt_tls_enabled $tls_status"
  
  echo "# HELP letsencrypt_acme_enabled ACME (Let's Encrypt) configuration enabled status"
  echo "# TYPE letsencrypt_acme_enabled gauge"
  echo "letsencrypt_acme_enabled $acme_status"
  
  if [[ -f "$renewal_log" ]]; then
    echo "# HELP letsencrypt_renewal_success Last renewal success status (1 = success, 0 = failed)"
    echo "# TYPE letsencrypt_renewal_success gauge"
    echo "letsencrypt_renewal_success{domain=\"$subject\"} $renewal_success"
    
    echo "# HELP letsencrypt_renewal_last_attempt_time_seconds Timestamp of last renewal attempt"
    echo "# TYPE letsencrypt_renewal_last_attempt_time_seconds gauge"
    echo "letsencrypt_renewal_last_attempt_time_seconds{domain=\"$subject\"} $last_renewal_attempt"
  fi
  
  return 0
}

# Function to run HTTP server
run_http_server() {
  local port=$1
  log_info "Starting HTTP server on port $port"
  
  # Create a temporary metrics file
  local temp_metrics=$(mktemp)
  
  # Handle cleanup on exit
  trap 'rm -f "$temp_metrics"' EXIT
  
  # Generate metrics
  get_certificate_metrics > "$temp_metrics"
  
  # Check if netcat is available
  if command -v nc &> /dev/null; then
    while true; do
      # Regenerate metrics before each request
      get_certificate_metrics > "$temp_metrics"
      
      # Serve HTTP using netcat
      { echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"; cat "$temp_metrics"; } | nc -l -p "$port" -q 1
      
      log_info "Metrics served at $(date)"
    done
  else
    log_error "Netcat (nc) is required for HTTP server mode but was not found"
    exit 1
  fi
}

# Function to display script usage
show_help() {
  echo "Prometheus Metrics Exporter for Let's Encrypt Certificates"
  echo
  echo "Usage: $0 [options]"
  echo
  echo "Options:"
  echo "  -c, --config FILE     Path to Elemta configuration file"
  echo "  -o, --output FILE     Output file for Prometheus metrics (default: $METRICS_FILE)"
  echo "  -w, --http            Run as HTTP server instead of writing to file"
  echo "  -p, --port PORT       HTTP server port (default: $HTTP_PORT)"
  echo "  -h, --help            Display this help message"
  echo
  echo "Examples:"
  echo "  $0                             # Write metrics to default file"
  echo "  $0 -o /tmp/le_metrics.prom     # Specify custom output file"
  echo "  $0 -w -p 8080                  # Run as HTTP server on port 8080"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--config)
      CONFIG_PARAM="$2"
      shift 2
      ;;
    -o|--output)
      METRICS_FILE="$2"
      shift 2
      ;;
    -w|--http)
      HTTP_MODE=true
      shift
      ;;
    -p|--port)
      HTTP_PORT="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Verify required commands are available
check_command openssl
check_command grep
check_command sed

# Find and set configuration file
find_config_file "$CONFIG_PARAM"

if [[ "$HTTP_MODE" == true ]]; then
  # Run as HTTP server
  run_http_server "$HTTP_PORT"
else
  # Ensure metrics directory exists
  metrics_dir=$(dirname "$METRICS_FILE")
  if [[ ! -d "$metrics_dir" ]]; then
    log_info "Creating metrics directory: $metrics_dir"
    mkdir -p "$metrics_dir"
  fi
  
  # Generate metrics and write to file
  get_certificate_metrics > "$METRICS_FILE"
  log_success "Metrics written to $METRICS_FILE"
fi

exit 0 