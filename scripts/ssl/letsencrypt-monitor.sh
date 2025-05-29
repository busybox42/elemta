#!/usr/bin/env bash
#
# Elemta Let's Encrypt Certificate Monitoring Script
# This script sets up and integrates Let's Encrypt certificate monitoring with Prometheus
#

set -e

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths
DEFAULT_CONFIG_PATHS=(
  "/etc/elemta/elemta.toml"
  "/var/elemta/config/elemta.toml"
  "./elemta.toml"
)
CONFIG_FILE=""
CERT_DIR="/var/elemta/certs"
METRICS_PORT="9090"
INTERVAL="12h"

# Help message
function show_help {
  echo -e "${BLUE}Elemta Let's Encrypt Certificate Monitoring Script${NC}"
  echo ""
  echo "This script sets up and integrates Let's Encrypt certificate monitoring with Prometheus."
  echo ""
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  -c, --config FILE     Path to Elemta configuration file"
  echo "  -d, --cert-dir DIR    Path to certificate directory (default: /var/elemta/certs)"
  echo "  -p, --port PORT       Metrics server port (default: 9090)"
  echo "  -i, --interval TIME   Check interval (e.g., 12h, 1d) (default: 12h)"
  echo "  -h, --help            Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0 --cert-dir /etc/letsencrypt/live/mail.example.com"
  echo "  $0 --port 8080 --interval 6h"
  echo ""
}

# Function to log messages
function log_success { echo -e "${GREEN}✓ $1${NC}"; }
function log_warning { echo -e "${YELLOW}! $1${NC}"; }
function log_error { echo -e "${RED}✗ $1${NC}"; }
function log_info { echo -e "${BLUE}i $1${NC}"; }

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--config)
      CONFIG_FILE="$2"
      shift 2
      ;;
    -d|--cert-dir)
      CERT_DIR="$2"
      shift 2
      ;;
    -p|--port)
      METRICS_PORT="$2"
      shift 2
      ;;
    -i|--interval)
      INTERVAL="$2"
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

# Check if configuration file exists
function find_config_file() {
  if [[ -n "$CONFIG_FILE" ]]; then
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
      log_warning "Could not find Elemta configuration file. Using default settings."
    else
      log_info "Using configuration file: $CONFIG_FILE"
    fi
  fi
}

# Extract configuration values from the config file
function get_config_value() {
  local section=$1
  local key=$2
  
  if [[ -z "$CONFIG_FILE" ]]; then
    return
  fi
  
  # For simple key in main section
  if [[ "$section" == "main" ]]; then
    grep -E "^$key\s*=" "$CONFIG_FILE" | cut -d= -f2- | tr -d ' "' || echo ""
    return
  fi
  
  # For key in a specific section
  local in_section=false
  while IFS= read -r line; do
    if [[ "$line" =~ ^\[$section\] ]]; then
      in_section=true
    elif [[ "$line" =~ ^\[.*\] ]]; then
      in_section=false
    elif [[ "$in_section" == true && "$line" =~ ^$key\s*= ]]; then
      echo "$line" | cut -d= -f2- | tr -d ' "'
      return
    fi
  done < "$CONFIG_FILE"
  
  # For key in a nested section (like tls.letsencrypt)
  if [[ "$section" == *"."* ]]; then
    local parent=${section%.*}
    local child=${section#*.}
    local in_parent=false
    local in_child=false
    
    while IFS= read -r line; do
      if [[ "$line" =~ ^\[$parent\] ]]; then
        in_parent=true
      elif [[ "$in_parent" == true && "$line" =~ ^\[$child\] ]]; then
        in_child=true
      elif [[ "$line" =~ ^\[.*\] ]]; then
        in_parent=false
        in_child=false
      elif [[ "$in_child" == true && "$line" =~ ^$key\s*= ]]; then
        echo "$line" | cut -d= -f2- | tr -d ' "'
        return
      fi
    done < "$CONFIG_FILE"
  fi
  
  echo ""
}

# Check TLS and ACME configuration
function check_tls_config() {
  if [[ -z "$CONFIG_FILE" ]]; then
    log_warning "No configuration file found, unable to check TLS settings."
    return
  fi
  
  local tls_enabled=$(get_config_value "tls" "enabled")
  if [[ "$tls_enabled" != "true" ]]; then
    log_warning "TLS is not enabled in configuration."
  else
    log_success "TLS is enabled in configuration."
  fi
  
  local acme_enabled=$(get_config_value "tls.letsencrypt" "enabled")
  if [[ "$acme_enabled" != "true" ]]; then
    log_warning "Let's Encrypt integration is not enabled in configuration."
  else
    log_success "Let's Encrypt integration is enabled in configuration."
    
    local domain=$(get_config_value "tls.letsencrypt" "domain")
    if [[ -n "$domain" ]]; then
      log_info "Domain: $domain"
    fi
    
    local email=$(get_config_value "tls.letsencrypt" "email")
    if [[ -n "$email" ]]; then
      log_info "Email: $email"
    fi
    
    local cache_dir=$(get_config_value "tls.letsencrypt" "cache_dir")
    if [[ -n "$cache_dir" ]]; then
      CERT_DIR="$cache_dir"
      log_info "Using certificate directory from config: $CERT_DIR"
    fi
  fi
}

# Set up systemd service for certificate monitoring
function setup_monitoring_service() {
  log_info "Setting up certificate monitoring service..."
  
  # Create service directory if it doesn't exist
  local service_dir="/etc/systemd/system"
  if [[ ! -d "$service_dir" ]]; then
    log_warning "System does not use systemd, skipping service installation."
    return 1
  fi
  
  # Create the service file
  local service_file="$service_dir/elemta-cert-monitor.service"
  
  cat > "$service_file" <<EOF
[Unit]
Description=Elemta Certificate Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/env bash $0 --cert-dir "$CERT_DIR" --interval "$INTERVAL"
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
  
  log_success "Created service file: $service_file"
  
  # Reload systemd
  systemctl daemon-reload
  
  log_info "You can now enable and start the service with:"
  echo "  sudo systemctl enable elemta-cert-monitor.service"
  echo "  sudo systemctl start elemta-cert-monitor.service"
  
  return 0
}

# Update Prometheus configuration to scrape certificate metrics
function update_prometheus_config() {
  local prometheus_config="/etc/prometheus/prometheus.yml"
  
  if [[ ! -f "$prometheus_config" ]]; then
    log_warning "Prometheus configuration not found at $prometheus_config"
    log_info "To configure Prometheus manually, add the following job to your configuration:"
    cat <<EOF
  - job_name: 'elemta-certificates'
    static_configs:
      - targets: ['localhost:$METRICS_PORT']
    metrics_path: '/metrics'
    scrape_interval: 1h
EOF
    return 1
  fi
  
  # Check if the job already exists
  if grep -q "job_name: 'elemta-certificates'" "$prometheus_config"; then
    log_info "Prometheus already configured to scrape certificate metrics."
    return 0
  fi
  
  # Make a backup
  cp "$prometheus_config" "${prometheus_config}.bak"
  log_info "Backed up Prometheus configuration to ${prometheus_config}.bak"
  
  # Find the scrape_configs section and add our job
  local temp_file=$(mktemp)
  
  awk -v port="$METRICS_PORT" '
  /scrape_configs:/{
    print $0;
    job_added=1;
    print "  - job_name: '\''elemta-certificates'\''";
    print "    static_configs:";
    print "      - targets: ['\''localhost:" port "'\''']";
    print "    metrics_path: '\''/metrics'\''";
    print "    scrape_interval: 1h";
    next;
  }
  {print}
  ' "$prometheus_config" > "$temp_file"
  
  mv "$temp_file" "$prometheus_config"
  log_success "Updated Prometheus configuration"
  
  # Reload Prometheus
  if systemctl is-active --quiet prometheus; then
    systemctl reload prometheus
    log_success "Reloaded Prometheus service"
  else
    log_warning "Prometheus service is not active. Please restart it manually:"
    echo "  sudo systemctl restart prometheus"
  fi
  
  return 0
}

# Show metrics for existing certificates
function show_certificate_metrics() {
  log_info "Checking certificates in $CERT_DIR..."
  
  if [[ ! -d "$CERT_DIR" ]]; then
    log_warning "Certificate directory does not exist: $CERT_DIR"
    return 1
  fi
  
  local cert_files=()
  while IFS= read -r -d '' file; do
    cert_files+=("$file")
  done < <(find "$CERT_DIR" -type f -name "*.pem" -o -name "*.crt" -o -name "*.cert" -print0)
  
  if [[ ${#cert_files[@]} -eq 0 ]]; then
    log_warning "No certificate files found in $CERT_DIR"
    return 1
  fi
  
  log_success "Found ${#cert_files[@]} certificate files"
  
  # Show metrics for each certificate
  for cert_file in "${cert_files[@]}"; do
    # Skip private key files
    if [[ "$(basename "$cert_file")" == "privkey.pem" ]]; then
      continue
    fi
    
    log_info "Certificate: $cert_file"
    
    # Get certificate info
    local cert_info=$(openssl x509 -noout -text -in "$cert_file" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
      log_warning "Failed to read certificate: $cert_file"
      continue
    fi
    
    local subject=$(echo "$cert_info" | grep "Subject:" | sed 's/.*CN\s*=\s*\([^,]*\).*/\1/')
    local issuer=$(echo "$cert_info" | grep "Issuer:" | sed 's/.*CN\s*=\s*\([^,]*\).*/\1/')
    local not_before=$(openssl x509 -noout -startdate -in "$cert_file" | cut -d= -f2)
    local not_after=$(openssl x509 -noout -enddate -in "$cert_file" | cut -d= -f2)
    
    local not_before_date=$(date -d "$not_before" "+%Y-%m-%d %H:%M:%S")
    local not_after_date=$(date -d "$not_after" "+%Y-%m-%d %H:%M:%S")
    
    local current_time=$(date +%s)
    local expiry_time=$(date -d "$not_after" +%s)
    local days_left=$(( (expiry_time - current_time) / 86400 ))
    
    echo "  Subject: $subject"
    echo "  Issuer: $issuer"
    echo "  Valid from: $not_before_date"
    echo "  Valid until: $not_after_date"
    echo "  Days until expiry: $days_left"
    
    # Color-coded expiry status
    if [[ $days_left -lt 0 ]]; then
      echo -e "  Status: ${RED}EXPIRED${NC}"
    elif [[ $days_left -lt 7 ]]; then
      echo -e "  Status: ${RED}CRITICAL - Expires in less than 7 days${NC}"
    elif [[ $days_left -lt 14 ]]; then
      echo -e "  Status: ${YELLOW}WARNING - Expires in less than 14 days${NC}"
    elif [[ $days_left -lt 30 ]]; then
      echo -e "  Status: ${YELLOW}NOTICE - Expires in less than 30 days${NC}"
    else
      echo -e "  Status: ${GREEN}OK - Valid for $days_left days${NC}"
    fi
    
    echo ""
  done
  
  return 0
}

# Start the metrics server
function start_metrics_server() {
  log_info "Starting certificate metrics server on port $METRICS_PORT..."
  
  # Create metrics endpoint
  python3 -c "
import http.server
import socketserver
import os
import subprocess
import time
import threading
import re
import json
from datetime import datetime

# Certificate directory to monitor
CERT_DIR = '$CERT_DIR'
CHECK_INTERVAL = '$INTERVAL'

# Convert interval string to seconds
def parse_interval(interval_str):
    match = re.match(r'(\d+)([hms])', interval_str)
    if not match:
        return 43200  # Default: 12 hours
    
    value, unit = match.groups()
    seconds = int(value)
    
    if unit == 'm':
        seconds *= 60
    elif unit == 'h':
        seconds *= 3600
    elif unit == 'd':
        seconds *= 86400
        
    return seconds

# Get certificate metrics
def get_certificate_metrics():
    metrics = []
    
    # Find all certificate files
    cert_files = []
    for ext in ['.pem', '.crt', '.cert']:
        try:
            for root, _, files in os.walk(CERT_DIR):
                for file in files:
                    if file.endswith(ext) and file != 'privkey.pem':
                        cert_files.append(os.path.join(root, file))
        except Exception as e:
            print(f'Error scanning for certificates: {e}')
    
    for cert_file in cert_files:
        try:
            # Get certificate info using OpenSSL
            cmd = ['openssl', 'x509', '-noout', '-text', '-in', cert_file]
            cert_info = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
            
            # Extract subject and issuer
            subject_match = re.search(r'Subject:.*?CN\s*=\s*([^,\n]*)', cert_info, re.DOTALL)
            issuer_match = re.search(r'Issuer:.*?CN\s*=\s*([^,\n]*)', cert_info, re.DOTALL)
            
            subject = subject_match.group(1).strip() if subject_match else 'unknown'
            issuer = issuer_match.group(1).strip() if issuer_match else 'unknown'
            
            # Get validity dates
            cmd = ['openssl', 'x509', '-noout', '-startdate', '-enddate', '-in', cert_file]
            dates = subprocess.check_output(cmd).decode('utf-8').strip().split('\\n')
            
            not_before = dates[0].split('=')[1]
            not_after = dates[1].split('=')[1]
            
            not_before_time = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            not_after_time = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            
            # Calculate seconds until expiry
            now = datetime.now()
            seconds_until_expiry = (not_after_time - now).total_seconds()
            
            # Check if certificate is valid
            is_valid = 1 if now > not_before_time and now < not_after_time else 0
            
            # Add to metrics
            metrics.append({
                'domain': subject,
                'issuer': issuer,
                'expires': seconds_until_expiry,
                'valid': is_valid,
                'file': cert_file
            })
            
            print(f'Processed certificate {cert_file}: domain={subject}, issuer={issuer}, ' +
                  f'expires_in={seconds_until_expiry/86400:.1f} days, valid={is_valid==1}')
                  
        except Exception as e:
            print(f'Error processing certificate {cert_file}: {e}')
    
    return metrics

# Update metrics periodically
def update_metrics_loop():
    while True:
        try:
            global certificate_metrics
            certificate_metrics = get_certificate_metrics()
        except Exception as e:
            print(f'Error updating metrics: {e}')
        
        # Sleep until next check
        time.sleep(parse_interval(CHECK_INTERVAL))

# Store metrics
certificate_metrics = []

# Start metrics update thread
update_thread = threading.Thread(target=update_metrics_loop, daemon=True)
update_thread.start()

# HTTP handler for metrics endpoint
class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            # Write Prometheus metrics
            self.wfile.write(b'# HELP elemta_tls_certificate_expiry_seconds Time in seconds until certificate expiry\\n')
            self.wfile.write(b'# TYPE elemta_tls_certificate_expiry_seconds gauge\\n')
            
            self.wfile.write(b'# HELP elemta_tls_certificate_valid Whether the certificate is valid (1) or not (0)\\n')
            self.wfile.write(b'# TYPE elemta_tls_certificate_valid gauge\\n')
            
            for cert in certificate_metrics:
                domain = cert['domain'].replace('\"', '\\\\\\'')
                issuer = cert['issuer'].replace('\"', '\\\\\\'')
                
                self.wfile.write(f'elemta_tls_certificate_expiry_seconds{{domain=\"{domain}\",issuer=\"{issuer}\"}} {cert[\"expires\"]}\\n'.encode())
                self.wfile.write(f'elemta_tls_certificate_valid{{domain=\"{domain}\",issuer=\"{issuer}\"}} {cert[\"valid\"]}\\n'.encode())
                
            # Add additional metadata
            self.wfile.write(f'# HELP elemta_certificate_monitor_info Certificate monitor information\\n'.encode())
            self.wfile.write(f'# TYPE elemta_certificate_monitor_info gauge\\n'.encode())
            self.wfile.write(f'elemta_certificate_monitor_info{{version=\"1.0\",cert_dir=\"{CERT_DIR}\",interval=\"{CHECK_INTERVAL}\"}} 1\\n'.encode())
            
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            health = {'status': 'ok', 'certificates': len(certificate_metrics)}
            self.wfile.write(json.dumps(health).encode())
            
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Elemta Certificate Monitor</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    table { border-collapse: collapse; width: 100%; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    .expired { color: red; font-weight: bold; }
                    .warning { color: orange; font-weight: bold; }
                    .valid { color: green; }
                    .links { margin-top: 20px; }
                    .links a { margin-right: 10px; }
                </style>
            </head>
            <body>
                <h1>Elemta Certificate Monitor</h1>
                <p>Certificate directory: %s</p>
                <p>Check interval: %s</p>
                <h2>Certificates</h2>
                <table>
                    <tr>
                        <th>Domain</th>
                        <th>Issuer</th>
                        <th>Expires In</th>
                        <th>Status</th>
                        <th>File</th>
                    </tr>
            ''' % (CERT_DIR, CHECK_INTERVAL)
            
            for cert in certificate_metrics:
                days_left = cert['expires'] / 86400
                status = 'valid'
                status_text = 'Valid'
                
                if days_left < 0:
                    status = 'expired'
                    status_text = 'EXPIRED'
                elif days_left < 7:
                    status = 'warning'
                    status_text = 'Expires soon (< 7 days)'
                elif days_left < 30:
                    status = 'warning'
                    status_text = 'Expires soon (< 30 days)'
                
                html += '''
                <tr>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%.1f days</td>
                    <td class=\"%s\">%s</td>
                    <td>%s</td>
                </tr>
                ''' % (cert['domain'], cert['issuer'], days_left, status, status_text, cert['file'])
            
            html += '''
                </table>
                <div class=\"links\">
                    <a href=\"/metrics\">View Prometheus Metrics</a>
                    <a href=\"/health\">Health Check</a>
                </div>
            </body>
            </html>
            '''
            
            self.wfile.write(html.encode())
            
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def log_message(self, format, *args):
        # Customize logging
        print(f'{self.address_string()} - {format%args}')

# Run HTTP server
with socketserver.TCPServer(('', $METRICS_PORT), MetricsHandler) as httpd:
    print(f'Certificate metrics server started at http://localhost:$METRICS_PORT')
    print(f'Monitoring certificates in {CERT_DIR}')
    httpd.serve_forever()
" &

  # Store the PID
  SERVER_PID=$!
  
  # Wait a bit to see if the server starts successfully
  sleep 2
  if kill -0 $SERVER_PID 2>/dev/null; then
    log_success "Certificate metrics server started (PID: $SERVER_PID)"
    log_info "Available endpoints:"
    echo "  http://localhost:$METRICS_PORT/ - HTML dashboard"
    echo "  http://localhost:$METRICS_PORT/metrics - Prometheus metrics"
    echo "  http://localhost:$METRICS_PORT/health - Health check"
    
    # Save PID to file
    echo $SERVER_PID > /tmp/elemta-cert-monitor.pid
    log_info "PID saved to /tmp/elemta-cert-monitor.pid"
  else
    log_error "Failed to start metrics server"
    return 1
  fi
  
  # Wait for server to finish (this keeps the script running)
  wait $SERVER_PID
  log_info "Certificate metrics server stopped"
  
  return 0
}

# Main function
function main() {
  # Check for required tools
  for cmd in openssl python3; do
    if ! command -v $cmd >/dev/null 2>&1; then
      log_error "Required command not found: $cmd"
      exit 1
    fi
  done
  
  log_info "Elemta Let's Encrypt Certificate Monitoring"
  log_info "============================================"
  
  # Find configuration file
  find_config_file
  
  # Check TLS configuration
  check_tls_config
  
  # Check if certificate directory exists
  if [[ ! -d "$CERT_DIR" ]]; then
    log_warning "Certificate directory does not exist: $CERT_DIR"
    log_info "Creating directory: $CERT_DIR"
    mkdir -p "$CERT_DIR" || {
      log_error "Failed to create certificate directory: $CERT_DIR"
      exit 1
    }
  fi
  
  # Show metrics for existing certificates
  show_certificate_metrics
  
  # Set up monitoring service if running as root
  if [[ $EUID -eq 0 ]]; then
    setup_monitoring_service
    update_prometheus_config
  else
    log_warning "Not running as root. Skipping service installation and Prometheus configuration."
    log_info "Run as root to set up systemd service and configure Prometheus."
  fi
  
  # Start the metrics server (this will keep running until interrupted)
  start_metrics_server
  
  return 0
}

# Run the main function
main 