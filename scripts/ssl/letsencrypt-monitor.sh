#!/bin/bash

# Let's Encrypt Monitor for Elemta
# This script periodically runs the troubleshooter, checks for problems, and attempts remediation

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default settings
CHECK_INTERVAL=24  # hours
AUTO_REMEDIATE=true
SEND_ALERTS=true
ALERT_EMAIL=""
LOG_FILE="/var/log/elemta-letsencrypt-monitor.log"
TROUBLESHOOTER_PATH="$(dirname "$0")/letsencrypt-troubleshooter.sh"
RENEWAL_THRESHOLD=14  # days
FORCE_RENEWAL_THRESHOLD=3  # days
CONFIG_FILE=""

# Usage information
function show_usage {
    echo "Usage: $0 [options] <domain>"
    echo "Options:"
    echo "  -c, --config FILE       Path to elemta.toml configuration file"
    echo "  -i, --interval HOURS    Check interval in hours (default: 24)"
    echo "  -n, --no-remediate      Disable automatic remediation"
    echo "  -e, --email ADDRESS     Email address for alerts"
    echo "  -l, --log FILE          Log file path (default: /var/log/elemta-letsencrypt-monitor.log)"
    echo "  -q, --quiet             Run in quiet mode (only log errors)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Example: $0 --email admin@example.com --interval 12 mail.example.com"
    exit 1
}

# Logging functions
function log {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color=""
    local prefix=""
    
    case $level in
        INFO)
            color=$BLUE
            prefix="INFO"
            ;;
        SUCCESS)
            color=$GREEN
            prefix="SUCCESS"
            ;;
        WARNING)
            color=$YELLOW
            prefix="WARNING"
            ;;
        ERROR)
            color=$RED
            prefix="ERROR"
            ;;
        *)
            prefix="LOG"
            ;;
    esac
    
    # Echo to console
    if [ "$QUIET_MODE" != "true" ] || [ "$level" == "ERROR" ]; then
        echo -e "${color}[${prefix}]${NC} ${message}"
    fi
    
    # Write to log file
    echo "[${timestamp}] [${prefix}] ${message}" >> "$LOG_FILE"
}

# Function to send email alerts
function send_alert {
    local subject="$1"
    local body="$2"
    
    if [ "$SEND_ALERTS" = "true" ] && [ -n "$ALERT_EMAIL" ]; then
        log "INFO" "Sending alert email to $ALERT_EMAIL"
        if command -v mail &> /dev/null; then
            echo -e "$body" | mail -s "Elemta Let's Encrypt: $subject" "$ALERT_EMAIL"
        else
            log "ERROR" "Could not send email alert - 'mail' command not found"
        fi
    fi
}

# Function to check if Elemta is running
function check_elemta_running {
    log "INFO" "Checking if Elemta is running"
    
    if command -v systemctl &> /dev/null && systemctl list-unit-files | grep -q elemta; then
        if systemctl is-active --quiet elemta; then
            log "SUCCESS" "Elemta systemd service is running"
            return 0
        else
            log "ERROR" "Elemta systemd service is not running"
            return 1
        fi
    elif [ -f /etc/init.d/elemta ]; then
        if /etc/init.d/elemta status | grep -q "running"; then
            log "SUCCESS" "Elemta init.d service is running"
            return 0
        else
            log "ERROR" "Elemta init.d service is not running"
            return 1
        fi
    elif command -v docker &> /dev/null; then
        if docker ps | grep -q elemta; then
            log "SUCCESS" "Elemta Docker container is running"
            return 0
        else
            log "ERROR" "Elemta Docker container is not running"
            return 1
        fi
    else
        log "ERROR" "Could not determine if Elemta is running"
        return 1
    fi
}

# Function to restart Elemta
function restart_elemta {
    log "WARNING" "Attempting to restart Elemta"
    
    if command -v systemctl &> /dev/null && systemctl list-unit-files | grep -q elemta; then
        systemctl restart elemta
        if systemctl is-active --quiet elemta; then
            log "SUCCESS" "Successfully restarted Elemta systemd service"
            return 0
        else
            log "ERROR" "Failed to restart Elemta systemd service"
            return 1
        fi
    elif [ -f /etc/init.d/elemta ]; then
        /etc/init.d/elemta restart
        if /etc/init.d/elemta status | grep -q "running"; then
            log "SUCCESS" "Successfully restarted Elemta init.d service"
            return 0
        else
            log "ERROR" "Failed to restart Elemta init.d service"
            return 1
        fi
    elif command -v docker &> /dev/null && docker ps -a | grep -q elemta; then
        docker_id=$(docker ps -a | grep elemta | awk '{print $1}')
        docker restart $docker_id
        if docker ps | grep -q elemta; then
            log "SUCCESS" "Successfully restarted Elemta Docker container"
            return 0
        else
            log "ERROR" "Failed to restart Elemta Docker container"
            return 1
        fi
    else
        log "ERROR" "Could not determine how to restart Elemta"
        return 1
    fi
}

# Function to force certificate renewal
function force_renewal {
    log "WARNING" "Attempting to force certificate renewal"
    
    # Attempt certificate renewal if Elemta provides a CLI for it
    if command -v elemta &> /dev/null; then
        log "INFO" "Using elemta CLI to force renewal"
        if elemta cert renew; then
            log "SUCCESS" "Certificate renewal initiated successfully"
            return 0
        else
            log "ERROR" "Failed to initiate certificate renewal via CLI"
            return 1
        fi
    else
        # Alternative method: restart Elemta with a flag or environment variable
        log "INFO" "No elemta CLI available, trying restart"
        restart_elemta
        return $?
    fi
}

# Function to analyze troubleshooter output
function analyze_output {
    local output_file=$1
    local issues=()
    local critical_issues=0
    local certificates_expiring=false
    local days_remaining=999
    
    log "INFO" "Analyzing troubleshooter output"
    
    # Check for critical issues
    if grep -q "ERROR.*Port 80 is not open" "$output_file"; then
        issues+=("Port 80 is not accessible for ACME challenge verification")
        critical_issues=$((critical_issues + 1))
    fi
    
    if grep -q "ERROR.*Domain does not point to this server" "$output_file"; then
        issues+=("Domain does not point to this server's IP address")
        critical_issues=$((critical_issues + 1))
    fi
    
    if grep -q "ERROR.*TLS is not enabled" "$output_file"; then
        issues+=("TLS is not enabled in the configuration")
        critical_issues=$((critical_issues + 1))
    fi
    
    if grep -q "ERROR.*ACME is not enabled" "$output_file"; then
        issues+=("ACME (Let's Encrypt) is not enabled in the configuration")
        critical_issues=$((critical_issues + 1))
    fi
    
    if grep -q "ERROR.*Certificate has EXPIRED" "$output_file"; then
        issues+=("Certificate has EXPIRED")
        certificates_expiring=true
        days_remaining=0
        critical_issues=$((critical_issues + 1))
    fi
    
    # Check for certificate expiration
    if grep -q "WARNING.*Certificate will expire soon" "$output_file"; then
        # Extract days left
        days_line=$(grep "WARNING.*Certificate will expire soon" "$output_file")
        if [[ $days_line =~ ([0-9]+)\ days ]]; then
            days_remaining=${BASH_REMATCH[1]}
            if [ "$days_remaining" -lt "$RENEWAL_THRESHOLD" ]; then
                issues+=("Certificate will expire in $days_remaining days")
                certificates_expiring=true
                if [ "$days_remaining" -lt "$FORCE_RENEWAL_THRESHOLD" ]; then
                    critical_issues=$((critical_issues + 1))
                fi
            fi
        fi
    fi
    
    if grep -q "ERROR.*Elemta .* is not running" "$output_file"; then
        issues+=("Elemta service is not running")
        critical_issues=$((critical_issues + 1))
    fi
    
    # Summarize findings
    if [ ${#issues[@]} -eq 0 ]; then
        log "SUCCESS" "No issues found with Let's Encrypt setup"
        return 0
    else
        log "WARNING" "Found ${#issues[@]} issue(s), $critical_issues critical"
        for issue in "${issues[@]}"; do
            log "WARNING" "- $issue"
        done
        
        # Prepare and send alert if there are critical issues
        if [ $critical_issues -gt 0 ]; then
            local alert_subject="CRITICAL: Let's Encrypt issues for $DOMAIN"
            local alert_body="The following issues were found with your Let's Encrypt setup for $DOMAIN:\n\n"
            for issue in "${issues[@]}"; do
                alert_body+="- $issue\n"
            done
            alert_body+="\nPlease check your Elemta server as soon as possible.\n"
            alert_body+="\nFor more details, see: $LOG_FILE\n"
            
            send_alert "$alert_subject" "$alert_body"
        fi
        
        # Set appropriate exit status for remediation
        if [ $certificates_expiring = true ]; then
            return 2  # Certificate needs renewal
        elif [ $critical_issues -gt 0 ]; then
            return 1  # Critical issues
        else
            return 0  # Non-critical issues
        fi
    fi
}

# Function to attempt remediation
function attempt_remediation {
    local error_code=$1
    local attempts=0
    local max_attempts=3
    
    if [ "$AUTO_REMEDIATE" != "true" ]; then
        log "INFO" "Auto-remediation is disabled, skipping"
        return 1
    fi
    
    log "WARNING" "Attempting automatic remediation"
    
    case $error_code in
        1)  # Critical issues
            # First check if Elemta is running
            if ! check_elemta_running; then
                log "WARNING" "Elemta is not running, attempting to start"
                restart_elemta
                attempts=$((attempts + 1))
            fi
            ;;
        2)  # Certificate expiration
            log "WARNING" "Certificate is expiring soon, attempting forced renewal"
            force_renewal
            attempts=$((attempts + 1))
            ;;
        *)
            log "WARNING" "No specific remediation available for error code $error_code"
            return 1
            ;;
    esac
    
    if [ $attempts -gt 0 ]; then
        # Wait for changes to take effect
        log "INFO" "Waiting 60 seconds for changes to take effect"
        sleep 60
        
        # Run troubleshooter again to see if remediation helped
        local output_file="/tmp/elemta-troubleshooter-remediation.log"
        log "INFO" "Running troubleshooter again to verify remediation"
        bash "$TROUBLESHOOTER_PATH" "$DOMAIN" "$CONFIG_FILE" > "$output_file" 2>&1
        
        # Analyze results
        analyze_output "$output_file"
        local new_status=$?
        
        if [ $new_status -eq 0 ]; then
            log "SUCCESS" "Remediation was successful"
            send_alert "Remediation Successful" "Automatic remediation of Let's Encrypt issues for $DOMAIN was successful."
            return 0
        else
            log "ERROR" "Remediation was not completely successful (status: $new_status)"
            send_alert "Remediation Incomplete" "Automatic remediation of Let's Encrypt issues for $DOMAIN was not completely successful. Manual intervention may be required."
            return 1
        fi
    fi
    
    return 1
}

# Process command line arguments
QUIET_MODE=false
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -i|--interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        -n|--no-remediate)
            AUTO_REMEDIATE=false
            shift
            ;;
        -e|--email)
            ALERT_EMAIL="$2"
            shift 2
            ;;
        -l|--log)
            LOG_FILE="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        -*)
            echo "Unknown option: $1"
            show_usage
            ;;
        *)
            DOMAIN="$1"
            shift
            ;;
    esac
done

# Check if domain is provided
if [ -z "$DOMAIN" ]; then
    echo "Error: Domain name is required"
    show_usage
fi

# Check if troubleshooter exists
if [ ! -f "$TROUBLESHOOTER_PATH" ]; then
    echo "Error: Troubleshooter script not found at $TROUBLESHOOTER_PATH"
    exit 1
fi

# Create log directory if it doesn't exist
log_dir=$(dirname "$LOG_FILE")
if [ ! -d "$log_dir" ]; then
    mkdir -p "$log_dir"
    if [ $? -ne 0 ]; then
        echo "Error: Could not create log directory: $log_dir"
        exit 1
    fi
fi

# Initial check
log "INFO" "=== Let's Encrypt Monitor for Elemta ==="
log "INFO" "Starting initial check for domain: $DOMAIN"
log "INFO" "Troubleshooter path: $TROUBLESHOOTER_PATH"

# Prepare command
troubleshooter_cmd="$TROUBLESHOOTER_PATH $DOMAIN"
if [ -n "$CONFIG_FILE" ]; then
    troubleshooter_cmd="$troubleshooter_cmd $CONFIG_FILE"
    log "INFO" "Using config file: $CONFIG_FILE"
fi

# Run troubleshooter
output_file="/tmp/elemta-troubleshooter.log"
log "INFO" "Running troubleshooter and saving output to $output_file"
bash $troubleshooter_cmd > "$output_file" 2>&1
exit_code=$?

if [ $exit_code -ne 0 ]; then
    log "ERROR" "Troubleshooter failed with exit code $exit_code"
    cat "$output_file" >> "$LOG_FILE"  # Append troubleshooter output to our log
    exit $exit_code
fi

# Analyze the output
analyze_output "$output_file"
analysis_status=$?

# Attempt remediation if necessary
if [ $analysis_status -ne 0 ]; then
    attempt_remediation $analysis_status
    remediation_status=$?
    
    if [ $remediation_status -eq 0 ]; then
        log "SUCCESS" "Automatic remediation was successful"
    else
        log "WARNING" "Automatic remediation was not completely successful"
    fi
fi

# Add to cron if running in standalone mode and not already in cron
if [ -t 1 ] && [ "$CHECK_INTERVAL" -gt 0 ]; then
    # Only suggest cron if we're in a terminal
    log "INFO" "To schedule regular checks, add the following to your crontab:"
    log "INFO" "0 */$CHECK_INTERVAL * * * $(readlink -f "$0") --quiet $DOMAIN"
    
    # Ask if user wants to install cron job
    if [ "$QUIET_MODE" != "true" ]; then
        read -p "Would you like to install this cron job now? (y/n): " install_cron
        if [ "$install_cron" = "y" ] || [ "$install_cron" = "Y" ]; then
            (crontab -l 2>/dev/null || echo "") | grep -v "$(basename "$0") --quiet $DOMAIN" > /tmp/elemta-crontab
            echo "0 */$CHECK_INTERVAL * * * $(readlink -f "$0") --quiet $DOMAIN" >> /tmp/elemta-crontab
            if crontab /tmp/elemta-crontab; then
                log "SUCCESS" "Cron job installed successfully"
            else
                log "ERROR" "Failed to install cron job"
            fi
            rm /tmp/elemta-crontab
        fi
    fi
fi

log "INFO" "Monitoring run completed"
exit $analysis_status
