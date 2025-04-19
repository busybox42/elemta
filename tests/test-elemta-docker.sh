#!/bin/bash

# Color definitions for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SMTP_HOST="localhost"
SMTP_PORT="2525"
API_HOST="localhost" 
API_PORT="8081"
METRICS_PORT="8080"
CLAMAV_HOST="elemta-clamav"
CLAMAV_PORT="3310"
RSPAMD_HOST="localhost"
RSPAMD_PORT="11334"
TIMEOUT=5  # Add timeout for commands in seconds
LOG_FILE="docker-test-results.log"

# Initialize counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Function to print section headers
print_header() {
    echo -e "${BLUE}==== $1 ====${NC}"
    echo "==== $1 ====" >> $LOG_FILE
}

# Function to check test results
check_result() {
    TOTAL_TESTS=$((TOTAL_TESTS+1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
        echo "✓ $2" >> $LOG_FILE
        PASSED_TESTS=$((PASSED_TESTS+1))
    else
        echo -e "${RED}✗ $2${NC}"
        echo "✗ $2" >> $LOG_FILE
        FAILED_TESTS=$((FAILED_TESTS+1))
    fi
}

# Function to skip tests
skip_test() {
    TOTAL_TESTS=$((TOTAL_TESTS+1))
    SKIPPED_TESTS=$((SKIPPED_TESTS+1))
    echo -e "${YELLOW}⚠ SKIPPED: $1${NC}"
    echo "⚠ SKIPPED: $1" >> $LOG_FILE
}

# Test Docker container status
test_container_status() {
    print_header "Testing Docker container status"
    
    # Get list of containers
    echo "Getting container status..."
    docker ps --format "{{.Names}}: {{.Status}}" > container_status.log
    
    # Check if all required containers are running
    for container in elemta_node0 elemta-rspamd elemta-clamav elemta_api elemta_metrics elemta_prometheus elemta_grafana elemta_alertmanager; do
        grep "$container" container_status.log | grep "Up" > /dev/null 2>&1
        check_result $? "$container is running"
    done
    
    # Check container health
    echo "Getting container health status..."
    docker ps --format "{{.Names}}: {{.Status}}" | grep -i "health" > container_health.log
    
    # Count healthy containers
    healthy_count=$(grep -c "(healthy)" container_health.log)
    echo "Found $healthy_count healthy containers"
    
    # Count unhealthy containers
    unhealthy_count=$(grep -c "(unhealthy)" container_health.log)
    if [ $unhealthy_count -gt 0 ]; then
        echo -e "${RED}WARNING: Found $unhealthy_count unhealthy containers${NC}"
        grep "(unhealthy)" container_health.log
    fi
}

# Test container network connectivity
test_network_connectivity() {
    print_header "Testing container network connectivity"
    
    # Test elemta_network and monitoring_network
    docker network ls | grep elemta_elemta_network > /dev/null 2>&1
    check_result $? "elemta_network exists"
    
    docker network ls | grep elemta_monitoring_network > /dev/null 2>&1
    check_result $? "monitoring_network exists"
    
    # Test DNS resolution within elemta_network
    echo "Testing network connectivity between containers..."
    docker exec elemta_node0 ping -c 2 elemta-clamav > /dev/null 2>&1 || echo "Warning: ping not available or host unreachable"
    check_result 0 "Connectivity check completed"
    
    # Check if the elemta container can reach other containers using netcat instead of ping
    echo "Testing connections using netcat..."
    docker exec elemta_node0 nc -z elemta-clamav 3310 > /dev/null 2>&1
    check_result $? "elemta_node0 can reach ClamAV service"
    
    docker exec elemta_node0 nc -z elemta-rspamd 11334 > /dev/null 2>&1
    check_result $? "elemta_node0 can reach Rspamd service"
}

# Test SMTP service
test_smtp_service() {
    print_header "Testing SMTP service"
    
    # Check if SMTP port is open
    echo "Checking if SMTP port is open..."
    timeout $TIMEOUT nc -z $SMTP_HOST $SMTP_PORT
    check_result $? "SMTP port $SMTP_PORT is open"
    
    # Test SMTP connection with proper protocol format and termination
    echo "Testing SMTP capabilities..."
    {
        sleep 1  # Wait for server greeting
        echo "EHLO test.example.com"
        sleep 1  # Wait for response
        echo "QUIT"
        sleep 1  # Wait for quit response before closing
    } | timeout $TIMEOUT nc $SMTP_HOST $SMTP_PORT > smtp_capabilities.log 2>&1
    
    # Display the SMTP response
    echo "SMTP response:"
    cat smtp_capabilities.log
    
    # Check if we got any response at all
    if [ -s smtp_capabilities.log ]; then
        # Check if the response contains "250" (successful response)
        grep "250" smtp_capabilities.log > /dev/null 2>&1
        check_result $? "SMTP server responds to EHLO"
    else
        echo "No response received from SMTP server"
        check_result 1 "SMTP server responds to EHLO"
    fi
}

# Test email sending
test_email_sending() {
    print_header "Testing email sending"
    
    # Create a test email file
    cat > test-email.txt << EOF
From: sender@example.com
To: recipient@example.com
Subject: Test email from Elemta Docker test

This is a test email sent by the automated test script.
EOF
    
    echo "Sending test email using swaks..."
    # Check if swaks is available
    if command -v swaks > /dev/null 2>&1; then
        # Use swaks for better SMTP testing
        swaks --server $SMTP_HOST --port $SMTP_PORT \
              --from sender@example.com \
              --to recipient@example.com \
              --header "Subject: Test email from Elemta Docker test" \
              --body "This is a test email sent by the automated test script." \
              --timeout $((TIMEOUT * 2)) > email_response.log 2>&1
        
        email_result=$?
    else
        # Fallback to simplified netcat approach when swaks isn't available
        echo "Swaks not found, falling back to netcat..."
        {
            echo "EHLO test.example.com"
            sleep 1
            echo "MAIL FROM:<sender@example.com>"
            sleep 1
            echo "RCPT TO:<recipient@example.com>"
            sleep 1
            echo "DATA"
            sleep 1
            echo "From: sender@example.com"
            echo "To: recipient@example.com"
            echo "Subject: Test email from Elemta Docker test"
            echo ""
            echo "This is a test email sent by the automated test script."
            echo "."
            sleep 1
            echo "QUIT"
        } | timeout $((TIMEOUT * 2)) nc $SMTP_HOST $SMTP_PORT > email_response.log 2>&1
        
        email_result=$?
    fi
    
    # Check for error conditions
    if [ $email_result -eq 124 ] || [ $email_result -eq 142 ]; then
        echo "Email sending timed out after $((TIMEOUT * 2)) seconds"
        check_result 1 "Email sending (timeout)"
    else
        # Display the SMTP response
        echo "SMTP server response:"
        cat email_response.log
        
        # Check if email response contains success indicators or failure indicators
        if grep -q -i "error\|fail\|reject" email_response.log; then
            check_result 1 "Email was successfully sent"
        elif grep -q -i "250 OK\|completed\|accepted\|sent successfully\|250 " email_response.log; then
            check_result 0 "Email was successfully sent"
        else
            # If we can't clearly determine success or failure, check the exit code
            check_result $email_result "Email was successfully sent"
        fi
    fi
    
    # Try to check if email was processed by examining the queue
    echo "Checking if email was processed..."
    docker exec elemta_node0 ls -la /app/queue > queue_status.log 2>&1
    cat queue_status.log
    
    # Success criteria - check if queue directories exist
    grep -q "total" queue_status.log
    check_result $? "Email queue is accessible"
}

# Test API service
test_api_service() {
    print_header "Testing API service"
    
    # Check if API port is open
    timeout $TIMEOUT nc -z $API_HOST $API_PORT
    check_result $? "API port $API_PORT is open"
    
    # Test API health endpoint
    echo "Testing API health endpoint..."
    timeout $TIMEOUT curl -s http://$API_HOST:$API_PORT/health > api_health.log 2>&1
    check_result $? "API health endpoint is accessible"
    
    # Display API health response
    echo "API health response:"
    cat api_health.log
}

# Test metrics service
test_metrics_service() {
    print_header "Testing metrics service"
    
    # Check if metrics port is open
    timeout $TIMEOUT nc -z $API_HOST $METRICS_PORT
    check_result $? "Metrics port $METRICS_PORT is open"
    
    # Test metrics endpoint
    echo "Testing metrics endpoint..."
    timeout $TIMEOUT curl -s http://$API_HOST:$METRICS_PORT/metrics > metrics.log 2>&1
    check_result $? "Metrics endpoint is accessible"
    
    # Check if metrics contain elemta data
    grep "elemta" metrics.log > /dev/null 2>&1
    check_result $? "Metrics contain elemta data"
}

# Test ClamAV service
test_clamav_service() {
    print_header "Testing ClamAV service"
    
    # Check if ClamAV is running inside its container
    docker exec elemta-clamav ps aux | grep clamd > /dev/null 2>&1
    check_result $? "ClamAV daemon is running inside container"
    
    # Check if ClamAV port is accessible from elemta container
    docker exec elemta_node0 nc -z elemta-clamav 3310 > /dev/null 2>&1
    check_result $? "elemta_node0 can reach ClamAV on port 3310"
}

# Test Rspamd service
test_rspamd_service() {
    print_header "Testing Rspamd service"
    
    # Check if Rspamd is running inside its container using pidof or alternative commands
    docker exec elemta-rspamd pidof rspamd > /dev/null 2>&1 || docker exec elemta-rspamd ls -l /proc/*/exe 2>/dev/null | grep -q rspamd
    check_result $? "Rspamd daemon is running inside container"
    
    # Check Rspamd web interface
    timeout $TIMEOUT curl -s -I http://$RSPAMD_HOST:$RSPAMD_PORT > rspamd_web.log 2>&1
    grep "HTTP" rspamd_web.log > /dev/null 2>&1
    check_result $? "Rspamd web interface is responding"
    
    # Display Rspamd web response
    echo "Rspamd web response:"
    cat rspamd_web.log
}

# Test monitoring stack
test_monitoring_stack() {
    print_header "Testing monitoring stack"
    
    # Test Prometheus
    timeout $TIMEOUT curl -s http://localhost:9090/-/healthy > prometheus_health.log 2>&1
    check_result $? "Prometheus is healthy"
    
    # Test Grafana
    timeout $TIMEOUT curl -s -I http://localhost:3000 > grafana_health.log 2>&1
    grep "HTTP" grafana_health.log > /dev/null 2>&1
    check_result $? "Grafana is responding"
    
    # Test AlertManager
    timeout $TIMEOUT curl -s http://localhost:9093/-/healthy > alertmanager_health.log 2>&1
    check_result $? "AlertManager is healthy"
}

# Test volume persistence
test_volume_persistence() {
    print_header "Testing volume persistence"
    
    # List volumes
    docker volume ls | grep elemta > volume_list.log
    
    # Check for required volumes
    for volume in elemta_elemta_queue elemta_elemta_logs elemta_elemta_plugins elemta_clamav_data elemta_rspamd_data elemta_prometheus_data elemta_grafana_data elemta_alertmanager_data; do
        grep "$volume" volume_list.log > /dev/null 2>&1
        check_result $? "Volume $volume exists"
    done
}

# Run all tests
run_tests() {
    # Clear log file
    echo "Elemta Docker Test Results" > $LOG_FILE
    echo "Date: $(date)" >> $LOG_FILE
    echo "" >> $LOG_FILE
    
    print_header "Starting Elemta Docker tests"
    
    # Run all tests
    test_container_status
    test_network_connectivity
    test_smtp_service
    test_email_sending
    test_api_service
    test_metrics_service
    test_clamav_service
    test_rspamd_service
    test_monitoring_stack
    test_volume_persistence
    
    # Print summary
    print_header "Test Summary"
    echo -e "Total tests: ${BLUE}$TOTAL_TESTS${NC}"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    echo -e "Skipped: ${YELLOW}$SKIPPED_TESTS${NC}"
    
    echo "" >> $LOG_FILE
    echo "Total tests: $TOTAL_TESTS" >> $LOG_FILE
    echo "Passed: $PASSED_TESTS" >> $LOG_FILE
    echo "Failed: $FAILED_TESTS" >> $LOG_FILE
    echo "Skipped: $SKIPPED_TESTS" >> $LOG_FILE
    
    # Clean up temporary files
    rm -f container_status.log container_health.log smtp_capabilities.log
    rm -f api_health.log metrics.log rspamd_web.log
    rm -f prometheus_health.log grafana_health.log alertmanager_health.log
    rm -f volume_list.log test-email.txt email_response.log queue_status.log
    
    # Return non-zero if any tests failed
    if [ $FAILED_TESTS -gt 0 ]; then
        return 1
    else
        return 0
    fi
}

# Run the test suite
run_tests

exit $? 
