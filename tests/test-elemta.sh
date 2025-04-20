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
API_PORT="8080"
CLAMAV_HOST="localhost"
CLAMAV_PORT="3310"
RSPAMD_HOST="localhost"
RSPAMD_PORT="11334"
MONITORING_ENABLED=true
LOG_FILE="test-results.log"
TIMEOUT=5  # Add timeout for commands in seconds

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

# Function to check if a service is up
check_service() {
    echo "Checking service $1:$2"
    timeout $TIMEOUT nc -z $1 $2 > /dev/null 2>&1
    return $?
}

# Function to create test email
create_test_email() {
    local file=$1
    local subject=$2
    local content=$3
    
    cat > $file << EOF
From: sender@example.com
To: recipient@example.com
Subject: $subject

$content
EOF
    echo "Created test email: $file"
}

# Function to test SMTP connectivity
test_smtp_connectivity() {
    print_header "Testing SMTP connectivity"
    check_service $SMTP_HOST $SMTP_PORT
    check_result $? "SMTP service is accessible on $SMTP_HOST:$SMTP_PORT"
}

# Function to test email sending
test_email_sending() {
    print_header "Testing email sending"
    
    # Create simple test email
    create_test_email "test-email.txt" "Test Email" "This is a test email."
    
    # Send email with timeout
    echo "Sending test email..."
    timeout $TIMEOUT cat test-email.txt | nc $SMTP_HOST $SMTP_PORT > smtp_response.log 2>&1
    result=$?
    if [ $result -eq 124 ]; then
        echo "Command timed out after $TIMEOUT seconds"
        check_result 1 "Email sending timed out"
    else
        grep "250 " smtp_response.log > /dev/null 2>&1
        check_result $? "Email can be sent through SMTP"
    fi
    echo "SMTP response:"
    cat smtp_response.log
}

# Function to test metrics endpoint
test_metrics_endpoint() {
    print_header "Testing metrics endpoint"
    
    echo "Checking metrics endpoint..."
    timeout $TIMEOUT curl -s http://$API_HOST:$API_PORT/metrics > /dev/null 2>&1
    check_result $? "Metrics endpoint is accessible"
    
    # Check specific metrics if needed
    echo "Checking for elemta metrics..."
    timeout $TIMEOUT curl -s http://$API_HOST:$API_PORT/metrics | grep "elemta" > /dev/null 2>&1
    check_result $? "Elemta metrics are present"
}

# Function to test ClamAV
test_clamav() {
    print_header "Testing ClamAV antivirus"
    
    check_service $CLAMAV_HOST $CLAMAV_PORT
    if [ $? -eq 0 ]; then
        # Create test email with EICAR test signature
        create_test_email "virus-test.txt" "Virus Test" "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        # Send email with virus test
        echo "Sending virus test email..."
        timeout $TIMEOUT cat virus-test.txt | nc $SMTP_HOST $SMTP_PORT > virus_response.log 2>&1
        result=$?
        if [ $result -eq 124 ]; then
            echo "Command timed out after $TIMEOUT seconds"
            check_result 1 "Virus email sending timed out"
        else
            grep "550 " virus_response.log > /dev/null 2>&1
            check_result $? "ClamAV detects and rejects EICAR test file"
        fi
        echo "Virus response:"
        cat virus_response.log
    else
        skip_test "ClamAV service not accessible"
    fi
}

# Function to test Rspamd
test_rspamd() {
    print_header "Testing Rspamd"
    
    check_service $RSPAMD_HOST $RSPAMD_PORT
    if [ $? -eq 0 ]; then
        # Test Rspamd controller status
        echo "Checking Rspamd controller..."
        timeout $TIMEOUT curl -s http://$RSPAMD_HOST:$RSPAMD_PORT/stat > rspamd_stat.log 2>&1
        check_result $? "Rspamd controller is accessible"
        echo "Rspamd stat response:"
        cat rspamd_stat.log
        
        # Create spam test email
        create_test_email "spam-test.txt" "Make money fast!" "This is definitely not spam, but you can make $1,000,000 working from home! Buy now! Free! Discount!"
        
        # Send spam test email
        echo "Sending spam test email..."
        timeout $TIMEOUT cat spam-test.txt | nc $SMTP_HOST $SMTP_PORT > spam_response.log 2>&1
        result=$?
        if [ $result -eq 124 ]; then
            echo "Command timed out after $TIMEOUT seconds"
            check_result 1 "Spam email sending timed out"
        else
            check_result $? "Email with spam characteristics processed"
        fi
        echo "Spam response:"
        cat spam_response.log
    else
        skip_test "Rspamd service not accessible"
    fi
}

# Function to test monitoring
test_monitoring() {
    if [ "$MONITORING_ENABLED" = true ]; then
        print_header "Testing monitoring stack"
        
        # Test Grafana
        echo "Checking Grafana..."
        timeout $TIMEOUT curl -s http://localhost:3000 > /dev/null 2>&1
        check_result $? "Grafana is accessible"
        
        # Test Prometheus
        echo "Checking Prometheus..."
        timeout $TIMEOUT curl -s http://localhost:9090/-/healthy > /dev/null 2>&1
        check_result $? "Prometheus is accessible and healthy"
        
        # Test AlertManager
        echo "Checking AlertManager..."
        timeout $TIMEOUT curl -s http://localhost:9093/-/healthy > /dev/null 2>&1
        check_result $? "AlertManager is accessible and healthy"
    else
        skip_test "Monitoring tests disabled"
    fi
}

# Function to run Go unit tests
test_go_units() {
    print_header "Running Go unit tests"
    
    # Run Go unit tests and capture output
    echo "Running Go unit tests..."
    timeout 30 go test -v ./... > go_tests.log 2>&1
    check_result $? "Go unit tests completed"
    
    # Parse Go test results for more detailed reporting
    passes=$(grep -c "PASS" go_tests.log)
    fails=$(grep -c "FAIL" go_tests.log)
    
    echo -e "Unit tests summary: ${GREEN}$passes passed${NC}, ${RED}$fails failed${NC}"
    echo "Unit tests summary: $passes passed, $fails failed" >> $LOG_FILE
}

# Main function to run tests
run_tests() {
    # Clear log file
    echo "Elemta Test Results" > $LOG_FILE
    echo "Date: $(date)" >> $LOG_FILE
    echo "" >> $LOG_FILE
    
    print_header "Starting Elemta tests"
    
    # Run all tests
    test_smtp_connectivity
    test_email_sending
    test_metrics_endpoint
    test_clamav
    test_rspamd
    test_monitoring
    test_go_units
    
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
    
    # Return non-zero if any tests failed
    if [ $FAILED_TESTS -gt 0 ]; then
        return 1
    else
        return 0
    fi
}

# Run the test suite
run_tests

# Cleanup
rm -f test-email.txt virus-test.txt spam-test.txt
rm -f smtp_response.log virus_response.log spam_response.log go_tests.log rspamd_stat.log

exit $? 