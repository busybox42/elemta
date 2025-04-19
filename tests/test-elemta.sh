#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test configuration
SMTP_HOST=${SMTP_HOST:-localhost}
SMTP_PORT=${SMTP_PORT:-2525}
API_HOST=${API_HOST:-localhost}
API_PORT=${API_PORT:-8080}
CLAMD_HOST=${CLAMD_HOST:-localhost}
CLAMD_PORT=${CLAMD_PORT:-3310}
RSPAMD_HOST=${RSPAMD_HOST:-localhost}
RSPAMD_PORT=${RSPAMD_PORT:-11334}
RSPAMD_MILTER_PORT=${RSPAMD_MILTER_PORT:-11332}
TEST_EMAIL="test@example.com"
TEST_RECIPIENT="recipient@example.com"

# Counters for test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Temporary files
LOG_FILE="/tmp/elemta-test-$(date +%s).log"
EMAIL_FILE="/tmp/test-email-$(date +%s).eml"

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

# Function to check the result of a test
check_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "${GREEN}✓ PASS:${NC} $2"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "${RED}✗ FAIL:${NC} $2"
        if [ -n "$3" ]; then
            echo -e "${YELLOW}  Details: $3${NC}"
        fi
    fi
}

# Function to skip a test
skip_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    echo -e "${PURPLE}⦸ SKIP:${NC} $1"
    if [ -n "$2" ]; then
        echo -e "${YELLOW}  Reason: $2${NC}"
    fi
}

# Function to check if a service is available
check_service() {
    local host=$1
    local port=$2
    local service=$3
    
    nc -z -w 5 $host $port &>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $service is available at $host:$port${NC}"
        return 0
    else
        echo -e "${RED}✗ $service is not available at $host:$port${NC}"
        return 1
    fi
}

# Function to check if monitoring is enabled
is_monitoring_enabled() {
    nc -z -w 2 localhost 3000 &>/dev/null && \
    nc -z -w 2 localhost 9090 &>/dev/null && \
    nc -z -w 2 localhost 9093 &>/dev/null
    return $?
}

# Function to create a test email
create_test_email() {
    cat > $EMAIL_FILE << EOF
From: $TEST_EMAIL
To: $TEST_RECIPIENT
Subject: Elemta Test Email

This is a test email sent by the Elemta test script.
The purpose of this email is to verify the functionality of the Elemta email platform.

Best regards,
Elemta Test Script
EOF

    if [ -f "$EMAIL_FILE" ]; then
        return 0
    else
        return 1
    fi
}

# Function to test SMTP service
test_smtp_service() {
    print_header "Testing SMTP Service"
    
    # Check if SMTP service is available
    check_service $SMTP_HOST $SMTP_PORT "SMTP Service"
    if [ $? -ne 0 ]; then
        skip_test "SMTP connection test" "SMTP service not available"
        skip_test "SMTP authentication test" "SMTP service not available"
        skip_test "SMTP message submission test" "SMTP service not available"
        return 1
    fi
    
    # Test SMTP connection
    timeout 5 telnet $SMTP_HOST $SMTP_PORT <<< "QUIT" &> $LOG_FILE
    check_result $? "SMTP connection test" "Failed to connect to SMTP server"
    
    # Test SMTP EHLO command
    echo -e "EHLO elemta-test\nQUIT" | timeout 5 telnet $SMTP_HOST $SMTP_PORT &> $LOG_FILE
    grep -q "250" $LOG_FILE
    check_result $? "SMTP EHLO command test" "EHLO command failed or returned unexpected response"
    
    # Test basic email submission if test email exists
    if create_test_email; then
        (echo "EHLO elemta-test"; 
         echo "MAIL FROM:<$TEST_EMAIL>"; 
         echo "RCPT TO:<$TEST_RECIPIENT>"; 
         echo "DATA"; 
         cat $EMAIL_FILE; 
         echo "."; 
         echo "QUIT") | timeout 10 telnet $SMTP_HOST $SMTP_PORT &> $LOG_FILE
        
        grep -q "250 2.0.0 Ok:" $LOG_FILE
        check_result $? "SMTP message submission test" "Failed to submit test email"
    else
        skip_test "SMTP message submission test" "Failed to create test email"
    fi
}

# Function to test API/Metrics endpoint
test_api_endpoint() {
    print_header "Testing API/Metrics Endpoint"
    
    # Check if API service is available
    check_service $API_HOST $API_PORT "API/Metrics Service"
    if [ $? -ne 0 ]; then
        skip_test "API health check" "API service not available"
        skip_test "Metrics endpoint check" "API service not available"
        return 1
    fi
    
    # Test the health endpoint
    curl -s -f http://$API_HOST:$API_PORT/health &> $LOG_FILE
    check_result $? "API health check" "Health endpoint returned an error"
    
    # Test the metrics endpoint
    curl -s -f http://$API_HOST:$API_PORT/metrics &> $LOG_FILE
    check_result $? "Metrics endpoint check" "Metrics endpoint returned an error"
    
    # Check for specific metrics
    grep -q "elemta_" $LOG_FILE
    check_result $? "Elemta metrics presence check" "No Elemta metrics found in the response"
}

# Function to test ClamAV
test_clamd_service() {
    print_header "Testing ClamAV Service"
    
    # Check if ClamAV service is available
    check_service $CLAMD_HOST $CLAMD_PORT "ClamAV Service"
    if [ $? -ne 0 ]; then
        skip_test "ClamAV PING test" "ClamAV service not available"
        skip_test "ClamAV version check" "ClamAV service not available"
        skip_test "ClamAV EICAR test" "ClamAV service not available"
        return 1
    fi
    
    # Test ClamAV PING command
    echo -e "PING\n" | nc $CLAMD_HOST $CLAMD_PORT &> $LOG_FILE
    grep -q "PONG" $LOG_FILE
    check_result $? "ClamAV PING test" "PING command failed or returned unexpected response"
    
    # Test ClamAV VERSION command
    echo -e "VERSION\n" | nc $CLAMD_HOST $CLAMD_PORT &> $LOG_FILE
    grep -q "ClamAV" $LOG_FILE
    check_result $? "ClamAV version check" "VERSION command failed or returned unexpected response"
    
    # Test ClamAV with EICAR test virus
    EICAR="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    echo -e "INSTREAM\n" | cat - <(echo -n -e "${EICAR}" | (printf "z%08x" $(echo -n "${EICAR}" | wc -c); cat -)) <(echo -e "\0\0\0\0") | nc $CLAMD_HOST $CLAMD_PORT &> $LOG_FILE
    grep -q "FOUND" $LOG_FILE
    check_result $? "ClamAV EICAR test" "EICAR test failed or returned unexpected response"
}

# Function to test Rspamd
test_rspamd_service() {
    print_header "Testing Rspamd Service"
    
    # Check if Rspamd service is available
    check_service $RSPAMD_HOST $RSPAMD_PORT "Rspamd Service"
    if [ $? -ne 0 ]; then
        skip_test "Rspamd ping test" "Rspamd service not available"
        skip_test "Rspamd stat check" "Rspamd service not available"
        return 1
    fi
    
    # Test Rspamd ping
    curl -s -f http://$RSPAMD_HOST:$RSPAMD_PORT/ping &> $LOG_FILE
    check_result $? "Rspamd ping test" "Failed to ping Rspamd"
    
    # Test Rspamd stat
    curl -s -f http://$RSPAMD_HOST:$RSPAMD_PORT/stat &> $LOG_FILE
    check_result $? "Rspamd stat check" "Failed to get Rspamd stats"
    
    # Check if Rspamd milter port is available
    check_service $RSPAMD_HOST $RSPAMD_MILTER_PORT "Rspamd Milter Service"
    if [ $? -ne 0 ]; then
        skip_test "Rspamd milter connection test" "Rspamd milter service not available"
    else
        # Basic connection test to milter port
        timeout 5 telnet $RSPAMD_HOST $RSPAMD_MILTER_PORT &> /dev/null
        check_result $? "Rspamd milter connection test" "Failed to connect to Rspamd milter port"
    fi
}

# Function to test monitoring stack
test_monitoring_stack() {
    print_header "Testing Monitoring Stack"
    
    if ! is_monitoring_enabled; then
        skip_test "Grafana check" "Monitoring stack not enabled"
        skip_test "Prometheus check" "Monitoring stack not enabled"
        skip_test "AlertManager check" "Monitoring stack not enabled"
        return 0
    fi
    
    # Test Grafana
    curl -s -f http://localhost:3000/api/health &> $LOG_FILE
    check_result $? "Grafana check" "Failed to connect to Grafana or health check failed"
    
    # Test Prometheus
    curl -s -f http://localhost:9090/api/v1/status/buildinfo &> $LOG_FILE
    check_result $? "Prometheus check" "Failed to connect to Prometheus or status check failed"
    
    # Test AlertManager
    curl -s -f http://localhost:9093/api/v1/status &> $LOG_FILE
    check_result $? "AlertManager check" "Failed to connect to AlertManager or status check failed"
}

# Function to run Go unit tests if available
run_unit_tests() {
    print_header "Running Go Unit Tests"
    
    if ! command -v go &> /dev/null; then
        skip_test "Go unit tests" "Go is not installed"
        return 1
    fi
    
    if [ ! -d "./tests/unit" ]; then
        skip_test "Go unit tests" "Unit test directory not found"
        return 1
    fi
    
    # Run Go unit tests
    go test -v ./tests/unit/... &> $LOG_FILE
    check_result $? "Go unit tests" "Some unit tests failed"
    
    # Count test results
    passed=$(grep -c "PASS:" $LOG_FILE || echo "0")
    failed=$(grep -c "FAIL:" $LOG_FILE || echo "0")
    skipped=$(grep -c "SKIP:" $LOG_FILE || echo "0")
    
    echo -e "${YELLOW}  Unit test summary: $passed passed, $failed failed, $skipped skipped${NC}"
}

# Main function to run all tests
run_tests() {
    echo -e "${BLUE}=======================================${NC}"
    echo -e "${BLUE}= Elemta Email Platform Test Suite =${NC}"
    echo -e "${BLUE}=======================================${NC}"
    echo -e "${YELLOW}Started at $(date)${NC}\n"
    
    # Run all test functions
    test_smtp_service
    test_api_endpoint
    test_clamd_service
    test_rspamd_service
    test_monitoring_stack
    run_unit_tests
    
    # Print test summary
    print_header "Test Summary"
    echo -e "Total tests: ${BLUE}$TOTAL_TESTS${NC}"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    echo -e "Skipped: ${PURPLE}$SKIPPED_TESTS${NC}"
    
    # Calculate success rate
    if [ $TOTAL_TESTS -gt 0 ]; then
        SUCCESS_RATE=$((($PASSED_TESTS * 100) / ($TOTAL_TESTS - $SKIPPED_TESTS)))
        echo -e "Success rate: ${YELLOW}$SUCCESS_RATE%${NC}"
    fi
    
    echo -e "\n${YELLOW}Completed at $(date)${NC}"
    echo -e "${BLUE}=======================================${NC}"
    
    # Cleanup
    rm -f $LOG_FILE $EMAIL_FILE
    
    # Return appropriate exit code
    if [ $FAILED_TESTS -gt 0 ]; then
        return 1
    else
        return 0
    fi
}

# Run tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_tests
    exit $?
fi 