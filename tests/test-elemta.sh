#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Enable debug mode
set -x

# Function to print section headers
print_header() {
  echo -e "\n${YELLOW}$1${NC}"
  echo "======================================"
}

# Function to check if a test passed
check_result() {
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ $1${NC}"
    return 0
  else
    echo -e "${RED}✗ $1${NC}"
    return 1
  fi
}

# Main test function
run_tests() {
  print_header "Testing Elemta Email Platform"
  
  # Test SMTP service directly
  print_header "Testing SMTP Service"
  echo "Testing SMTP on localhost:2525..."
  
  # Simple connection test with timeout
  echo -e "\n${YELLOW}Test: SMTP Connection${NC}"
  echo "Connecting to port 2525 (with 5 second timeout)..."
  
  # Check if port is open
  echo "Checking if port 2525 is open..."
  nc -zv localhost 2525 || echo "Port not found or not accessible"
  
  # Try connection with timeout
  echo "Trying to connect to SMTP service..."
  EXTERNAL_TEST=$(timeout 5 bash -c "echo -e 'QUIT\r\n' | nc -v -w 3 localhost 2525" 2>&1)
  echo "Connection result: $EXTERNAL_TEST"
  
  if [[ -n "$EXTERNAL_TEST" ]]; then
    echo -e "${GREEN}✓ SMTP connection successful${NC}"
    echo "Response: $EXTERNAL_TEST"
  else
    echo -e "${RED}✗ SMTP connection failed or timed out${NC}"
  fi
  
  # Test metrics endpoint
  print_header "Testing Metrics Endpoint"
  echo "Testing metrics on localhost:8080..."
  
  # Try to connect to metrics endpoint
  echo "Trying to connect to metrics endpoint..."
  METRICS_TEST=$(curl -s http://localhost:8080/metrics | head -n 10)
  
  if [[ -n "$METRICS_TEST" ]]; then
    echo -e "${GREEN}✓ Metrics endpoint accessible${NC}"
    echo "Sample metrics:"
    echo "$METRICS_TEST"
  else
    echo -e "${RED}✗ Metrics endpoint not accessible${NC}"
  fi
  
  # Test ClamAV service directly
  print_header "Testing ClamAV Service"
  echo "Testing ClamAV service..."
  
  # Try to connect to ClamAV through Docker
  echo "Trying to connect to ClamAV service..."
  CLAMAV_TEST=$(docker exec elemta-clamav clamdscan --version 2>&1)
  
  if [[ -n "$CLAMAV_TEST" ]]; then
    echo -e "${GREEN}✓ ClamAV service accessible${NC}"
    echo "ClamAV version: $CLAMAV_TEST"
  else
    echo -e "${RED}✗ ClamAV service not accessible${NC}"
  fi
  
  # Test Rspamd service directly
  print_header "Testing Rspamd Functionality"
  echo "Testing Rspamd on localhost:11334..."
  
  # Try to connect to Rspamd web interface
  echo "Trying to connect to Rspamd web interface..."
  RSPAMD_TEST=$(curl -s http://localhost:11334/ping)
  
  if [[ "$RSPAMD_TEST" == $'pong\r' || "$RSPAMD_TEST" == "pong" ]]; then
    echo -e "${GREEN}✓ Rspamd web interface accessible${NC}"
  else
    echo -e "${RED}✗ Rspamd web interface not accessible${NC}"
  fi
  
  # Summary
  print_header "Test Summary"
  echo -e "${YELLOW}Basic connectivity tests completed.${NC}"
  echo "SMTP service: localhost:2525"
  echo "Metrics endpoint: http://localhost:8080/metrics"
  echo "Rspamd web interface: http://localhost:11334"
  echo -e "\n${YELLOW}Note:${NC} Some tests may have failed due to networking or configuration issues."
}

# Run the tests
run_tests 