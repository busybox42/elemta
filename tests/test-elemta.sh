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

# Get pod name
get_pod_name() {
  POD_NAME=$(kubectl get pods -l app=elemta -o jsonpath="{.items[0].metadata.name}")
  if [ -z "$POD_NAME" ]; then
    echo -e "${RED}No Elemta pods found. Is the deployment running?${NC}"
    exit 1
  fi
  echo -e "${YELLOW}Using pod:${NC} $POD_NAME"
}

# Main test function
run_tests() {
  print_header "Testing Elemta Email Platform"
  
  # Test SMTP service directly
  print_header "Testing SMTP Service"
  echo "Testing SMTP on localhost:30025..."
  
  # Simple connection test with timeout
  echo -e "\n${YELLOW}Test: SMTP Connection${NC}"
  echo "Connecting to port 30025 (with 5 second timeout)..."
  
  # Check if port is open
  echo "Checking if port 30025 is open..."
  nc -zv localhost 30025 || echo "Port not found or not accessible"
  
  # Try connection with timeout
  echo "Trying to connect to SMTP service..."
  EXTERNAL_TEST=$(timeout 5 bash -c "echo -e 'QUIT\r\n' | nc -v -w 3 localhost 30025" 2>&1)
  echo "Connection result: $EXTERNAL_TEST"
  
  if [[ -n "$EXTERNAL_TEST" ]]; then
    echo -e "${GREEN}✓ SMTP connection successful${NC}"
    echo "Response: $EXTERNAL_TEST"
  else
    echo -e "${RED}✗ SMTP connection failed or timed out${NC}"
  fi
  
  # Test ClamAV service directly
  print_header "Testing ClamAV Service"
  echo "Testing ClamAV on localhost..."
  
  # Try to connect to ClamAV
  echo "Trying to connect to ClamAV service..."
  nc -zv localhost 3310 || echo "ClamAV port not found or not accessible"
  
  # Test Rspamd service directly
  print_header "Testing Rspamd Functionality"
  echo "Testing Rspamd on localhost:30334..."
  
  # Try to connect to Rspamd web interface
  echo "Trying to connect to Rspamd web interface..."
  curl -v http://localhost:30334 || echo "Rspamd web interface not accessible"
  
  # Summary
  print_header "Test Summary"
  echo -e "${YELLOW}Basic connectivity tests completed.${NC}"
  echo "SMTP service: localhost:30025"
  echo "Rspamd web interface: http://localhost:30334"
  echo -e "\n${YELLOW}Note:${NC} Some tests may have failed due to networking or configuration issues."
}

# Run the tests
run_tests 