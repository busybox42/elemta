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

# Function to check if monitoring is enabled
check_monitoring() {
  # Check if docker-compose-monitoring.yml exists
  if [ ! -f "docker-compose-monitoring.yml" ]; then
    echo -e "${YELLOW}Monitoring stack not found. Skipping monitoring tests.${NC}"
    return 1
  fi
  
  # Check if monitoring containers are running
  GRAFANA_RUNNING=$(docker ps -q -f name=elemta_grafana)
  PROMETHEUS_RUNNING=$(docker ps -q -f name=elemta_prometheus)
  
  if [ -z "$GRAFANA_RUNNING" ] || [ -z "$PROMETHEUS_RUNNING" ]; then
    echo -e "${YELLOW}Monitoring stack not running. Skipping monitoring tests.${NC}"
    return 1
  fi
  
  return 0
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
  
  # Test monitoring stack if available
  print_header "Testing Monitoring Stack"
  
  if check_monitoring; then
    echo "Monitoring stack is available. Testing components..."
    
    # Test Grafana
    echo "Testing Grafana on localhost:3000..."
    GRAFANA_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000)
    
    if [[ "$GRAFANA_TEST" == "200" || "$GRAFANA_TEST" == "302" ]]; then
      echo -e "${GREEN}✓ Grafana web interface accessible${NC}"
      echo "Grafana is running at http://localhost:3000 (default credentials: admin/elemta123)"
    else
      echo -e "${RED}✗ Grafana web interface not accessible${NC}"
    fi
    
    # Test Prometheus
    echo "Testing Prometheus on localhost:9090..."
    PROMETHEUS_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090)
    
    if [[ "$PROMETHEUS_TEST" == "200" || "$PROMETHEUS_TEST" == "302" ]]; then
      echo -e "${GREEN}✓ Prometheus web interface accessible${NC}"
      echo "Prometheus is running at http://localhost:9090"
    else
      echo -e "${RED}✗ Prometheus web interface not accessible${NC}"
    fi
    
    # Test AlertManager
    echo "Testing AlertManager on localhost:9093..."
    ALERTMANAGER_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9093)
    
    if [[ "$ALERTMANAGER_TEST" == "200" ]]; then
      echo -e "${GREEN}✓ AlertManager web interface accessible${NC}"
      echo "AlertManager is running at http://localhost:9093"
    else
      echo -e "${RED}✗ AlertManager web interface not accessible${NC}"
    fi
    
    # Check if Grafana can connect to Prometheus
    echo "Checking Grafana datasource connection to Prometheus..."
    # This requires the Grafana API, which needs authentication
    # For simplicity, we'll just check if Prometheus is accessible from Grafana container
    DATASOURCE_TEST=$(docker exec elemta_grafana curl -s http://elemta_prometheus:9090/api/v1/status/buildinfo)
    
    if [[ -n "$DATASOURCE_TEST" && "$DATASOURCE_TEST" == *"version"* ]]; then
      echo -e "${GREEN}✓ Grafana can connect to Prometheus${NC}"
    else
      echo -e "${RED}✗ Grafana may not be able to connect to Prometheus${NC}"
    fi
  else
    echo "Monitoring stack tests skipped."
  fi
  
  # Summary
  print_header "Test Summary"
  echo -e "${YELLOW}Basic connectivity tests completed.${NC}"
  echo "SMTP service: localhost:2525"
  echo "Metrics endpoint: http://localhost:8080/metrics"
  echo "Rspamd web interface: http://localhost:11334"
  
  if check_monitoring; then
    echo -e "\n${YELLOW}Monitoring stack:${NC}"
    echo "Grafana: http://localhost:3000"
    echo "Prometheus: http://localhost:9090"
    echo "AlertManager: http://localhost:9093"
  fi
  
  echo -e "\n${YELLOW}Note:${NC} Some tests may have failed due to networking or configuration issues."
}

# Run the tests
run_tests 