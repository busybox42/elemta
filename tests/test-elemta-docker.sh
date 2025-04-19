#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Enable debug mode if DEBUG is set
[ -n "$DEBUG" ] && set -x

# Test configuration - IMPORTANT: container naming convention in docker-compose.yml
# Some containers have prefix elemta- (elemta-clamav, elemta-rspamd)
# Some containers have prefix elemta_ (elemta_api, elemta_metrics, elemta_node0)
# This script handles both naming conventions

# Counters for test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

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

# Function to check if a container is running - handles both naming conventions
check_container() {
    local service_name=$1
    local container_name
    
    # Handle different naming conventions in docker-compose.yml
    case $service_name in
        # Services with elemta- prefix
        clamav|rspamd)
            container_name="elemta-$service_name"
            ;;
        # Services with elemta_ prefix
        api|metrics|node0|prometheus|grafana|alertmanager)
            container_name="elemta_$service_name"
            ;;
        *)
            container_name="elemta_$service_name"
            ;;
    esac
    
    # Check if container exists and is running
    docker ps -q -f name="$container_name" | grep -q .
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Container $container_name is running${NC}"
        return 0
    else
        echo -e "${RED}✗ Container $container_name is not running${NC}"
        return 1
    fi
}

# Function to check container health status - handles both naming conventions
check_container_health() {
    local service_name=$1
    local container_name
    
    # Handle different naming conventions in docker-compose.yml
    case $service_name in
        # Services with elemta- prefix
        clamav|rspamd)
            container_name="elemta-$service_name"
            ;;
        # Services with elemta_ prefix
        api|metrics|node0|prometheus|grafana|alertmanager)
            container_name="elemta_$service_name"
            ;;
        *)
            container_name="elemta_$service_name"
            ;;
    esac
    
    # Check if container exists and is running
    if ! docker ps -q -f name="$container_name" | grep -q .; then
        echo -e "${RED}✗ Container $container_name is not running${NC}"
        return 1
    fi
    
    # Get health status
    local health=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null)
    
    # If container has no health check
    if [ -z "$health" ] || [ "$health" = "<nil>" ]; then
        echo -e "${YELLOW}! Container $container_name has no health check${NC}"
        return 0
    fi
    
    if [ "$health" = "healthy" ]; then
        echo -e "${GREEN}✓ Container $container_name is healthy${NC}"
        return 0
    else
        echo -e "${RED}✗ Container $container_name health status: $health${NC}"
        
        # Show last health check log
        echo -e "${YELLOW}  Last health check:${NC}"
        docker inspect --format='{{json .State.Health.Log}}' "$container_name" | jq -r '.[-1].Output' | sed 's/^/    /'
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
  check_container "grafana" && check_container "prometheus"
  return $?
}

# Function to test all containers health status
test_container_health() {
    print_header "Testing Container Health Status"
    
    # Only check containers that actually exist in docker-compose.yml
    local containers=("node0" "api" "metrics" "clamav" "rspamd" "prometheus" "grafana" "alertmanager")
    local all_healthy=true
    
    for container in "${containers[@]}"; do
        if ! check_container_health "$container"; then
            all_healthy=false
        fi
    done
    
    check_result $? "All required containers are healthy" "One or more containers are unhealthy"
    
    # Check logs for any obvious errors
    print_header "Checking Container Logs for Errors"
    
    for container in "${containers[@]}"; do
        # Handle different naming conventions
        local container_name
        case $container in
            # Services with elemta- prefix
            clamav|rspamd)
                container_name="elemta-$container"
                ;;
            # Services with elemta_ prefix
            api|metrics|node0|prometheus|grafana|alertmanager)
                container_name="elemta_$container"
                ;;
            *)
                container_name="elemta_$container"
                ;;
        esac
        
        echo -e "${YELLOW}Checking logs for $container_name:${NC}"
        
        # Get the last 10 lines that contain ERROR or error
        local errors=$(docker logs "$container_name" 2>&1 | grep -i "error" | tail -10)
        
        if [ -n "$errors" ]; then
            echo -e "${RED}Found errors in $container_name logs:${NC}"
            echo "$errors" | sed 's/^/    /'
        else
            echo -e "${GREEN}No obvious errors found in $container_name logs${NC}"
        fi
    done
}

# Main test function
run_tests() {
    print_header "Elemta Docker Test Suite"
    echo -e "${YELLOW}Started at $(date)${NC}\n"
    
    # Test container health
    test_container_health
  
    # Test SMTP service directly
    print_header "Testing SMTP Service"
    
    # Check if SMTP container is running (service is "elemta" in docker-compose.yml, container is elemta_node0)
    if ! check_container "node0"; then
        skip_test "SMTP connection test" "SMTP container not running"
    else
        # Simple connection test with timeout
        echo "Testing SMTP on localhost:2525..."
        timeout 5 bash -c "echo -e 'QUIT\r\n' | nc -v -w 3 localhost 2525" &>/dev/null
        check_result $? "SMTP connection test" "Failed to connect to SMTP server"
        
        # Try EHLO command
        (echo -e "EHLO elemta-test\r\nQUIT\r\n" | nc -w 3 localhost 2525) &>/dev/null
        check_result $? "SMTP EHLO command test" "EHLO command failed"
    fi
  
    # Test metrics endpoint
    print_header "Testing Metrics Endpoint"
    
    # Check if metrics container is running
    if ! check_container "metrics"; then
        skip_test "Metrics endpoint test" "Metrics container not running"
    else
        # Try to fetch metrics
        local metrics=$(curl -s -f http://localhost:8080/metrics 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$metrics" ]; then
            check_result 0 "Metrics endpoint test" 
            echo -e "${YELLOW}Sample metrics (first 5 lines):${NC}"
            echo "$metrics" | head -5 | sed 's/^/    /'
        else
            check_result 1 "Metrics endpoint test" "Failed to access metrics endpoint"
        fi
    fi
  
    # Test ClamAV service
    print_header "Testing ClamAV Service"
    
    # Check if ClamAV container is running
    if ! check_container "clamav"; then
        skip_test "ClamAV test" "ClamAV container not running"
    else
        # Try to connect to ClamAV service
        nc -z localhost 3310 &>/dev/null
        check_result $? "ClamAV service connectivity" "Failed to connect to ClamAV"
        
        # Check ClamAV version using Docker exec
        docker exec "elemta-clamav" clamdscan --version &>/dev/null
        check_result $? "ClamAV command execution" "Failed to execute clamdscan command"
    fi
  
    # Test Rspamd service
    print_header "Testing Rspamd Functionality"
    
    # Check if Rspamd container is running
    if ! check_container "rspamd"; then
        skip_test "Rspamd test" "Rspamd container not running"
    else
        # Test Rspamd ping endpoint
        local rspamd_ping=$(curl -s http://localhost:11334/ping 2>/dev/null)
        if [[ "$rspamd_ping" == "pong"* ]]; then
            check_result 0 "Rspamd ping test"
        else
            check_result 1 "Rspamd ping test" "Failed to ping Rspamd"
        fi
        
        # Test Rspamd stat endpoint
        curl -s -f http://localhost:11334/stat &>/dev/null
        check_result $? "Rspamd stat test" "Failed to access Rspamd stats"
    fi
  
    # Test monitoring stack if available
    print_header "Testing Monitoring Stack"
    
    if check_monitoring; then
        # Test Grafana
        curl -s -f http://localhost:3000/api/health &>/dev/null
        check_result $? "Grafana health check" "Failed to check Grafana health"
        
        # Test Prometheus
        curl -s -f http://localhost:9090/api/v1/status/buildinfo &>/dev/null
        check_result $? "Prometheus API check" "Failed to check Prometheus API"
        
        # Test AlertManager
        curl -s -f http://localhost:9093/api/v1/status &>/dev/null
        check_result $? "AlertManager API check" "Failed to check AlertManager API"
    else
        skip_test "Monitoring tests" "Monitoring stack not available"
    fi
  
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
    
    # Return appropriate exit code
    if [ $FAILED_TESTS -gt 0 ]; then
        return 1
    else
        return 0
    fi
}

# Run the tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_tests
    exit $?
fi 
