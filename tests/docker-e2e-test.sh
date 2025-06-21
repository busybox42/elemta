#!/bin/bash

# Elemta Docker End-to-End Test Suite
# Tests all Docker deployment scenarios and core functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
COMPOSE_FILE="docker-compose.yml"
TEST_EMAIL="test@example.com"
SMTP_PORT="2525"
WEB_PORT="8025"
API_PORT="8081"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test functions
test_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if ports are available
    if netstat -tlnp 2>/dev/null | grep -q ":${SMTP_PORT} "; then
        log_warning "Port ${SMTP_PORT} is already in use"
    fi
    
    log_success "Prerequisites check passed"
}

build_containers() {
    log_info "Building Docker containers..."
    
    docker-compose build --no-cache
    
    if [ $? -eq 0 ]; then
        log_success "Container build completed"
    else
        log_error "Container build failed"
        exit 1
    fi
}

deploy_services() {
    log_info "Deploying Docker services..."
    
    # Clean up any existing containers
    docker-compose down -v --remove-orphans 2>/dev/null || true
    
    # Start services
    docker-compose up -d
    
    if [ $? -eq 0 ]; then
        log_success "Services deployed"
    else
        log_error "Service deployment failed"
        exit 1
    fi
}

wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        local healthy_count=0
        local total_services=0
        
        # Count healthy services
        while read -r line; do
            if [[ $line == *"Up (healthy)"* ]]; then
                ((healthy_count++))
            fi
            if [[ $line == *"Up"* ]]; then
                ((total_services++))
            fi
        done < <(docker-compose ps)
        
        if [ $healthy_count -eq 12 ] && [ $total_services -eq 12 ]; then
            log_success "All services are healthy"
            return 0
        fi
        
        log_info "Waiting for services... ($healthy_count/12 healthy)"
        sleep 5
        ((attempt++))
    done
    
    log_error "Services failed to become healthy within timeout"
    docker-compose logs
    exit 1
}

test_smtp_connectivity() {
    log_info "Testing SMTP connectivity..."
    
    # Test basic connection
    if timeout 10 bash -c "echo >/dev/tcp/localhost/${SMTP_PORT}"; then
        log_success "SMTP port ${SMTP_PORT} is accessible"
    else
        log_error "Cannot connect to SMTP port ${SMTP_PORT}"
        return 1
    fi
    
    # Test SMTP greeting
    local greeting=$(echo -e "QUIT\r\n" | nc -w 5 localhost ${SMTP_PORT} | head -1)
    if [[ $greeting == *"220"* ]] && [[ $greeting == *"Elemta"* ]]; then
        log_success "SMTP greeting received: $greeting"
    else
        log_error "Invalid SMTP greeting: $greeting"
        return 1
    fi
}

test_web_interface() {
    log_info "Testing web interface..."
    
    # Test web interface availability
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${WEB_PORT}/)
    if [ "$status_code" = "200" ]; then
        log_success "Web interface is accessible"
    else
        log_error "Web interface returned status code: $status_code"
        return 1
    fi
    
    # Test queue API
    local queue_response=$(curl -s http://localhost:${API_PORT}/api/queue/stats)
    if [[ $queue_response == *"active"* ]] && [[ $queue_response == *"deferred"* ]]; then
        log_success "Queue API is working"
    else
        log_error "Queue API response invalid: $queue_response"
        return 1
    fi
}

test_email_flow() {
    log_info "Testing email flow..."
    
    # Create test message
    local test_message="Subject: Docker E2E Test
From: test@example.com
To: user@example.com

This is a test message from the Docker E2E test suite.
Timestamp: $(date)
"
    
    # Send email via SMTP
    {
        echo -e "HELO test.example.com\r"
        echo -e "MAIL FROM:<test@example.com>\r"
        echo -e "RCPT TO:<user@example.com>\r"
        echo -e "DATA\r"
        echo -e "$test_message"
        echo -e ".\r"
        echo -e "QUIT\r"
    } | nc -w 10 localhost ${SMTP_PORT} > /tmp/smtp_response.txt
    
    # Check SMTP response
    if grep -q "250 OK" /tmp/smtp_response.txt; then
        log_success "Email sent successfully"
    else
        log_error "Email sending failed"
        cat /tmp/smtp_response.txt
        return 1
    fi
    
    # Wait for processing
    sleep 5
    
    # Check queue stats
    local queue_stats=$(curl -s http://localhost:${API_PORT}/api/queue/stats)
    log_info "Queue stats: $queue_stats"
}

test_plugin_functionality() {
    log_info "Testing plugin functionality..."
    
    # Test RSpamd integration
    local rspamd_status=$(curl -s http://localhost:11334/stat)
    if [[ $rspamd_status == *"scanned"* ]]; then
        log_success "RSpamd plugin is working"
    else
        log_warning "RSpamd plugin may not be working properly"
    fi
    
    # Test ClamAV integration (via container logs)
    if docker-compose logs clamav | grep -q "started"; then
        log_success "ClamAV service is running"
    else
        log_warning "ClamAV service may not be running properly"
    fi
}

test_monitoring() {
    log_info "Testing monitoring stack..."
    
    # Test Prometheus
    local prometheus_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/-/healthy)
    if [ "$prometheus_status" = "200" ]; then
        log_success "Prometheus is healthy"
    else
        log_warning "Prometheus health check failed: $prometheus_status"
    fi
    
    # Test Grafana
    local grafana_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health)
    if [ "$grafana_status" = "200" ]; then
        log_success "Grafana is healthy"
    else
        log_warning "Grafana health check failed: $grafana_status"
    fi
    
    # Test metrics endpoint
    local metrics=$(curl -s http://localhost:${API_PORT}/metrics)
    if [[ $metrics == *"elemta_"* ]]; then
        log_success "Metrics endpoint is working"
    else
        log_warning "Metrics endpoint may not be working"
    fi
}

test_security() {
    log_info "Testing security features..."
    
    # Test TLS capability
    if echo | openssl s_client -connect localhost:${SMTP_PORT} -starttls smtp -verify_return_error 2>&1 | grep -q "Verify return code: 0"; then
        log_success "TLS/STARTTLS is working"
    else
        log_warning "TLS/STARTTLS may have issues"
    fi
    
    # Test authentication requirement
    local auth_test=$(echo -e "HELO test\r\nMAIL FROM:<test@example.com>\r\nQUIT\r\n" | nc -w 5 localhost ${SMTP_PORT})
    if [[ $auth_test == *"250"* ]]; then
        log_info "SMTP accepts unauthenticated connections (development mode)"
    else
        log_info "SMTP requires authentication (production mode)"
    fi
}

performance_test() {
    log_info "Running basic performance test..."
    
    # Simple connection test
    local start_time=$(date +%s%N)
    for i in {1..10}; do
        echo -e "HELO test\r\nQUIT\r\n" | nc -w 2 localhost ${SMTP_PORT} > /dev/null
    done
    local end_time=$(date +%s%N)
    
    local duration=$(( (end_time - start_time) / 1000000 ))
    local avg_per_connection=$(( duration / 10 ))
    
    log_info "10 connections completed in ${duration}ms (avg: ${avg_per_connection}ms per connection)"
    
    if [ $avg_per_connection -lt 100 ]; then
        log_success "Performance test passed"
    else
        log_warning "Performance may be slower than expected"
    fi
}

cleanup() {
    log_info "Cleaning up test environment..."
    
    # Save logs if tests failed
    if [ "${TEST_FAILED:-0}" = "1" ]; then
        local log_dir="test-logs-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$log_dir"
        docker-compose logs > "$log_dir/docker-compose.log"
        log_info "Logs saved to $log_dir/"
    fi
    
    # Stop services
    docker-compose down
    
    # Clean up temporary files
    rm -f /tmp/smtp_response.txt
    
    log_success "Cleanup completed"
}

# Main test execution
main() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "                                           ELEMTA DOCKER E2E TEST SUITE                                           "
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Setup trap for cleanup
    trap cleanup EXIT
    
    local tests_passed=0
    local tests_failed=0
    
    # Run test phases
    test_prerequisites
    
    if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
        build_containers
    fi
    
    deploy_services
    wait_for_services
    
    # Core functionality tests
    if test_smtp_connectivity; then ((tests_passed++)); else ((tests_failed++)); TEST_FAILED=1; fi
    if test_web_interface; then ((tests_passed++)); else ((tests_failed++)); TEST_FAILED=1; fi
    if test_email_flow; then ((tests_passed++)); else ((tests_failed++)); TEST_FAILED=1; fi
    
    # Extended tests
    if test_plugin_functionality; then ((tests_passed++)); else ((tests_failed++)); fi
    if test_monitoring; then ((tests_passed++)); else ((tests_failed++)); fi
    if test_security; then ((tests_passed++)); else ((tests_failed++)); fi
    
    # Performance test (optional)
    if [[ "${SKIP_PERFORMANCE:-0}" != "1" ]]; then
        if performance_test; then ((tests_passed++)); else ((tests_failed++)); fi
    fi
    
    # Summary
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "                                                  TEST SUMMARY                                                   "
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_success "Tests passed: $tests_passed"
    if [ $tests_failed -gt 0 ]; then
        log_error "Tests failed: $tests_failed"
        exit 1
    else
        log_success "All tests passed!"
    fi
}

# Handle command line arguments
case "${1:-}" in
    "help"|"-h"|"--help")
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  --skip-build     Skip container build"
        echo "  --skip-performance Skip performance test"
        echo "  help             Show this help"
        exit 0
        ;;
    "--skip-build")
        export SKIP_BUILD=1
        shift
        ;;
    "--skip-performance")
        export SKIP_PERFORMANCE=1
        shift
        ;;
esac

# Run main test suite
main "$@" 