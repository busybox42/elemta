#!/bin/bash

# Quick Elemta Test Script for existing deployment
# Tests core functionality without deploying new services

# set -e  # Don't exit on non-zero commands, we handle errors explicitly

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
SMTP_PORT="2525"
WEB_PORT="8025"
API_PORT="8081"

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                    ELEMTA QUICK TEST SUITE                    "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

tests_passed=0
tests_failed=0

# Test SMTP connectivity
log_info "Testing SMTP connectivity..."
if timeout 5 bash -c "echo >/dev/tcp/localhost/${SMTP_PORT}" 2>/dev/null; then
    log_success "SMTP port ${SMTP_PORT} is accessible"
    ((tests_passed++))
else
    log_error "Cannot connect to SMTP port ${SMTP_PORT}"
    ((tests_failed++))
fi

# Test SMTP greeting
log_info "Testing SMTP greeting..."
greeting=$(echo -e "QUIT\r\n" | nc -w 3 localhost ${SMTP_PORT} 2>/dev/null | head -1 || echo "No response")
if [[ $greeting == *"220"* ]] && [[ $greeting == *"Elemta"* ]]; then
    log_success "SMTP greeting: $greeting"
    ((tests_passed++))
else
    log_warning "SMTP greeting: $greeting"
    ((tests_failed++))
fi

# Test web interface
log_info "Testing web interface..."
web_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${WEB_PORT}/ 2>/dev/null || echo "000")
if [ "$web_status" = "200" ]; then
    log_success "Web interface is accessible"
    ((tests_passed++))
else
    log_warning "Web interface status: $web_status"
    ((tests_failed++))
fi

# Test API
log_info "Testing API..."
api_response=$(curl -s http://localhost:${API_PORT}/api/queue/stats 2>/dev/null || echo "{}")
if [[ $api_response == *"active"* ]] && [[ $api_response == *"deferred"* ]]; then
    log_success "Queue API is working"
    ((tests_passed++))
else
    log_warning "Queue API response: $api_response"
    ((tests_failed++))
fi

# Test email sending
log_info "Testing email sending..."
smtp_response=$(mktemp)
{
    echo -e "HELO test.example.com\r"
    echo -e "MAIL FROM:<test@example.com>\r"
    echo -e "RCPT TO:<user@example.com>\r"
    echo -e "DATA\r"
    echo -e "Subject: Test\r"
    echo -e "\r"
    echo -e "Test message $(date)\r"
    echo -e ".\r"
    echo -e "QUIT\r"
} | nc -w 5 localhost ${SMTP_PORT} > "$smtp_response" 2>/dev/null

if grep -q "250.*OK" "$smtp_response"; then
    log_success "Email sent successfully"
    ((tests_passed++))
else
    log_warning "Email sending may have issues"
    head -3 "$smtp_response"
    ((tests_failed++))
fi
rm -f "$smtp_response"

# Test monitoring
log_info "Testing monitoring..."
prometheus_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/-/healthy 2>/dev/null || echo "000")
if [ "$prometheus_status" = "200" ]; then
    log_success "Prometheus is healthy"
    ((tests_passed++))
else
    log_warning "Prometheus status: $prometheus_status"
    ((tests_failed++))
fi

grafana_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health 2>/dev/null || echo "000")
if [ "$grafana_status" = "200" ]; then
    log_success "Grafana is healthy"
    ((tests_passed++))
else
    log_warning "Grafana status: $grafana_status"
    ((tests_failed++))
fi

# Test metrics
log_info "Testing metrics..."
metrics=$(curl -s http://localhost:${API_PORT}/metrics 2>/dev/null | head -5 || echo "No metrics")
if [[ $metrics == *"elemta_"* ]]; then
    log_success "Metrics endpoint is working"
    ((tests_passed++))
else
    log_warning "Metrics may not be available"
    ((tests_failed++))
fi

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                        TEST SUMMARY                        "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_success "Tests passed: $tests_passed"
if [ $tests_failed -gt 0 ]; then
    log_warning "Tests failed/warned: $tests_failed"
    log_info "Note: Some failures may be expected in development mode"
else
    log_success "All tests passed!"
fi

echo ""
log_info "Service URLs:"
log_info "  Web UI:     http://localhost:8025"
log_info "  SMTP:       localhost:2525"
log_info "  API:        http://localhost:8081"
log_info "  Prometheus: http://localhost:9090"
log_info "  Grafana:    http://localhost:3000"
log_info "  RSpamd:     http://localhost:11334" 