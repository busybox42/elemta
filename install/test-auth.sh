#!/bin/bash
# Quick authentication test script for Elemta

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Elemta Authentication Test    ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_header

# Change to the parent directory (Elemta project root)
cd "$(dirname "$0")/.."

# Test SMTP connection
print_info "Testing SMTP connection..."
if echo "QUIT" | nc localhost 2525 >/dev/null 2>&1; then
    print_success "SMTP service is responding"
else
    print_error "SMTP service is not responding"
    exit 1
fi

# Test PLAIN authentication
print_info "Testing PLAIN authentication..."
if printf "EHLO test\nAUTH PLAIN %s\nQUIT\n" "$(printf '\0demo@example.com\0demo123' | base64)" | nc localhost 2525 2>/dev/null | grep -q "235 2.7.0 Authentication successful"; then
    print_success "PLAIN authentication working"
else
    print_error "PLAIN authentication failed"
fi

# Test LOGIN authentication
print_info "Testing LOGIN authentication..."
if printf "EHLO test\nAUTH LOGIN\n%s\n%s\nQUIT\n" "$(printf 'demo@example.com' | base64)" "$(printf 'demo123' | base64)" | nc localhost 2525 2>/dev/null | grep -q "235 2.7.0 Authentication successful"; then
    print_success "LOGIN authentication working"
else
    print_error "LOGIN authentication failed"
fi

# Test invalid authentication
print_info "Testing invalid authentication rejection..."
if printf "EHLO test\nAUTH PLAIN %s\nQUIT\n" "$(printf '\0invalid@example.com\0wrongpassword' | base64)" | nc localhost 2525 2>/dev/null | grep -q "535 5.7.8 Authentication credentials invalid"; then
    print_success "Invalid authentication correctly rejected"
else
    print_error "Invalid authentication not properly rejected"
fi

echo ""
print_success "Authentication test complete!"
echo ""
echo -e "${BLUE}📧 Available demo users:${NC}"
echo "  - demo@example.com / demo123"
echo "  - alan@example.com / password123"
echo "  - admin@example.com / admin123"
echo "  - test@example.com / test123"
echo ""
echo -e "${BLUE}🧪 Run full test suite:${NC}"
echo "  make test-docker"
