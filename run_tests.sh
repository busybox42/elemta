#!/bin/bash
#
# Elemta Test Runner Script
#
# This script runs the comprehensive test suite against the Docker deployment.
# It's designed to be run after any changes to validate functionality.
#
# Usage:
#     ./run_tests.sh                    # Run all tests
#     ./run_tests.sh --category basic   # Run specific category
#     ./run_tests.sh --help             # Show help

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
HOST="localhost"
PORT="2525"
CATEGORY=""
SPECIFIC_TEST=""
VERBOSE=false

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to show help
show_help() {
    echo "Elemta Test Runner Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --host HOST        SMTP server host (default: localhost)"
    echo "  --port PORT        SMTP server port (default: 2525)"
    echo "  --category CAT     Run specific test category"
    echo "  --test TEST        Run specific test"
    echo "  --list             List all available tests"
    echo "  --verbose          Verbose output"
    echo "  --help             Show this help"
    echo ""
    echo "Test Categories:"
    echo "  basic              Core SMTP functionality"
    echo "  auth               Authentication tests"
    echo "  security           Security tests (buffer overflow, injection, etc.)"
    echo "  content            Email content validation"
    echo "  memory             Memory and resource management"
    echo "  rate               Rate limiting tests"
    echo "  logging            Logging and monitoring"
    echo "  integration        End-to-end tests"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests"
    echo "  $0 --category security               # Run security tests only"
    echo "  $0 --test smtp_greeting              # Run specific test"
    echo "  $0 --host 192.168.1.100 --port 25   # Test remote server"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --category)
            CATEGORY="$2"
            shift 2
            ;;
        --test)
            SPECIFIC_TEST="$2"
            shift 2
            ;;
        --list)
            python3 test_elemta_comprehensive.py --list
            exit 0
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_status $RED "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check if Docker is running
if ! docker compose ps | grep -q "elemta-node0.*Up"; then
    print_status $RED "❌ Elemta Docker container is not running!"
    print_status $YELLOW "Please start the Docker deployment first:"
    print_status $YELLOW "  docker compose up -d"
    exit 1
fi

# Check if test script exists
if [ ! -f "test_elemta_comprehensive.py" ]; then
    print_status $RED "❌ Test script not found: test_elemta_comprehensive.py"
    exit 1
fi

# Wait for service to be ready
print_status $BLUE "🔍 Checking if SMTP service is ready..."
for i in {1..30}; do
    if timeout 5 bash -c "echo 'QUIT' | nc $HOST $PORT" >/dev/null 2>&1; then
        print_status $GREEN "✅ SMTP service is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_status $RED "❌ SMTP service is not responding after 30 seconds"
        exit 1
    fi
    sleep 1
done

# Build test command
TEST_CMD="python3 test_elemta_comprehensive.py --host $HOST --port $PORT"

if [ -n "$CATEGORY" ]; then
    TEST_CMD="$TEST_CMD --category $CATEGORY"
fi

if [ -n "$SPECIFIC_TEST" ]; then
    TEST_CMD="$TEST_CMD --test $SPECIFIC_TEST"
fi

# Run tests
print_status $BLUE "🚀 Running Elemta comprehensive tests..."
print_status $BLUE "Command: $TEST_CMD"
echo ""

# Execute the test command
if $TEST_CMD; then
    print_status $GREEN "🎉 All tests passed!"
    exit 0
else
    print_status $RED "❌ Some tests failed!"
    exit 1
fi
