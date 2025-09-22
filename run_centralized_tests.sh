#!/bin/bash
#
# Elemta Centralized Test Runner
#
# This script provides a unified interface to run all Elemta tests using
# the centralized test suite. It replaces the need for multiple test scripts
# and provides consistent testing across different deployment types.
#
# Usage:
#     ./run_centralized_tests.sh                    # Run all tests
#     ./run_centralized_tests.sh --category security # Run security tests
#     ./run_centralized_tests.sh --test smtp-greeting # Run specific test
#     ./run_centralized_tests.sh --help              # Show help

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEPLOYMENT="docker-desktop"
HOST="localhost"
SMTP_PORT="2525"
TIMEOUT="30"
VERBOSE=false
PARALLEL=false
MAX_WORKERS="4"
CATEGORIES=""
SPECIFIC_TESTS=""
SKIP_TESTS=""

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to show help
show_help() {
    echo "Elemta Centralized Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --deployment TYPE     Deployment type (docker-desktop, docker-dev, local)"
    echo "  --host HOST          SMTP server host (default: localhost)"
    echo "  --smtp-port PORT     SMTP server port (default: 2525)"
    echo "  --timeout SECONDS    Test timeout in seconds (default: 30)"
    echo "  --category CAT       Test categories to run (can be specified multiple times)"
    echo "  --test TEST          Specific tests to run (can be specified multiple times)"
    echo "  --skip TEST          Tests to skip (can be specified multiple times)"
    echo "  --verbose, -v        Verbose output"
    echo "  --parallel, -p       Run tests in parallel"
    echo "  --max-workers N      Maximum parallel workers (default: 4)"
    echo "  --help               Show this help"
    echo ""
    echo "Test Categories:"
    echo "  deployment           Docker deployment tests"
    echo "  smtp                 SMTP protocol tests"
    echo "  auth                 Authentication tests"
    echo "  security             Security tests"
    echo "  performance          Performance tests"
    echo "  e2e                  End-to-end tests"
    echo "  monitoring           Monitoring and metrics tests"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests"
    echo "  $0 --category security               # Run security tests only"
    echo "  $0 --test smtp-greeting              # Run specific test"
    echo "  $0 --deployment docker-dev --verbose # Test dev deployment with verbose output"
    echo "  $0 --parallel --max-workers 8        # Run tests in parallel with 8 workers"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --deployment)
            DEPLOYMENT="$2"
            shift 2
            ;;
        --host)
            HOST="$2"
            shift 2
            ;;
        --smtp-port)
            SMTP_PORT="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --category)
            if [ -z "$CATEGORIES" ]; then
                CATEGORIES="--category $2"
            else
                CATEGORIES="$CATEGORIES --category $2"
            fi
            shift 2
            ;;
        --test)
            if [ -z "$SPECIFIC_TESTS" ]; then
                SPECIFIC_TESTS="--test $2"
            else
                SPECIFIC_TESTS="$SPECIFIC_TESTS --test $2"
            fi
            shift 2
            ;;
        --skip)
            if [ -z "$SKIP_TESTS" ]; then
                SKIP_TESTS="--skip $2"
            else
                SKIP_TESTS="$SKIP_TESTS --skip $2"
            fi
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --parallel|-p)
            PARALLEL=true
            shift
            ;;
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
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

# Check if centralized test script exists
if [ ! -f "test_elemta_centralized.py" ]; then
    print_status $RED "❌ Centralized test script not found: test_elemta_centralized.py"
    exit 1
fi

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    print_status $RED "❌ Python 3 is required but not installed"
    exit 1
fi

# For Docker deployments, check if Docker is running
if [[ "$DEPLOYMENT" == "docker-desktop" || "$DEPLOYMENT" == "docker-dev" ]]; then
    if ! docker compose ps | grep -q "elemta-node0.*Up"; then
        print_status $RED "❌ Elemta Docker container is not running!"
        print_status $YELLOW "Please start the Docker deployment first:"
        print_status $YELLOW "  docker compose up -d"
        exit 1
    fi
fi

# Wait for service to be ready (for Docker deployments)
if [[ "$DEPLOYMENT" == "docker-desktop" || "$DEPLOYMENT" == "docker-dev" ]]; then
    print_status $BLUE "🔍 Checking if SMTP service is ready..."
    for i in {1..30}; do
        if timeout 5 bash -c "echo 'QUIT' | nc $HOST $SMTP_PORT" >/dev/null 2>&1; then
            print_status $GREEN "✅ SMTP service is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_status $RED "❌ SMTP service is not responding after 30 seconds"
            exit 1
        fi
        sleep 1
    done
fi

# Build test command
TEST_CMD="python3 test_elemta_centralized.py --deployment $DEPLOYMENT --host $HOST --smtp-port $SMTP_PORT --timeout $TIMEOUT --max-workers $MAX_WORKERS"

if [ "$VERBOSE" = true ]; then
    TEST_CMD="$TEST_CMD --verbose"
fi

if [ "$PARALLEL" = true ]; then
    TEST_CMD="$TEST_CMD --parallel"
fi

if [ -n "$CATEGORIES" ]; then
    TEST_CMD="$TEST_CMD $CATEGORIES"
fi

if [ -n "$SPECIFIC_TESTS" ]; then
    TEST_CMD="$TEST_CMD $SPECIFIC_TESTS"
fi

if [ -n "$SKIP_TESTS" ]; then
    TEST_CMD="$TEST_CMD $SKIP_TESTS"
fi

# Run tests
print_status $BLUE "🚀 Running Elemta centralized tests..."
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
