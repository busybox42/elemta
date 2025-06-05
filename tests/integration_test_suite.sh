#!/bin/bash

# Elemta Integration Test Suite
# Consolidates all integration tests into a single comprehensive test runner

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$TEST_DIR")"
FAILED_TESTS=()
PASSED_TESTS=()
SKIPPED_TESTS=()

# Test categories
UNIT_TESTS=true
INTEGRATION_TESTS=true
LDAP_TESTS=true
SMTP_TESTS=true
ROUNDCUBE_TESTS=true
DOCKER_TESTS=true

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

run_test() {
    local test_name="$1"
    local test_command="$2"
    local category="$3"
    
    echo -e "\n${BLUE}━━━ Running: $test_name ━━━${NC}"
    
    if eval "$test_command"; then
        log_success "$test_name"
        PASSED_TESTS+=("$category: $test_name")
        return 0
    else
        log_error "$test_name"
        FAILED_TESTS+=("$category: $test_name")
        return 1
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    # Check if Docker containers are running
    if ! docker ps | grep -q elemta; then
        log_warning "Elemta containers not running, starting them..."
        cd "$ROOT_DIR"
        docker-compose up -d
        sleep 30
    fi
    
    # Check Go
    if ! command -v go &> /dev/null; then
        log_error "Go is required but not installed"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 is required but not installed"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

run_unit_tests() {
    if [ "$UNIT_TESTS" != "true" ]; then
        log_info "Skipping unit tests"
        return 0
    fi
    
    log_info "Running Go unit tests..."
    cd "$ROOT_DIR"
    
    # Run all unit tests
    run_test "Go Unit Tests" \
        "go test -v -cover ./internal/... ./plugins/..." \
        "UNIT"
}

run_integration_tests() {
    if [ "$INTEGRATION_TESTS" != "true" ]; then
        log_info "Skipping integration tests"
        return 0
    fi
    
    log_info "Running integration tests..."
    cd "$ROOT_DIR"
    
    # Database integration tests
    if [ -f "$TEST_DIR/scripts/run-datasource-tests.sh" ]; then
        run_test "Database Integration Tests" \
            "bash tests/scripts/run-datasource-tests.sh all" \
            "INTEGRATION"
    fi
}

run_ldap_tests() {
    if [ "$LDAP_TESTS" != "true" ]; then
        log_info "Skipping LDAP tests"
        return 0
    fi
    
    log_info "Running LDAP tests..."
    cd "$TEST_DIR"
    
    # LDAP authentication test
    if [ -f "test_ldap_success.py" ]; then
        run_test "LDAP Authentication" \
            "python3 test_ldap_success.py" \
            "LDAP"
    fi
    
    # Enhanced LDAP test
    if [ -f "test-enhanced-ldap.sh" ]; then
        run_test "Enhanced LDAP Integration" \
            "bash test-enhanced-ldap.sh" \
            "LDAP"
    fi
}

run_smtp_tests() {
    if [ "$SMTP_TESTS" != "true" ]; then
        log_info "Skipping SMTP tests"
        return 0
    fi
    
    log_info "Running SMTP tests..."
    cd "$TEST_DIR"
    
    # SMTP authentication test
    if [ -f "test_smtp_auth.py" ]; then
        run_test "SMTP Authentication" \
            "python3 test_smtp_auth.py" \
            "SMTP"
    fi
    
    # Complete SMTP session test
    if [ -f "test_smtp_complete.py" ]; then
        run_test "SMTP Complete Session" \
            "python3 test_smtp_complete.py" \
            "SMTP"
    fi
    
    # Relay control tests
    if [ -f "test_relay_control.py" ]; then
        run_test "SMTP Relay Control" \
            "python3 test_relay_control.py" \
            "SMTP"
    fi
    
    # External relay tests
    if [ -f "test_external_relay.py" ]; then
        run_test "SMTP External Relay" \
            "python3 test_external_relay.py" \
            "SMTP"
    fi
    
    # LMTP delivery test
    if [ -f "test_lmtp_direct.py" ]; then
        run_test "LMTP Direct Delivery" \
            "python3 test_lmtp_direct.py" \
            "SMTP"
    fi
}

run_roundcube_tests() {
    if [ "$ROUNDCUBE_TESTS" != "true" ]; then
        log_info "Skipping Roundcube tests"
        return 0
    fi
    
    log_info "Running Roundcube tests..."
    cd "$TEST_DIR"
    
    # Roundcube webmail test
    if [ -f "test-roundcube-webmail.sh" ]; then
        run_test "Roundcube Webmail" \
            "bash test-roundcube-webmail.sh" \
            "ROUNDCUBE"
    fi
    
    # Roundcube login test
    if [ -f "test-roundcube-login-complete.sh" ]; then
        run_test "Roundcube Login Complete" \
            "bash test-roundcube-login-complete.sh" \
            "ROUNDCUBE"
    fi
    
    # Roundcube sending test
    if [ -f "test-roundcube-sending-simple.sh" ]; then
        run_test "Roundcube Email Sending" \
            "bash test-roundcube-sending-simple.sh" \
            "ROUNDCUBE"
    fi
}

run_docker_tests() {
    if [ "$DOCKER_TESTS" != "true" ]; then
        log_info "Skipping Docker tests"
        return 0
    fi
    
    log_info "Running Docker tests..."
    cd "$TEST_DIR"
    
    # Docker environment test
    if [ -f "test-elemta-docker.sh" ]; then
        run_test "Elemta Docker Environment" \
            "bash test-elemta-docker.sh" \
            "DOCKER"
    fi
}

print_summary() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}                            TEST SUMMARY                            ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo -e "\n${GREEN}PASSED TESTS (${#PASSED_TESTS[@]}):${NC}"
    for test in "${PASSED_TESTS[@]}"; do
        echo -e "  ✅ $test"
    done
    
    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo -e "\n${RED}FAILED TESTS (${#FAILED_TESTS[@]}):${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ❌ $test"
        done
    fi
    
    if [ ${#SKIPPED_TESTS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}SKIPPED TESTS (${#SKIPPED_TESTS[@]}):${NC}"
        for test in "${SKIPPED_TESTS[@]}"; do
            echo -e "  ⏭️  $test"
        done
    fi
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
        return 0
    else
        echo -e "${RED}❌ ${#FAILED_TESTS[@]} TEST(S) FAILED${NC}"
        return 1
    fi
}

usage() {
    echo "Usage: $0 [OPTIONS] [CATEGORIES...]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  --no-unit           Skip unit tests"
    echo "  --no-integration    Skip integration tests"
    echo "  --no-ldap           Skip LDAP tests"
    echo "  --no-smtp           Skip SMTP tests"
    echo "  --no-roundcube      Skip Roundcube tests"
    echo "  --no-docker         Skip Docker tests"
    echo ""
    echo "Categories (run specific categories only):"
    echo "  unit                Run only unit tests"
    echo "  integration         Run only integration tests"
    echo "  ldap                Run only LDAP tests"
    echo "  smtp                Run only SMTP tests"
    echo "  roundcube           Run only Roundcube tests"
    echo "  docker              Run only Docker tests"
    echo ""
    echo "Examples:"
    echo "  $0                  Run all tests"
    echo "  $0 unit smtp        Run only unit and SMTP tests"
    echo "  $0 --no-docker      Run all tests except Docker tests"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        --no-unit)
            UNIT_TESTS=false
            shift
            ;;
        --no-integration)
            INTEGRATION_TESTS=false
            shift
            ;;
        --no-ldap)
            LDAP_TESTS=false
            shift
            ;;
        --no-smtp)
            SMTP_TESTS=false
            shift
            ;;
        --no-roundcube)
            ROUNDCUBE_TESTS=false
            shift
            ;;
        --no-docker)
            DOCKER_TESTS=false
            shift
            ;;
        unit|integration|ldap|smtp|roundcube|docker)
            # If specific categories are specified, disable all first
            if [ "$1" == "unit" ] && [ "$UNIT_TESTS" == "true" ]; then
                UNIT_TESTS=false
                INTEGRATION_TESTS=false
                LDAP_TESTS=false
                SMTP_TESTS=false
                ROUNDCUBE_TESTS=false
                DOCKER_TESTS=false
            fi
            
            case $1 in
                unit) UNIT_TESTS=true ;;
                integration) INTEGRATION_TESTS=true ;;
                ldap) LDAP_TESTS=true ;;
                smtp) SMTP_TESTS=true ;;
                roundcube) ROUNDCUBE_TESTS=true ;;
                docker) DOCKER_TESTS=true ;;
            esac
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}                    ELEMTA INTEGRATION TEST SUITE                   ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    check_prerequisites
    
    # Run test categories
    run_unit_tests
    run_integration_tests
    run_ldap_tests
    run_smtp_tests
    run_roundcube_tests
    run_docker_tests
    
    print_summary
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 