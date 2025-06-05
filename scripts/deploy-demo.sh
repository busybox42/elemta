#!/bin/bash

# Elemta Demo Environment Deployment
# Deploys complete test environment with 10 users, distribution lists, and forwarding

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

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

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker is running
    if ! docker ps &>/dev/null; then
        log_error "Docker is not running or not accessible"
        exit 1
    fi
    
    # Check if LDAP container is running
    if ! docker ps | grep -q elemta-ldap; then
        log_error "LDAP container (elemta-ldap) is not running"
        log_info "Please start the Elemta stack first: docker-compose up -d"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

clear_existing_data() {
    log_info "Clearing existing LDAP data..."
    
    # Remove existing users (ignore errors if they don't exist)
    docker exec elemta-ldap ldapdelete -x -D "cn=admin,dc=example,dc=com" -w admin -r "ou=people,dc=example,dc=com" 2>/dev/null || true
    docker exec elemta-ldap ldapdelete -x -D "cn=admin,dc=example,dc=com" -w admin -r "ou=groups,dc=example,dc=com" 2>/dev/null || true
    docker exec elemta-ldap ldapdelete -x -D "cn=admin,dc=example,dc=com" -w admin -r "ou=mailgroups,dc=example,dc=com" 2>/dev/null || true
    docker exec elemta-ldap ldapdelete -x -D "cn=admin,dc=example,dc=com" -w admin -r "ou=domains,dc=example,dc=com" 2>/dev/null || true
    
    log_success "Existing data cleared"
}

deploy_ldap_data() {
    log_info "Deploying demo LDAP data..."
    
    # Copy and deploy the demo LDIF
    docker cp "$ROOT_DIR/docker/ldap/demo-complete.ldif" elemta-ldap:/tmp/
    
    if docker exec elemta-ldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin -f /tmp/demo-complete.ldif; then
        log_success "LDAP data deployed successfully"
    else
        log_error "Failed to deploy LDAP data"
        return 1
    fi
}

create_user_directories() {
    log_info "Creating user mail directories..."
    
    # Get list of users from LDAP
    users=(
        "demo@example.com"
        "john.smith@example.com"
        "sarah.johnson@example.com"
        "mike.davis@example.com"
        "alice.wilson@example.com"
        "tom.anderson@example.com"
        "lisa.chen@example.com"
        "robert.kim@example.com"
        "emily.brown@example.com"
        "david.martinez@example.com"
    )
    
    # Create directories for each user
    for user in "${users[@]}"; do
        docker run --rm -v elemta_dovecot_data:/var/mail alpine:latest sh -c "
            mkdir -p /var/mail/$user/{new,cur,tmp,sieve} &&
            chown -R 5000:5000 /var/mail/$user
        " || log_warning "Failed to create directories for $user"
    done
    
    log_success "User directories created"
}

sync_sieve_filters() {
    log_info "Syncing Sieve filters from LDAP..."
    
    # Ensure the sync script exists
    if ! docker exec elemta-ldap test -f /scripts/ldap-sieve-sync-simple.sh; then
        docker cp "$ROOT_DIR/docker/dovecot/ldap-sieve-sync-simple.sh" elemta-ldap:/scripts/
        docker exec elemta-ldap chmod +x /scripts/ldap-sieve-sync-simple.sh
    fi
    
    # Run the sync
    if docker exec elemta-ldap bash /scripts/ldap-sieve-sync-simple.sh; then
        log_success "Sieve filters synchronized"
    else
        log_warning "Sieve filter sync had some issues (may be non-critical)"
    fi
}

test_deployment() {
    log_info "Testing deployment..."
    
    # Test LDAP connectivity
    if docker exec elemta-ldap ldapsearch -x -b "dc=example,dc=com" "(mail=demo@example.com)" mail >/dev/null 2>&1; then
        log_success "LDAP connectivity test passed"
    else
        log_error "LDAP connectivity test failed"
        return 1
    fi
    
    # Test user count
    user_count=$(docker exec elemta-ldap ldapsearch -x -b "ou=people,dc=example,dc=com" "(objectClass=posixAccount)" mail | grep -c "mail:" || echo "0")
    if [ "$user_count" -eq "10" ]; then
        log_success "All 10 users deployed correctly"
    else
        log_warning "Expected 10 users, found $user_count"
    fi
    
    # Test distribution lists
    group_count=$(docker exec elemta-ldap ldapsearch -x -b "ou=mailgroups,dc=example,dc=com" "(objectClass=mailGroup)" mail | grep -c "mail:" || echo "0")
    if [ "$group_count" -ge "5" ]; then
        log_success "Distribution lists deployed correctly ($group_count groups)"
    else
        log_warning "Expected at least 5 distribution lists, found $group_count"
    fi
}

show_summary() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}                          DEMO DEPLOYMENT SUMMARY                          ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo -e "\n${GREEN}👥 TEST USERS (10):${NC}"
    echo -e "  📧 demo@example.com (password: demo123) - Main test account"
    echo -e "  👔 john.smith@example.com (password: password123) - CEO → forwards to alice.wilson"
    echo -e "  💻 sarah.johnson@example.com (password: password123) - CTO"
    echo -e "  💰 mike.davis@example.com (password: password123) - Sales Manager"
    echo -e "  📋 alice.wilson@example.com (password: password123) - Executive Assistant"
    echo -e "  🛠️  tom.anderson@example.com (password: password123) - Senior Developer"
    echo -e "  📈 lisa.chen@example.com (password: password123) - Marketing Manager → forwards to marketing-team"
    echo -e "  🎧 robert.kim@example.com (password: password123) - Support Engineer"
    echo -e "  🔍 emily.brown@example.com (password: password123) - QA Engineer"
    echo -e "  👥 david.martinez@example.com (password: password123) - HR Manager"
    
    echo -e "\n${GREEN}📮 DISTRIBUTION LISTS (6):${NC}"
    echo -e "  🌐 all@example.com - All company users"
    echo -e "  👔 management@example.com - Management team"
    echo -e "  💻 engineering@example.com - Engineering team"
    echo -e "  💰 revenue@example.com - Sales and Marketing"
    echo -e "  🎧 support@example.com - Support team"
    echo -e "  📈 marketing-team@example.com - Marketing team"
    
    echo -e "\n${GREEN}📧 EMAIL FORWARDING:${NC}"
    echo -e "  🔄 john.smith@example.com → alice.wilson@example.com"
    echo -e "  🔄 lisa.chen@example.com → marketing-team@example.com"
    
    echo -e "\n${GREEN}🔧 SIEVE FILTERS:${NC}"
    echo -e "  📝 Each user has custom Sieve filters for organizing email"
    echo -e "  🎯 Filters include priority handling, folder sorting, and automation"
    
    echo -e "\n${GREEN}🧪 TESTING CAPABILITIES:${NC}"
    echo -e "  ✅ SMTP authentication testing (10 different users)"
    echo -e "  ✅ Distribution list delivery testing"
    echo -e "  ✅ Email forwarding testing"
    echo -e "  ✅ Sieve filter testing (ManageSieve)"
    echo -e "  ✅ Roundcube address book integration"
    echo -e "  ✅ LDAP search and filtering"
    
    echo -e "\n${BLUE}🚀 NEXT STEPS:${NC}"
    echo -e "  1. Test Roundcube login: http://localhost:8025"
    echo -e "  2. Test ManageSieve filters interface"
    echo -e "  3. Send test emails between users"
    echo -e "  4. Run integration test suite: ./tests/integration_test_suite.sh"
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

main() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}                        ELEMTA DEMO DEPLOYMENT                         ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    check_prerequisites
    clear_existing_data
    deploy_ldap_data
    create_user_directories
    sync_sieve_filters
    test_deployment
    show_summary
    
    log_success "Demo environment deployed successfully!"
}

# Handle script arguments
if [[ $# -gt 0 ]]; then
    case $1 in
        --clear-only)
            check_prerequisites
            clear_existing_data
            log_success "Existing data cleared"
            exit 0
            ;;
        --test-only)
            check_prerequisites
            test_deployment
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clear-only    Only clear existing LDAP data"
            echo "  --test-only     Only run deployment tests"
            echo "  --help, -h      Show this help message"
            echo ""
            echo "Default: Deploy complete demo environment"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
fi

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 