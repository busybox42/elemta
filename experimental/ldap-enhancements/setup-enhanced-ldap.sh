#!/bin/bash
# Enhanced LDAP Setup for Elemta MTA
# Adds comprehensive email features: forwarding, aliases, distribution lists

set -e

LDAP_ADMIN_DN="cn=admin,dc=example,dc=com"
LDAP_PASSWORD="admin"
LDAP_BASE="dc=example,dc=com"
LDAP_HOST="localhost"
LDAP_PORT="389"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Wait for LDAP server to be ready
wait_for_ldap() {
    log_info "Waiting for LDAP server to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -b "${LDAP_BASE}" -s base > /dev/null 2>&1; then
            log_success "LDAP server is ready"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    log_error "LDAP server failed to start within 60 seconds"
    return 1
}

# Add enhanced mail schema
add_enhanced_schema() {
    log_info "Adding enhanced mail schema..."
    
    # Check if schema already exists
    if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -b "cn=schema,cn=config" "(cn=*enhanced-mail*)" > /dev/null 2>&1; then
        log_warning "Enhanced mail schema already exists, skipping..."
        return 0
    fi
    
    # Add the schema
    if ldapadd -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "cn=config" -w "${LDAP_PASSWORD}" \
       -f docker/ldap/enhanced-mail.ldif; then
        log_success "Enhanced mail schema added successfully"
    else
        log_error "Failed to add enhanced mail schema"
        return 1
    fi
}

# Load enhanced bootstrap data
load_enhanced_data() {
    log_info "Loading enhanced bootstrap data..."
    
    # Remove existing data first (if any)
    log_info "Cleaning existing data..."
    ldapdelete -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -r "ou=people,${LDAP_BASE}" 2>/dev/null || true
    ldapdelete -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -r "ou=groups,${LDAP_BASE}" 2>/dev/null || true
    ldapdelete -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -r "ou=mailgroups,${LDAP_BASE}" 2>/dev/null || true
    ldapdelete -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -r "ou=domains,${LDAP_BASE}" 2>/dev/null || true
    
    # Load new enhanced data
    if ldapadd -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -f docker/ldap/bootstrap-enhanced.ldif; then
        log_success "Enhanced bootstrap data loaded successfully"
    else
        log_error "Failed to load enhanced bootstrap data"
        return 1
    fi
}

# Verify schema and data
verify_setup() {
    log_info "Verifying enhanced LDAP setup..."
    
    # Check users
    log_info "Checking users..."
    local users=("sender" "recipient" "admin")
    for user in "${users[@]}"; do
        if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
           -b "uid=${user},ou=people,${LDAP_BASE}" "(objectClass=mailUser)" | grep -q "mailEnabled"; then
            log_success "User ${user} has enhanced mail attributes"
        else
            log_error "User ${user} missing mail attributes"
        fi
    done
    
    # Check mail groups
    log_info "Checking mail groups..."
    local groups=("staff" "it-dept" "management")
    for group in "${groups[@]}"; do
        if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
           -b "cn=${group},ou=mailgroups,${LDAP_BASE}" "(objectClass=mailGroup)" | grep -q "rfc822MailMember"; then
            log_success "Mail group ${group} configured correctly"
        else
            log_error "Mail group ${group} configuration issue"
        fi
    done
    
    # Check domain configuration
    log_info "Checking domain configuration..."
    if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -b "${LDAP_BASE}" "(objectClass=mailDomain)" | grep -q "mailHost"; then
        log_success "Domain mail configuration found"
    else
        log_warning "Domain mail configuration not found"
    fi
}

# Display summary
show_summary() {
    log_info "=== Enhanced LDAP Setup Summary ==="
    echo -e "${GREEN}Users with enhanced mail features:${NC}"
    echo "  • sender@example.com (with aliases: send@example.com, test.sender@example.com)"
    echo "  • recipient@example.com (with forwarding and aliases)"
    echo "  • admin@example.com (with auto-reply and multiple aliases)"
    echo ""
    echo -e "${GREEN}Distribution Lists:${NC}"
    echo "  • staff@example.com (all users)"
    echo "  • it@example.com (IT department)"
    echo "  • management@example.com (management team)"
    echo ""
    echo -e "${GREEN}Enhanced Features Available:${NC}"
    echo "  • Email forwarding (mailForwardingAddress)"
    echo "  • Email aliases (mailAlternateAddress)"
    echo "  • Auto-reply messages (mailAutoReply)"
    echo "  • Mail quotas (mailQuota)"
    echo "  • Access policies (mailAccessPolicy)"
    echo "  • Sieve filters (mailSieveFilter)"
    echo "  • Roundcube preferences (mailUITheme, mailPreferredLanguage)"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Update Elemta MTA to use enhanced attributes"
    echo "  2. Configure Dovecot for mail forwarding"
    echo "  3. Update Roundcube for enhanced LDAP integration"
    echo "  4. Test distribution lists and forwarding"
}

# Main execution
main() {
    log_info "Starting Enhanced LDAP Setup for Elemta MTA"
    
    # Wait for LDAP to be ready
    wait_for_ldap
    
    # Add enhanced schema
    add_enhanced_schema
    
    # Load enhanced data
    load_enhanced_data
    
    # Verify setup
    verify_setup
    
    # Show summary
    show_summary
    
    log_success "Enhanced LDAP setup completed successfully!"
}

# Run only if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 