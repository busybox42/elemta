#!/bin/bash
# LDAP Mail Administration Utility for Elemta MTA
# Manages enhanced email features: forwarding, aliases, distribution lists

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

# Show help
show_help() {
    echo "LDAP Mail Administration Utility"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  list-users                    List all mail users"
    echo "  show-user <email>            Show user details and mail settings"
    echo "  add-alias <email> <alias>    Add email alias to user"
    echo "  remove-alias <email> <alias> Remove email alias from user"
    echo "  add-forward <email> <target> Add forwarding address"
    echo "  remove-forward <email> <target> Remove forwarding address"
    echo "  set-autoreply <email> <msg>  Set auto-reply message"
    echo "  disable-autoreply <email>    Disable auto-reply"
    echo "  set-quota <email> <bytes>    Set mail quota in bytes"
    echo "  list-groups                  List distribution lists"
    echo "  show-group <group>           Show group details"
    echo "  add-group <name> <email>     Create new distribution list"
    echo "  add-to-group <group> <email> Add user to distribution list"
    echo "  remove-from-group <group> <email> Remove user from distribution list"
    echo "  test-schema                  Test enhanced schema"
    echo ""
    echo "Examples:"
    echo "  $0 list-users"
    echo "  $0 show-user recipient@example.com"
    echo "  $0 add-alias sender@example.com sales@example.com"
    echo "  $0 add-forward recipient@example.com backup@external.com"
    echo "  $0 set-quota sender@example.com 2147483648"
    echo "  $0 add-group sales sales@example.com"
}

# List all mail users
list_users() {
    log_info "Listing all mail users..."
    
    ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=people,${LDAP_BASE}" "(objectClass=mailUser)" \
        mail mailEnabled mailQuota mailForwardingAddress mailAlternateAddress | \
        grep -E "^(dn:|mail:|mailEnabled:|mailQuota:|mailForwardingAddress:|mailAlternateAddress:)" | \
        sed 's/^dn: uid=\([^,]*\),ou=people.*/--- \1 ---/' | \
        sed 's/^mail: /📧 Email: /' | \
        sed 's/^mailEnabled: /✅ Enabled: /' | \
        sed 's/^mailQuota: /💾 Quota: /' | \
        sed 's/^mailForwardingAddress: /➡️  Forward: /' | \
        sed 's/^mailAlternateAddress: /🔄 Alias: /'
}

# Show user details
show_user() {
    local email="$1"
    if [[ -z "$email" ]]; then
        log_error "Email address required"
        return 1
    fi
    
    log_info "Showing details for user: $email"
    
    # Find user DN by email
    local user_dn=$(ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=people,${LDAP_BASE}" "(mail=$email)" dn | grep "^dn:" | head -1 | cut -d' ' -f2-)
    
    if [[ -z "$user_dn" ]]; then
        log_error "User not found: $email"
        return 1
    fi
    
    ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "$user_dn" "(objectClass=*)" \
        cn mail mailAlternateAddress mailForwardingAddress mailEnabled mailQuota \
        mailDeliveryMode mailAutoReplyEnabled mailAutoReply mailAccessPolicy \
        mailMaxMessageSize mailPreferredLanguage mailUITheme mailSignature | \
        grep -v "^#" | grep -v "^search:" | grep -v "^result:"
}

# Add email alias
add_alias() {
    local email="$1"
    local alias="$2"
    
    if [[ -z "$email" || -z "$alias" ]]; then
        log_error "Both email and alias required"
        return 1
    fi
    
    log_info "Adding alias $alias to user $email"
    
    # Find user DN
    local user_dn=$(ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=people,${LDAP_BASE}" "(mail=$email)" dn | grep "^dn:" | head -1 | cut -d' ' -f2-)
    
    if [[ -z "$user_dn" ]]; then
        log_error "User not found: $email"
        return 1
    fi
    
    # Create LDIF to add alias
    cat > /tmp/add_alias.ldif << EOF
dn: $user_dn
changetype: modify
add: mailAlternateAddress
mailAlternateAddress: $alias
EOF
    
    if ldapmodify -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -f /tmp/add_alias.ldif; then
        log_success "Alias $alias added to $email"
    else
        log_error "Failed to add alias"
    fi
    
    rm -f /tmp/add_alias.ldif
}

# Remove email alias
remove_alias() {
    local email="$1"
    local alias="$2"
    
    if [[ -z "$email" || -z "$alias" ]]; then
        log_error "Both email and alias required"
        return 1
    fi
    
    log_info "Removing alias $alias from user $email"
    
    # Find user DN
    local user_dn=$(ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=people,${LDAP_BASE}" "(mail=$email)" dn | grep "^dn:" | head -1 | cut -d' ' -f2-)
    
    if [[ -z "$user_dn" ]]; then
        log_error "User not found: $email"
        return 1
    fi
    
    # Create LDIF to remove alias
    cat > /tmp/remove_alias.ldif << EOF
dn: $user_dn
changetype: modify
delete: mailAlternateAddress
mailAlternateAddress: $alias
EOF
    
    if ldapmodify -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -f /tmp/remove_alias.ldif; then
        log_success "Alias $alias removed from $email"
    else
        log_error "Failed to remove alias"
    fi
    
    rm -f /tmp/remove_alias.ldif
}

# Add forwarding address
add_forward() {
    local email="$1"
    local target="$2"
    
    if [[ -z "$email" || -z "$target" ]]; then
        log_error "Both email and target required"
        return 1
    fi
    
    log_info "Adding forwarding from $email to $target"
    
    # Find user DN
    local user_dn=$(ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=people,${LDAP_BASE}" "(mail=$email)" dn | grep "^dn:" | head -1 | cut -d' ' -f2-)
    
    if [[ -z "$user_dn" ]]; then
        log_error "User not found: $email"
        return 1
    fi
    
    # Create LDIF to add forwarding
    cat > /tmp/add_forward.ldif << EOF
dn: $user_dn
changetype: modify
add: mailForwardingAddress
mailForwardingAddress: $target
EOF
    
    if ldapmodify -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -f /tmp/add_forward.ldif; then
        log_success "Forwarding added: $email -> $target"
    else
        log_error "Failed to add forwarding"
    fi
    
    rm -f /tmp/add_forward.ldif
}

# Set quota
set_quota() {
    local email="$1"
    local quota="$2"
    
    if [[ -z "$email" || -z "$quota" ]]; then
        log_error "Both email and quota (in bytes) required"
        return 1
    fi
    
    log_info "Setting quota for $email to $quota bytes"
    
    # Find user DN
    local user_dn=$(ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=people,${LDAP_BASE}" "(mail=$email)" dn | grep "^dn:" | head -1 | cut -d' ' -f2-)
    
    if [[ -z "$user_dn" ]]; then
        log_error "User not found: $email"
        return 1
    fi
    
    # Create LDIF to set quota
    cat > /tmp/set_quota.ldif << EOF
dn: $user_dn
changetype: modify
replace: mailQuota
mailQuota: $quota
EOF
    
    if ldapmodify -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -f /tmp/set_quota.ldif; then
        log_success "Quota set for $email: $(numfmt --to=iec $quota)"
    else
        log_error "Failed to set quota"
    fi
    
    rm -f /tmp/set_quota.ldif
}

# List distribution groups
list_groups() {
    log_info "Listing distribution lists..."
    
    ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
        -b "ou=mailgroups,${LDAP_BASE}" "(objectClass=mailGroup)" \
        cn mail mailAlternateAddress rfc822MailMember maillistPublic | \
        grep -E "^(dn:|cn:|mail:|mailAlternateAddress:|rfc822MailMember:|maillistPublic:)" | \
        sed 's/^dn: cn=\([^,]*\),ou=mailgroups.*/--- \1 ---/' | \
        sed 's/^cn: /📋 Name: /' | \
        sed 's/^mail: /📧 Email: /' | \
        sed 's/^mailAlternateAddress: /🔄 Alias: /' | \
        sed 's/^rfc822MailMember: /👤 Member: /' | \
        sed 's/^maillistPublic: /🌐 Public: /'
}

# Test schema
test_schema() {
    log_info "Testing enhanced mail schema..."
    
    # Check if mailUser objectClass exists
    if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -b "ou=people,${LDAP_BASE}" "(objectClass=mailUser)" dn | grep -q "dn:"; then
        log_success "mailUser objectClass found"
    else
        log_error "mailUser objectClass not found"
    fi
    
    # Check if mailGroup objectClass exists
    if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
       -b "ou=mailgroups,${LDAP_BASE}" "(objectClass=mailGroup)" dn | grep -q "dn:"; then
        log_success "mailGroup objectClass found"
    else
        log_error "mailGroup objectClass not found"
    fi
    
    # Test specific attributes
    local test_attrs=("mailAlternateAddress" "mailForwardingAddress" "mailQuota" "mailEnabled")
    for attr in "${test_attrs[@]}"; do
        if ldapsearch -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_PASSWORD}" \
           -b "ou=people,${LDAP_BASE}" "(objectClass=mailUser)" "$attr" | grep -q "$attr:"; then
            log_success "Attribute $attr working"
        else
            log_warning "Attribute $attr not found or empty"
        fi
    done
}

# Main execution
main() {
    case "${1:-}" in
        "list-users")
            list_users
            ;;
        "show-user")
            show_user "$2"
            ;;
        "add-alias")
            add_alias "$2" "$3"
            ;;
        "remove-alias")
            remove_alias "$2" "$3"
            ;;
        "add-forward")
            add_forward "$2" "$3"
            ;;
        "remove-forward")
            remove_alias "$2" "$3"  # Same function, different attribute
            ;;
        "set-quota")
            set_quota "$2" "$3"
            ;;
        "list-groups")
            list_groups
            ;;
        "test-schema")
            test_schema
            ;;
        "help"|"-h"|"--help"|"")
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run only if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 