#!/bin/bash
# User Management Script for Elemta LDAP
# Uses Docker to manage LDAP users with SSHA512 passwords

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LDAP_CONTAINER="elemta-ldap"
LDAP_ADMIN_DN="cn=admin,dc=example,dc=com"
LDAP_ADMIN_PASS="admin"
LDAP_BASE_DN="dc=example,dc=com"
PEOPLE_OU="ou=people,dc=example,dc=com"

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

# Check if LDAP container is running
check_ldap() {
    if ! docker ps | grep -q "$LDAP_CONTAINER"; then
        log_error "LDAP container '$LDAP_CONTAINER' is not running"
        exit 1
    fi
}

# Generate SSHA512 password
generate_ssha512() {
    local password="$1"
    # Use Python to generate SSHA512 since it's more reliable
    python3 -c "
import hashlib
import base64
import os
password = '$password'
salt = os.urandom(8)
hash_obj = hashlib.sha512()
hash_obj.update(password.encode('utf-8'))
hash_obj.update(salt)
digest = hash_obj.digest()
ssha512 = base64.b64encode(digest + salt).decode('ascii')
print('{SSHA512}' + ssha512)
"
}

# List all users
list_users() {
    log_info "Listing all users..."
    docker exec "$LDAP_CONTAINER" ldapsearch -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASS" \
        -b "$PEOPLE_OU" "(objectClass=inetOrgPerson)" uid mail cn | \
        grep -E "^(dn:|uid:|mail:|cn:)" | \
        awk '
        /^dn:/ { if (user) print ""; user=1; print $0 }
        /^uid:/ { print "  " $0 }
        /^mail:/ { print "  " $0 }
        /^cn:/ { print "  " $0 }
        END { if (user) print "" }
        '
}

# Add new user with SSHA512 password
add_user() {
    local email="$1"
    local password="$2"
    local first_name="$3"
    local last_name="$4"
    local display_name="$5"
    
    if [ -z "$email" ] || [ -z "$password" ] || [ -z "$first_name" ] || [ -z "$last_name" ]; then
        log_error "Usage: add-user <email> <password> <first_name> <last_name> [display_name]"
        return 1
    fi
    
    # Extract username from email
    local username=$(echo "$email" | cut -d'@' -f1 | tr '.' '_')
    local uid_number=$((5000 + $(date +%s) % 1000))
    
    # Set display name if not provided
    if [ -z "$display_name" ]; then
        display_name="$first_name $last_name"
    fi
    
    # Generate SSHA512 password
    local ssha512_pass=$(generate_ssha512 "$password")
    
    log_info "Adding user $email with SSHA512 password..."
    
    # Create LDIF
    cat > /tmp/new_user_${username}.ldif << EOF
dn: uid=${username},${PEOPLE_OU}
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ${username}
cn: ${display_name}
sn: ${last_name}
givenName: ${first_name}
displayName: ${display_name}
mail: ${email}
userPassword: ${ssha512_pass}
uidNumber: ${uid_number}
gidNumber: 5000
homeDirectory: /var/mail/${email}
loginShell: /bin/false
EOF
    
    # Copy to container and add
    docker cp "/tmp/new_user_${username}.ldif" "$LDAP_CONTAINER:/tmp/new_user_${username}.ldif"
    
    if docker exec "$LDAP_CONTAINER" ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASS" \
        -f "/tmp/new_user_${username}.ldif"; then
        log_success "User $email added successfully with SSHA512 password"
        
        # Create mailbox directory
        docker exec elemta-dovecot mkdir -p "/var/mail/${email}/{new,cur,tmp}" 2>/dev/null || true
        docker exec elemta-dovecot chown -R vmail:vmail "/var/mail/${email}" 2>/dev/null || true
        
        log_success "Mailbox created for $email"
    else
        log_error "Failed to add user $email"
        return 1
    fi
    
    # Cleanup
    rm -f "/tmp/new_user_${username}.ldif"
    docker exec "$LDAP_CONTAINER" rm -f "/tmp/new_user_${username}.ldif"
}

# Change user password to SSHA512
change_password() {
    local email="$1"
    local new_password="$2"
    
    if [ -z "$email" ] || [ -z "$new_password" ]; then
        log_error "Usage: change-password <email> <new_password>"
        return 1
    fi
    
    # Extract username from email
    local username=$(echo "$email" | cut -d'@' -f1 | tr '.' '_')
    
    # Generate SSHA512 password
    local ssha512_pass=$(generate_ssha512 "$new_password")
    
    log_info "Changing password for $email to SSHA512..."
    
    # Create LDIF for password change
    cat > /tmp/change_pass_${username}.ldif << EOF
dn: uid=${username},${PEOPLE_OU}
changetype: modify
replace: userPassword
userPassword: ${ssha512_pass}
EOF
    
    # Copy to container and modify
    docker cp "/tmp/change_pass_${username}.ldif" "$LDAP_CONTAINER:/tmp/change_pass_${username}.ldif"
    
    if docker exec "$LDAP_CONTAINER" ldapmodify -x -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASS" \
        -f "/tmp/change_pass_${username}.ldif"; then
        log_success "Password changed for $email to SSHA512"
    else
        log_error "Failed to change password for $email"
        return 1
    fi
    
    # Cleanup
    rm -f "/tmp/change_pass_${username}.ldif"
    docker exec "$LDAP_CONTAINER" rm -f "/tmp/change_pass_${username}.ldif"
}

# Test user authentication
test_auth() {
    local email="$1"
    local password="$2"
    
    if [ -z "$email" ] || [ -z "$password" ]; then
        log_error "Usage: test-auth <email> <password>"
        return 1
    fi
    
    # Extract username from email
    local username=$(echo "$email" | cut -d'@' -f1 | tr '.' '_')
    
    log_info "Testing authentication for $email..."
    
    if docker exec "$LDAP_CONTAINER" ldapwhoami -x -D "uid=${username},${PEOPLE_OU}" -w "$password"; then
        log_success "Authentication successful for $email"
    else
        log_error "Authentication failed for $email"
        return 1
    fi
}

# Show help
show_help() {
    echo "User Management Script for Elemta LDAP"
    echo "Uses SSHA512 password hashing"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  list-users                           List all users"
    echo "  add-user <email> <pass> <first> <last> [display]  Add new user with SSHA512"
    echo "  change-password <email> <new_pass>   Change user password to SSHA512"
    echo "  test-auth <email> <password>         Test user authentication"
    echo "  help                                 Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 list-users"
    echo "  $0 add-user alice@example.com secret123 Alice Smith"
    echo "  $0 change-password test@example.com newpass456"
    echo "  $0 test-auth test@example.com password"
}

# Main execution
main() {
    check_ldap
    
    case "${1:-help}" in
        "list-users")
            list_users
            ;;
        "add-user")
            add_user "$2" "$3" "$4" "$5" "$6"
            ;;
        "change-password")
            change_password "$2" "$3"
            ;;
        "test-auth")
            test_auth "$2" "$3"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run the script
main "$@" 