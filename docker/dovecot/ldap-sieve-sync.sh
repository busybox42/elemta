#!/bin/bash

# LDAP to Sieve File Synchronization Script
# Extracts Sieve scripts from LDAP description field and creates .sieve files

LDAP_HOST="elemta-ldap"
LDAP_PORT="389"
LDAP_BIND_DN="cn=admin,dc=example,dc=com"
LDAP_BIND_PW="admin"
LDAP_BASE="ou=people,dc=example,dc=com"
SIEVE_DIR="/var/mail"

# Function to create sieve script for a user
create_sieve_script() {
    local user_email="$1"
    local sieve_content="$2"
    local script_name="$3"
    
    # Create user sieve directory
    local user_dir="$SIEVE_DIR/$user_email/sieve"
    mkdir -p "$user_dir"
    
    # Create the sieve script file
    echo "$sieve_content" > "$user_dir/$script_name.sieve"
    
    # Create symlink for active script
    ln -sf "$script_name.sieve" "$user_dir/.dovecot.sieve"
    
    # Set proper ownership
    chown -R vmail:vmail "$user_dir"
    chmod -R 700 "$user_dir"
    
    echo "Created Sieve script for $user_email: $script_name"
}

# Get all users with Sieve scripts from LDAP
echo "🔄 Syncing Sieve scripts from LDAP..."

# Search for users with description containing Sieve scripts
ldapsearch -x -H "ldap://$LDAP_HOST:$LDAP_PORT" \
           -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PW" \
           -b "$LDAP_BASE" \
           "(&(objectClass=inetOrgPerson)(description=*))" \
           mail description | \
while IFS= read -r line; do
    if [[ $line =~ ^mail:\ (.+)$ ]]; then
        user_email="${BASH_REMATCH[1]}"
    elif [[ $line =~ ^description:\ (.+)$ ]]; then
        description="${BASH_REMATCH[1]}"
        
        # Parse description: role|script_name|script_content
        if [[ $description =~ ^([^|]*)\|([^|]*)\|(.+)$ ]]; then
            role="${BASH_REMATCH[1]}"
            script_name="${BASH_REMATCH[2]}"
            script_content="${BASH_REMATCH[3]}"
            
            if [[ -n "$user_email" && -n "$script_name" && -n "$script_content" ]]; then
                create_sieve_script "$user_email" "$script_content" "$script_name"
            fi
        fi
        
        # Reset for next user
        user_email=""
    fi
done

echo "✅ LDAP Sieve synchronization completed!"

# List created scripts
echo ""
echo "📋 Created Sieve scripts:"
find "$SIEVE_DIR" -name "*.sieve" -type f 2>/dev/null | while read -r script; do
    user=$(echo "$script" | cut -d'/' -f4)
    script_name=$(basename "$script" .sieve)
    echo "  📄 $user: $script_name"
done 