#!/bin/bash
# Initialize LDAP users on first startup

set -e

# Only run if users don't exist yet
if ldapsearch -x -H ldap://localhost -b "ou=people,dc=example,dc=com" "(uid=demo)" | grep -q "uid: demo"; then
    echo "Users already exist, skipping initialization"
    exit 0
fi

echo "Initializing LDAP users from 99-stress-users.ldif..."

# Load bootstrap file
ldapadd -x -D "cn=admin,dc=example,dc=com" -w "$LDAP_ADMIN_PASSWORD" -f /docker-entrypoint-initdb.d/99-stress-users.ldif || true

echo "LDAP users initialized"

