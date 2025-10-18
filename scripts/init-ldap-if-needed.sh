#!/bin/bash
# Initialize LDAP users if they don't exist
# This script runs after docker-setup to ensure users are loaded

set -e

echo "🔍 Checking if LDAP users need initialization..."

# Wait for LDAP to be healthy
timeout=60
counter=0
while ! docker exec elemta-ldap ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com" -s base > /dev/null 2>&1; do
    sleep 2
    counter=$((counter + 2))
    if [ $counter -ge $timeout ]; then
        echo "❌ LDAP failed to become healthy"
        exit 1
    fi
done

# Check if users already exist
if docker exec elemta-ldap ldapsearch -x -H ldapi:/// -Y EXTERNAL -b "ou=people,dc=example,dc=com" "(uid=user)" 2>/dev/null | grep -q "uid: user"; then
    echo "✅ LDAP users already initialized"
    exit 0
fi

echo "📝 LDAP users not found, adding them now..."

# Add users using ldapadd
docker exec elemta-ldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin -f /docker-entrypoint-initdb.d/bootstrap.ldif 2>&1

# Wait a moment for LDAP to process the additions
sleep 2

# Verify
if docker exec elemta-ldap ldapsearch -x -H ldapi:/// -Y EXTERNAL -b "ou=people,dc=example,dc=com" "(uid=user)" 2>&1 | grep -q "dn: uid=user"; then
    echo "✅ LDAP users initialized successfully"
    exit 0
else
    echo "⚠️  Users added but verification unclear - continuing anyway"
    exit 0
fi

