#!/bin/bash
# Initialize LDAP users for testing

set -e

echo "Waiting for LDAP to be ready..."
timeout=60
counter=0
while ! docker exec elemta-ldap ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com" -s base > /dev/null 2>&1; do
    sleep 2
    counter=$((counter + 2))
    if [ $counter -ge $timeout ]; then
        echo "❌ LDAP failed to become ready"
        exit 1
    fi
done

echo "LDAP is ready. Adding test users..."

# First, create the people OU
docker exec elemta-ldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin << 'EOF' 2>&1 || echo "(ou=people may already exist)"
dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people
EOF

# Now add users
docker exec elemta-ldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin << 'EOF' 2>&1 || echo "(users may already exist)"

dn: uid=user,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Test User
sn: User
uid: user
mail: user@example.com
userPassword: password

dn: uid=demo,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Demo User
sn: User
uid: demo
mail: demo@example.com
userPassword: demo123

dn: uid=sender,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Sender User
sn: Sender
uid: sender
mail: sender@example.com
userPassword: password

dn: uid=recipient,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: Recipient User
sn: Recipient
uid: recipient
mail: recipient@example.com
userPassword: password
EOF

echo "Verifying users were added..."
docker exec elemta-ldap ldapsearch -x -b "ou=people,dc=example,dc=com" "(uid=demo)" uid | grep -q "uid: demo" && echo "✅ Demo user found" || echo "❌ Demo user not found"
docker exec elemta-ldap ldapsearch -x -b "ou=people,dc=example,dc=com" "(uid=user)" uid | grep -q "uid: user" && echo "✅ User found" || echo "❌ User not found"

echo "Testing authentication..."
docker exec elemta-ldap ldapwhoami -x -D "uid=demo,ou=people,dc=example,dc=com" -w demo123 && echo "✅ Demo auth works" || echo "❌ Demo auth failed"

echo "✅ LDAP users initialized"

