#!/bin/bash

echo "=== Testing Authentication Chain ==="

echo "1. Testing LDAP user lookup..."
docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=people,dc=example,dc=com" "(mail=recipient@example.com)" mail userPassword

echo -e "\n2. Testing LDAP bind authentication..."
docker exec elemta-ldap ldapsearch -x -H ldap://localhost:389 -D "uid=recipient,ou=people,dc=example,dc=com" -w password -b "ou=people,dc=example,dc=com" "(mail=recipient@example.com)" mail

echo -e "\n3. Testing Dovecot LDAP config..."
docker exec elemta-dovecot cat /etc/dovecot/dovecot-ldap.conf.ext

echo -e "\n4. Testing direct IMAP authentication..."
echo -e "a001 LOGIN recipient@example.com password\na002 LOGOUT" | docker exec -i elemta-dovecot nc localhost 14143

echo -e "\n5. Testing Roundcube IMAP connection..."
docker exec elemta_roundcube php -r "
\$imap = imap_open('{elemta-dovecot:14143/novalidate-cert}INBOX', 'recipient@example.com', 'password');
if (\$imap) {
    echo 'SUCCESS: IMAP authentication worked' . PHP_EOL;
    imap_close(\$imap);
} else {
    echo 'FAILED: IMAP authentication failed - ' . imap_last_error() . PHP_EOL;
}
"

echo -e "\nAuthentication chain test completed." 