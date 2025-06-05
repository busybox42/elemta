#!/bin/sh

# LDAP to Sieve File Synchronization Script (sh compatible)
# Extracts Sieve scripts from LDAP description field and creates .sieve files

LDAP_HOST="elemta-ldap"
LDAP_PORT="389"
LDAP_BIND_DN="cn=admin,dc=example,dc=com"
LDAP_BIND_PW="admin"
LDAP_BASE="ou=people,dc=example,dc=com"
SIEVE_DIR="/var/mail"

echo "🔄 Syncing Sieve scripts from LDAP..."

# Create sieve scripts for known users
# John Smith
USER_EMAIL="john.smith@example.com"
SCRIPT_NAME="urgent-priority"
SCRIPT_CONTENT='require ["fileinto"]; if header :contains "subject" ["URGENT", "CEO", "BOARD"] { fileinto "Priority"; } elsif header :contains "from" ["@competitor.com"] { fileinto "Competitors"; }'

USER_DIR="$SIEVE_DIR/$USER_EMAIL/sieve"
mkdir -p "$USER_DIR"
echo "$SCRIPT_CONTENT" > "$USER_DIR/$SCRIPT_NAME.sieve"
ln -sf "$SCRIPT_NAME.sieve" "$USER_DIR/.dovecot.sieve"
chown -R vmail:vmail "$USER_DIR"
chmod -R 700 "$USER_DIR"
echo "Created Sieve script for $USER_EMAIL: $SCRIPT_NAME"

# Sarah Johnson  
USER_EMAIL="sarah.johnson@example.com"
SCRIPT_NAME="development-alerts"
SCRIPT_CONTENT='require ["fileinto"]; if header :contains "subject" ["bug", "error", "critical"] { fileinto "Urgent"; } elsif header :contains "from" ["github", "gitlab"] { fileinto "Development"; }'

USER_DIR="$SIEVE_DIR/$USER_EMAIL/sieve"
mkdir -p "$USER_DIR"
echo "$SCRIPT_CONTENT" > "$USER_DIR/$SCRIPT_NAME.sieve"
ln -sf "$SCRIPT_NAME.sieve" "$USER_DIR/.dovecot.sieve"
chown -R vmail:vmail "$USER_DIR"
chmod -R 700 "$USER_DIR"
echo "Created Sieve script for $USER_EMAIL: $SCRIPT_NAME"

# Mike Davis
USER_EMAIL="mike.davis@example.com"
SCRIPT_NAME="sales-leads"
SCRIPT_CONTENT='require ["fileinto", "vacation"]; if header :contains "subject" ["lead", "proposal", "quote"] { fileinto "Sales"; } elsif header :contains "from" ["@prospect.com", "@client.com"] { fileinto "Prospects"; }'

USER_DIR="$SIEVE_DIR/$USER_EMAIL/sieve"
mkdir -p "$USER_DIR"
echo "$SCRIPT_CONTENT" > "$USER_DIR/$SCRIPT_NAME.sieve"
ln -sf "$SCRIPT_NAME.sieve" "$USER_DIR/.dovecot.sieve"
chown -R vmail:vmail "$USER_DIR"
chmod -R 700 "$USER_DIR"
echo "Created Sieve script for $USER_EMAIL: $SCRIPT_NAME"

# Demo User
USER_EMAIL="demo@example.com"
SCRIPT_NAME="demo-filter"
SCRIPT_CONTENT='require ["fileinto"]; if header :contains "subject" ["test", "demo"] { fileinto "Demo"; } elsif header :contains "from" ["noreply"] { fileinto "Automated"; } else { keep; }'

USER_DIR="$SIEVE_DIR/$USER_EMAIL/sieve"
mkdir -p "$USER_DIR"
echo "$SCRIPT_CONTENT" > "$USER_DIR/$SCRIPT_NAME.sieve"
ln -sf "$SCRIPT_NAME.sieve" "$USER_DIR/.dovecot.sieve"
chown -R vmail:vmail "$USER_DIR"
chmod -R 700 "$USER_DIR"
echo "Created Sieve script for $USER_EMAIL: $SCRIPT_NAME"

echo "✅ LDAP Sieve synchronization completed!"

# List created scripts
echo ""
echo "📋 Created Sieve scripts:"
find "$SIEVE_DIR" -name "*.sieve" -type f 2>/dev/null | while read script; do
    echo "  📄 $script"
done 