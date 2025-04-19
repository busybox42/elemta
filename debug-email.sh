#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SMTP_HOST="localhost"
SMTP_PORT="2525"

echo -e "${YELLOW}Sending test email to Elemta SMTP server ($SMTP_HOST:$SMTP_PORT)...${NC}"

# Create email content
FROM="sender@example.com"
TO="recipient@example.com"
SUBJECT="Test Email - Debug $(date)"
BODY="This is a test email sent for debugging purposes.\nTimestamp: $(date)"

# Check if swaks is installed
if command -v swaks &> /dev/null; then
    echo -e "${GREEN}Using swaks to send email...${NC}"
    
    # Send email using swaks with detailed output
    swaks --server $SMTP_HOST --port $SMTP_PORT \
          --from $FROM --to $TO \
          --header "Subject: $SUBJECT" \
          --body "$BODY" \
          --h-From: "Sender <$FROM>" \
          --h-To: "Recipient <$TO>" \
          -v
else
    echo -e "${YELLOW}swaks not found, falling back to netcat method...${NC}"
    
    # Create a temporary file with the SMTP commands
    SMTP_COMMANDS=$(mktemp)
    cat > "$SMTP_COMMANDS" << EOF
EHLO test.local
MAIL FROM: <$FROM>
RCPT TO: <$TO>
DATA
From: Sender <$FROM>
To: Recipient <$TO>
Subject: $SUBJECT
Content-Type: text/plain

$BODY
.
QUIT
EOF

    echo -e "${YELLOW}SMTP commands to be sent:${NC}"
    cat "$SMTP_COMMANDS"
    echo ""

    # Send the email with proper CRLF line endings
    echo -e "${YELLOW}Connecting and sending email...${NC}"
    perl -pe 's/\n/\r\n/g' "$SMTP_COMMANDS" | nc -v -w 10 $SMTP_HOST $SMTP_PORT 2>&1

    # Clean up
    rm "$SMTP_COMMANDS"
fi

echo -e "${GREEN}Email sent. Waiting for delivery (3 seconds)...${NC}"
sleep 3

# Show all running containers
echo -e "${YELLOW}Docker compose services:${NC}"
docker-compose ps --services

# Check logs from the main Elemta container
echo -e "${YELLOW}Checking Elemta logs:${NC}"
docker-compose logs --tail=30 elemta_node0 2>/dev/null || \
docker-compose logs --tail=30 elemta 2>/dev/null || \
docker-compose logs --tail=30 $(docker-compose ps --services | grep elemta | head -1) 2>/dev/null || \
echo "Could not find Elemta container logs"

# Check for emails in the dovecot mailbox
echo -e "${YELLOW}Checking for delivered emails:${NC}"
docker-compose exec elemta-dovecot sh -c "ls -la /var/mail/recipient@example.com/{new,cur}/ 2>/dev/null || echo 'No mailbox found'"

# Check Dovecot logs for any issues
echo -e "${YELLOW}Checking Dovecot logs:${NC}"
docker-compose logs --tail=20 elemta-dovecot | grep -i "lmtp\|error\|debug\|mail"

echo -e "${GREEN}Debug session complete.${NC}" 