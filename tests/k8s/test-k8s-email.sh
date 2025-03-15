#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing Elemta Kubernetes Deployment${NC}"
echo "======================================"

# Get pod name
POD_NAME=$(kubectl get pods -l app=elemta -o jsonpath="{.items[0].metadata.name}")
echo -e "${YELLOW}Using pod:${NC} $POD_NAME"

# Test 1: Check if all containers are running
echo -e "\n${YELLOW}Test 1: Checking container status${NC}"
CONTAINERS_READY=$(kubectl get pod $POD_NAME -o jsonpath="{.status.containerStatuses[*].ready}" | tr ' ' '\n' | grep -c "true")
if [ "$CONTAINERS_READY" -eq 3 ]; then
  echo -e "${GREEN}✓ All containers are running${NC}"
else
  echo -e "${RED}✗ Not all containers are running${NC}"
  kubectl get pod $POD_NAME -o jsonpath="{.status.containerStatuses[*].name}" | tr ' ' '\n'
  exit 1
fi

# Test 2: Test ClamAV connection from elemta container
echo -e "\n${YELLOW}Test 2: Testing ClamAV connection${NC}"
CLAMAV_TEST=$(kubectl exec $POD_NAME -c elemta -- nc -z -v elemta-clamav 3310 2>&1)
if [[ $CLAMAV_TEST == *"succeeded"* ]]; then
  echo -e "${GREEN}✓ ClamAV connection successful${NC}"
else
  echo -e "${RED}✗ ClamAV connection failed${NC}"
  echo "$CLAMAV_TEST"
  exit 1
fi

# Test 3: Test Rspamd connection from elemta container
echo -e "\n${YELLOW}Test 3: Testing Rspamd connection${NC}"
RSPAMD_TEST=$(kubectl exec $POD_NAME -c elemta -- nc -z -v elemta-rspamd 11333 2>&1)
if [[ $RSPAMD_TEST == *"succeeded"* ]]; then
  echo -e "${GREEN}✓ Rspamd connection successful${NC}"
else
  echo -e "${RED}✗ Rspamd connection failed${NC}"
  echo "$RSPAMD_TEST"
  exit 1
fi

# Test 4: Send a test email through the SMTP server
echo -e "\n${YELLOW}Test 4: Sending test email${NC}"
SMTP_PORT=$(kubectl get service elemta -o jsonpath="{.spec.ports[0].nodePort}")

echo -e "Connecting to SMTP server at localhost:${SMTP_PORT}"

# Create a temporary file for the email
EMAIL_FILE=$(mktemp)
cat > $EMAIL_FILE << EOF
HELO example.com
MAIL FROM: <sender@example.com>
RCPT TO: <recipient@example.com>
DATA
Subject: Test Email from Kubernetes

This is a test email sent through the Elemta SMTP server running in Kubernetes.
.
QUIT
EOF

# Use timeout to prevent hanging if the server doesn't respond
RESPONSE=$(timeout 10 nc localhost $SMTP_PORT < $EMAIL_FILE)
rm $EMAIL_FILE

if [[ $RESPONSE == *"250"* ]]; then
  echo -e "${GREEN}✓ Email sent successfully${NC}"
  echo "Server response:"
  echo "$RESPONSE"
else
  echo -e "${RED}✗ Email sending failed${NC}"
  echo "Server response:"
  echo "$RESPONSE"
  exit 1
fi

# Test 5: Check Rspamd web interface
echo -e "\n${YELLOW}Test 5: Checking Rspamd web interface${NC}"
RSPAMD_PORT=$(kubectl get service elemta-rspamd -o jsonpath="{.spec.ports[?(@.name=='rspamd-web')].nodePort}")
RSPAMD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$RSPAMD_PORT)

if [ "$RSPAMD_STATUS" -eq 200 ]; then
  echo -e "${GREEN}✓ Rspamd web interface is accessible${NC}"
else
  echo -e "${RED}✗ Rspamd web interface is not accessible (HTTP status: $RSPAMD_STATUS)${NC}"
  exit 1
fi

echo -e "\n${GREEN}All tests passed! The Elemta Kubernetes deployment is working correctly.${NC}"
echo "You can access the Rspamd web interface at http://localhost:$RSPAMD_PORT"
echo "You can send emails to the SMTP server at localhost:$SMTP_PORT" 