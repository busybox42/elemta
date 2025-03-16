#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Generating test load for Elemta SMTP server...${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
  exit 1
fi

# Check if the monitoring stack is running
if ! docker-compose -f docker-compose-monitoring.yml ps | grep -q "Up"; then
  echo -e "${RED}Error: Monitoring stack is not running. Please start it first.${NC}"
  echo -e "${YELLOW}Run: docker-compose -f docker-compose-monitoring.yml up -d${NC}"
  exit 1
fi

# Get the Elemta container ID
ELEMTA_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q elemta)
if [ -z "$ELEMTA_CONTAINER" ]; then
  echo -e "${RED}Error: Elemta container is not running.${NC}"
  exit 1
fi

# Function to send a test email
send_test_email() {
  local from=$1
  local to=$2
  local subject=$3
  local body=$4
  local delay=${5:-0}
  
  echo -e "${YELLOW}Sending test email from ${from} to ${to}...${NC}"
  
  # Create a temporary file with the email content
  TMP_FILE=$(mktemp)
  cat > $TMP_FILE << EOF
EHLO example.com
MAIL FROM: <${from}>
RCPT TO: <${to}>
DATA
Subject: ${subject}
From: <${from}>
To: <${to}>

${body}
.
QUIT
EOF

  # Send the email using netcat
  cat $TMP_FILE | nc -w 5 localhost 2525
  
  # Remove the temporary file
  rm $TMP_FILE
  
  # Wait if delay is specified
  if [ $delay -gt 0 ]; then
    sleep $delay
  fi
}

# Generate some test load
echo -e "${YELLOW}Sending test emails...${NC}"

# Send 10 emails with different senders and recipients
for i in {1..10}; do
  send_test_email "sender${i}@example.com" "recipient${i}@example.com" "Test Email ${i}" "This is test email ${i}" 1
done

# Send emails that would trigger greylisting (same sender/recipient pairs)
echo -e "\n${YELLOW}Sending emails to trigger greylisting...${NC}"
for i in {1..5}; do
  send_test_email "greylist${i}@example.com" "target${i}@example.com" "Greylisting Test ${i}" "This email should trigger greylisting" 1
  
  # Send the same email again immediately (should be greylisted)
  send_test_email "greylist${i}@example.com" "target${i}@example.com" "Greylisting Test ${i} (retry)" "This email should be accepted after delay" 1
done

# Wait a bit and then send the same emails again (should pass greylisting if delay is configured short enough for testing)
echo -e "\n${YELLOW}Waiting 30 seconds before retrying greylisted emails...${NC}"
sleep 30

echo -e "${YELLOW}Retrying greylisted emails...${NC}"
for i in {1..5}; do
  send_test_email "greylist${i}@example.com" "target${i}@example.com" "Greylisting Test ${i} (final retry)" "This email should pass greylisting now" 1
done

echo -e "\n${GREEN}Test load generation completed.${NC}"
echo -e "${YELLOW}You can now check the metrics in Grafana:${NC} http://localhost:3000" 