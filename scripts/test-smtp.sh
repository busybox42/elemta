#!/bin/bash

# Script to test SMTP functionality using swaks

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing SMTP Functionality for Elemta${NC}"
echo "======================================"

# Default values
SERVER="localhost"
PORT="2526"
FROM="sender@example.com"
TO="recipient@example.com"
SUBJECT="Test Email"
BODY="This is a test email sent by swaks."
NUM_EMAILS=3
DELAY=1

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --server|-s)
      SERVER="$2"
      shift 2
      ;;
    --port|-p)
      PORT="$2"
      shift 2
      ;;
    --from|-f)
      FROM="$2"
      shift 2
      ;;
    --to|-t)
      TO="$2"
      shift 2
      ;;
    --subject|-S)
      SUBJECT="$2"
      shift 2
      ;;
    --body|-b)
      BODY="$2"
      shift 2
      ;;
    --count|-c)
      NUM_EMAILS="$2"
      shift 2
      ;;
    --delay|-d)
      DELAY="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --server, -s    SMTP server address (default: localhost)"
      echo "  --port, -p      SMTP server port (default: 2526)"
      echo "  --from, -f      Sender email address (default: sender@example.com)"
      echo "  --to, -t        Recipient email address (default: recipient@example.com)"
      echo "  --subject, -S   Email subject (default: Test Email)"
      echo "  --body, -b      Email body (default: This is a test email sent by swaks.)"
      echo "  --count, -c     Number of emails to send (default: 3)"
      echo "  --delay, -d     Delay between emails in seconds (default: 1)"
      echo "  --help, -h      Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if swaks is installed
if ! command -v swaks &> /dev/null; then
    echo -e "${RED}Error: swaks is not installed.${NC}"
    echo "Please install swaks first:"
    echo "  sudo apt-get install swaks    # Debian/Ubuntu"
    echo "  sudo yum install swaks        # CentOS/RHEL"
    echo "  brew install swaks            # macOS with Homebrew"
    exit 1
fi

# Check queue before sending emails
echo -e "\n${YELLOW}Checking queue before sending emails:${NC}"
./scripts/elemta-cli.sh queue -config /app/config/elemta.toml stats

# Send emails
echo -e "\n${YELLOW}Sending $NUM_EMAILS test emails...${NC}"
for i in $(seq 1 $NUM_EMAILS); do
    echo -e "\n${YELLOW}Sending email $i of $NUM_EMAILS...${NC}"
    
    # Generate a unique message ID
    MSG_ID="test-$(date +%s)-$i@example.com"
    
    # Send email using swaks
    swaks --server "$SERVER" --port "$PORT" \
          --from "$FROM" --to "$TO" \
          --header "Subject: $SUBJECT #$i" \
          --header "Message-ID: <$MSG_ID>" \
          --body "$BODY (Email #$i)" \
          --h-From: "Test Sender <$FROM>" \
          --h-To: "Test Recipient <$TO>"
    
    # Check the result
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Email $i sent successfully!${NC}"
    else
        echo -e "${RED}Failed to send email $i.${NC}"
    fi
    
    # Wait before sending the next email
    if [ $i -lt $NUM_EMAILS ]; then
        echo "Waiting $DELAY seconds before sending the next email..."
        sleep $DELAY
    fi
done

# Wait for emails to be processed
echo -e "\n${YELLOW}Waiting for emails to be processed...${NC}"
sleep 5

# Check queue after sending emails
echo -e "\n${YELLOW}Checking queue after sending emails:${NC}"
./scripts/elemta-cli.sh queue -config /app/config/elemta.toml stats

# List messages in the queue
echo -e "\n${YELLOW}Listing messages in the queue:${NC}"
./scripts/elemta-cli.sh queue -config /app/config/elemta.toml list

echo -e "\n${GREEN}SMTP test complete!${NC}"
echo "You can now use the following commands to manage the queue:"
echo "  ./scripts/elemta-cli.sh queue list     - List all messages in the queue"
echo "  ./scripts/elemta-cli.sh queue stats    - Show queue statistics"
echo "  ./scripts/elemta-cli.sh queue view ID  - View details of a specific message" 