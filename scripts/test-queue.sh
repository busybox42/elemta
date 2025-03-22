#!/bin/bash

# Script to test queue functionality by creating sample messages and running queue operations

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
  echo -e "\n${BLUE}======================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}======================================${NC}"
}

# Function to create a test message and return the ID
create_test_message() {
    local queue_type="$1"
    local from="$2"
    local to="$3"
    local subject="$4"
    
    local msg_id="MSG$(date +%s)-$RANDOM"
    
    # Create message content
    local message="From: $from
To: $to
Subject: $subject
Message-ID: <$msg_id@example.com>
Date: $(date -R)
Content-Type: text/plain; charset=UTF-8

This is a test message for the $queue_type queue.
Created at $(date).
"
    
    # Create metadata
    local metadata="{
  \"id\": \"$msg_id\",
  \"from\": \"$from\",
  \"to\": [\"$to\"],
  \"created\": \"$(date +"%Y-%m-%d %H:%M:%S")\",
  \"attempts\": 0,
  \"next_retry\": \"$(date +"%Y-%m-%d %H:%M:%S")\",
  \"size\": ${#message},
  \"status\": \"pending\"
}"
    
    # Create data file
    docker exec elemta mkdir -p /app/queue/data
    echo "$message" | docker exec -i elemta bash -c "cat > /app/queue/data/${msg_id}.eml"
    
    # Create metadata file in the appropriate queue directory
    docker exec elemta mkdir -p /app/queue/${queue_type}
    echo "$metadata" | docker exec -i elemta bash -c "cat > /app/queue/${queue_type}/${msg_id}.json"
    
    echo "$msg_id"
}

print_header "Testing Queue Functionality"

# Create a test message in the active queue
echo -e "${YELLOW}Creating test message in active queue...${NC}"
MSG_ID=$(create_test_message "active" "sender@example.com" "recipient@example.org" "Test active message")
echo -e "${GREEN}Created message with ID: $MSG_ID${NC}"

# Check queue statistics
print_header "Queue Statistics"
./scripts/elemta-cli.sh queue stats

# View the message details
print_header "Message Details"
./scripts/elemta-cli.sh queue view $MSG_ID

# List all messages
print_header "All Queue Messages"
./scripts/elemta-cli.sh queue list

# Test message deletion
print_header "Testing Message Deletion"
echo -e "${YELLOW}Deleting message $MSG_ID...${NC}"
./scripts/elemta-cli.sh queue delete $MSG_ID
echo -e "${GREEN}Message deleted${NC}"

# Verify deletion
print_header "Verification After Deletion"
./scripts/elemta-cli.sh queue list

print_header "Queue Test Complete"
echo -e "${GREEN}Queue test completed successfully!${NC}"
echo "You can explore the queue with the following commands:"
echo "  ./scripts/elemta-cli.sh queue list     - List all messages in the queue"
echo "  ./scripts/elemta-cli.sh queue stats    - Show queue statistics"
echo "  ./scripts/elemta-cli.sh queue view ID  - View details of a specific message" 