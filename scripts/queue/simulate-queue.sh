#!/bin/bash

# Script to simulate the queue functionality by manually creating queue entries
# This is useful for testing the queue processing logic without running the full SMTP server

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

# Check if the elemta container is running
if ! docker ps | grep -q "elemta.*healthy"; then
    echo -e "${RED}Error: elemta container is not running.${NC}"
    echo "Please start the container with 'docker-compose up -d' first."
    exit 1
fi

# Create sample message content
print_header "Creating Sample Messages"

# Function to create a test message
create_test_message() {
    local msg_id="$1"
    local queue_type="$2"
    local from="$3"
    local to="$4"
    local subject="$5"
    local attempts="$6"
    local next_retry=$(date -d "+$7 minutes" +"%Y-%m-%d %H:%M:%S")
    
    echo -e "${GREEN}Creating message $msg_id in $queue_type queue${NC}"
    
    # Create message content
    local message="From: $from
To: $to
Subject: $subject
Message-ID: <$msg_id@example.com>
Date: $(date -R)
Content-Type: text/plain; charset=UTF-8

This is a test message $msg_id for the $queue_type queue.
Created at $(date).
"
    
    # Create metadata
    local metadata="{
  \"id\": \"$msg_id\",
  \"from\": \"$from\",
  \"to\": [\"$to\"],
  \"created\": \"$(date +"%Y-%m-%d %H:%M:%S")\",
  \"attempts\": $attempts,
  \"next_retry\": \"$next_retry\",
  \"size\": ${#message},
  \"status\": \"$([ "$queue_type" == "active" ] && echo "pending" || echo "$queue_type")\"
}"
    
    # Create data file
    docker exec elemta mkdir -p /app/queue/data
    echo "$message" | docker exec -i elemta bash -c "cat > /app/queue/data/${msg_id}.eml"
    
    # Create metadata file in the appropriate queue directory
    docker exec elemta mkdir -p /app/queue/${queue_type}
    echo "$metadata" | docker exec -i elemta bash -c "cat > /app/queue/${queue_type}/${msg_id}.json"
    
    echo -e "${GREEN}Message $msg_id created successfully${NC}"
}

# Show stats before creating messages
print_header "Queue Stats Before"
./scripts/elemta-cli.sh queue stats

# Create test messages in different queues
create_test_message "MSG$(date +%s)1" "active" "sender1@example.com" "recipient1@example.org" "Test active message 1" 0 5
create_test_message "MSG$(date +%s)2" "active" "sender2@example.com" "recipient2@example.org" "Test active message 2" 0 10
create_test_message "MSG$(date +%s)3" "deferred" "sender3@example.com" "recipient3@example.org" "Test deferred message" 2 30
create_test_message "MSG$(date +%s)4" "held" "sender4@example.com" "recipient4@example.org" "Test held message" 0 0
create_test_message "MSG$(date +%s)5" "failed" "sender5@example.com" "recipient5@example.org" "Test failed message" 5 0

# Show stats after creating messages
print_header "Queue Stats After"
./scripts/elemta-cli.sh queue stats

# List all messages
print_header "Queue Contents"
./scripts/elemta-cli.sh queue list

print_header "Queue Simulation Complete"
echo -e "${GREEN}Queue simulation completed successfully!${NC}"
echo "You can now explore the queue with the following commands:"
echo "  ./scripts/elemta-cli.sh queue list     - List all messages in the queue"
echo "  ./scripts/elemta-cli.sh queue stats    - Show queue statistics"
echo "  ./scripts/elemta-cli.sh queue view ID  - View details of a specific message" 