#!/bin/bash

# Simple script to test queue functionality

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing Queue Functionality${NC}"
echo "======================================"

# Check if the elemta-cli container is running
if ! docker ps | grep -q elemta-cli; then
    echo -e "${RED}Error: elemta-cli container is not running.${NC}"
    echo "Please start the container first with: make docker-deploy"
    exit 1
fi

# Function to generate a random UUID
generate_uuid() {
    local uuid=""
    uuid=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -n 1)
    uuid="${uuid}-$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 4 | head -n 1)"
    uuid="${uuid}-$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 4 | head -n 1)"
    uuid="${uuid}-$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 4 | head -n 1)"
    uuid="${uuid}-$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 12 | head -n 1)"
    echo "$uuid"
}

# Create a simple queue entry
create_queue_entry() {
    local queue_type="active"
    local msg_id=$(generate_uuid)
    local sender="sender@example.com"
    local recipient="recipient@example.com"
    local subject="Test Message"
    local current_time=$(date -u +"%Y-%m-%dT%H:%M:%S.%NZ")
    local expiry_time=$(date -u -d "+7 days" +"%Y-%m-%dT%H:%M:%S.%NZ")
    
    # Create message content
    local message="From: ${sender}
To: ${recipient}
Subject: ${subject}
Message-ID: <${msg_id}@example.com>
Date: $(date -R)

This is a test message for the ${queue_type} queue.
This message was generated by the Elemta queue simulator.
"
    
    echo -e "${YELLOW}Creating message with ID: ${msg_id}${NC}"
    
    # Create data file
    docker exec elemta-cli mkdir -p /app/queue/data
    echo "$message" | docker exec -i elemta-cli bash -c "cat > /app/queue/data/${msg_id}.eml"
    
    # Create metadata file
    docker exec elemta-cli mkdir -p /app/queue/${queue_type}
    
    # Create metadata JSON
    local metadata="{\"id\":\"${msg_id}\",\"from\":\"${sender}\",\"to\":[\"${recipient}\"],\"status\":\"queued\",\"created_at\":\"${current_time}\",\"updated_at\":\"${current_time}\",\"size\":${#message},\"received_at\":\"${current_time}\",\"retry\":{\"attempts\":1,\"last_attempt\":\"${current_time}\",\"next_attempt\":\"${current_time}\",\"last_error\":\"\"},\"priority\":1,\"queue_type\":\"${queue_type}\",\"retry_count\":1,\"next_retry\":\"${current_time}\",\"last_error\":\"\",\"attempts\":[],\"delivery_status\":{\"${recipient}\":{\"status\":\"queued\",\"last_attempt\":\"${current_time}\",\"retry_count\":0,\"next_retry\":\"${current_time}\",\"dsn_sent\":false}},\"last_delivery_attempt\":\"${current_time}\",\"first_attempt_time\":\"${current_time}\",\"expiry_time\":\"${expiry_time}\",\"dsn\":false}"
    
    echo "$metadata" | docker exec -i elemta-cli bash -c "cat > /app/queue/${queue_type}/${msg_id}.json"
    
    echo -e "${GREEN}Created ${queue_type} message with ID ${msg_id}${NC}"
    return 0
}

# Check queue before creating entries
echo -e "\n${YELLOW}Checking queue before creating entries:${NC}"
docker exec elemta-cli /app/elemta-queue -config /app/config/elemta.toml stats

# Create a few queue entries
echo -e "\n${YELLOW}Creating queue entries:${NC}"
for i in {1..3}; do
    create_queue_entry
done

# Check queue after creating entries
echo -e "\n${YELLOW}Checking queue after creating entries:${NC}"
docker exec elemta-cli /app/elemta-queue -config /app/config/elemta.toml stats

# List messages in the queue
echo -e "\n${YELLOW}Listing messages in the queue:${NC}"
docker exec elemta-cli /app/elemta-queue -config /app/config/elemta.toml list

echo -e "\n${GREEN}Queue test complete!${NC}" 