#!/bin/bash

# Script to check the format and structure of the queue directory

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

# Check the queue directory structure
print_header "Queue Directory Structure"
docker exec elemta ls -la /app/queue

# Check the contents of each queue subdirectory
for dir in active deferred held failed data; do
    print_header "Contents of $dir queue"
    docker exec elemta ls -la /app/queue/$dir 2>/dev/null || echo "Directory does not exist"
done

# Sample a queue entry if available
print_header "Sample Queue Entry"
for dir in active deferred held failed; do
    SAMPLE_FILE=$(docker exec elemta ls -1 /app/queue/$dir 2>/dev/null | head -n 1)
    if [ ! -z "$SAMPLE_FILE" ]; then
        echo -e "${GREEN}Found sample file in $dir queue: $SAMPLE_FILE${NC}"
        echo -e "${YELLOW}Contents:${NC}"
        docker exec elemta cat /app/queue/$dir/$SAMPLE_FILE
        
        # Check corresponding data file
        MSG_ID="${SAMPLE_FILE%.json}"
        echo -e "\n${GREEN}Checking data file for $MSG_ID${NC}"
        docker exec elemta ls -la /app/queue/data/$MSG_ID.eml 2>/dev/null || echo "Data file does not exist"
        break
    fi
done

# Check queue configuration
print_header "Queue Configuration"
echo -e "${GREEN}Queue configuration in elemta.toml:${NC}"
docker exec elemta cat /app/config/elemta.toml | grep -i queue

# Check queue command help
print_header "Queue Command Help"
docker exec elemta /app/elemta queue --help

echo -e "\n${GREEN}Queue check complete!${NC}" 