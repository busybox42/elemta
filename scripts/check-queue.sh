#!/bin/bash

# Script to check the queue format and structure

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

# Check if the elemta-cli container is running
if ! docker ps | grep -q elemta-cli; then
    echo -e "${RED}Error: elemta-cli container is not running.${NC}"
    echo "Please start the container first."
    exit 1
fi

print_header "Checking Queue Directory Structure"

# Check queue directory structure
echo -e "${YELLOW}Queue directory structure:${NC}"
docker exec elemta-cli ls -la /app/queue

# Check queue subdirectories
for dir in active deferred held failed data; do
    echo -e "\n${YELLOW}Contents of /app/queue/$dir:${NC}"
    docker exec elemta-cli ls -la /app/queue/$dir 2>/dev/null || echo "Directory does not exist"
done

print_header "Checking Queue Files Format"

# Check a sample file from each queue type
for dir in active deferred held failed; do
    echo -e "\n${YELLOW}Sample file from $dir queue:${NC}"
    SAMPLE_FILE=$(docker exec elemta-cli ls -1 /app/queue/$dir 2>/dev/null | head -n 1)
    
    if [ -n "$SAMPLE_FILE" ]; then
        echo "File: $SAMPLE_FILE"
        echo -e "${YELLOW}File content:${NC}"
        docker exec elemta-cli cat /app/queue/$dir/$SAMPLE_FILE
        
        # If it's a metadata file, check the corresponding data file
        if [[ "$SAMPLE_FILE" == *.meta ]]; then
            MSG_ID=$(echo "$SAMPLE_FILE" | sed 's/\.meta$//')
            echo -e "\n${YELLOW}Corresponding data file:${NC}"
            docker exec elemta-cli ls -la /app/queue/data/$MSG_ID.eml 2>/dev/null || echo "Data file does not exist"
        fi
    else
        echo "No files found in $dir queue"
    fi
done

print_header "Checking Queue Configuration"

# Check queue configuration
echo -e "${YELLOW}Queue configuration in elemta.toml:${NC}"
docker exec elemta-cli cat /app/config/elemta.toml | grep -i queue

print_header "Checking Queue Command"

# Check queue command
echo -e "${YELLOW}Queue command help:${NC}"
docker exec elemta-cli /app/elemta-queue --help

print_header "Queue Statistics"

# Check queue statistics
echo -e "${YELLOW}Queue statistics:${NC}"
./scripts/elemta-cli.sh queue -config /app/config/elemta.toml stats

print_header "Queue Check Complete"

echo -e "${GREEN}Queue check complete!${NC}"
echo "If you're having issues with the queue, check the following:"
echo "1. Make sure the queue directory structure is correct"
echo "2. Make sure the queue files have the correct format"
echo "3. Make sure the queue configuration is correct"
echo "4. Try clearing the queue and creating new messages"
echo "5. Check the logs for any errors" 