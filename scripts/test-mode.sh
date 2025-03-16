#!/bin/bash

# Comprehensive test script for Elemta that combines queue simulation and SMTP testing

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
SMTP_SERVER="localhost"
SMTP_PORT="2526"
NUM_EMAILS=3
CLEAR_QUEUE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --type|-t)
      TEST_TYPE="$2"
      shift 2
      ;;
    --server|-s)
      SMTP_SERVER="$2"
      shift 2
      ;;
    --port|-p)
      SMTP_PORT="$2"
      shift 2
      ;;
    --count|-c)
      NUM_EMAILS="$2"
      shift 2
      ;;
    --clear|-C)
      CLEAR_QUEUE=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --type, -t      Test type: all, smtp, queue, python (default: all)"
      echo "  --server, -s    SMTP server address (default: localhost)"
      echo "  --port, -p      SMTP server port (default: 2526)"
      echo "  --count, -c     Number of emails to send (default: 3)"
      echo "  --clear, -C     Clear the queue before testing"
      echo "  --help, -h      Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Function to print section headers
print_header() {
  echo -e "\n${BLUE}======================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}======================================${NC}"
}

# Function to check if Docker is running
check_docker() {
  if ! docker info &>/dev/null; then
    echo -e "${RED}Error: Docker is not running.${NC}"
    echo "Please start Docker and try again."
    exit 1
  fi
}

# Function to check if the elemta-cli container is running
check_elemta_cli() {
  if ! docker ps | grep -q elemta-cli; then
    echo -e "${YELLOW}The elemta-cli container is not running.${NC}"
    echo "Starting it now..."
    
    # Check if the container exists but is stopped
    if docker ps -a | grep -q elemta-cli; then
      docker start elemta-cli
    else
      # Check if the image exists
      if ! docker images | grep -q elemta-cli; then
        echo "Building the elemta-cli image..."
        docker-compose -f docker-compose-cli.yml build
      fi
      
      echo "Starting the elemta-cli container..."
      docker run -d --name elemta-cli --network elemta_elemta_network -p 2526:25 -p 5871:587 -p 8083:8080 elemta-cli
    fi
    
    # Wait for the container to be healthy
    echo "Waiting for the container to be ready..."
    for i in {1..10}; do
      if docker ps | grep -q "elemta-cli.*healthy"; then
        break
      fi
      echo "Waiting... ($i/10)"
      sleep 3
    done
  fi
}

# Function to clear the queue
clear_queue() {
  print_header "Clearing the Queue"
  
  # Use the Python script to clear the queue
  docker exec -it elemta-cli python3 /app/scripts/mock-queue.py clear
  
  echo -e "${GREEN}Queue cleared successfully!${NC}"
}

# Function to test queue functionality
test_queue() {
  print_header "Testing Queue Functionality"
  
  # Check queue before creating messages
  echo -e "\n${YELLOW}Checking queue before creating messages:${NC}"
  ./scripts/elemta-cli.sh queue -config /app/config/elemta.toml stats
  
  # Use the Python script to create queue entries
  echo -e "\n${YELLOW}Creating queue entries using Python script:${NC}"
  docker exec -it elemta-cli python3 /app/scripts/mock-queue.py create 3 2 1 1
  
  # Check queue after creating messages
  echo -e "\n${YELLOW}Checking queue after creating messages:${NC}"
  ./scripts/elemta-cli.sh queue -config /app/config/elemta.toml stats
  
  # List messages in the queue
  echo -e "\n${YELLOW}Listing messages in the queue:${NC}"
  ./scripts/elemta-cli.sh queue -config /app/config/elemta.toml list
  
  echo -e "\n${GREEN}Queue test complete!${NC}"
}

# Function to test SMTP functionality
test_smtp() {
  print_header "Testing SMTP Functionality"
  
  # Check if swaks is installed
  if ! command -v swaks &> /dev/null; then
    echo -e "${RED}Error: swaks is not installed.${NC}"
    echo "Please install swaks first:"
    echo "  sudo apt-get install swaks    # Debian/Ubuntu"
    echo "  sudo yum install swaks        # CentOS/RHEL"
    echo "  brew install swaks            # macOS with Homebrew"
    return 1
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
    swaks --server "$SMTP_SERVER" --port "$SMTP_PORT" \
          --from "sender@example.com" --to "recipient@example.com" \
          --header "Subject: Test Email #$i" \
          --header "Message-ID: <$MSG_ID>" \
          --body "This is a test email sent by swaks. (Email #$i)" \
          --h-From: "Test Sender <sender@example.com>" \
          --h-To: "Test Recipient <recipient@example.com>"
    
    # Check the result
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}Email $i sent successfully!${NC}"
    else
      echo -e "${RED}Failed to send email $i.${NC}"
    fi
    
    # Wait before sending the next email
    if [ $i -lt $NUM_EMAILS ]; then
      echo "Waiting 1 second before sending the next email..."
      sleep 1
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
}

# Function to test Python functionality
test_python() {
  print_header "Testing Python Functionality"
  
  # Check if the Python script exists in the container
  if ! docker exec elemta-cli test -f /app/scripts/mock-queue.py; then
    echo -e "${YELLOW}Copying mock-queue.py to the container...${NC}"
    docker cp scripts/mock-queue.py elemta-cli:/app/scripts/
    docker exec elemta-cli chmod +x /app/scripts/mock-queue.py
  fi
  
  # Run the Python script in the container
  echo -e "\n${YELLOW}Running Python script in the container:${NC}"
  docker exec -it elemta-cli python3 /app/scripts/mock-queue.py stats
  
  echo -e "\n${GREEN}Python test complete!${NC}"
}

# Main function
main() {
  print_header "Elemta Test Mode"
  echo "Test Type: $TEST_TYPE"
  echo "SMTP Server: $SMTP_SERVER"
  echo "SMTP Port: $SMTP_PORT"
  echo "Number of Emails: $NUM_EMAILS"
  echo "Clear Queue: $CLEAR_QUEUE"
  
  # Check Docker
  check_docker
  
  # Check elemta-cli container
  check_elemta_cli
  
  # Copy the Python script to the container if it doesn't exist
  if ! docker exec elemta-cli test -f /app/scripts/mock-queue.py; then
    echo -e "\n${YELLOW}Copying mock-queue.py to the container...${NC}"
    docker cp scripts/mock-queue.py elemta-cli:/app/scripts/
    docker exec elemta-cli chmod +x /app/scripts/mock-queue.py
  fi
  
  # Clear the queue if requested
  if [ "$CLEAR_QUEUE" = true ]; then
    clear_queue
  fi
  
  # Run the requested tests
  case "$TEST_TYPE" in
    all)
      test_queue
      test_smtp
      test_python
      ;;
    queue)
      test_queue
      ;;
    smtp)
      test_smtp
      ;;
    python)
      test_python
      ;;
    *)
      echo -e "${RED}Error: Unknown test type: $TEST_TYPE${NC}"
      echo "Valid test types are: all, smtp, queue, python"
      exit 1
      ;;
  esac
  
  print_header "Test Summary"
  echo -e "${GREEN}All tests completed!${NC}"
  echo "You can now use the following commands to manage the queue:"
  echo "  ./scripts/elemta-cli.sh queue list     - List all messages in the queue"
  echo "  ./scripts/elemta-cli.sh queue stats    - Show queue statistics"
  echo "  ./scripts/elemta-cli.sh queue view ID  - View details of a specific message"
}

# Run the main function
main 