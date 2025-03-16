#!/bin/bash

# Script to deploy and test Elemta in one go

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

# Step 1: Undeploy any existing containers
print_header "Undeploying existing containers"
docker-compose down --remove-orphans || true
docker stop elemta-cli || true
docker rm elemta-cli || true
docker network prune -f || true
echo -e "${GREEN}Undeployment complete!${NC}"

# Step 2: Build the Docker images
print_header "Building Docker images"
docker build -t elemta:latest .
docker build -t elemta-cli:latest -f Dockerfile.cli .
echo -e "${GREEN}Docker build complete!${NC}"

# Step 3: Deploy with Docker Compose
print_header "Deploying with Docker Compose"
docker-compose up -d
docker run -d --name elemta-cli --network elemta_elemta_network -p 2526:25 -p 5871:587 -p 8083:8080 elemta-cli:latest
echo -e "${GREEN}Docker deployment complete!${NC}"

# Step 4: Wait for containers to be ready
print_header "Waiting for containers to be ready"
echo "Waiting for elemta container..."
for i in {1..10}; do
  if docker ps | grep -q "elemta.*healthy"; then
    echo "Elemta container is ready!"
    break
  fi
  echo "Waiting... ($i/10)"
  sleep 3
done

echo "Waiting for elemta-cli container..."
for i in {1..10}; do
  if docker ps | grep -q "elemta-cli.*healthy"; then
    echo "Elemta-cli container is ready!"
    break
  fi
  echo "Waiting... ($i/10)"
  sleep 3
done

# Step 5: Run the SMTP test
print_header "Running SMTP test"
./scripts/test-smtp.sh
echo -e "${GREEN}SMTP test complete!${NC}"

# Step 6: Run the queue simulation
print_header "Running queue simulation"
./scripts/simulate-queue.sh
echo -e "${GREEN}Queue simulation complete!${NC}"

# Step 7: Check the queue
print_header "Checking queue"
./scripts/check-queue.sh
echo -e "${GREEN}Queue check complete!${NC}"

# Step 8: Run the test mode
print_header "Running test mode"
./scripts/test-mode.sh
echo -e "${GREEN}Test mode complete!${NC}"

print_header "Deployment and Testing Complete"
echo -e "${GREEN}All tests completed successfully!${NC}"
echo "You can now use the following commands to manage the queue:"
echo "  ./scripts/elemta-cli.sh queue list     - List all messages in the queue"
echo "  ./scripts/elemta-cli.sh queue stats    - Show queue statistics"
echo "  ./scripts/elemta-cli.sh queue view ID  - View details of a specific message" 