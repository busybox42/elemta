#!/bin/bash

# Script to generate test security events for ClamAV and Rspamd

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Generating test security events for Elemta...${NC}"

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

# Check if ClamAV is running
if ! docker-compose -f docker-compose-monitoring.yml ps -q clamav &>/dev/null; then
  echo -e "${RED}Error: ClamAV container is not running. Security monitoring may be incomplete.${NC}"
  exit 1
fi

# Check if Rspamd is running
if ! docker-compose -f docker-compose-monitoring.yml ps -q rspamd &>/dev/null; then
  echo -e "${RED}Error: Rspamd container is not running. Security monitoring may be incomplete.${NC}"
  exit 1
fi

# Copy test files to containers
echo -e "\n${YELLOW}Copying test files to containers...${NC}"

# Copy EICAR test file to ClamAV container
CLAMAV_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q clamav)
docker cp tests/data/eicar.txt $CLAMAV_CONTAINER:/tmp/eicar.txt
echo -e "${GREEN}Copied EICAR test file to ClamAV container.${NC}"

# Copy GTUBE test file to Rspamd container
RSPAMD_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q rspamd)
docker cp tests/data/gtube.txt $RSPAMD_CONTAINER:/tmp/gtube.txt
echo -e "${GREEN}Copied GTUBE test file to Rspamd container.${NC}"

# Generate ClamAV events
echo -e "\n${YELLOW}Generating ClamAV events...${NC}"
for i in {1..5}; do
  echo -e "${YELLOW}Running ClamAV scan $i of 5...${NC}"
  docker exec $CLAMAV_CONTAINER clamdscan /tmp/eicar.txt || true
  sleep 1
done
echo -e "${GREEN}Generated ClamAV events.${NC}"

# Generate Rspamd events
echo -e "\n${YELLOW}Generating Rspamd events...${NC}"
for i in {1..5}; do
  echo -e "${YELLOW}Running Rspamd scan $i of 5...${NC}"
  docker exec $RSPAMD_CONTAINER rspamc scan /tmp/gtube.txt || true
  sleep 1
done
echo -e "${GREEN}Generated Rspamd events.${NC}"

echo -e "\n${GREEN}Security events generation completed.${NC}"
echo -e "${YELLOW}You should now see security metrics in Prometheus and Grafana.${NC}"
echo -e "${YELLOW}Check the metrics at:${NC}"
echo -e "${GREEN}Prometheus:${NC} http://localhost:9090"
echo -e "${GREEN}Grafana:${NC} http://localhost:3000 (admin/elemta123)" 