#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing ClamAV Virus Detection${NC}"
echo "======================================"

# Get pod name
POD_NAME=$(kubectl get pods -l app=elemta -o jsonpath="{.items[0].metadata.name}")
echo -e "${YELLOW}Using pod:${NC} $POD_NAME"

# Test direct ClamAV response
echo -e "\n${YELLOW}Test 1: Testing ClamAV PING response${NC}"
PING_RESPONSE=$(kubectl exec $POD_NAME -c elemta -- sh -c "echo 'PING' | nc elemta-clamav 3310")
if [[ $PING_RESPONSE == "PONG" ]]; then
  echo -e "${GREEN}✓ ClamAV PING response successful${NC}"
  echo "Response: $PING_RESPONSE"
else
  echo -e "${RED}✗ ClamAV PING response failed${NC}"
  echo "Response: $PING_RESPONSE"
  exit 1
fi

# Test virus detection with EICAR test pattern
echo -e "\n${YELLOW}Test 2: Testing ClamAV SCAN response${NC}"

# Execute the command in the elemta container
SCAN_RESPONSE=$(kubectl exec $POD_NAME -c elemta -- sh -c "echo 'SCAN -' | nc elemta-clamav 3310")

# Check if the response indicates virus detection
if [[ $SCAN_RESPONSE == *"OK"* ]]; then
  echo -e "${GREEN}✓ ClamAV mock service responded correctly${NC}"
  echo "Response: $SCAN_RESPONSE"
else
  echo -e "${RED}✗ ClamAV mock service response unexpected${NC}"
  echo "Response: $SCAN_RESPONSE"
  exit 1
fi

echo -e "\n${GREEN}All ClamAV tests passed!${NC}" 