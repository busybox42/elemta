#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing Rspamd Functionality${NC}"
echo "======================================"

# Get pod name
POD_NAME=$(kubectl get pods -l app=elemta -o jsonpath="{.items[0].metadata.name}")
echo -e "${YELLOW}Using pod:${NC} $POD_NAME"

# Test 1: Check Rspamd web interface
echo -e "\n${YELLOW}Test 1: Checking Rspamd web interface${NC}"
RSPAMD_PORT=$(kubectl get service elemta-rspamd -o jsonpath="{.spec.ports[?(@.name=='rspamd-web')].nodePort}")
RSPAMD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$RSPAMD_PORT)

if [ "$RSPAMD_STATUS" -eq 200 ]; then
  echo -e "${GREEN}✓ Rspamd web interface is accessible${NC}"
  echo "Rspamd web interface: http://localhost:$RSPAMD_PORT"
else
  echo -e "${RED}✗ Rspamd web interface is not accessible (HTTP status: $RSPAMD_STATUS)${NC}"
  exit 1
fi

# Test 2: Check Rspamd protocol
echo -e "\n${YELLOW}Test 2: Testing Rspamd protocol connection${NC}"
RSPAMD_TEST=$(kubectl exec $POD_NAME -c elemta -- sh -c "printf 'CHECK RSPAMD/1.0\r\nContent-Length: 0\r\n\r\n' | nc elemta-rspamd 11333")
if [[ -n "$RSPAMD_TEST" ]]; then
  echo -e "${GREEN}✓ Rspamd connection successful${NC}"
  echo "Response received:"
  echo "$RSPAMD_TEST"
else
  echo -e "${RED}✗ Rspamd connection failed${NC}"
  exit 1
fi

# Test 3: Check Rspamd API
echo -e "\n${YELLOW}Test 3: Testing Rspamd API${NC}"
API_RESPONSE=$(curl -s http://localhost:$RSPAMD_PORT/stat)
if [[ -n "$API_RESPONSE" ]]; then
  echo -e "${GREEN}✓ Rspamd API is accessible${NC}"
  echo "API response:"
  echo "$API_RESPONSE" | head -10
else
  echo -e "${RED}✗ Rspamd API is not accessible${NC}"
  exit 1
fi

echo -e "\n${GREEN}All Rspamd tests passed!${NC}" 