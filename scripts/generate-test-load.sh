#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Generating Test Load for Elemta${NC}"
echo "======================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
  exit 1
fi

# Check if the Elemta container is running
ELEMTA_RUNNING=$(docker ps -q -f name=elemta)
if [ -z "$ELEMTA_RUNNING" ]; then
  echo -e "${RED}Error: Elemta container is not running.${NC}"
  echo "Please start the Elemta container first."
  exit 1
fi

# Function to send SMTP traffic
send_smtp_traffic() {
  local count=$1
  echo "Sending $count SMTP messages..."
  
  for i in $(seq 1 $count); do
    echo -e "HELO localhost\r\nMAIL FROM:<test$i@example.com>\r\nRCPT TO:<recipient$i@example.com>\r\nDATA\r\nSubject: Test Email $i\r\n\r\nThis is test email $i.\r\n.\r\nQUIT\r\n" | nc -w 3 localhost 2525 > /dev/null 2>&1
    echo -n "."
  done
  echo " Done!"
}

# Function to check metrics
check_metrics() {
  echo "Checking metrics..."
  METRICS=$(curl -s http://localhost:8080/metrics)
  
  # Extract some key metrics
  CONNECTIONS=$(echo "$METRICS" | grep "elemta_connections_total" | grep -v "TYPE" | awk '{print $2}')
  MESSAGES_RECEIVED=$(echo "$METRICS" | grep "elemta_messages_received_total" | grep -v "TYPE" | awk '{print $2}')
  MESSAGES_DELIVERED=$(echo "$METRICS" | grep "elemta_messages_delivered_total" | grep -v "TYPE" | awk '{print $2}')
  
  echo "Current metrics:"
  echo "- Connections: $CONNECTIONS"
  echo "- Messages received: $MESSAGES_RECEIVED"
  echo "- Messages delivered: $MESSAGES_DELIVERED"
}

# Generate SMTP traffic
echo "Generating SMTP traffic..."
send_smtp_traffic 10
sleep 2
check_metrics

# Generate more SMTP traffic
echo -e "\nGenerating more SMTP traffic..."
send_smtp_traffic 20
sleep 2
check_metrics

# Generate even more SMTP traffic
echo -e "\nGenerating even more SMTP traffic..."
send_smtp_traffic 30
sleep 2
check_metrics

# Test ClamAV if available
CLAMAV_RUNNING=$(docker ps -q -f name=elemta-clamav)
if [ -n "$CLAMAV_RUNNING" ]; then
  echo -e "\nTesting ClamAV..."
  
  # Create EICAR test file
  echo "Creating EICAR test file..."
  EICAR="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  
  # Send email with EICAR test file
  echo "Sending email with EICAR test file..."
  echo -e "HELO localhost\r\nMAIL FROM:<virus@example.com>\r\nRCPT TO:<recipient@example.com>\r\nDATA\r\nSubject: Virus Test Email\r\n\r\n$EICAR\r\n.\r\nQUIT\r\n" | nc -w 3 localhost 2525 > /dev/null 2>&1
  
  echo "Done!"
fi

# Test Rspamd if available
RSPAMD_RUNNING=$(docker ps -q -f name=elemta-rspamd)
if [ -n "$RSPAMD_RUNNING" ]; then
  echo -e "\nTesting Rspamd..."
  
  # Create GTUBE test string
  echo "Creating GTUBE test string..."
  GTUBE="XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
  
  # Send email with GTUBE test string
  echo "Sending email with GTUBE test string..."
  echo -e "HELO localhost\r\nMAIL FROM:<spam@example.com>\r\nRCPT TO:<recipient@example.com>\r\nDATA\r\nSubject: Spam Test Email\r\n\r\n$GTUBE\r\n.\r\nQUIT\r\n" | nc -w 3 localhost 2525 > /dev/null 2>&1
  
  echo "Done!"
fi

echo -e "\n${GREEN}Test load generation completed${NC}"
echo "You should now see metrics in Grafana if the monitoring stack is running."
echo "Visit http://localhost:3000 to check the dashboards." 