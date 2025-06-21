#!/bin/bash

# Dashboard Population Wrapper Script
# Simple interface for populating all Grafana dashboards with test data

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Elemta Dashboard Population Test${NC}"
echo "=================================="

# Check if Python script exists
if [ ! -f "scripts/test-dashboard-population.py" ]; then
    echo -e "${RED}❌ Error: Dashboard population script not found!${NC}"
    echo "Expected: scripts/test-dashboard-population.py"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}❌ Error: Not in Elemta project root directory!${NC}"
    echo "Please run this script from the Elemta project root."
    exit 1
fi

# Check Docker services
echo -e "${YELLOW}🔍 Checking Docker services...${NC}"
if ! docker-compose ps | grep -q "Up"; then
    echo -e "${RED}❌ Error: Docker services not running!${NC}"
    echo "Please start services first:"
    echo "  docker-compose up -d"
    exit 1
fi

# Count running services
RUNNING_SERVICES=$(docker-compose ps | grep "Up" | wc -l)
echo -e "${GREEN}✅ Found ${RUNNING_SERVICES} running services${NC}"

# Install Python dependencies if needed
echo -e "${YELLOW}📦 Checking Python dependencies...${NC}"
if ! python3 -c "import requests" 2>/dev/null; then
    echo -e "${YELLOW}Installing requests library...${NC}"
    pip3 install requests
fi

# Show help if requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    python3 scripts/test-dashboard-population.py --help
    exit 0
fi

# Show quick status
echo -e "${YELLOW}📊 Quick service status:${NC}"
echo "• SMTP Server: $(curl -s localhost:2525 >/dev/null 2>&1 && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}❌ Down${NC}")"
echo "• Metrics API: $(curl -s localhost:8080/metrics >/dev/null 2>&1 && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}❌ Down${NC}")"
echo "• Prometheus: $(curl -s localhost:9090 >/dev/null 2>&1 && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}❌ Down${NC}")"
echo "• Grafana: $(curl -s localhost:3000 >/dev/null 2>&1 && echo -e "${GREEN}✅ Running${NC}" || echo -e "${RED}❌ Down${NC}")"
echo ""

# Run the dashboard population
echo -e "${BLUE}🚀 Starting dashboard population...${NC}"
echo ""

if python3 scripts/test-dashboard-population.py; then
    echo ""
    echo -e "${GREEN}🎉 Dashboard population completed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}📊 Check your dashboards:${NC}"
    echo "• Grafana: http://localhost:3000 (admin:elemta123)"
    echo "• Prometheus: http://localhost:9090"
    echo "• Metrics: http://localhost:8080/metrics"
    echo ""
    echo -e "${YELLOW}📈 Expected dashboard data:${NC}"
    echo "• Overview Dashboard: Basic SMTP connection and message metrics"
    echo "• Main Dashboard: Detailed performance, queue, and throughput metrics"
    echo "• Greylisting Dashboard: Greylisting events and statistics"
    echo "• Security Dashboard: Authentication failures, security events"
    echo "• Let's Encrypt Dashboard: Certificate monitoring (already working)"
    
    exit 0
else
    echo ""
    echo -e "${RED}❌ Dashboard population failed!${NC}"
    echo "Check the error messages above and ensure all services are running."
    exit 1
fi 