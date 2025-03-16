#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Verifying Elemta Monitoring Stack${NC}"
echo "======================================"

# Check if docker-compose-monitoring.yml exists
if [ ! -f "docker-compose-monitoring.yml" ]; then
  echo -e "${RED}Error: docker-compose-monitoring.yml not found${NC}"
  echo "Please run ./scripts/start-monitoring.sh first."
  exit 1
fi

# Check if monitoring containers are running
echo "Checking if monitoring containers are running..."
GRAFANA_RUNNING=$(docker ps -q -f name=elemta_grafana)
PROMETHEUS_RUNNING=$(docker ps -q -f name=prometheus)
ALERTMANAGER_RUNNING=$(docker ps -q -f name=alertmanager)

if [ -z "$GRAFANA_RUNNING" ]; then
  echo -e "${RED}Grafana container is not running${NC}"
  echo "Please run ./scripts/start-monitoring.sh first."
  exit 1
fi

if [ -z "$PROMETHEUS_RUNNING" ]; then
  echo -e "${RED}Prometheus container is not running${NC}"
  echo "Please run ./scripts/start-monitoring.sh first."
  exit 1
fi

if [ -z "$ALERTMANAGER_RUNNING" ]; then
  echo -e "${RED}AlertManager container is not running${NC}"
  echo "Please run ./scripts/start-monitoring.sh first."
  exit 1
fi

echo -e "${GREEN}All monitoring containers are running${NC}"

# Check if Grafana is accessible
echo "Checking if Grafana is accessible..."
GRAFANA_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000)

if [[ "$GRAFANA_TEST" == "200" || "$GRAFANA_TEST" == "302" ]]; then
  echo -e "${GREEN}Grafana is accessible at http://localhost:3000${NC}"
else
  echo -e "${RED}Grafana is not accessible at http://localhost:3000${NC}"
  echo "HTTP status code: $GRAFANA_TEST"
  exit 1
fi

# Check if Prometheus is accessible
echo "Checking if Prometheus is accessible..."
PROMETHEUS_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090)

if [[ "$PROMETHEUS_TEST" == "200" || "$PROMETHEUS_TEST" == "302" ]]; then
  echo -e "${GREEN}Prometheus is accessible at http://localhost:9090${NC}"
else
  echo -e "${RED}Prometheus is not accessible at http://localhost:9090${NC}"
  echo "HTTP status code: $PROMETHEUS_TEST"
  exit 1
fi

# Check if AlertManager is accessible
echo "Checking if AlertManager is accessible..."
ALERTMANAGER_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9093)

if [[ "$ALERTMANAGER_TEST" == "200" ]]; then
  echo -e "${GREEN}AlertManager is accessible at http://localhost:9093${NC}"
else
  echo -e "${RED}AlertManager is not accessible at http://localhost:9093${NC}"
  echo "HTTP status code: $ALERTMANAGER_TEST"
  exit 1
fi

# Check if Prometheus can scrape Elemta metrics
echo "Checking if Prometheus can scrape Elemta metrics..."
SCRAPE_TEST=$(curl -s "http://localhost:9090/api/v1/query?query=up{job=%22elemta%22}")

if [[ "$SCRAPE_TEST" == *"\"status\":\"success\""* && "$SCRAPE_TEST" == *"\"value\":[1"* ]]; then
  echo -e "${GREEN}Prometheus can scrape Elemta metrics${NC}"
else
  echo -e "${YELLOW}Warning: Prometheus may not be able to scrape Elemta metrics${NC}"
  echo "This could be because the Elemta service is not running or not exposing metrics."
  echo "Response: $SCRAPE_TEST"
fi

# Check if Grafana has the Prometheus datasource configured
echo "Checking if Grafana has the Prometheus datasource configured..."
# This requires the Grafana API, which needs authentication
# For simplicity, we'll just check if the datasource configuration file exists
if [ -f "monitoring/grafana/provisioning/datasources/datasource.yml" ]; then
  echo -e "${GREEN}Grafana datasource configuration exists${NC}"
else
  echo -e "${RED}Grafana datasource configuration does not exist${NC}"
  echo "Please run ./scripts/start-monitoring.sh first."
  exit 1
fi

# Check if Grafana has dashboards configured
echo "Checking if Grafana has dashboards configured..."
if [ -f "monitoring/grafana/dashboards/elemta_overview.json" ]; then
  echo -e "${GREEN}Grafana dashboard configuration exists${NC}"
else
  echo -e "${RED}Grafana dashboard configuration does not exist${NC}"
  echo "Please run ./scripts/start-monitoring.sh first."
  exit 1
fi

echo -e "\n${GREEN}All monitoring components are running and accessible${NC}"
echo "Grafana: http://localhost:3000 (default credentials: admin/elemta123)"
echo "Prometheus: http://localhost:9090"
echo "AlertManager: http://localhost:9093"

echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Log in to Grafana at http://localhost:3000 with admin/elemta123"
echo "2. Check the Elemta Overview dashboard"
echo "3. Run ./scripts/generate-test-load.sh to generate test metrics"
echo "4. Run ./tests/test-elemta.sh to verify all components"

# Check if metrics server is running
echo -e "\n${YELLOW}Checking Metrics Server:${NC}"
if curl -s http://localhost:8080/metrics > /dev/null; then
  echo -e "${GREEN}✓ Metrics server is running and accessible${NC}"
  echo "  URL: http://localhost:8080/metrics"
else
  echo -e "${RED}✗ Metrics server is not accessible${NC}"
  echo "  Could not connect to http://localhost:8080/metrics"
fi

# Check if Prometheus is running
echo -e "\n${YELLOW}Checking Prometheus:${NC}"
if curl -s http://localhost:9090/-/healthy > /dev/null; then
  echo -e "${GREEN}✓ Prometheus is running and healthy${NC}"
  echo "  URL: http://localhost:9090"
else
  echo -e "${RED}✗ Prometheus is not accessible${NC}"
  echo "  Could not connect to http://localhost:9090"
fi

# Check if Grafana is running
echo -e "\n${YELLOW}Checking Grafana:${NC}"
if curl -s http://localhost:3000/api/health > /dev/null; then
  echo -e "${GREEN}✓ Grafana is running and healthy${NC}"
  echo "  URL: http://localhost:3000 (default credentials: admin/elemta123)"
else
  echo -e "${RED}✗ Grafana is not accessible${NC}"
  echo "  Could not connect to http://localhost:3000"
fi

# Check if AlertManager is running
echo -e "\n${YELLOW}Checking AlertManager:${NC}"
if curl -s http://localhost:9093/-/healthy > /dev/null; then
  echo -e "${GREEN}✓ AlertManager is running and healthy${NC}"
  echo "  URL: http://localhost:9093"
else
  echo -e "${RED}✗ AlertManager is not accessible${NC}"
  echo "  Could not connect to http://localhost:9093"
fi

# Check if Prometheus can scrape the metrics
echo -e "\n${YELLOW}Checking Prometheus targets:${NC}"
TARGETS=$(curl -s http://localhost:9090/api/v1/targets | grep -o '"health":"up"' | wc -l)
if [ "$TARGETS" -gt 0 ]; then
  echo -e "${GREEN}✓ Prometheus has $TARGETS healthy targets${NC}"
else
  echo -e "${RED}✗ Prometheus has no healthy targets${NC}"
  echo "  Check Prometheus configuration and target connectivity"
fi

echo -e "\n${YELLOW}Monitoring Stack Verification Complete${NC}"
echo "======================================"
echo -e "Access the monitoring stack at:"
echo -e "  Grafana: ${GREEN}http://localhost:3000${NC} (default credentials: admin/elemta123)"
echo -e "  Prometheus: ${GREEN}http://localhost:9090${NC}"
echo -e "  AlertManager: ${GREEN}http://localhost:9093${NC}"
echo -e "  Metrics: ${GREEN}http://localhost:8080/metrics${NC}" 