#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Verifying Elemta monitoring stack...${NC}"

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

# Function to check if a service is running
check_service() {
  local service=$1
  local container_id=$(docker-compose -f docker-compose-monitoring.yml ps -q $service)
  
  if [ -z "$container_id" ]; then
    echo -e "${RED}Error: $service container is not running.${NC}"
    return 1
  else
    echo -e "${GREEN}$service is running.${NC}"
    return 0
  fi
}

# Check all services
echo -e "\n${YELLOW}Checking services...${NC}"
check_service "elemta" || exit 1
check_service "prometheus" || exit 1
check_service "grafana" || exit 1
check_service "alertmanager" || exit 1

# Check Elemta metrics endpoint
echo -e "\n${YELLOW}Checking Elemta metrics endpoint...${NC}"
ELEMTA_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q elemta)
METRICS=$(docker exec $ELEMTA_CONTAINER curl -s http://localhost:8080/metrics)
if [ -z "$METRICS" ]; then
  echo -e "${RED}Error: Could not get metrics from Elemta.${NC}"
  exit 1
else
  echo -e "${GREEN}Successfully retrieved metrics from Elemta.${NC}"
  echo -e "${YELLOW}Sample metrics:${NC}"
  echo "$METRICS" | head -n 10
fi

# Check Prometheus targets
echo -e "\n${YELLOW}Checking Prometheus targets...${NC}"
PROMETHEUS_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q prometheus)
TARGETS=$(docker exec $PROMETHEUS_CONTAINER curl -s http://localhost:9090/api/v1/targets)
if [[ $TARGETS != *"elemta"* ]]; then
  echo -e "${RED}Error: Elemta target not found in Prometheus.${NC}"
  exit 1
else
  echo -e "${GREEN}Elemta target found in Prometheus.${NC}"
fi

# Check Prometheus rules
echo -e "\n${YELLOW}Checking Prometheus rules...${NC}"
RULES=$(docker exec $PROMETHEUS_CONTAINER curl -s http://localhost:9090/api/v1/rules)
if [[ $RULES != *"elemta_alerts"* ]]; then
  echo -e "${RED}Error: Elemta alert rules not found in Prometheus.${NC}"
  exit 1
else
  echo -e "${GREEN}Elemta alert rules found in Prometheus.${NC}"
fi

# Check AlertManager
echo -e "\n${YELLOW}Checking AlertManager...${NC}"
ALERTMANAGER_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q alertmanager)
STATUS=$(docker exec $ALERTMANAGER_CONTAINER curl -s http://localhost:9093/api/v2/status)
if [[ $STATUS != *"config"* ]]; then
  echo -e "${RED}Error: AlertManager is not responding properly.${NC}"
  exit 1
else
  echo -e "${GREEN}AlertManager is responding properly.${NC}"
fi

# Check Grafana datasources
echo -e "\n${YELLOW}Checking Grafana datasources...${NC}"
GRAFANA_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q grafana)
DATASOURCES=$(docker exec $GRAFANA_CONTAINER curl -s -u admin:admin http://localhost:3000/api/datasources)
if [[ $DATASOURCES != *"Prometheus"* ]]; then
  echo -e "${RED}Error: Prometheus datasource not found in Grafana.${NC}"
  exit 1
else
  echo -e "${GREEN}Prometheus datasource found in Grafana.${NC}"
fi

# Check Grafana dashboards
echo -e "\n${YELLOW}Checking Grafana dashboards...${NC}"
DASHBOARDS=$(docker exec $GRAFANA_CONTAINER curl -s -u admin:admin http://localhost:3000/api/search?query=Elemta)
if [[ $DASHBOARDS != *"Elemta"* ]]; then
  echo -e "${YELLOW}Warning: Elemta dashboards not found in Grafana.${NC}"
  echo -e "${YELLOW}This might be normal if you haven't imported the dashboards yet.${NC}"
else
  echo -e "${GREEN}Elemta dashboards found in Grafana.${NC}"
fi

# Check Grafana alerts
echo -e "\n${YELLOW}Checking Grafana alerts...${NC}"
ALERTS=$(docker exec $GRAFANA_CONTAINER curl -s -u admin:admin http://localhost:3000/api/alerts)
if [[ $ALERTS == *"[]"* ]]; then
  echo -e "${YELLOW}Warning: No alerts found in Grafana.${NC}"
  echo -e "${YELLOW}This might be normal if you haven't created any alerts yet.${NC}"
else
  echo -e "${GREEN}Alerts found in Grafana.${NC}"
fi

# Generate some test metrics
echo -e "\n${YELLOW}Generating test metrics...${NC}"
./scripts/generate-test-load.sh > /dev/null 2>&1 &
PID=$!

# Wait for a bit to let metrics be generated
echo -e "${YELLOW}Waiting for metrics to be generated...${NC}"
sleep 10
kill $PID 2>/dev/null || true

# Check if metrics were generated
echo -e "\n${YELLOW}Checking if metrics were generated...${NC}"
METRICS_AFTER=$(docker exec $ELEMTA_CONTAINER curl -s http://localhost:8080/metrics)
if [[ $METRICS_AFTER == $METRICS ]]; then
  echo -e "${YELLOW}Warning: Metrics don't appear to have changed. Test load generation might not be working.${NC}"
else
  echo -e "${GREEN}Metrics have changed. Test load generation is working.${NC}"
fi

echo -e "\n${YELLOW}Monitoring URLs:${NC}"
echo -e "${GREEN}Grafana:${NC} http://localhost:3000 (admin/admin)"
echo -e "${GREEN}Prometheus:${NC} http://localhost:9090"
echo -e "${GREEN}AlertManager:${NC} http://localhost:9093"

echo -e "\n${GREEN}Verification completed successfully.${NC}"
echo -e "${YELLOW}The monitoring stack is properly set up and functioning.${NC}" 