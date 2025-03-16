#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing Elemta monitoring setup...${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
  exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose > /dev/null 2>&1; then
  echo -e "${RED}Error: docker-compose is not installed. Please install it and try again.${NC}"
  exit 1
fi

# Check if the monitoring stack is running
if ! docker-compose -f docker-compose-monitoring.yml ps | grep -q "Up"; then
  echo -e "${YELLOW}Monitoring stack is not running. Starting it now...${NC}"
  docker-compose -f docker-compose-monitoring.yml up -d
  
  # Wait for services to start
  echo -e "${YELLOW}Waiting for services to start...${NC}"
  sleep 10
else
  echo -e "${GREEN}Monitoring stack is already running.${NC}"
fi

# Test Elemta metrics endpoint
echo -e "\n${YELLOW}Testing Elemta metrics endpoint...${NC}"
ELEMTA_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q elemta)
if [ -z "$ELEMTA_CONTAINER" ]; then
  echo -e "${RED}Error: Elemta container is not running.${NC}"
else
  METRICS=$(docker exec $ELEMTA_CONTAINER curl -s http://localhost:8080/metrics)
  if [ -z "$METRICS" ]; then
    echo -e "${RED}Error: Could not get metrics from Elemta.${NC}"
  else
    echo -e "${GREEN}Successfully retrieved metrics from Elemta.${NC}"
    echo -e "${YELLOW}Sample metrics:${NC}"
    echo "$METRICS" | head -n 10
  fi
fi

# Test Prometheus connection to Elemta
echo -e "\n${YELLOW}Testing Prometheus connection to Elemta...${NC}"
PROMETHEUS_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q prometheus)
if [ -z "$PROMETHEUS_CONTAINER" ]; then
  echo -e "${RED}Error: Prometheus container is not running.${NC}"
else
  TARGETS=$(docker exec $PROMETHEUS_CONTAINER curl -s http://localhost:9090/api/v1/targets)
  if [[ $TARGETS != *"elemta"* ]]; then
    echo -e "${RED}Error: Elemta target not found in Prometheus.${NC}"
  else
    echo -e "${GREEN}Elemta target found in Prometheus.${NC}"
  fi
fi

# Test Grafana connection to Prometheus
echo -e "\n${YELLOW}Testing Grafana connection to Prometheus...${NC}"
GRAFANA_CONTAINER=$(docker-compose -f docker-compose-monitoring.yml ps -q grafana)
if [ -z "$GRAFANA_CONTAINER" ]; then
  echo -e "${RED}Error: Grafana container is not running.${NC}"
else
  DATASOURCES=$(docker exec $GRAFANA_CONTAINER curl -s -u admin:admin http://localhost:3000/api/datasources)
  if [[ $DATASOURCES != *"Prometheus"* ]]; then
    echo -e "${RED}Error: Prometheus datasource not found in Grafana.${NC}"
  else
    echo -e "${GREEN}Prometheus datasource found in Grafana.${NC}"
  fi
fi

# Test Grafana dashboards
echo -e "\n${YELLOW}Testing Grafana dashboards...${NC}"
if [ -z "$GRAFANA_CONTAINER" ]; then
  echo -e "${RED}Error: Grafana container is not running.${NC}"
else
  DASHBOARDS=$(docker exec $GRAFANA_CONTAINER curl -s -u admin:admin http://localhost:3000/api/search?query=Elemta)
  if [[ $DASHBOARDS != *"Elemta"* ]]; then
    echo -e "${RED}Warning: Elemta dashboards not found in Grafana.${NC}"
    echo -e "${YELLOW}This might be normal if you haven't imported the dashboards yet.${NC}"
  else
    echo -e "${GREEN}Elemta dashboards found in Grafana.${NC}"
  fi
fi

echo -e "\n${YELLOW}Monitoring URLs:${NC}"
echo -e "${GREEN}Grafana:${NC} http://localhost:3000 (admin/admin)"
echo -e "${GREEN}Prometheus:${NC} http://localhost:9090"

echo -e "\n${GREEN}Test completed.${NC}" 