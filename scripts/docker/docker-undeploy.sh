#!/bin/bash

# Script to cleanly undeploy the Elemta monitoring stack

set -e

echo "Stopping and removing all containers..."
docker-compose -f docker-compose-monitoring.yml down

echo "Removing volumes..."
docker volume rm elemta_prometheus_data elemta_grafana_data elemta_alertmanager_data elemta_clamav_data elemta_rspamd_data 2>/dev/null || true

echo "Cleaning up any orphaned containers..."
docker container prune -f

echo "Cleaning up any unused networks..."
docker network prune -f

echo "Cleaning up any unused volumes..."
docker volume prune -f

echo "Undeployment complete!"
echo "To redeploy, run:"
echo "  ./scripts/monitoring/setup-monitoring.sh"
echo "  ./scripts/monitoring/setup-security-monitoring.sh"
echo "  docker-compose -f docker-compose-monitoring.yml up -d" 