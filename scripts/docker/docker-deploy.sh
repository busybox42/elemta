#!/bin/bash

# Script to deploy the Elemta monitoring stack

set -e

echo "Setting up monitoring environment..."
./scripts/setup-monitoring.sh

echo "Setting up security monitoring..."
./scripts/setup-security-monitoring.sh

echo "Updating Prometheus configuration..."
cat > monitoring/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'elemta'
    scrape_interval: 5s
    static_configs:
      - targets: ['elemta:8080']
        labels:
          instance: 'elemta-server'

  - job_name: 'rspamd'
    scrape_interval: 5s
    static_configs:
      - targets: ['rspamd:11334']
        labels:
          instance: 'rspamd-server'

  - job_name: 'prometheus'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:9090']
EOF

echo "Creating necessary directories..."
mkdir -p logs queue config/rspamd/local.d

echo "Starting the monitoring stack..."
docker-compose -f docker-compose-monitoring.yml up -d

echo "Deployment complete!"
echo "Access the services at:"
echo "- Elemta: http://localhost:2525 (SMTP)"
echo "- Prometheus: http://localhost:9090"
echo "- Grafana: http://localhost:3000 (admin/elemta123)"
echo "- AlertManager: http://localhost:9093"
echo "- Rspamd Web Interface: http://localhost:11334"

echo "To verify the deployment, run:"
echo "  ./scripts/verify-monitoring-stack.sh" 