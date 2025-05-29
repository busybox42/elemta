#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Elemta Monitoring Stack${NC}"
echo "======================================"

# Check if docker-compose-monitoring.yml exists
if [ ! -f "docker-compose-monitoring.yml" ]; then
  echo -e "${RED}Error: docker-compose-monitoring.yml not found${NC}"
  exit 1
fi

# Create required directories if they don't exist
echo "Creating required directories..."
mkdir -p monitoring/prometheus
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards
mkdir -p monitoring/grafana/dashboards
mkdir -p monitoring/alertmanager
mkdir -p config/rspamd

# Create Prometheus configuration
echo "Creating Prometheus configuration..."
cat > monitoring/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

rule_files:
  - 'alert_rules.yml'

scrape_configs:
  - job_name: 'elemta'
    static_configs:
      - targets: ['elemta:8080']
  
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

# Create Prometheus alert rules
echo "Creating Prometheus alert rules..."
cat > monitoring/prometheus/alert_rules.yml << EOF
groups:
- name: elemta_alerts
  rules:
  - alert: HighActiveConnections
    expr: elemta_connections_active > 100
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High number of active connections"
      description: "There are {{ \$value }} active connections, which is above the threshold of 100."

  - alert: QueueSizeGrowing
    expr: sum(elemta_queue_size) > 1000
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Queue size is growing"
      description: "The total queue size is {{ \$value }}, which is above the threshold of 1000."

  - alert: HighDeliveryFailureRate
    expr: (elemta_delivery_failures_total / elemta_delivery_attempts_total) * 100 > 20
    for: 15m
    labels:
      severity: critical
    annotations:
      summary: "High delivery failure rate"
      description: "The delivery failure rate is {{ \$value }}%, which is above the threshold of 20%."
EOF

# Create Grafana datasource configuration
echo "Creating Grafana datasource configuration..."
cat > monitoring/grafana/provisioning/datasources/datasource.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
EOF

# Create Grafana dashboard provisioning configuration
echo "Creating Grafana dashboard provisioning configuration..."
cat > monitoring/grafana/provisioning/dashboards/dashboards.yml << EOF
apiVersion: 1

providers:
  - name: 'Default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
EOF

# Create a simple Grafana dashboard
echo "Creating Grafana dashboard..."
cat > monitoring/grafana/dashboards/elemta_overview.json << EOF
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 2,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.3.7",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "elemta_connections_active",
          "interval": "",
          "legendFormat": "Active Connections",
          "refId": "A"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Active Connections",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 4,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.3.7",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "elemta_messages_received_total",
          "interval": "",
          "legendFormat": "Messages Received",
          "refId": "A"
        },
        {
          "expr": "elemta_messages_delivered_total",
          "interval": "",
          "legendFormat": "Messages Delivered",
          "refId": "B"
        },
        {
          "expr": "elemta_messages_failed_total",
          "interval": "",
          "legendFormat": "Messages Failed",
          "refId": "C"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Message Statistics",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    }
  ],
  "refresh": "5s",
  "schemaVersion": 26,
  "style": "dark",
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "Elemta Overview",
  "uid": "elemta-overview",
  "version": 1
}
EOF

# Create AlertManager configuration
echo "Creating AlertManager configuration..."
cat > monitoring/alertmanager/alertmanager.yml << EOF
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://127.0.0.1:5001/'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF

# Start the monitoring stack
echo "Starting monitoring stack..."
docker-compose -f docker-compose-monitoring.yml up -d

# Check if the stack started successfully
if [ $? -eq 0 ]; then
  echo -e "${GREEN}Monitoring stack started successfully${NC}"
  echo "Grafana: http://localhost:3000 (default credentials: admin/elemta123)"
  echo "Prometheus: http://localhost:9090"
  echo "AlertManager: http://localhost:9093"
else
  echo -e "${RED}Failed to start monitoring stack${NC}"
  exit 1
fi

echo -e "\n${YELLOW}Note:${NC} It may take a few moments for all services to initialize."
echo "Run ./tests/test-elemta.sh to verify the setup." 