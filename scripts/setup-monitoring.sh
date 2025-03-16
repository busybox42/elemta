#!/bin/bash
set -e

# Create necessary directories
mkdir -p monitoring/prometheus
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards
mkdir -p monitoring/grafana/provisioning/alerting
mkdir -p monitoring/grafana/dashboards
mkdir -p monitoring/alertmanager

# Check if prometheus.yml exists, if not create it
if [ ! -f monitoring/prometheus/prometheus.yml ]; then
  echo "Creating Prometheus configuration..."
  cat > monitoring/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'elemta'
    scrape_interval: 5s
    static_configs:
      - targets: ['elemta:8080']
        labels:
          instance: elemta-server

  - job_name: 'prometheus'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:9090']
EOF
fi

# Create Prometheus rules directory
mkdir -p monitoring/prometheus/rules

# Check if alert rules exist, if not create them
if [ ! -f monitoring/prometheus/rules/elemta_alerts.yml ]; then
  echo "Creating Prometheus alert rules..."
  cat > monitoring/prometheus/rules/elemta_alerts.yml << EOF
groups:
  - name: elemta_alerts
    rules:
      - alert: HighActiveConnections
        expr: elemta_connections_active > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High number of active connections
          description: There are more than 100 active connections for more than 5 minutes.

      - alert: QueueSizeGrowing
        expr: sum(elemta_queue_size) > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: Queue size is growing
          description: The total queue size is greater than 1000 for more than 10 minutes.

      - alert: HighDeliveryFailureRate
        expr: elemta_delivery_failures_total / elemta_delivery_attempts_total > 0.2
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: High delivery failure rate
          description: The delivery failure rate is greater than 20% for more than 15 minutes.
EOF
fi

# Check if datasource configuration exists, if not create it
if [ ! -f monitoring/grafana/provisioning/datasources/prometheus.yaml ]; then
  echo "Creating Grafana datasource configuration..."
  cat > monitoring/grafana/provisioning/datasources/prometheus.yaml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    version: 1
EOF
fi

# Check if dashboard provisioning configuration exists, if not create it
if [ ! -f monitoring/grafana/provisioning/dashboards/elemta.yaml ]; then
  echo "Creating Grafana dashboard provisioning configuration..."
  cat > monitoring/grafana/provisioning/dashboards/elemta.yaml << EOF
apiVersion: 1

providers:
  - name: 'Elemta'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
EOF
fi

# Check if alerting configuration exists, if not create it
if [ ! -f monitoring/grafana/provisioning/alerting/elemta-alerts.yaml ]; then
  echo "Creating Grafana alerting configuration..."
  cat > monitoring/grafana/provisioning/alerting/elemta-alerts.yaml << EOF
apiVersion: 1

groups:
  - name: Elemta Alerts
    folder: Elemta
    interval: 1m
    rules:
      - name: High Active Connections
        condition: A
        data:
          - refId: A
            datasourceUid: Prometheus
            model:
              expr: elemta_connections_active > 100
              intervalMs: 60000
              maxDataPoints: 43200
        noDataState: OK
        execErrState: Alerting
        for: 5m
        annotations:
          summary: High number of active connections
          description: There are more than 100 active connections for more than 5 minutes.
        labels:
          severity: warning

      - name: Queue Size Growing
        condition: A
        data:
          - refId: A
            datasourceUid: Prometheus
            model:
              expr: sum(elemta_queue_size) > 1000
              intervalMs: 60000
              maxDataPoints: 43200
        noDataState: OK
        execErrState: Alerting
        for: 10m
        annotations:
          summary: Queue size is growing
          description: The total queue size is greater than 1000 for more than 10 minutes.
        labels:
          severity: warning

      - name: High Delivery Failure Rate
        condition: A
        data:
          - refId: A
            datasourceUid: Prometheus
            model:
              expr: elemta_delivery_failures_total / elemta_delivery_attempts_total > 0.2
              intervalMs: 60000
              maxDataPoints: 43200
        noDataState: OK
        execErrState: Alerting
        for: 15m
        annotations:
          summary: High delivery failure rate
          description: The delivery failure rate is greater than 20% for more than 15 minutes.
        labels:
          severity: critical
EOF
fi

# Check if AlertManager configuration exists, if not create it
if [ ! -f monitoring/alertmanager/alertmanager.yml ]; then
  echo "Creating AlertManager configuration..."
  cat > monitoring/alertmanager/alertmanager.yml << EOF
global:
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alertmanager@example.com'
  smtp_auth_username: 'alertmanager'
  smtp_auth_password: 'password'
  smtp_require_tls: true

route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'email-notifications'
  routes:
    - match:
        severity: critical
      receiver: 'email-notifications'
      continue: true
    - match:
        severity: warning
      receiver: 'slack-notifications'
      continue: true

receivers:
  - name: 'email-notifications'
    email_configs:
      - to: 'admin@example.com'
        send_resolved: true
        html: |
          {{ range .Alerts }}
          <h3>{{ .Annotations.summary }}</h3>
          <p>{{ .Annotations.description }}</p>
          <p>Severity: {{ .Labels.severity }}</p>
          <p>Started: {{ .StartsAt }}</p>
          {{ end }}

  - name: 'slack-notifications'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
        channel: '#elemta-alerts'
        send_resolved: true
        title: '{{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *{{ .Annotations.summary }}*
          {{ .Annotations.description }}
          Severity: {{ .Labels.severity }}
          {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname']
EOF
fi

# Make the script executable
chmod +x scripts/setup-monitoring.sh

echo "Monitoring setup complete. You can now run docker-compose -f docker-compose-monitoring.yml up" 