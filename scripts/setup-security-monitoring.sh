#!/bin/bash

# Setup script for Elemta security monitoring with ClamAV and Rspamd

set -e

echo "Setting up Elemta security monitoring environment..."

# Create necessary directories
mkdir -p monitoring/alertmanager
mkdir -p monitoring/prometheus/rules
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards
mkdir -p monitoring/grafana/dashboards
mkdir -p config/rspamd/local.d

# Create AlertManager configuration if it doesn't exist
if [ ! -f monitoring/alertmanager/alertmanager.yml ]; then
  cat > monitoring/alertmanager/alertmanager.yml << EOF
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 1h
  receiver: 'email-notifications'
  routes:
  - match:
      severity: critical
    receiver: 'email-notifications'
    continue: true
  - match:
      severity: warning
    receiver: 'slack-notifications'

receivers:
- name: 'email-notifications'
  email_configs:
  - to: 'admin@example.com'
    from: 'alertmanager@elemta.example.com'
    smarthost: 'smtp.example.com:587'
    auth_username: 'alertmanager'
    auth_password: 'password'
    send_resolved: true
- name: 'slack-notifications'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
    channel: '#elemta-alerts'
    send_resolved: true

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname']
EOF
  echo "Created AlertManager configuration"
fi

# Create Prometheus alert rules for security
cat > monitoring/prometheus/rules/security_alerts.yml << EOF
groups:
- name: security_alerts
  rules:
  - alert: HighVirusDetectionRate
    expr: rate(elemta_clamav_virus_detected_total[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: High virus detection rate
      description: More than 10% of scanned emails contain viruses.

  - alert: RspamdHighSpamRate
    expr: rate(elemta_rspamd_spam_total[5m]) / rate(elemta_rspamd_scans_total[5m]) > 0.3
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High spam detection rate
      description: More than 30% of scanned emails are classified as spam.

  - alert: ClamAVDatabaseOutdated
    expr: time() - elemta_clamav_database_updated_timestamp > 86400
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: ClamAV database outdated
      description: The ClamAV virus database has not been updated in more than 24 hours.

  - alert: SecurityScanLatencyHigh
    expr: elemta_security_scan_latency_seconds > 5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: Security scan latency high
      description: Security scanning is taking more than 5 seconds on average.
EOF
echo "Created Prometheus security alert rules"

echo "Setup complete! You can now start the monitoring stack with:"
echo "docker-compose -f docker-compose-monitoring.yml up -d"
echo ""
echo "Access the services at:"
echo "- Elemta: http://localhost:2525 (SMTP)"
echo "- Prometheus: http://localhost:9090"
echo "- Grafana: http://localhost:3000 (admin/elemta123)"
echo "- AlertManager: http://localhost:9093"
echo "- Rspamd Web Interface: http://localhost:11334" 