# Let's Encrypt Certificate Monitoring for Elemta SMTP Server

This guide explains how to set up and use the Let's Encrypt certificate monitoring system for Elemta SMTP Server. The monitoring system allows you to track certificate expiration, validity, and renewal attempts through Prometheus metrics and Grafana dashboards.

## Overview

The Let's Encrypt monitoring system consists of several components:

1. **Certificate Metrics Collector**: Collects data about your certificates and exposes them as Prometheus metrics
2. **Prometheus Integration**: Scrapes the metrics for storage and alerting
3. **Grafana Dashboard**: Visualizes certificate status and renewal history
4. **Alerting**: Configurable alerts for certificate expiration and renewal failures

## Prerequisites

- Elemta SMTP Server with Let's Encrypt integration
- Prometheus server (optional, but recommended for metrics storage)
- Grafana (optional, for visualization)
- Python 3.6+ (for the metrics server)
- OpenSSL (for certificate inspection)

## Getting Started

### 1. Install the Monitoring Script

The monitoring script is included in the Elemta SMTP Server distribution. You can find it at:

```
scripts/letsencrypt-monitor.sh
```

Make sure the script is executable:

```bash
chmod +x scripts/letsencrypt-monitor.sh
```

### 2. Start the Monitoring Service

You can run the monitoring script directly:

```bash
sudo ./scripts/letsencrypt-monitor.sh
```

Or set it up as a system service:

```bash
sudo ./scripts/letsencrypt-monitor.sh --setup-service
```

This will:
- Create a systemd service for continuous monitoring
- Configure the service to start on boot
- Start the monitoring service immediately

### 3. Command Line Options

The monitoring script accepts several command line options:

- `--config FILE`: Path to Elemta configuration file
- `--cert-dir DIR`: Path to certificate directory (default: /var/elemta/certs)
- `--port PORT`: Metrics server port (default: 9090)
- `--interval TIME`: Check interval (e.g., 12h, 1d) (default: 12h)
- `--help`: Show help message

Example:

```bash
./scripts/letsencrypt-monitor.sh --cert-dir /etc/letsencrypt/live/mail.example.com --port 8080
```

### 4. Accessing the Metrics Dashboard

The monitoring script starts a web server with several endpoints:

- `http://localhost:9090/`: HTML dashboard for certificate status
- `http://localhost:9090/metrics`: Prometheus metrics endpoint
- `http://localhost:9090/health`: Health check endpoint

You can access the HTML dashboard in your browser to view the current status of your certificates.

## Prometheus Integration

### 1. Configuring Prometheus

If you're using Prometheus, add the following job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'elemta-certificates'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 1h
```

If the monitoring script is running on a different host or port, adjust the target accordingly.

### 2. Available Metrics

The following metrics are available:

- `elemta_tls_certificate_expiry_seconds`: Time in seconds until certificate expiry
- `elemta_tls_certificate_valid`: Whether the certificate is valid (1) or not (0)
- `elemta_letsencrypt_renewal_status`: Status of the last Let's Encrypt renewal (1=success, 0=failed)
- `elemta_letsencrypt_renewal_attempts_total`: Total number of renewal attempts
- `elemta_letsencrypt_last_renewal_timestamp`: Unix timestamp of the last renewal attempt

All metrics include labels for `domain` and `issuer` where applicable.

## Grafana Dashboard

A pre-configured Grafana dashboard is available at:

```
monitoring/grafana/dashboards/letsencrypt-dashboard.json
```

To use it:

1. Import the dashboard into your Grafana instance
2. Select your Prometheus data source
3. Save the dashboard

The dashboard includes:
- Certificate expiry timelines
- Validity status
- Renewal history
- Detailed certificate information

## Alerting

### 1. Example Prometheus Alerting Rules

Add these rules to your Prometheus configuration for certificate monitoring:

```yaml
groups:
- name: certificate_alerts
  rules:
  - alert: CertificateExpiringSoon
    expr: min(elemta_tls_certificate_expiry_seconds) / 86400 < 14
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "Certificate expiring soon"
      description: "TLS certificate for Elemta will expire in {{ $value | printf \"%.1f\" }} days"

  - alert: CertificateExpired
    expr: min(elemta_tls_certificate_expiry_seconds) <= 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Certificate expired"
      description: "TLS certificate for Elemta has expired"

  - alert: CertificateInvalid
    expr: min(elemta_tls_certificate_valid) == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Certificate invalid"
      description: "TLS certificate for Elemta is invalid"

  - alert: RenewalFailure
    expr: min(elemta_letsencrypt_renewal_status) == 0
    for: 1h
    labels:
      severity: critical
    annotations:
      summary: "Certificate renewal failed"
      description: "Let's Encrypt certificate renewal for Elemta has failed"
```

### 2. Email Notifications

You can configure email notifications using Alertmanager. Here's an example configuration:

```yaml
global:
  smtp_smarthost: 'localhost:25'
  smtp_from: 'alertmanager@example.com'
  smtp_require_tls: false

route:
  receiver: 'email-notifications'
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

receivers:
- name: 'email-notifications'
  email_configs:
  - to: 'admin@example.com'
    send_resolved: true
```

## Troubleshooting

### Common Issues

1. **Certificate metrics not updating**
   - Check that the certificate directory is correct
   - Ensure the monitoring script is running
   - Verify the certificate files are readable

2. **Cannot connect to metrics server**
   - Check if the server is running
   - Verify the port is not already in use
   - Check if a firewall is blocking access

3. **Metrics show in HTML dashboard but not in Prometheus**
   - Verify Prometheus configuration
   - Check network connectivity between Prometheus and the metrics server

### Logging

The monitoring script logs to standard output. If running as a service, logs are available via:

```bash
journalctl -u elemta-cert-monitor.service
```

## Advanced Configuration

### Custom Certificate Directories

If your certificates are stored in a non-standard location (e.g., Let's Encrypt's default directory), you can specify it:

```bash
./scripts/letsencrypt-monitor.sh --cert-dir /etc/letsencrypt/live/example.com/
```

### Adjusting Check Intervals

For more frequent checking, adjust the interval:

```bash
./scripts/letsencrypt-monitor.sh --interval 3h
```

Valid intervals include:
- `30m`: 30 minutes
- `1h`: 1 hour
- `12h`: 12 hours
- `1d`: 1 day

## Integration with Existing Monitoring

The Let's Encrypt monitoring system is designed to work alongside Elemta's built-in monitoring. It complements the existing system by providing more detailed certificate metrics and alerting capabilities. 