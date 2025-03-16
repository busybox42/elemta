# Elemta Monitoring

This directory contains configuration files for monitoring Elemta SMTP server using Prometheus and Grafana.

## Setup

The monitoring setup consists of six components:

1. **Elemta SMTP Server** - Exposes metrics on port 8080
2. **ClamAV** - Provides virus scanning capabilities
3. **Rspamd** - Provides spam filtering capabilities
4. **Prometheus** - Scrapes metrics from Elemta and stores them
5. **Grafana** - Visualizes metrics from Prometheus
6. **AlertManager** - Handles alerting based on metric thresholds

## Quick Start

To set up the monitoring environment, run:

```bash
# For basic monitoring
./scripts/setup-monitoring.sh

# For security monitoring with ClamAV and Rspamd
./scripts/setup-security-monitoring.sh
```

These scripts will create the necessary directories and configuration files.

Then, start the monitoring stack with:

```bash
docker-compose -f docker-compose-monitoring.yml up -d
```

## Accessing the Dashboards

- **Grafana**: http://localhost:3000 (default credentials: admin/elemta123)
- **Prometheus**: http://localhost:9090
- **AlertManager**: http://localhost:9093
- **Rspamd Web Interface**: http://localhost:11334

## Available Metrics

Elemta exposes the following metrics:

### SMTP Server Metrics
- `elemta_connections_total` - Total number of SMTP connections
- `elemta_connections_active` - Current active SMTP connections
- `elemta_messages_received_total` - Total messages received
- `elemta_messages_delivered_total` - Total messages delivered
- `elemta_messages_failed_total` - Total messages that failed delivery

### Queue Metrics
- `elemta_queue_size{queue_type="active"}` - Size of the active queue
- `elemta_queue_size{queue_type="deferred"}` - Size of the deferred queue
- `elemta_queue_size{queue_type="held"}` - Size of the held queue
- `elemta_queue_size{queue_type="failed"}` - Size of the failed queue

### Delivery Metrics
- `elemta_delivery_attempts_total` - Total delivery attempts
- `elemta_delivery_successes_total` - Total successful deliveries
- `elemta_delivery_failures_total` - Total failed deliveries

### Security Metrics
- `elemta_auth_attempts_total` - Total authentication attempts
- `elemta_auth_successes_total` - Total successful authentications
- `elemta_auth_failures_total` - Total failed authentications
- `elemta_tls_connections_total` - Total TLS connections
- `elemta_tls_handshake_failures_total` - Total TLS handshake failures

### ClamAV Metrics
- `elemta_clamav_scans_total` - Total number of ClamAV scans
- `elemta_clamav_virus_detected_total` - Total number of viruses detected
- `elemta_clamav_scan_errors_total` - Total number of scan errors
- `elemta_clamav_scan_duration_seconds` - Duration of ClamAV scans
- `elemta_clamav_database_updated_timestamp` - Timestamp of the last database update

### Rspamd Metrics
- `elemta_rspamd_scans_total` - Total number of Rspamd scans
- `elemta_rspamd_spam_total` - Total number of spam messages detected
- `elemta_rspamd_ham_total` - Total number of ham (non-spam) messages
- `elemta_rspamd_scan_duration_seconds` - Duration of Rspamd scans
- `elemta_rspamd_score` - Spam score for messages
- `elemta_rspamd_actions_total` - Actions taken by Rspamd (reject, greylist, add header)

### Plugin Metrics
- `elemta_plugin_execution_total{plugin="plugin_name"}` - Total plugin executions
- `elemta_plugin_execution_time_seconds{plugin="plugin_name"}` - Plugin execution time

## Alerting

The monitoring setup includes alerting capabilities through both Prometheus AlertManager and Grafana's built-in alerting.

### Configured Alerts

The following alerts are pre-configured:

1. **High Active Connections** - Triggers when there are more than 100 active connections for more than 5 minutes
2. **Queue Size Growing** - Triggers when the total queue size is greater than 1000 for more than 10 minutes
3. **High Delivery Failure Rate** - Triggers when the delivery failure rate is greater than 20% for more than 15 minutes
4. **High Authentication Failure Rate** - Triggers when the authentication failure rate is greater than 30% for more than 5 minutes
5. **Greylisting Database Size** - Triggers when the greylisting database has more than 5000 entries for more than 30 minutes

### Security Alerts

Additional security alerts are configured:

1. **HighVirusDetectionRate** - Triggers when more than 10% of scanned emails contain viruses
2. **RspamdHighSpamRate** - Triggers when more than 30% of scanned emails are classified as spam
3. **ClamAVDatabaseOutdated** - Triggers when the ClamAV virus database hasn't been updated in more than 24 hours
4. **SecurityScanLatencyHigh** - Triggers when security scanning takes more than 5 seconds on average

### Alert Notification Channels

Alerts can be sent through various channels:

- **Email** - Configured in AlertManager for critical alerts
- **Slack** - Configured in AlertManager for warning alerts

To customize notification channels, edit the following files:

- `monitoring/alertmanager/alertmanager.yml` - For AlertManager notifications
- `monitoring/grafana/provisioning/alerting/elemta-alerts.yaml` - For Grafana alerts

## Custom Dashboards

The monitoring setup includes several dashboards:

1. **Elemta Overview** - General metrics about the SMTP server
2. **Greylisting** - Metrics specific to the greylisting plugin
3. **Security** - Metrics from ClamAV and Rspamd

You can create additional custom dashboards in Grafana to visualize specific metrics or add alerts.

## Security Monitoring

For detailed information about security monitoring with ClamAV and Rspamd, see [Security Monitoring](security-monitoring.md).

## Troubleshooting

If you encounter issues with the monitoring setup:

1. Check that Elemta is exposing metrics on port 8080
2. Verify that Prometheus can reach Elemta (check the Prometheus targets page)
3. Ensure Grafana can connect to Prometheus (check the Grafana datasource settings)
4. Check that AlertManager is properly configured (check the AlertManager status page)
5. Verify that ClamAV and Rspamd are running (check Docker container status)

For more detailed information, check the logs:

```bash
docker-compose -f docker-compose-monitoring.yml logs prometheus
docker-compose -f docker-compose-monitoring.yml logs grafana
docker-compose -f docker-compose-monitoring.yml logs alertmanager
docker-compose -f docker-compose-monitoring.yml logs clamav
docker-compose -f docker-compose-monitoring.yml logs rspamd
``` 