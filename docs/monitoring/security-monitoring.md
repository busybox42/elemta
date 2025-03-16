# Security Monitoring for Elemta

This document describes how to set up and use the security monitoring features for Elemta SMTP server, including ClamAV for virus scanning and Rspamd for spam filtering.

## Overview

Elemta integrates with two powerful security tools:

1. **ClamAV**: An open-source antivirus engine for detecting trojans, viruses, malware, and other malicious threats.
2. **Rspamd**: A fast, free and open-source spam filtering system with extensive filtering capabilities.

Both tools are integrated into the monitoring stack to provide real-time visibility into security threats.

## Setup

The security monitoring is included in the main monitoring stack. To set up the complete monitoring environment with security features:

```bash
# Run the security monitoring setup script
./scripts/setup-security-monitoring.sh

# Start the monitoring stack
docker-compose -f docker-compose-monitoring.yml up -d
```

## Components

### ClamAV

ClamAV runs as a Docker container and provides virus scanning capabilities. The ClamAV exporter exposes metrics to Prometheus.

Key features:
- Real-time virus scanning of all incoming emails
- Automatic virus database updates
- Metrics on scan results, performance, and database status

### Rspamd

Rspamd provides advanced spam filtering with multiple detection methods:

- Content analysis
- SPF, DKIM, and DMARC verification
- URL blacklists
- Fuzzy hashing
- Bayes classification
- RBL (Real-time Blackhole Lists)

Rspamd exposes metrics directly to Prometheus.

## Metrics

### ClamAV Metrics

| Metric | Description |
|--------|-------------|
| `elemta_clamav_scans_total` | Total number of ClamAV scans |
| `elemta_clamav_virus_detected_total` | Total number of viruses detected |
| `elemta_clamav_scan_errors_total` | Total number of scan errors |
| `elemta_clamav_scan_duration_seconds` | Duration of ClamAV scans |
| `elemta_clamav_database_updated_timestamp` | Timestamp of the last database update |

### Rspamd Metrics

| Metric | Description |
|--------|-------------|
| `elemta_rspamd_scans_total` | Total number of Rspamd scans |
| `elemta_rspamd_spam_total` | Total number of spam messages detected |
| `elemta_rspamd_ham_total` | Total number of ham (non-spam) messages |
| `elemta_rspamd_scan_duration_seconds` | Duration of Rspamd scans |
| `elemta_rspamd_score` | Spam score for messages |
| `elemta_rspamd_actions_total` | Actions taken by Rspamd (reject, greylist, add header) |

## Dashboards

A dedicated security dashboard is available in Grafana, showing:

- ClamAV scan statistics and virus detections
- Rspamd spam scores and actions
- Combined security metrics
- Threat type distribution

Access the dashboard at: http://localhost:3000/d/elemta-security/elemta-security-dashboard

## Alerts

The following security-related alerts are configured:

1. **HighVirusDetectionRate**: Triggers when more than 10% of scanned emails contain viruses.
2. **RspamdHighSpamRate**: Triggers when more than 30% of scanned emails are classified as spam.
3. **ClamAVDatabaseOutdated**: Triggers when the ClamAV virus database hasn't been updated in more than 24 hours.
4. **SecurityScanLatencyHigh**: Triggers when security scanning takes more than 5 seconds on average.

## Configuration

### ClamAV Configuration

ClamAV is configured in the Elemta configuration file:

```yaml
plugins:
  - name: clamav
    enabled: true
    config:
      host: clamav
      port: 3310
      timeout: 30s
      action: reject
      log_clean: false
```

### Rspamd Configuration

Rspamd is configured in the Elemta configuration file:

```yaml
plugins:
  - name: rspamd
    enabled: true
    config:
      host: rspamd
      port: 11334
      timeout: 15s
      reject_score: 15.0
      add_headers: true
```

Additional Rspamd configuration files are located in `config/rspamd/`.

## Troubleshooting

### ClamAV Issues

- **ClamAV not scanning**: Check if the ClamAV container is running and if the Elemta server can connect to it.
- **Outdated virus database**: Run `docker exec elemta_clamav_1 freshclam` to manually update the database.

### Rspamd Issues

- **Rspamd not scanning**: Check if the Rspamd container is running and if the Elemta server can connect to it.
- **High false positive rate**: Adjust the reject score in the Elemta configuration or tune Rspamd rules.

## Web Interfaces

- **Rspamd Web Interface**: http://localhost:11334 - Provides a web UI for Rspamd with statistics and configuration options.

## References

- [ClamAV Documentation](https://www.clamav.net/documents/clam-antivirus-user-manual)
- [Rspamd Documentation](https://rspamd.com/doc/index.html)
- [Prometheus Documentation](https://prometheus.io/docs/introduction/overview/)
- [Grafana Documentation](https://grafana.com/docs/) 