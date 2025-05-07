# Let's Encrypt Integration Guide for Elemta SMTP Server

This guide provides comprehensive instructions for configuring, managing, and monitoring Let's Encrypt certificates with the Elemta SMTP server.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Automatic Setup](#automatic-setup)
  - [Manual Setup](#manual-setup)
- [Configuration Options](#configuration-options)
- [Certificate Management](#certificate-management)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Advanced Use Cases](#advanced-use-cases)
- [FAQ](#faq)

## Overview

Let's Encrypt integration allows the Elemta SMTP server to automatically obtain, use, and renew TLS certificates for encrypted email communication. This provides:

- Free, trusted TLS certificates
- Automatic renewal
- Enhanced security for email transmission
- Improved deliverability by meeting modern email security standards

Elemta's ACME client implementation handles all aspects of certificate management, from initial request through automatic renewal.

## Prerequisites

Before setting up Let's Encrypt with Elemta, ensure:

1. Your Elemta server is publicly accessible on the internet
2. You have a fully qualified domain name (FQDN) pointing to your server
3. Ports 80 and 443 are accessible for the Let's Encrypt validation process
4. Port 25 (SMTP), 465 (SMTPS), and/or 587 (Submission) are open as needed
5. You have system privileges to modify configuration files

## Setup

### Automatic Setup

The fastest way to set up Let's Encrypt is using our automated setup script:

```bash
curl -sSL https://raw.githubusercontent.com/elemta/elemta/main/scripts/letsencrypt-setup.sh | sudo bash
```

Or download and run it manually:

```bash
wget https://raw.githubusercontent.com/elemta/elemta/main/scripts/letsencrypt-setup.sh
chmod +x letsencrypt-setup.sh
sudo ./letsencrypt-setup.sh
```

The script will:
1. Check your system for prerequisites
2. Verify domain DNS configuration
3. Configure Elemta for Let's Encrypt
4. Set up automatic certificate renewal
5. Restart Elemta with the new configuration

### Manual Setup

To manually configure Let's Encrypt:

1. Create a directory for certificates:
   ```bash
   sudo mkdir -p /var/elemta/certs
   sudo chown elemta:elemta /var/elemta/certs
   ```

2. Edit your Elemta configuration file (`/etc/elemta/elemta.toml`):
   ```toml
   [tls]
   enabled = true
   start_tls = true
   cert_file = ""  # Leave empty for Let's Encrypt
   key_file = ""   # Leave empty for Let's Encrypt
   
   [acme]
   enabled = true
   email = "admin@yourdomain.com"  # Replace with your email
   domains = ["mail.yourdomain.com"]  # Replace with your domain
   directory_url = "https://acme-v02.api.letsencrypt.org/directory"
   cert_storage_path = "/var/elemta/certs"
   renewal_window_days = 30
   renewal_check_interval_hours = 24
   ```

3. Restart Elemta:
   ```bash
   sudo systemctl restart elemta
   ```

## Configuration Options

### TLS Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable TLS support | `false` |
| `start_tls` | Enable STARTTLS command | `true` |
| `cert_file` | Path to existing certificate file (leave empty for Let's Encrypt) | `""` |
| `key_file` | Path to existing private key file (leave empty for Let's Encrypt) | `""` |

### ACME Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable Let's Encrypt integration | `false` |
| `email` | Contact email for Let's Encrypt account | Required |
| `domains` | List of domains for certificate | Required |
| `directory_url` | ACME directory URL | `https://acme-v02.api.letsencrypt.org/directory` |
| `cert_storage_path` | Directory to store certificates | `/var/elemta/certs` |
| `renewal_window_days` | Days before expiry to renew | `30` |
| `renewal_check_interval_hours` | Hours between renewal checks | `24` |
| `staging` | Use Let's Encrypt staging environment | `false` |

## Certificate Management

### Manual Renewal

While automatic renewal is configured by default, you can manually trigger renewal:

```bash
sudo systemctl restart elemta
```

Elemta will check for certificates near expiration and renew if needed.

### Viewing Certificate Information

To view current certificate details:

```bash
openssl x509 -in /var/elemta/certs/certificate.pem -text -noout
```

### Certificate Paths

When using Let's Encrypt, certificates are stored at:
- Certificate: `/var/elemta/certs/certificate.pem`
- Private key: `/var/elemta/certs/private_key.pem`
- Full chain: `/var/elemta/certs/fullchain.pem`

## Monitoring

### Certificate Metrics

Elemta provides Prometheus metrics for Let's Encrypt certificates. To use these metrics:

1. Install the metrics script:
   ```bash
   sudo wget -O /usr/local/bin/letsencrypt-metrics.sh https://raw.githubusercontent.com/elemta/elemta/main/scripts/letsencrypt-metrics.sh
   sudo chmod +x /usr/local/bin/letsencrypt-metrics.sh
   ```

2. Set up a cron job to update metrics:
   ```bash
   echo "*/15 * * * * root /usr/local/bin/letsencrypt-metrics.sh" | sudo tee /etc/cron.d/elemta-letsencrypt-metrics
   ```

3. Or run as an HTTP metrics server:
   ```bash
   sudo /usr/local/bin/letsencrypt-metrics.sh --server --port 9090
   ```

### Available Metrics

- `letsencrypt_cert_expiry_seconds` - Time remaining until certificate expires
- `letsencrypt_cert_issued_time_seconds` - When the certificate was issued
- `letsencrypt_cert_valid` - Whether the certificate is valid (1) or not (0)
- `letsencrypt_renewal_success` - Whether the last renewal was successful (1) or not (0)
- `letsencrypt_renewal_last_attempt_time_seconds` - When the last renewal was attempted
- `letsencrypt_tls_enabled` - Whether TLS is enabled in the configuration
- `letsencrypt_acme_enabled` - Whether ACME is enabled in the configuration

### Grafana Dashboard

We provide a Grafana dashboard for visualizing certificate metrics. Import the dashboard from:

```
https://raw.githubusercontent.com/elemta/elemta/main/dashboards/elemta-letsencrypt-dashboard.json
```

## Troubleshooting

### Common Issues

1. **Challenge Validation Failure**
   - Ensure ports 80/443 are open to the internet
   - Verify DNS points to the correct IP address
   - Check firewall rules

2. **Certificate Not Being Used**
   - Verify TLS is properly enabled in configuration
   - Check Elemta logs for certificate loading errors
   - Ensure certificate files have proper permissions

3. **Renewal Failures**
   - Check for rate limiting issues
   - Verify domain still resolves correctly
   - Check disk space for certificate storage

### Diagnostic Tool

Use our diagnostic script to troubleshoot Let's Encrypt issues:

```bash
sudo wget -O /usr/local/bin/letsencrypt-troubleshooter.sh https://raw.githubusercontent.com/elemta/elemta/main/scripts/letsencrypt-troubleshooter.sh
sudo chmod +x /usr/local/bin/letsencrypt-troubleshooter.sh
sudo /usr/local/bin/letsencrypt-troubleshooter.sh your-domain.com
```

### Logs

Check Elemta logs for ACME-related messages:

```bash
sudo journalctl -u elemta | grep -i "acme\|tls\|certificate\|letsencrypt"
```

## Advanced Use Cases

### Using Staging Environment

For testing, use the Let's Encrypt staging environment:

```toml
[acme]
enabled = true
# Other options...
staging = true
```

### Multiple Domains

To secure multiple domains with a single certificate:

```toml
[acme]
enabled = true
domains = ["mail.example.com", "smtp.example.com", "example.com"]
# Other options...
```

### DNS Validation

For servers behind firewalls, DNS validation is available:

```toml
[acme]
enabled = true
validation_method = "dns"
dns_provider = "cloudflare"  # Or other supported provider
dns_credentials_file = "/etc/elemta/dns-credentials.json"
# Other options...
```

## FAQ

**Q: How often are certificates renewed?**
A: Elemta attempts renewal when certificates are within the renewal window (default 30 days before expiry).

**Q: What happens if renewal fails?**
A: Elemta will continue using the existing certificate and retry renewal according to the configured interval.

**Q: Can I use existing certificates instead of Let's Encrypt?**
A: Yes, specify the paths in the `cert_file` and `key_file` options under the `[tls]` section.

**Q: Does Elemta support wildcard certificates?**
A: Yes, when using DNS validation.

**Q: Is there a rate limit for Let's Encrypt certificates?**
A: Yes, Let's Encrypt has rate limits. See [their documentation](https://letsencrypt.org/docs/rate-limits/) for details.

---

For more information, visit our [official documentation](https://elemta.com/docs/encryption/letsencrypt) or [open an issue](https://github.com/elemta/elemta/issues) if you encounter problems. 