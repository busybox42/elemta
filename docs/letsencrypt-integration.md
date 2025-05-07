# Let's Encrypt Integration in Elemta SMTP Server

This document outlines the Let's Encrypt integration for automatic TLS certificate management in the Elemta SMTP server.

## Overview

Elemta SMTP Server now includes full support for automatically obtaining and renewing TLS certificates using Let's Encrypt. This eliminates the need for manual certificate management and ensures that your SMTP server always has valid, up-to-date TLS certificates.

## Features

- **Automatic Certificate Acquisition**: Automatically obtains TLS certificates from Let's Encrypt when the server starts
- **Automatic Certificate Renewal**: Monitors certificate expiration and renews certificates before they expire
- **HTTP-01 Challenge Support**: Built-in HTTP server for domain ownership validation via the HTTP-01 challenge method
- **Configurable Renewal Settings**: Customize when and how often certificates are renewed
- **Production and Staging Support**: Switch between Let's Encrypt production and staging environments
- **Expiration Notifications**: Sends notifications when certificates are about to expire
- **Command-Line Tools**: Manage certificates using Elemta's command-line tools

## Configuration

To enable Let's Encrypt support, add the following to your `elemta.toml` configuration file:

```toml
[tls]
enabled = true
listen_addr = ":465"
enable_starttls = true

[tls.letsencrypt]
enabled = true
domain = "mail.example.com"
email = "admin@example.com"
cache_dir = "/etc/elemta/certs/letsencrypt"
staging = false

[tls.renewal]
auto_renew = true
renewal_days = 30
check_interval = "24h"
renewal_timeout = "5m"
```

### Configuration Options

#### Let's Encrypt Configuration

- `enabled`: Enable or disable Let's Encrypt integration
- `domain`: The domain name for which to obtain a certificate (must be publicly accessible)
- `email`: Your email address for Let's Encrypt registration and notifications
- `cache_dir`: Directory to store Let's Encrypt data and certificates
- `staging`: Use Let's Encrypt staging environment for testing (doesn't count against rate limits)

#### Certificate Renewal Configuration

- `auto_renew`: Enable or disable automatic certificate renewal
- `renewal_days`: Renew the certificate when it has this many days remaining
- `check_interval`: How often to check certificate status (e.g., "24h", "12h")
- `renewal_timeout`: Maximum time to wait for certificate renewal (e.g., "5m")

## Command-Line Tools

Elemta includes command-line tools for certificate management:

```bash
# Display certificate information
elemta cert info

# Force certificate renewal
elemta cert renew

# Test ACME challenge setup
elemta cert test
```

## Requirements for Let's Encrypt

For Let's Encrypt to work properly:

1. Your server must be publicly accessible from the internet
2. DNS must be properly configured to point to your server
3. Port 80 must be open and accessible for the HTTP-01 challenge
4. Port 443 is recommended to be open for the TLS-ALPN-01 challenge

## Troubleshooting

If you encounter issues with Let's Encrypt:

1. Ensure your domain is correctly configured in DNS
2. Verify that port 80 is accessible from the internet
3. Check certificate status using `elemta cert info`
4. Look for Let's Encrypt-related log messages
5. Try using the staging environment first by setting `staging = true`

## Security Considerations

- Always keep your Let's Encrypt cache directory secure
- Certificates are automatically renewed 30 days before expiration by default
- The Let's Encrypt account is tied to the email address provided in configuration

## Monitoring

The Elemta SMTP server logs certificate renewal activities and sends notifications when:

- Certificates are successfully renewed
- Certificate renewal fails
- Certificates are about to expire (30, 14, 7, 3, and 1 days before expiration) 