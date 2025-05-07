# Let's Encrypt Quick Start Guide for Elemta SMTP Server

This guide provides step-by-step instructions for setting up Let's Encrypt integration with your Elemta SMTP server.

## Prerequisites

Before you begin, ensure:

1. Your server is publicly accessible on the internet
2. DNS records for your domain point to your server's IP address
3. Ports 80 (HTTP) and 465/587 (SMTP with TLS) are open in your firewall
4. You have administrative access to the server

## Step 1: Update Your Configuration

Edit your `elemta.toml` configuration file to enable Let's Encrypt:

```toml
# Basic server configuration
hostname = "mail.example.com"  # Replace with your domain
listen_addr = "0.0.0.0:25"
queue_dir = "/var/spool/elemta/queue"

# TLS configuration
[tls]
enabled = true
listen_addr = ":465"  # SMTPS port
enable_starttls = true  # For port 587 support

# Let's Encrypt configuration
[tls.letsencrypt]
enabled = true
domain = "mail.example.com"  # Replace with your domain
email = "admin@example.com"  # Replace with your email
cache_dir = "/etc/elemta/certs/letsencrypt"
staging = false  # Set to true for testing

# Certificate renewal configuration
[tls.renewal]
auto_renew = true
renewal_days = 30
check_interval = "24h"
renewal_timeout = "5m"
```

## Step 2: Create Required Directories

Ensure that the cache directory exists:

```bash
sudo mkdir -p /etc/elemta/certs/letsencrypt
sudo chmod 700 /etc/elemta/certs/letsencrypt
```

## Step 3: Test ACME Challenge Setup

Before starting the server, test if your ACME challenge setup is correct:

```bash
elemta cert test
```

This will check if your server is correctly configured to handle Let's Encrypt validation.

## Step 4: Start Elemta SMTP Server

Start the Elemta SMTP server:

```bash
elemta start
```

During the first startup, Elemta will:
1. Register with Let's Encrypt
2. Validate domain ownership via HTTP-01 challenge
3. Request and install TLS certificates
4. Set up automatic renewal

## Step 5: Verify Certificate Installation

Check that the certificates were obtained successfully:

```bash
elemta cert info
```

You should see output confirming that a Let's Encrypt certificate was issued for your domain.

## Step 6: Test SMTP with TLS

Test your SMTP server with TLS:

```bash
openssl s_client -connect mail.example.com:465 -starttls smtp
```

You should see certificate information showing your Let's Encrypt certificate.

## Troubleshooting

### Certificate Issuance Fails

If certificate issuance fails:

1. Verify DNS settings with `dig mail.example.com`
2. Check that port 80 is accessible with `curl -I http://mail.example.com/.well-known/acme-challenge/test`
3. Look for errors in logs: `tail -f /var/log/elemta.log`
4. Try staging mode first: set `staging = true` in your configuration
5. Force certificate renewal: `elemta cert renew`

### Rate Limits

Let's Encrypt has rate limits:
- 5 duplicate certificates per week
- 50 certificates per domain per week

Use `staging = true` for testing to avoid hitting production rate limits.

## Production Considerations

1. **Backup Your Certificates**: Regularly backup the contents of your Let's Encrypt cache directory.

2. **Monitor Certificate Renewals**: Set up monitoring to alert you if certificate renewal fails.

3. **Firewall Configuration**: Ensure port 80 remains open for renewal challenges.

4. **Certificate Transparency**: Your domain will appear in public Certificate Transparency logs.

## Next Steps

- Configure proper mail delivery with SPF, DKIM, and DMARC
- Set up monitoring for certificate expiry
- Consider implementing a more robust TLS policy 