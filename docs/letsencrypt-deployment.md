# Deploying Elemta with Let's Encrypt Integration

This guide provides practical deployment examples for setting up Elemta with Let's Encrypt integration in various environments.

## Prerequisites

Before deploying, ensure your server meets these requirements:
- A public domain name pointing to your server
- Port 80 accessible from the internet (for ACME HTTP challenges)
- Port 25, 465, or 587 open depending on your SMTP configuration
- Proper DNS records (A, MX, etc.) for your mail domain
- Root or sudo access on your server

## Example 1: Basic Deployment with Docker

This example shows how to deploy Elemta with Let's Encrypt using Docker:

```bash
# Create the necessary directories
mkdir -p /var/elemta/config
mkdir -p /var/elemta/data
mkdir -p /var/elemta/certs

# Create a basic elemta.toml configuration file
cat > /var/elemta/config/elemta.toml << EOF
[server]
hostname = "mail.example.com"
greeting = "Elemta SMTP Server"

[tls]
enabled = true
listen_addr = ":465"
starttls_enabled = true

# Let's Encrypt configuration
cert_renewal = true
acme_enabled = true
acme_email = "admin@example.com"
acme_domain = "mail.example.com"
acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
acme_storage_path = "/var/elemta/certs/acme"
endpoint_port = 80
endpoint_path = "/.well-known/acme-challenge/"
renewal_days = 30
check_interval = "24h"
EOF

# Run Elemta in Docker
docker run -d \
  --name elemta \
  -p 25:25 \
  -p 80:80 \
  -p 465:465 \
  -p 587:587 \
  -v /var/elemta/config:/etc/elemta \
  -v /var/elemta/data:/var/lib/elemta \
  -v /var/elemta/certs:/var/elemta/certs \
  elemta/elemta:latest
```

## Example 2: Systemd Service Deployment

For a native installation using systemd:

```bash
# Assuming Elemta is installed in /usr/local/bin/elemta

# Create configuration directory
mkdir -p /etc/elemta
mkdir -p /var/lib/elemta
mkdir -p /var/elemta/certs

# Create configuration file
cat > /etc/elemta/elemta.toml << EOF
[server]
hostname = "mail.example.com"
greeting = "Elemta SMTP Server"

[tls]
enabled = true
listen_addr = ":465"
starttls_enabled = true

# Let's Encrypt configuration
cert_renewal = true
acme_enabled = true
acme_email = "admin@example.com"
acme_domain = "mail.example.com"
acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
acme_storage_path = "/var/elemta/certs/acme"
endpoint_port = 80
endpoint_path = "/.well-known/acme-challenge/"
renewal_days = 30
check_interval = "24h"
EOF

# Create systemd service file
cat > /etc/systemd/system/elemta.service << EOF
[Unit]
Description=Elemta SMTP Server
After=network.target

[Service]
Type=simple
User=elemta
Group=elemta
ExecStart=/usr/local/bin/elemta serve --config /etc/elemta/elemta.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

# Create dedicated user
useradd -r -s /bin/false elemta

# Set permissions
chown -R elemta:elemta /etc/elemta
chown -R elemta:elemta /var/lib/elemta
chown -R elemta:elemta /var/elemta

# Enable and start the service
systemctl daemon-reload
systemctl enable elemta
systemctl start elemta
```

## Example 3: Cloud Deployment (AWS EC2)

This example shows deployment on an AWS EC2 instance:

```bash
#!/bin/bash
# Elemta deployment script for AWS EC2

# Install required dependencies
apt update
apt install -y curl unzip

# Download the latest Elemta release
curl -L -o elemta.zip https://github.com/elemta/elemta/releases/latest/download/elemta_linux_amd64.zip
unzip elemta.zip -d /usr/local/bin/
chmod +x /usr/local/bin/elemta

# Create configuration directory
mkdir -p /etc/elemta
mkdir -p /var/lib/elemta
mkdir -p /var/elemta/certs

# Create configuration file
cat > /etc/elemta/elemta.toml << EOF
[server]
hostname = "mail.example.com"
greeting = "Elemta SMTP Server"

[tls]
enabled = true
listen_addr = ":465"
starttls_enabled = true

# Let's Encrypt configuration
cert_renewal = true
acme_enabled = true
acme_email = "admin@example.com"
acme_domain = "mail.example.com"
acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
acme_storage_path = "/var/elemta/certs/acme"
endpoint_port = 80
endpoint_path = "/.well-known/acme-challenge/"
renewal_days = 30
check_interval = "24h"
EOF

# Create systemd service
cat > /etc/systemd/system/elemta.service << EOF
[Unit]
Description=Elemta SMTP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/elemta serve --config /etc/elemta/elemta.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

# Start Elemta
systemctl daemon-reload
systemctl enable elemta
systemctl start elemta

# Verify status
systemctl status elemta
```

## Verifying Let's Encrypt Certificate

After deployment, verify your Let's Encrypt certificate:

```bash
# Check the certificate using OpenSSL
openssl s_client -connect mail.example.com:465 -showcerts

# For STARTTLS on port 587
openssl s_client -connect mail.example.com:587 -starttls smtp -showcerts
```

## Security Considerations

1. **Firewall Configuration**:
   ```bash
   # Using ufw (Ubuntu/Debian)
   ufw allow 25/tcp
   ufw allow 80/tcp   # For Let's Encrypt validation
   ufw allow 465/tcp
   ufw allow 587/tcp
   
   # Using firewalld (CentOS/RHEL)
   firewall-cmd --permanent --add-service=smtp
   firewall-cmd --permanent --add-port=80/tcp
   firewall-cmd --permanent --add-port=465/tcp
   firewall-cmd --permanent --add-port=587/tcp
   firewall-cmd --reload
   ```

2. **SELinux Configuration** (if applicable):
   ```bash
   # Allow Elemta to bind to ports
   semanage port -a -t smtp_port_t -p tcp 465
   semanage port -a -t smtp_port_t -p tcp 587
   semanage port -m -t http_port_t -p tcp 80
   
   # Allow Elemta to access certificate directories
   semanage fcontext -a -t cert_t "/var/elemta/certs(/.*)?"
   restorecon -Rv /var/elemta/certs
   ```

## Troubleshooting

1. **Certificate Issuance Failures**:
   ```bash
   # Check if port 80 is accessible
   curl -I http://mail.example.com/.well-known/acme-challenge/test
   
   # Check Elemta logs
   journalctl -u elemta
   
   # Manually test the ACME challenge server
   elemta cert test-http --domain mail.example.com
   ```

2. **Certificate Renewal Issues**:
   ```bash
   # Force certificate renewal
   elemta cert renew --domain mail.example.com
   
   # Check certificate expiration
   elemta cert check --domain mail.example.com
   ```

## Production Tips

1. **Rate Limiting**: Be aware that Let's Encrypt applies rate limits. Avoid frequent re-issuance of certificates.

2. **Staging Environment**: For testing, use the Let's Encrypt staging environment by setting:
   ```toml
   acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
   ```

3. **Backup ACME Account**: Regularly backup your `/var/elemta/certs/acme` directory, which contains your ACME account information.

4. **Monitoring**: Set up monitoring for certificate expiration:
   ```bash
   # Example cron job to check certificate expiration
   0 0 * * * /usr/local/bin/elemta cert check --domain mail.example.com --warn-days 14 | mail -s "Certificate Status" admin@example.com
   ```

5. **TLS Settings**: For production environments, ensure you're using strong TLS settings:
   ```toml
   min_version = "1.2"
   cipher_suites = [
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
     "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
   ]
   ``` 