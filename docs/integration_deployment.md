# Elemta Mail Transfer Agent Integration Guide

This document outlines the deployment process for integrating Elemta with an existing mail system, leveraging external directory services for authentication and local mail delivery protocols.

## Architecture Overview

The integration consists of the following components:

1. **Elemta MTA**: 
   - Handles incoming SMTP connections on port 25
   - Authenticates users against directory services
   - Performs anti-virus and anti-spam scanning
   - Routes messages to mail storage via delivery protocols

2. **Mail Storage System**: 
   - Provides directory services for authentication and routing
   - Receives mail via delivery protocols
   - Handles user management and mailbox operations

3. **Supporting Services**:
   - ClamAV: Anti-virus scanning
   - Rspamd: Anti-spam filtering
   - Prometheus & Grafana: Monitoring and metrics

## Mail Flow Diagram

```
                                          ┌────────────┐
                                          │   ClamAV   │
                                          └────────────┘
                                                ▲
                                                │ Virus
                                                │ Scanning
                                                │
┌──────────┐    SMTP    ┌────────────┐         │         ┌────────────┐
│ External │───(25)────▶│   Elemta   │─────────┼────────▶│   Rspamd   │
│  Client  │            │    MTA     │         │         └────────────┘
└──────────┘            └────────────┘         │
                             │    ▲            │
                             │    │            │
                             ▼    │            │
                        ┌────────────┐         │
                        │  Queue &   │◀────────┘
                        │ Processing │
                        └────────────┘
                             │
                             │ Delivery Protocol
                             ▼
                        ┌────────────┐        ┌────────────┐
                        │    Mail    │◀──────▶│ Directory  │
                        │   System   │        │  Service   │
                        └────────────┘        └────────────┘
                             │
                             │
                             ▼
                        ┌────────────┐
                        │  Mailbox   │
                        │  Storage   │
                        └────────────┘
```

## Deployment Process

### 1. Prerequisites

Before beginning deployment, ensure you have:

- Docker and Docker Compose installed
- A domain name with proper DNS records (MX, A, SPF, DKIM)
- Access to modify DNS records
- Basic understanding of SMTP, directory services, and Docker
- Ability to generate SSL certificates

### 2. Setup Steps

#### 2.1 Initial Configuration

1. Clone the repository and navigate to the Elemta directory:
   ```bash
   git clone https://github.com/your-org/elemta.git
   cd elemta
   ```

2. Create the deployment directory structure:
   ```bash
   mkdir -p .deploy/production/certs/{mail,dkim}
   mkdir -p .deploy/production/config/{mail,rspamd/override.d,grafana/provisioning,prometheus}
   ```

3. Copy the configuration templates from this repository:
   ```bash
   cp -r templates/production/* .deploy/production/
   ```

#### 2.2 Customizing Configuration

1. Update domain settings in all configuration files:
   ```bash
   cd .deploy/production
   ./setup.sh
   ```
   
   When prompted, enter:
   - Your domain name (e.g., example.com)
   - Directory service credentials
   
   The script will:
   - Generate SSL certificates
   - Create DKIM keys
   - Update all configuration files with your domain
   - Generate secure passwords

2. Manually verify/customize the following files:
   - `config/elemta.toml`: Check directory service settings, plugins
   - `config/mail/mail.cf`: Adjust mail system-specific settings
   - `docker-compose.yml`: Adjust ports, resource limits if needed

#### 2.3 DNS Configuration

1. Add required DNS records:
   - MX record: `MX 10 mail.example.com.`
   - A record: `mail.example.com. A <your-server-ip>`
   - SPF record: `TXT "v=spf1 mx a:mail.example.com -all"`
   
2. Add the DKIM record (output from setup.sh):
   ```
   mail._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=<key-data-here>"
   ```

3. Add DMARC record:
   ```
   _dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"
   ```

### 3. Deployment

1. Build and start the containers:
   ```bash
   cd .deploy/production
   docker-compose build
   docker-compose up -d
   ```

2. Check the status of the containers:
   ```bash
   docker-compose ps
   ```

3. View logs for any immediate issues:
   ```bash
   docker-compose logs elemta
   docker-compose logs mail-system
   ```

### 4. Post-Deployment Configuration

#### 4.1 User Setup

1. Connect to the mail system container:
   ```bash
   docker exec -it mail_system bash
   ```

2. Create test users if needed using your mail system's user management tools.

#### 4.2 Verify Directory Service Integration

1. Test directory service connectivity from Elemta:
   ```bash
   docker exec -it elemta_prod bash
   ldapsearch -H ldap://directory-service:389 -D "cn=admin,dc=example,dc=com" \
     -w "password" -b "dc=example,dc=com" "(objectClass=account)"
   ```

2. Test authentication via Elemta CLI:
   ```bash
   docker exec -it elemta_prod /app/elemta-cli auth verify -u user1@example.com -p password
   ```

#### 4.3 Verify Mail Flow

1. Test mail delivery using the SMTP protocol:
   ```bash
   echo -e "From: user1@example.com\nTo: user2@example.com\nSubject: Test Email\n\nThis is a test." | \
   docker exec -i elemta_prod /app/elemta-cli send -f user1@example.com -t user2@example.com
   ```

2. Check mail logs:
   ```bash
   docker exec -it elemta_prod cat /app/logs/elemta.log | grep "mail delivery"
   docker exec -it mail_system grep "delivery" /var/log/mail.log
   ```

## Monitoring and Management

### 1. Monitoring

1. Access Grafana dashboard:
   - URL: http://your-server-ip:3000
   - Login with admin credentials from setup.sh

2. Check Prometheus metrics:
   - URL: http://your-server-ip:9090
   - Query `elemta_messages_total` to see message counts

### 2. Common Management Tasks

#### Mail Queue Management

```bash
# View queue statistics
docker exec -it elemta_prod /app/elemta-cli queue stats

# Process pending messages
docker exec -it elemta_prod /app/elemta-cli queue process

# View specific message
docker exec -it elemta_prod /app/elemta-cli queue view <message-id>
```

#### User Management

Use your mail system's native tools for user management.

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check directory service connection settings in elemta.toml
   - Verify directory service is running and accessible
   - Confirm user exists in directory
   
   ```bash
   # Test directory service connection
   docker exec -it elemta_prod ldapsearch -H ldap://directory-service:389 -D "cn=admin,dc=example,dc=com" \
     -w "password" -b "dc=example,dc=com" "(mail=user@example.com)"
   ```

2. **Mail Delivery Issues**
   - Check delivery protocol connection
   - Verify delivery ports are open between containers
   - Check mail service status
   
   ```bash
   # Test connectivity
   docker exec -it elemta_prod nc -zv mail-system <port>
   ```

3. **TLS/Certificate Issues**
   - Verify certificates are correctly mounted in containers
   - Check TLS settings in elemta.toml and mail system config
   
   ```bash
   # Verify certificate validity
   docker exec -it elemta_prod openssl x509 -in /app/certs/mail.example.com.crt -text -noout
   ```

### Log Analysis

Key log files to check:

- Elemta: `/app/logs/elemta.log`
- Mail system: Refer to your mail system's log locations

## Production Considerations

### Security Hardening

1. **Firewall Configuration**
   - Only expose necessary ports (25, 587)
   - Restrict access to management ports (3000, 9090)
   - Consider using a reverse proxy for management interfaces

2. **Certificate Management**
   - Replace self-signed certificates with proper CA-signed certs
   - Set up automatic certificate renewal

3. **Password Security**
   - Change all default passwords
   - Use strong passwords or authentication keys
   - Rotate credentials periodically

### Scaling

1. **Vertical Scaling**
   - Adjust container resources (CPU, memory) in docker-compose.yml
   - Use volume mounts on high-performance storage

2. **Horizontal Scaling**
   - Deploy multiple Elemta instances with shared database
   - Use load balancer for SMTP connections
   - Configure shared queue storage

### Backup Strategy

1. **Regular Backups**
   ```bash
   # Create backup directory
   mkdir -p /path/to/backups/$(date +%Y-%m-%d)
   
   # Backup configuration
   docker run --rm -v elemta_production_elemta_queue:/source -v /path/to/backups/$(date +%Y-%m-%d):/backup \
     alpine tar -czf /backup/elemta-queue.tar.gz /source
   
   # Backup mail system data
   docker run --rm -v elemta_production_mail_data:/source -v /path/to/backups/$(date +%Y-%m-%d):/backup \
     alpine tar -czf /backup/mail-data.tar.gz /source
   ```

2. **Backup Testing**
   - Regularly test restoring from backups
   - Verify mail flow after restoration

## Upgrade Process

1. **Backup First**
   - Create full backups before upgrading
   - Document current configuration

2. **Upgrade Steps**
   ```bash
   # Pull latest changes
   git pull origin main
   
   # Rebuild with new version
   cd .deploy/production
   docker-compose build --pull
   
   # Deploy new version
   docker-compose down
   docker-compose up -d
   ```

3. **Verification After Upgrade**
   - Check logs for errors
   - Test mail flow
   - Verify all integrations still work

## Conclusion

This deployment process sets up a production-ready Elemta integration with:

- Secure authentication via directory services
- Efficient mail delivery
- Comprehensive scanning and filtering
- Robust monitoring and metrics

For further assistance, consult the project documentation or contact support. 