# Elemta Integration Configuration Reference

This document provides detailed information about the configuration files used when integrating Elemta with external mail systems.

## Directory Structure

```
.deploy/production/
├── certs/                    # SSL certificates and DKIM keys
│   ├── mail/                 # Mail server specific certificates
│   └── dkim/                 # DKIM private and public keys
├── config/                   # Configuration files
│   ├── elemta.toml           # Main Elemta configuration
│   ├── users.json            # Fallback user authentication
│   ├── prometheus/           # Prometheus configuration
│   │   └── prometheus.yml    # Prometheus targets and settings
│   ├── grafana/              # Grafana dashboards and configuration
│   ├── rspamd/               # Rspamd configuration
│   │   └── override.d/       # Override configurations for Rspamd
│   └── mail/                 # Mail system configuration
│       ├── mail.cf           # Main mail system config
│       ├── transport         # Mail routing configuration 
│       └── ldap-config.cf    # LDAP mailbox lookup config
└── docker-compose.yml        # Docker Compose file
```

## Key Configuration Files

### 1. elemta.toml

This is the main configuration file for Elemta. Key sections include:

#### Server Settings
```toml
[server]
hostname = "mail.example.com"   # Public hostname for SMTP
listen = ":25"                  # SMTP listening port
submission_port = 587           # SMTP submission port
queue_dir = "/app/queue"        # Queue directory
max_size = 52428800             # Max message size (50MB)
```

#### TLS Configuration
```toml
[tls]
enabled = true
cert_file = "/app/certs/mail.example.com.crt"
key_file = "/app/certs/mail.example.com.key"
enable_starttls = true          # Enable STARTTLS for SMTP
enable_submission = true        # Enable TLS for submission port
```

#### Authentication Settings
```toml
[auth]
enabled = true
required = true                 # Require authentication for sending
datasource_type = "ldap"        # Use LDAP for authentication
fallback_type = "file"          # Fallback authentication method
fallback_path = "/app/config/users.json"

# LDAP auth settings
[auth.ldap]
host = "directory-service"      # LDAP server hostname
port = 389                      # LDAP port
use_ssl = false                 # Use SSL for LDAP
use_tls = true                  # Use TLS for LDAP
bind_dn = "cn=admin,dc=example,dc=com"  # LDAP bind DN
bind_password = "ldap_password" # LDAP bind password
base_dn = "ou=people,dc=example,dc=com"  # LDAP search base
user_filter = "(&(objectClass=inetOrgPerson)(mail=%s))"  # LDAP filter
```

#### Delivery Settings
```toml
[delivery]
mode = "lmtp"                   # Use LMTP for delivery (or "smtp")
host = "mail-system"            # Mail system hostname
port = 24                       # Delivery port (LMTP or SMTP)
timeout = 60                    # Delivery timeout in seconds
max_retries = 10                # Max delivery attempts
test_mode = false               # Production mode
default_domain = "example.com"  # Default domain for delivery
```

#### Directory Service Router
```toml
[router]
type = "ldap"                   # Use LDAP for mail routing
cache_ttl = 300                 # Cache routing results for 5 minutes

[router.ldap]
host = "directory-service"
port = 389
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = "ldap_password"
base_dn = "ou=people,dc=example,dc=com"
user_filter = "(&(objectClass=inetOrgPerson)(mail=%s))"
domain_filter = "(&(objectClass=domain)(dc=%s))"
```

#### Anti-Virus (ClamAV)
```toml
[plugins.clamav]
enabled = true
host = "elemta-clamav"          # ClamAV container name
port = 3310                     # ClamAV port
timeout = 60                    # Scan timeout
reject_on_failure = true        # Reject if scan fails
max_size = 26214400             # Max scan size (25MB)
```

#### Anti-Spam (Rspamd)
```toml
[plugins.rspamd]
enabled = true
host = "elemta-rspamd"          # Rspamd container name
port = 11334                    # Rspamd port
timeout = 30                    # Scan timeout
reject_on_spam = true           # Reject spam
threshold = 6.0                 # Spam score threshold
add_headers = true              # Add spam headers to messages
```

#### DKIM Signing
```toml
[plugins.dkim]
enabled = true
verify = true                   # Verify incoming DKIM signatures
sign = true                     # Sign outgoing messages
domains = ["example.com"]       # Domains to sign for
selector = "mail"               # DKIM selector
private_key = "/app/certs/dkim/example.com.private"  # DKIM private key
```

### 2. Mail System Configuration Files

The mail system configuration will vary depending on which system you're integrating with. Below are generic examples that may need to be adapted:

#### mail.cf
Main configuration file for the mail system:

```
# Transport maps for routing
transport_maps = hash:/opt/mail/conf/transport

# Relay domains
relay_domains = $mydestination, example.com

# LMTP/SMTP settings
lmtp_tcp_port = 24
lmtp_bind_address = 0.0.0.0
lmtp_tls_security_level = may
lmtp_sasl_auth_enable = yes

# Virtual mailbox configuration
virtual_mailbox_domains = example.com
virtual_mailbox_maps = ldap:/opt/mail/conf/ldap-config.cf
virtual_mailbox_base = /var/mail
```

#### transport
Mail routing configuration:

```
# Route all inbound mail through Elemta
example.com      smtp:elemta:25

# Default route for outbound mail
.                smtp:elemta:25
```

#### ldap-config.cf
LDAP configuration for mailbox lookups:

```
server_host = directory-service
server_port = 389
bind_dn = cn=admin,dc=example,dc=com
bind_pw = ldap_password
search_base = ou=people,dc=example,dc=com
scope = sub
query_filter = (&(objectClass=inetOrgPerson)(mail=%s))
result_attribute = mail
result_format = %s/
```

### 3. docker-compose.yml

Key configuration aspects:

#### Elemta Container
```yaml
elemta:
  image: elemta_node:latest
  ports:
    - "25:25"      # SMTP standard port
    - "587:587"    # Submission port
  volumes:
    - elemta_queue:/app/queue
    - ./config/elemta.toml:/app/config/elemta.toml:ro
    - ./certs:/app/certs:ro
  environment:
    - HOSTNAME=mail.example.com
    - DELIVERY_HOST=mail-system
    - DELIVERY_PORT=24
    - DELIVERY_MODE=lmtp
```

#### Mail System Container
```yaml
mail-system:
  image: mail_system:latest
  ports:
    - "24:24"     # LMTP/SMTP delivery port
  volumes:
    - mail_data:/var/mail
    - ./config/mail:/opt/mail/conf
    - ./certs/mail:/opt/mail/ssl
  environment:
    - MAIL_DOMAIN=example.com
    - LDAP_HOST=directory-service
    - LDAP_PORT=389
    - LDAP_BIND_DN=cn=admin,dc=example,dc=com
    - LDAP_BIND_PASSWORD=ldap_password
```

#### Directory Service Container
```yaml
directory-service:
  image: directory_service:latest
  ports:
    - "389:389"   # LDAP port
    - "636:636"   # LDAPS port
  volumes:
    - directory_data:/var/lib/ldap
    - ./config/ldap:/etc/ldap/conf.d
  environment:
    - LDAP_DOMAIN=example.com
    - LDAP_ADMIN_PASSWORD=ldap_password
```

## Environment Variables

### Elemta Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOSTNAME` | Public hostname for SMTP | mail.example.com |
| `NODE_ID` | Unique node identifier | 1 |
| `ELEMTA_CONFIG_PATH` | Path to config file | /app/config/elemta.toml |
| `DELIVERY_HOST` | Host for mail delivery | mail-system |
| `DELIVERY_PORT` | Port for mail delivery | 24 |
| `DELIVERY_MODE` | Delivery protocol | lmtp |

### Mail System Environment Variables

These will vary depending on your mail system, but commonly include:

| Variable | Description | Default |
|----------|-------------|---------|
| `MAIL_DOMAIN` | Primary email domain | example.com |
| `LDAP_HOST` | LDAP server hostname | directory-service |
| `LDAP_PORT` | LDAP server port | 389 |
| `LDAP_BIND_DN` | LDAP bind DN | cn=admin,dc=example,dc=com |
| `LDAP_BIND_PASSWORD` | LDAP bind password | (generated) |

## SSL Certificate Requirements

1. **Elemta Certificates**:
   - `/certs/mail.example.com.crt` - Domain certificate
   - `/certs/mail.example.com.key` - Private key

2. **Mail System Certificates**:
   - `/certs/mail/mail.crt` - Mail service certificate
   - `/certs/mail/mail.key` - Mail private key

3. **DKIM Keys**:
   - `/certs/dkim/example.com.private` - DKIM private key
   - `/certs/dkim/example.com.public` - DKIM public key (for DNS)

## DNS Records Required

1. **MX Record**:
   ```
   example.com. IN MX 10 mail.example.com.
   ```

2. **A Record**:
   ```
   mail.example.com. IN A <server-ip>
   ```

3. **SPF Record**:
   ```
   example.com. IN TXT "v=spf1 mx a:mail.example.com -all"
   ```

4. **DKIM Record**:
   ```
   mail._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=<public-key-data>"
   ```

5. **DMARC Record**:
   ```
   _dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"
   ```

## Security Recommendations

1. **File Permissions**:
   - Private keys: `600` (read/write for owner only)
   - Configuration files: `640` (read/write for owner, read for group)
   - Certificates: `644` (read/write for owner, read for others)

2. **Network Isolation**:
   - Use Docker networks to isolate services
   - Expose only necessary ports to the host

3. **Regular Updates**:
   - Keep Docker images updated
   - Apply security patches promptly

4. **Monitoring**:
   - Enable Prometheus metrics
   - Set up alerts for suspicious activity

5. **Backup Strategy**:
   - Regular encrypted backups
   - Offsite storage for disaster recovery 