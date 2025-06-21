# Elemta Production Deployment Guide

This guide covers deploying Elemta in production environments with security, reliability, and performance considerations.

## Production Requirements

### System Requirements

**Minimum Specifications**:
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 20GB SSD
- **Network**: 100 Mbps

**Recommended Specifications**:
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 100GB+ SSD with RAID
- **Network**: 1 Gbps with redundancy

### Software Requirements

- **Operating System**: Ubuntu 20.04+ or RHEL 8+
- **Docker**: 20.10+ and Docker Compose 2.0+
- **Go**: 1.23+ (for source builds)
- **SSL/TLS**: Valid certificates (Let's Encrypt or commercial)

## Deployment Methods

### Docker Production Deployment

#### 1. Prepare Production Environment

```bash
# Create production user
sudo useradd -r -s /bin/false elemta
sudo mkdir -p /opt/elemta
sudo chown elemta:elemta /opt/elemta

# Clone repository
cd /opt/elemta
git clone https://github.com/busybox42/elemta.git .
sudo chown -R elemta:elemta /opt/elemta
```

#### 2. Configure Production Settings

```bash
# Create production configuration
sudo cp config/elemta-default.toml /etc/elemta/elemta.toml
sudo chown elemta:elemta /etc/elemta/elemta.toml
sudo chmod 600 /etc/elemta/elemta.toml
```

**Production Configuration** (`/etc/elemta/elemta.toml`):
```toml
[server]
hostname = "mail.yourdomain.com"
listen_addr = "0.0.0.0:25"
max_message_size = 52428800  # 50MB
timeout = 300
workers = 8

[tls]
enabled = true
cert_file = "/etc/elemta/certs/fullchain.pem"
key_file = "/etc/elemta/certs/privkey.pem"
security_level = "strict"
enable_starttls = true
require_starttls = true

[auth]
enabled = true
required = true
mechanisms = ["PLAIN", "LOGIN"]
datasource = "ldap"

[auth.ldap]
host = "ldap.yourdomain.com"
port = 636
use_tls = true
bind_dn = "cn=elemta,ou=services,dc=yourdomain,dc=com"
bind_password = "your-secure-password"
base_dn = "ou=users,dc=yourdomain,dc=com"
user_filter = "(&(objectClass=inetOrgPerson)(mail=%s))"

[queue]
dir = "/var/spool/elemta/queue"
max_retries = 5
retry_schedule = [300, 900, 3600, 10800, 43200]  # 5m, 15m, 1h, 3h, 12h
max_queue_time = 432000  # 5 days
cleanup_interval = 3600
workers = 4

[logging]
level = "info"
console = false
file = "/var/log/elemta/elemta.log"
max_size = 100  # MB
max_backups = 10
max_age = 30  # days

[monitoring]
enabled = true
listen_addr = ":8081"
metrics_path = "/metrics"

[plugins]
enabled = true
directory = "/opt/elemta/plugins"
plugins = ["clamav", "rspamd", "dkim", "spf", "dmarc"]

[plugins.clamav]
socket = "/var/run/clamav/clamd.ctl"
timeout = 30

[plugins.rspamd]
url = "http://127.0.0.1:11333"
timeout = 10
```

#### 3. Set Up TLS Certificates

**Using Let's Encrypt**:
```bash
# Install certbot
sudo apt update
sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone \
  -d mail.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos \
  --no-eff-email

# Set up auto-renewal
echo "0 3 * * * root certbot renew --quiet" | sudo tee -a /etc/crontab

# Copy certificates to elemta directory
sudo mkdir -p /etc/elemta/certs
sudo cp /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem /etc/elemta/certs/
sudo cp /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem /etc/elemta/certs/
sudo chown elemta:elemta /etc/elemta/certs/*
sudo chmod 600 /etc/elemta/certs/*
```

#### 4. Create Production Docker Compose

**Production docker-compose.yml**:
```yaml
version: '3.8'

services:
  elemta:
    build: .
    container_name: elemta-production
    restart: unless-stopped
    ports:
      - "25:25"
      - "587:587"
      - "8081:8081"
    volumes:
      - /etc/elemta/elemta.toml:/app/config/elemta.toml:ro
      - /etc/elemta/certs:/app/certs:ro
      - /var/spool/elemta:/app/queue
      - /var/log/elemta:/app/logs
    environment:
      - ELEMTA_CONFIG=/app/config/elemta.toml
      - ELEMTA_LOG_LEVEL=info
    depends_on:
      - rspamd
      - clamav
    networks:
      - elemta-network
    healthcheck:
      test: ["CMD", "/app/elemta", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  rspamd:
    image: rspamd/rspamd:latest
    container_name: rspamd-production
    restart: unless-stopped
    volumes:
      - ./docker/rspamd:/etc/rspamd/override.d:ro
      - rspamd-data:/var/lib/rspamd
    networks:
      - elemta-network

  clamav:
    image: clamav/clamav:latest
    container_name: clamav-production
    restart: unless-stopped
    volumes:
      - clamav-data:/var/lib/clamav
    environment:
      - CLAMAV_NO_CLAMD=false
      - CLAMAV_NO_FRESHCLAMD=false
    networks:
      - elemta-network

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus-production
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    networks:
      - elemta-network

  grafana:
    image: grafana/grafana:latest
    container_name: grafana-production
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=your-secure-password
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    networks:
      - elemta-network

volumes:
  rspamd-data:
  clamav-data:
  prometheus-data:
  grafana-data:

networks:
  elemta-network:
    driver: bridge
```

#### 5. Deploy Production Services

```bash
# Create directories
sudo mkdir -p /var/spool/elemta/queue/{active,deferred,failed,hold,data}
sudo mkdir -p /var/log/elemta
sudo chown -R elemta:elemta /var/spool/elemta /var/log/elemta

# Start services
docker-compose -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose -f docker-compose.prod.yml ps
docker-compose -f docker-compose.prod.yml logs elemta
```

### Kubernetes Production Deployment

#### 1. Create Namespace and Secrets

```bash
# Create namespace
kubectl create namespace elemta-production

# Create TLS secret
kubectl create secret tls elemta-tls \
  --cert=fullchain.pem \
  --key=privkey.pem \
  -n elemta-production

# Create configuration secret
kubectl create secret generic elemta-config \
  --from-file=elemta.toml=/etc/elemta/elemta.toml \
  -n elemta-production
```

#### 2. Deploy Production Manifests

**production-deployment.yaml**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elemta
  namespace: elemta-production
  labels:
    app: elemta
    version: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: elemta
  template:
    metadata:
      labels:
        app: elemta
    spec:
      containers:
      - name: elemta
        image: elemta:latest
        ports:
        - containerPort: 25
        - containerPort: 587
        - containerPort: 8081
        env:
        - name: ELEMTA_CONFIG
          value: /app/config/elemta.toml
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: tls-certs
          mountPath: /app/certs
          readOnly: true
        - name: queue-storage
          mountPath: /app/queue
        livenessProbe:
          exec:
            command:
            - /app/elemta
            - health
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          tcpSocket:
            port: 25
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: config
        secret:
          secretName: elemta-config
      - name: tls-certs
        secret:
          secretName: elemta-tls
      - name: queue-storage
        persistentVolumeClaim:
          claimName: elemta-queue-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: elemta-smtp
  namespace: elemta-production
spec:
  type: LoadBalancer
  ports:
  - port: 25
    targetPort: 25
    protocol: TCP
    name: smtp
  - port: 587
    targetPort: 587
    protocol: TCP
    name: submission
  selector:
    app: elemta
---
apiVersion: v1
kind: Service
metadata:
  name: elemta-monitoring
  namespace: elemta-production
spec:
  type: ClusterIP
  ports:
  - port: 8081
    targetPort: 8081
    protocol: TCP
  selector:
    app: elemta
```

## Security Hardening

### System Security

```bash
# Set up firewall
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp
sudo ufw allow 993/tcp
sudo ufw allow 995/tcp

# Disable unused services
sudo systemctl disable cups
sudo systemctl disable avahi-daemon

# Set up fail2ban
sudo apt install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

**Fail2Ban Configuration** (`/etc/fail2ban/jail.d/elemta.conf`):
```ini
[elemta-smtp]
enabled = true
port = 25,587
filter = elemta-smtp
logpath = /var/log/elemta/elemta.log
maxretry = 5
bantime = 3600
```

### Application Security

1. **Use Strong Authentication**:
   - Require authentication for all SMTP submissions
   - Use secure authentication mechanisms (avoid PLAIN over unencrypted connections)
   - Implement rate limiting

2. **Enable TLS Everywhere**:
   - Require STARTTLS for all connections
   - Use strong cipher suites
   - Regularly update certificates

3. **Configure Email Security**:
   - Enable SPF, DKIM, DMARC validation
   - Implement virus and spam scanning
   - Set up content filtering

## Monitoring and Alerting

### Prometheus Metrics

Access metrics at: `http://your-server:8081/metrics`

Key metrics to monitor:
- `elemta_smtp_connections_total`
- `elemta_queue_messages_total`
- `elemta_delivery_attempts_total`
- `elemta_plugin_execution_duration`

### Grafana Dashboards

Import the provided dashboards:
- Elemta Overview: `monitoring/grafana/dashboards/elemta_overview.json`
- Security Dashboard: `monitoring/grafana/dashboards/security-dashboard.json`
- Queue Management: `monitoring/grafana/dashboards/queue-dashboard.json`

### Alert Rules

**Critical Alerts**:
- Service down
- Certificate expiration (< 7 days)
- Queue backup (> 1000 messages)
- High error rate (> 5%)

**Warning Alerts**:
- High memory usage (> 80%)
- High CPU usage (> 80%)
- Slow delivery times (> 5 minutes average)

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# Daily backup script

BACKUP_DIR="/backup/elemta/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp -r /etc/elemta "$BACKUP_DIR/"

# Backup queue (excluding active)
rsync -av --exclude='active/*' /var/spool/elemta/ "$BACKUP_DIR/queue/"

# Backup logs (last 7 days)
find /var/log/elemta -mtime -7 -type f -exec cp {} "$BACKUP_DIR/logs/" \;

# Compress backup
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"
rm -rf "$BACKUP_DIR"

# Cleanup old backups (keep 30 days)
find /backup/elemta -name "*.tar.gz" -mtime +30 -delete
```

### Recovery Procedures

**Service Recovery**:
```bash
# Stop services
docker-compose down

# Restore configuration
tar -xzf backup.tar.gz
cp -r backup/etc/elemta /etc/

# Restore queue
cp -r backup/queue/* /var/spool/elemta/

# Restart services
docker-compose up -d
```

## Performance Tuning

### System Optimization

```bash
# Increase file descriptor limits
echo "elemta soft nofile 65536" >> /etc/security/limits.conf
echo "elemta hard nofile 65536" >> /etc/security/limits.conf

# Optimize TCP settings
echo "net.core.rmem_max = 16777216" >> /etc/sysctl.conf
echo "net.core.wmem_max = 16777216" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 87380 16777216" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 16777216" >> /etc/sysctl.conf
sysctl -p
```

### Application Tuning

Adjust configuration based on load:
```toml
[server]
workers = 16  # 2x CPU cores
timeout = 300

[queue]
workers = 8   # CPU cores
batch_size = 100

[plugins]
timeout = 30
max_concurrent = 10
```

## Maintenance

### Regular Tasks

**Daily**:
- Monitor service health
- Check queue depths
- Review error logs

**Weekly**:
- Update security signatures (ClamAV, RSpamd)
- Review performance metrics
- Check certificate expiration

**Monthly**:
- Update system packages
- Review and rotate logs
- Test backup/recovery procedures
- Security audit

### Updates and Upgrades

```bash
# Update Elemta
cd /opt/elemta
git pull origin main
docker-compose build --no-cache
docker-compose up -d

# Update system
sudo apt update && sudo apt upgrade
sudo reboot  # if kernel updated
```

## Compliance and Regulations

### GDPR Compliance

- Log retention policies
- Data encryption at rest and in transit
- Right to data deletion
- Privacy by design

### Industry Standards

- Follow RFC standards for SMTP
- Implement proper SPF/DKIM/DMARC
- Regular security assessments
- Incident response procedures 