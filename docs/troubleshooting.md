# Elemta Troubleshooting Guide

This guide helps resolve common issues encountered when deploying and operating Elemta.

## Common Issues

### Build and Startup Issues

#### Build Fails with "Go Module Not Found"

**Problem**: Build fails with module or dependency errors.

**Solution**:
```bash
# Clean and re-download modules
go clean -modcache
go mod download
go mod tidy

# Rebuild
make clean
make build
```

#### Server Won't Start - Port Already in Use

**Problem**: `bind: address already in use` error.

**Solutions**:
```bash
# Check what's using the port
sudo netstat -tlnp | grep :25
sudo ss -tlnp | grep :25

# Kill process using the port
sudo fuser -k 25/tcp

# Or change the port in configuration
vim config/elemta.toml
# Change: listen_addr = ":2525"
```

#### Permission Denied on Queue Directory

**Problem**: Server can't write to queue directories.

**Solution**:
```bash
# Create and set permissions
sudo mkdir -p /var/spool/elemta/queue
sudo chown -R elemta:elemta /var/spool/elemta
sudo chmod -R 755 /var/spool/elemta

# Or use local directory
mkdir -p ./queue
# Update config: queue_dir = "./queue"
```

### Docker Issues

#### Docker Compose Fails to Start

**Problem**: Services fail to start with Docker Compose.

**Diagnostic Steps**:
```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs elemta
docker-compose logs rspamd
docker-compose logs ldap

# Check container health
docker inspect elemta_elemta_1 | grep Health -A 10
```

**Common Solutions**:
```bash
# Clean and restart
docker-compose down
docker system prune -f
docker-compose up -d

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d
```

#### Container Exits Immediately

**Problem**: Elemta container starts then exits.

**Debug Steps**:
```bash
# Run container interactively
docker run -it --rm elemta /bin/bash

# Check configuration
docker exec elemta_elemta_1 /app/elemta config validate

# View detailed logs
docker logs -f elemta_elemta_1
```

### SMTP Connection Issues

#### Cannot Connect to SMTP Server

**Problem**: Clients can't connect to SMTP server.

**Diagnostic Steps**:
```bash
# Test local connection
telnet localhost 2525

# Test Docker connection
telnet localhost 2525

# Check firewall
sudo ufw status
sudo iptables -L | grep 25

# Check server logs
tail -f logs/elemta.log
```

**Solutions**:
- Verify `listen_addr` in configuration
- Check firewall rules
- Ensure Docker port mapping is correct
- Verify TLS configuration if STARTTLS fails

#### SMTP Authentication Fails

**Problem**: Valid credentials rejected.

**Debug Steps**:
```bash
# Test authentication endpoint
curl -u admin:password http://localhost:8081/api/auth/test

# Check user configuration
cat config/users.json

# Check LDAP connectivity (if using LDAP)
ldapsearch -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin
```

**Solutions**:
- Verify authentication configuration in `elemta.toml`
- Check user credentials in data source
- Review auth logs in server output
- Test with simple file-based auth first

### Queue Issues

#### Messages Stuck in Queue

**Problem**: Messages not being delivered.

**Diagnostic Steps**:
```bash
# Check queue status
./bin/elemta-cli queue stats

# List stuck messages
./bin/elemta-cli queue list

# View specific message
./bin/elemta-cli queue view <message-id>
```

**Solutions**:
```bash
# Retry specific message
./bin/elemta-cli queue retry <message-id>

# Restart queue processor
docker-compose restart elemta

# Check delivery logs
tail -f logs/delivery.log
```

#### Queue Processor Not Running

**Problem**: Queue processor daemon not processing messages.

**Solutions**:
```bash
# Check if processor is running
ps aux | grep elemta-queue

# Start queue processor manually
./bin/elemta-queue -config config/elemta.toml

# Or restart service
systemctl restart elemta-queue
```

### TLS/SSL Issues

#### TLS Handshake Failures

**Problem**: STARTTLS command fails or TLS negotiation errors.

**Debug Steps**:
```bash
# Test TLS connection
openssl s_client -connect localhost:2525 -starttls smtp

# Check certificate validity
openssl x509 -in config/cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile ca.pem config/cert.pem
```

**Solutions**:
- Regenerate certificates if expired
- Check certificate permissions (readable by elemta user)
- Verify certificate matches hostname
- Review TLS configuration security level

#### Let's Encrypt Certificate Issues

**Problem**: Automatic certificate renewal fails.

**Solutions**:
```bash
# Manual certificate renewal
./scripts/ssl/letsencrypt-admin.sh renew

# Check certificate status
./scripts/ssl/letsencrypt-admin.sh status

# View renewal logs
tail -f /var/log/letsencrypt/letsencrypt.log
```

### Plugin Issues

#### Plugin Loading Fails

**Problem**: Plugins not loading or causing crashes.

**Debug Steps**:
```bash
# Check plugin directory
ls -la /app/plugins/

# Test plugin manually
./bin/elemta plugin test /app/plugins/clamav.so

# Check plugin logs
grep "plugin" logs/elemta.log
```

**Solutions**:
- Verify plugin file permissions
- Check plugin compatibility with current Go version
- Review plugin configuration
- Disable problematic plugins temporarily

#### Antivirus/Antispam Not Working

**Problem**: ClamAV or RSpamd not scanning messages.

**Debug Steps**:
```bash
# Test ClamAV connection
echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" | clamdscan -

# Test RSpamd connection
curl -X POST http://localhost:11333/symbols -d "Test message"

# Check service status
docker-compose ps rspamd clamav
```

### Performance Issues

#### High Memory Usage

**Problem**: Elemta consuming excessive memory.

**Diagnostic Steps**:
```bash
# Check memory usage
top -p $(pgrep elemta)
ps aux | grep elemta

# Analyze memory with pprof
go tool pprof http://localhost:8081/debug/pprof/heap
```

**Solutions**:
- Review queue size and message retention
- Check for memory leaks in plugins
- Adjust worker pool sizes
- Monitor garbage collection metrics

#### Slow Message Processing

**Problem**: Low throughput, messages backing up.

**Solutions**:
- Increase worker pool sizes in configuration
- Optimize database connections (if using SQL auth)
- Review plugin performance
- Check network latency to external services

## Monitoring and Debugging

### Enable Debug Logging

Add to configuration:
```toml
[logging]
level = "debug"
console = true
```

### Access Metrics

```bash
# Prometheus metrics
curl http://localhost:8081/metrics

# Health check
curl http://localhost:8081/health

# Queue statistics
curl http://localhost:8081/api/queue/stats
```

### Log File Locations

- **Main logs**: `logs/elemta.log`
- **Access logs**: `logs/access.log`
- **Error logs**: `logs/error.log`
- **Queue logs**: `logs/queue.log`
- **Docker logs**: `docker-compose logs elemta`

## Getting Help

If these troubleshooting steps don't resolve your issue:

1. **Check the logs** for specific error messages
2. **Review configuration** against examples in `config/`
3. **Test with minimal configuration** to isolate the problem
4. **Search existing issues** on GitHub
5. **Open a new issue** with:
   - Complete error messages
   - Configuration file (sanitized)
   - Steps to reproduce
   - Environment details (OS, Docker version, etc.)

### Useful Debug Commands

```bash
# Configuration validation
./bin/elemta config validate

# System information
./bin/elemta version --verbose

# Network connectivity test
./bin/elemta network test <hostname>

# Performance profiling
./bin/elemta profile --duration 30s
``` 