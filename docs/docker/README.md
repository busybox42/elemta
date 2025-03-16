# Docker Deployment for Elemta

This document provides instructions for deploying Elemta using Docker.

## Overview

The Docker deployment includes the following components:

- **Elemta SMTP Server**: The main SMTP server application
- **ClamAV**: Antivirus scanning service
- **Rspamd**: Spam filtering service

## Ports

The following ports are exposed by the Docker deployment:

- **2525**: SMTP service
- **8080**: Metrics endpoint
- **3310**: ClamAV service
- **11334**: Rspamd web interface

## Quick Start

To deploy Elemta using Docker:

1. Ensure Docker and Docker Compose are installed on your system
2. Clone the repository: `git clone https://github.com/elemta/elemta.git`
3. Navigate to the project directory: `cd elemta`
4. Build and start the containers: `docker-compose up -d`
5. Verify the deployment: `./tests/test-elemta.sh`

## Configuration

The Docker deployment uses the default configuration files located in the `config` directory. You can customize these files to suit your needs.

### Volumes

The following volumes are created for persistent storage:

- **elemta_config**: Configuration files
- **elemta_queue**: Message queue
- **elemta_logs**: Log files

## Testing

To test the deployment, run the provided test script:

```bash
./tests/test-elemta.sh
```

This script tests the following:

- SMTP service connectivity
- Metrics endpoint accessibility
- ClamAV service functionality
- Rspamd web interface accessibility

## Monitoring

The metrics endpoint is exposed on port 8080. You can access it at:

```
http://localhost:8080/metrics
```

This endpoint provides Prometheus-compatible metrics for monitoring the Elemta SMTP server.

## Troubleshooting

### Container Logs

To view the logs for a specific container:

```bash
docker logs elemta
docker logs elemta-clamav
docker logs elemta-rspamd
```

### Container Health

To check the health of the containers:

```bash
docker-compose ps
```

All containers should show as "Up (healthy)" when the deployment is working correctly.

## Security Considerations

- The default configuration exposes services on localhost only
- For production deployments, consider using a reverse proxy with TLS
- Review and customize the security settings in the configuration files 