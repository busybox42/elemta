# Docker Deployment for Elemta

This document provides instructions for deploying Elemta using Docker and Docker Compose.

## Prerequisites

- Docker Engine (version 20.10.0 or later)
- Docker Compose (version 2.0.0 or later)

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/busybox42/elemta.git
   cd elemta
   ```

2. Build and start the containers:
   ```bash
   docker-compose up -d
   ```

3. Check the logs:
   ```bash
   docker logs elemta
   ```

4. Stop the containers:
   ```bash
   docker-compose down
   ```

## Configuration

The Elemta server is configured using the `config/elemta.conf` file. This file is mounted as a volume in the Docker container, so you can modify it without rebuilding the image.

### Default Configuration

```json
{
    "hostname": "mail.evil-admin.com",
    "listen_addr": ":2525",
    "queue_dir": "./queue",
    "max_size": 26214400,
    "dev_mode": true,
    "allowed_relays": ["127.0.0.1", "::1", "192.168.65.1"],
    "max_workers": 5,
    "max_retries": 3,
    "max_queue_time": 3600,
    "retry_schedule": [60, 300, 900]
}
```

### Custom Configuration

You can create a custom configuration file and mount it in the container:

```yaml
version: '3.8'

services:
  elemta:
    # ... other settings ...
    volumes:
      - ./my-custom-config.json:/app/config/elemta.conf
      # ... other volumes ...
```

## Persistent Storage

The Docker Compose configuration includes volumes for persistent storage:

- `elemta_queue`: Stores the email queue
- `elemta_logs`: Stores the server logs
- `elemta_config`: Stores the configuration files
- `elemta_plugins`: Stores custom plugins

These volumes are managed by Docker and will persist across container restarts.

## Networking

The Elemta server listens on port 2525 by default. This port is exposed from the container and mapped to the host.

If you want to use a different port, you can modify the `ports` section in the `docker-compose.yml` file:

```yaml
ports:
  - "25:2525"  # Map host port 25 to container port 2525
```

## Security Considerations

- The Elemta server runs as a non-root user inside the container
- The server is configured to only allow relaying from localhost and Docker network by default
- Consider using a reverse proxy with TLS termination for secure SMTP connections

## Testing the Deployment

You can test your Docker deployment using the provided Python scripts:

```bash
# Test basic SMTP functionality
python3 test_smtp.py

# Test SMTP authentication (if enabled)
python3 test_smtp_auth.py
```

## Troubleshooting

### Container fails to start

Check the logs for errors:

```bash
docker logs elemta
```

### Cannot connect to the server

Make sure the port is correctly mapped and not blocked by a firewall:

```bash
telnet localhost 2525
```

### Emails are not being delivered

Check the queue directory for stuck messages:

```bash
docker exec -it elemta ls -la /app/queue
```

## Advanced Usage

### Building a custom image

You can build a custom image using the provided Dockerfile:

```bash
docker build -t my-elemta:custom .
```

### Running without Docker Compose

You can run the container directly using Docker:

```bash
docker run -d \
  --name elemta \
  -p 2525:2525 \
  -v $(pwd)/config:/app/config \
  -v elemta_queue:/app/queue \
  -v elemta_logs:/app/logs \
  elemta:latest
```

### Using Docker Compose for Testing

Elemta includes a separate Docker Compose configuration for testing:

```bash
docker-compose -f docker-compose.test.yml up -d
```

This will start a separate instance of Elemta on port 2526 for testing purposes. 