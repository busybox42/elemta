# Docker Test Files

This directory contains Docker-related files for testing the Elemta SMTP server.

## Available Files

- **docker-compose.test.yml**: Docker Compose configuration for testing
- **Dockerfile.test**: Dockerfile for building a test image

## Running Tests

To build and run the test container:

```bash
docker-compose -f tests/docker/docker-compose.test.yml up -d
```

To stop the test container:

```bash
docker-compose -f tests/docker/docker-compose.test.yml down
```

## Test Environment

The test environment runs Elemta with a custom configuration that:

- Listens on port 2526 (mapped to 2525 in the container)
- Uses separate volumes for queue, logs, and plugins
- Runs in a dedicated network 