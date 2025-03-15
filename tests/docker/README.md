# Docker Test Files

This directory contains Docker-related files for testing the Elemta SMTP server.

## Available Files

- **docker-compose.test.yml**: Docker Compose configuration for testing
- **Dockerfile.test**: Dockerfile for building a test image

## Running Tests

To build and run the test container:

```bash
make docker-test
```

Or manually:

```bash
docker-compose -f tests/docker/docker-compose.test.yml down --remove-orphans
docker-compose -f tests/docker/docker-compose.test.yml up -d --build
```

To stop the test container:

```bash
docker-compose -f tests/docker/docker-compose.test.yml down --remove-orphans
```

## Test Environment

The test environment runs Elemta with a custom configuration that:

- Listens on port 2526 (mapped to 2525 in the container)
- Uses separate volumes for queue, logs, and plugins
- Runs in a dedicated network
- Has antivirus and antispam scanning disabled for testing purposes
- Starts the server with the "server" command in the ENTRYPOINT

## Testing Against the Container

Once the test container is running, you can run the Python tests against it:

```bash
python3 tests/python/test_smtp.py
python3 tests/python/test_smtp_auth.py
SKIP_SECURITY_TESTS=true python3 tests/python/test_security.py --test all
```

Or use the Makefile target to run all tests:

```bash
make python-test
```

## Troubleshooting

If you encounter issues with the test container:

1. Check the container logs:
   ```bash
   docker logs elemta-test
   ```

2. Verify the container is running:
   ```bash
   docker ps | grep elemta-test
   ```

3. Rebuild the container if needed:
   ```bash
   docker-compose -f tests/docker/docker-compose.test.yml build
   ``` 