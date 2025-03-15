# Testing Elemta

This document provides comprehensive information about testing the Elemta SMTP server in various environments.

## Testing Approaches

Elemta can be tested in several environments:

1. **Local Testing**: Running tests directly against a local instance
2. **Docker Testing**: Using Docker containers for isolated testing
3. **Kubernetes Testing**: Testing in a Kubernetes cluster

## Local Testing

### Python Tests

The `tests/python` directory contains Python scripts for testing various aspects of Elemta:

- **test_smtp.py**: Tests basic SMTP functionality
- **test_smtp_auth.py**: Tests SMTP authentication
- **test_security.py**: Tests antivirus and antispam functionality

To run all Python tests:

```bash
make python-test
```

To run individual tests:

```bash
python3 tests/python/test_smtp.py
python3 tests/python/test_smtp_auth.py
python3 tests/python/test_security.py --test all
```

### Unit Tests

Go unit tests are available for testing individual components:

```bash
make unit-test
```

Or run specific package tests:

```bash
go test -v ./internal/smtp
go test -v ./internal/queue
```

### Code Coverage

To generate code coverage reports:

```bash
make coverage
```

This will run tests with coverage tracking and open an HTML report.

## Docker Testing

### Setup

The `tests/docker` directory contains Docker-related files for testing:

- **docker-compose.test.yml**: Docker Compose configuration
- **Dockerfile.test**: Dockerfile for building a test image

### Running Docker Tests

To build and start the test container:

```bash
make docker-test
```

Or manually:

```bash
docker-compose -f tests/docker/docker-compose.test.yml down --remove-orphans
docker-compose -f tests/docker/docker-compose.test.yml up -d --build
```

### Testing Against Docker Container

The Docker test container exposes port 2526, which can be used for testing:

```bash
python3 tests/python/test_smtp.py  # Uses localhost:2526 by default
```

### Stopping Docker Tests

To stop the test container:

```bash
docker-compose -f tests/docker/docker-compose.test.yml down --remove-orphans
```

## Kubernetes Testing

### Setup

The `k8s` directory contains Kubernetes deployment files, and `tests/k8s` contains test scripts.

### Deploying for Testing

To deploy Elemta to Kubernetes:

```bash
make k8s-deploy
```

### Running Kubernetes Tests

To run all Kubernetes tests:

```bash
make k8s-test
```

To run individual test scripts:

```bash
./tests/k8s/test-elemta.sh
./tests/k8s/simple-test.sh
./tests/k8s/test-clamav.sh
./tests/k8s/test-rspamd.sh
./tests/k8s/test-k8s-email.sh
```

### Cleaning Up

To remove the Kubernetes deployment:

```bash
make k8s-undeploy
```

## Security Testing

### Antivirus Testing

The `test_security.py` script includes tests for antivirus functionality using the EICAR test string:

```bash
python3 tests/python/test_security.py --test virus
```

For environments without antivirus scanning, you can skip these tests:

```bash
SKIP_SECURITY_TESTS=true python3 tests/python/test_security.py --test virus
```

### Antispam Testing

The `test_security.py` script also includes tests for antispam functionality using the GTUBE test string:

```bash
python3 tests/python/test_security.py --test spam
```

For environments without antispam scanning, you can skip these tests:

```bash
SKIP_SECURITY_TESTS=true python3 tests/python/test_security.py --test spam
```

## Troubleshooting Tests

### Common Issues

1. **Connection refused**: Ensure the server is running and listening on the expected port
2. **Authentication failures**: Check authentication configuration
3. **Security test failures**: Verify ClamAV and Rspamd are properly configured

### Docker-specific Issues

1. **Container not starting**: Check Docker logs
   ```bash
   docker logs elemta-test
   ```
2. **Network issues**: Verify port mappings
   ```bash
   docker ps
   ```

### Kubernetes-specific Issues

1. **Pods not starting**: Check pod status and events
   ```bash
   kubectl describe pod -l app=elemta
   ```
2. **Service connectivity**: Verify service endpoints
   ```bash
   kubectl get endpoints
   ```
3. **Configuration issues**: Check logs
   ```bash
   kubectl logs -l app=elemta -c elemta
   ```

## Adding New Tests

When adding new tests:

1. Place Python tests in `tests/python`
2. Place Kubernetes tests in `tests/k8s`
3. Update documentation to reflect new tests
4. Consider adding Makefile targets for convenience 