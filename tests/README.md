# Elemta Tests

This directory contains all tests for the Elemta Mail Transfer Agent (MTA).

## Directory Structure

- `unit/`: Go unit tests for various components
  - `smtp/`: Tests for the SMTP server implementation
  - `context/`: Tests for the context package
  
- `k8s/`: Kubernetes deployment tests
  - `test-elemta.sh`: Main test script for the Kubernetes deployment
  - `simple-test.sh`: Basic connectivity tests
  - `test-clamav.sh`: ClamAV-specific tests
  - `test-rspamd.sh`: Rspamd-specific tests
  - `test-k8s-email.sh`: End-to-end email flow tests
  - `test-deployment.yaml`: Test deployment configuration
  - `test-pod.yaml`: Test pod configuration
  - `k8s-test-summary.md`: Summary of Kubernetes test results

- `python/`: Python test scripts
  - `test_smtp.py`: Basic SMTP test
  - `test_smtp_auth.py`: SMTP authentication test
  - `test_security.py`: Security features test

- `docker/`: Docker test files
  - `docker-compose.test.yml`: Docker Compose test configuration
  - `Dockerfile.test`: Test Dockerfile

- `config/`: Test configuration files
  - `test-elemta.conf`: Test configuration for Elemta

- `data/`: Test data files
  - `eicar.txt`: EICAR test file for antivirus testing

## Running Tests

### Unit Tests

To run all Go unit tests:

```bash
make unit-test
```

### Kubernetes Tests

To run the main Kubernetes test:

```bash
make k8s-test
```

### Python Tests

To run a Python test:

```bash
python3 tests/python/test_smtp.py
```

### Docker Tests

To run Docker tests:

```bash
docker-compose -f tests/docker/docker-compose.test.yml up -d
```

## Adding New Tests

- For Go unit tests, add them to the appropriate subdirectory in `tests/unit/`
- For Kubernetes tests, add shell scripts to `tests/k8s/`
- For Python tests, add scripts to `tests/python/`
- For Docker tests, add files to `tests/docker/`
- For test configurations, add files to `tests/config/`
- For test data, add files to `tests/data/` 