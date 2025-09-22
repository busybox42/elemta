# Elemta Testing Guide

This document provides comprehensive information about testing the Elemta SMTP server, including the centralized test suite, individual test scripts, and testing best practices.

## Overview

Elemta uses a multi-layered testing approach:

1. **Go Unit Tests** - Test individual components and functions
2. **Centralized Test Suite** - Comprehensive integration and deployment testing
3. **Individual Test Scripts** - Specialized tests for specific functionality
4. **Docker Integration Tests** - Full deployment testing

## Centralized Test Suite

The centralized test suite (`test_elemta_centralized.py`) is the primary testing tool for Elemta. It provides:

- **Unified Interface** - Single script for all testing needs
- **Multiple Deployment Support** - Docker Desktop, Docker Dev, Local
- **Comprehensive Coverage** - SMTP, Auth, Security, Performance, E2E, Monitoring
- **Parallel Execution** - Run tests concurrently for faster execution
- **Detailed Reporting** - Clear pass/fail results with timing information

### Quick Start

```bash
# Run all tests against Docker Desktop deployment
./run_centralized_tests.sh

# Run security tests only
./run_centralized_tests.sh --category security

# Run specific test
./run_centralized_tests.sh --test smtp-greeting

# Run tests in parallel with verbose output
./run_centralized_tests.sh --parallel --verbose
```

### Test Categories

#### Deployment Tests
- **docker-containers-running** - Verify all Docker containers are running
- **docker-services-healthy** - Verify all Docker services are healthy

#### SMTP Protocol Tests
- **smtp-greeting** - Test SMTP server greeting
- **smtp-ehlo** - Test EHLO command
- **smtp-helo** - Test HELO command
- **smtp-mail-from** - Test MAIL FROM command
- **smtp-rcpt-to** - Test RCPT TO command
- **smtp-data** - Test DATA command and email sending
- **smtp-quit** - Test QUIT command

#### Authentication Tests
- **auth-plain** - Test AUTH PLAIN authentication
- **auth-login** - Test AUTH LOGIN authentication
- **auth-invalid** - Test invalid authentication rejection

#### Security Tests
- **security-command-injection** - Test command injection protection
- **security-buffer-overflow** - Test buffer overflow protection
- **security-sql-injection** - Test SQL injection protection

#### Performance Tests
- **performance-connection-limit** - Test connection limit handling
- **performance-rate-limiting** - Test rate limiting functionality

#### End-to-End Tests
- **e2e-email-delivery** - Test complete email delivery flow
- **e2e-webmail-access** - Test webmail access

#### Monitoring Tests
- **monitoring-metrics** - Test metrics endpoint
- **monitoring-health** - Test health check endpoint

### Command Line Options

#### Basic Options
- `--deployment {docker-desktop,docker-dev,local}` - Deployment type to test
- `--host HOST` - SMTP server host (default: localhost)
- `--smtp-port PORT` - SMTP server port (default: 2525)
- `--timeout SECONDS` - Test timeout in seconds (default: 30)

#### Test Selection
- `--category CATEGORY` - Run tests in specific category (can be specified multiple times)
- `--test TEST` - Run specific test (can be specified multiple times)
- `--skip TEST` - Skip specific test (can be specified multiple times)

#### Execution Options
- `--verbose, -v` - Verbose output
- `--parallel, -p` - Run tests in parallel
- `--max-workers N` - Maximum parallel workers (default: 4)

### Examples

```bash
# Test Docker Desktop deployment
./run_centralized_tests.sh --deployment docker-desktop

# Test Docker Dev deployment with verbose output
./run_centralized_tests.sh --deployment docker-dev --verbose

# Run security and authentication tests
./run_centralized_tests.sh --category security --category auth

# Run specific tests
./run_centralized_tests.sh --test smtp-greeting --test smtp-ehlo

# Skip problematic tests
./run_centralized_tests.sh --skip performance-connection-limit

# Run tests in parallel with 8 workers
./run_centralized_tests.sh --parallel --max-workers 8

# Test remote server
./run_centralized_tests.sh --host 192.168.1.100 --smtp-port 25
```

## Makefile Integration

The Makefile provides convenient shortcuts for common testing scenarios:

```bash
# Run Go unit tests
make test

# Run centralized test suite
make test-centralized

# Run Docker deployment tests
make test-docker

# Run security tests
make test-security

# Run all tests
make test-all
```

## Individual Test Scripts

While the centralized test suite covers most testing needs, individual test scripts are available for specialized testing:

### Python Test Scripts

- `test_elemta_complete.py` - Comprehensive test suite (legacy)
- `test_end_to_end.py` - End-to-end email delivery testing
- `test_smtp_command_security.py` - SMTP command security testing
- `test_email_content_validation.py` - Email content validation testing
- `test_rate_limiting.py` - Rate limiting testing
- `test_memory_exhaustion.py` - Memory exhaustion protection testing
- `test_email_logging.py` - Email logging testing
- `test_worker_pool_load.py` - Worker pool load testing

### Shell Test Scripts

- `run_tests.sh` - Legacy test runner
- `run_complete_tests.sh` - Legacy complete test runner
- `tests/integration_test_suite.sh` - Integration test suite
- `tests/quick-test.sh` - Quick functionality test

## Docker Testing

### Prerequisites

1. Docker and Docker Compose installed
2. Elemta Docker deployment running:
   ```bash
   docker compose up -d
   ```

### Testing Docker Deployment

```bash
# Test Docker Desktop deployment
./run_centralized_tests.sh --deployment docker-desktop

# Test with verbose output
./run_centralized_tests.sh --deployment docker-desktop --verbose

# Test specific categories
./run_centralized_tests.sh --deployment docker-desktop --category smtp --category auth
```

### Docker Service Verification

The centralized test suite automatically verifies:

- All required containers are running
- SMTP service is responding
- Webmail is accessible
- Metrics endpoint is working
- Health checks are passing

## Go Unit Testing

### Running Go Tests

```bash
# Run all Go tests
go test -v ./...

# Run tests for specific package
go test -v ./internal/smtp

# Run tests with coverage
go test -v -cover ./...

# Run tests with race detection
go test -v -race ./...
```

### Test Structure

Go tests are organized by package:

- `cmd/elemta/` - Command-line interface tests
- `internal/smtp/` - SMTP server tests
- `internal/queue/` - Queue management tests
- `internal/auth/` - Authentication tests
- `internal/plugin/` - Plugin system tests
- `plugins/` - Individual plugin tests

## Testing Best Practices

### Before Testing

1. **Start Docker Deployment**
   ```bash
   docker compose up -d
   ```

2. **Verify Services**
   ```bash
   docker compose ps
   ```

3. **Check Logs**
   ```bash
   docker compose logs elemta-node0
   ```

### During Testing

1. **Use Appropriate Test Categories**
   - Use `--category security` for security testing
   - Use `--category smtp` for protocol testing
   - Use `--category e2e` for end-to-end testing

2. **Monitor Test Execution**
   - Use `--verbose` for detailed output
   - Use `--parallel` for faster execution
   - Use `--timeout` to adjust timeouts

3. **Handle Test Failures**
   - Check Docker container status
   - Review Elemta logs
   - Verify network connectivity
   - Check service dependencies

### After Testing

1. **Review Test Results**
   - Check pass/fail summary
   - Review failed test details
   - Analyze performance metrics

2. **Clean Up**
   - Stop Docker containers if needed
   - Clean up test data
   - Reset configuration if modified

## Troubleshooting

### Common Issues

#### Docker Containers Not Running
```bash
# Check container status
docker compose ps

# Start containers
docker compose up -d

# Check logs
docker compose logs
```

#### SMTP Service Not Responding
```bash
# Check if port is open
nc -zv localhost 2525

# Check Elemta logs
docker compose logs elemta-node0

# Restart Elemta container
docker compose restart elemta-node0
```

#### Test Timeouts
```bash
# Increase timeout
./run_centralized_tests.sh --timeout 60

# Run tests sequentially
./run_centralized_tests.sh  # (remove --parallel)

# Check system resources
docker stats
```

#### Authentication Failures
```bash
# Check LDAP service
docker compose logs openldap

# Verify user credentials
docker exec -it openldap ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w admin

# Check Elemta auth logs
docker compose logs elemta-node0 | grep -i auth
```

### Debug Mode

For detailed debugging, use verbose mode:

```bash
./run_centralized_tests.sh --verbose --test smtp-greeting
```

This will show:
- Detailed test execution steps
- SMTP command/response logging
- Error details and stack traces
- Timing information

## Continuous Integration

### GitHub Actions

The centralized test suite can be integrated into CI/CD pipelines:

```yaml
- name: Run Elemta Tests
  run: |
    docker compose up -d
    ./run_centralized_tests.sh --deployment docker-desktop --parallel
```

### Local CI Testing

```bash
# Full test suite
make test-all

# Quick smoke test
./run_centralized_tests.sh --category smtp --category auth

# Security-focused testing
./run_centralized_tests.sh --category security --verbose
```

## Performance Testing

### Load Testing

For performance testing, use the specialized scripts:

```bash
# Worker pool load testing
python3 test_worker_pool_load.py

# Rate limiting testing
python3 test_rate_limiting.py

# Memory exhaustion testing
python3 test_memory_exhaustion.py
```

### Monitoring During Tests

```bash
# Monitor Docker resources
docker stats

# Monitor Elemta metrics
curl http://localhost:8080/metrics

# Monitor logs
docker compose logs -f elemta-node0
```

## Security Testing

### Security Test Categories

The centralized test suite includes comprehensive security testing:

- **Command Injection Protection** - Tests SMTP command injection prevention
- **Buffer Overflow Protection** - Tests buffer overflow prevention
- **SQL Injection Protection** - Tests SQL injection prevention
- **Authentication Security** - Tests auth bypass prevention
- **Input Validation** - Tests input sanitization

### Running Security Tests

```bash
# Run all security tests
./run_centralized_tests.sh --category security

# Run specific security test
./run_centralized_tests.sh --test security-command-injection

# Run security tests with verbose output
./run_centralized_tests.sh --category security --verbose
```

## Conclusion

The Elemta testing infrastructure provides comprehensive coverage of all functionality through multiple testing approaches. The centralized test suite is the recommended approach for most testing scenarios, while individual test scripts provide specialized testing capabilities.

For questions or issues with testing, refer to the troubleshooting section or check the Elemta logs for detailed error information.