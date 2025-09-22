# Elemta Testing Guide

This document describes the comprehensive testing framework for the Elemta SMTP server.

## Overview

The Elemta test suite consists of a comprehensive Python test script that consolidates all existing tests into a single, configurable test runner. This allows for easy validation of the SMTP server functionality after any changes.

## Test Scripts

### Primary Test Script: `test_elemta_comprehensive.py`

This is the main test script that consolidates all Elemta tests:

- **Basic SMTP Tests**: Core functionality (EHLO, MAIL, RCPT, DATA, QUIT)
- **Authentication Tests**: AUTH PLAIN and LOGIN mechanisms
- **Security Tests**: Buffer overflow, injection, and validation protection
- **Content Tests**: Email content validation and sanitization
- **Memory Tests**: Large message handling and resource management
- **Rate Limiting Tests**: Connection and message rate limiting
- **Logging Tests**: Email and security event logging
- **Integration Tests**: End-to-end email delivery

### Test Runner Script: `run_tests.sh`

A shell script wrapper that provides:
- Docker container health checking
- Service readiness verification
- Colored output and better formatting
- Command-line argument parsing

## Usage

### Running All Tests

```bash
# Using Python script directly
python3 test_elemta_comprehensive.py

# Using shell script wrapper
./run_tests.sh
```

### Running Specific Test Categories

```bash
# Run only security tests
python3 test_elemta_comprehensive.py --category security
./run_tests.sh --category security

# Run only basic SMTP tests
python3 test_elemta_comprehensive.py --category basic
./run_tests.sh --category basic

# Run only authentication tests
python3 test_elemta_comprehensive.py --category auth
./run_tests.sh --category auth
```

### Running Specific Tests

```bash
# Run a specific test
python3 test_elemta_comprehensive.py --test smtp_greeting
./run_tests.sh --test smtp_greeting

# Run multiple specific tests
python3 test_elemta_comprehensive.py --test smtp_greeting --test smtp_ehlo
```

### Listing Available Tests

```bash
# List all available tests and categories
python3 test_elemta_comprehensive.py --list
./run_tests.sh --list
```

### Testing Remote Servers

```bash
# Test a remote SMTP server
python3 test_elemta_comprehensive.py --host 192.168.1.100 --port 25
./run_tests.sh --host 192.168.1.100 --port 25
```

## Test Categories

### Basic Tests (`--category basic`)
- `smtp_greeting`: SMTP server greeting
- `smtp_ehlo`: EHLO command
- `smtp_mail_rcpt`: MAIL FROM and RCPT TO
- `smtp_data`: DATA command and message
- `smtp_quit`: QUIT command

### Authentication Tests (`--category auth`)
- `auth_plain`: AUTH PLAIN mechanism
- `auth_login`: AUTH LOGIN mechanism
- `auth_invalid`: Invalid authentication handling

### Security Tests (`--category security`)
- `security_buffer_overflow`: Buffer overflow protection
- `security_sql_injection`: SQL injection protection
- `security_command_injection`: Command injection protection
- `security_xss`: XSS protection
- `security_null_bytes`: Null byte protection
- `security_long_commands`: Long command protection

### Content Tests (`--category content`)
- `content_legitimate`: Legitimate email content acceptance
- `content_malicious_headers`: Malicious header detection
- `content_dangerous_attachments`: Dangerous attachment detection
- `content_unicode_attacks`: Unicode attack detection

### Memory Tests (`--category memory`)
- `memory_large_message`: Large message handling
- `memory_concurrent_connections`: Concurrent connection handling
- `memory_rapid_commands`: Rapid command handling

### Rate Limiting Tests (`--category rate`)
- `rate_connection_limits`: Connection rate limiting
- `rate_message_limits`: Message rate limiting

### Logging Tests (`--category logging`)
- `logging_email_events`: Email event logging
- `logging_security_events`: Security event logging

### Integration Tests (`--category integration`)
- `integration_end_to_end`: End-to-end email delivery
- `integration_queue_processing`: Queue processing

## Prerequisites

### Docker Deployment

The tests are designed to run against the Docker deployment:

```bash
# Start the Docker deployment
docker compose up -d

# Verify all services are running
docker compose ps
```

### Configuration

The test suite requires a permissive configuration for testing. The `config/elemta.toml` file should have:

```toml
[resources]
max_connections_per_ip = 1000  # Very permissive for testing
max_requests_per_window = 10000  # Very permissive for testing
```

## Test Results

### Success Criteria

- **Security Tests**: Should all pass (100% success rate)
- **Basic Tests**: Should mostly pass (80%+ success rate)
- **Authentication Tests**: Should pass for valid credentials
- **Content Tests**: May have some failures depending on validation strictness
- **Memory Tests**: Should handle large messages gracefully
- **Rate Limiting Tests**: May be skipped if rate limiter plugin not implemented

### Exit Codes

- `0`: All tests passed
- `1`: Some tests failed or error occurred

## Maintenance

### Adding New Tests

1. **Add test case to `test_elemta_comprehensive.py`**:
   ```python
   def _test_new_feature(self) -> TestResult:
       """Test new feature"""
       try:
           # Test implementation
           return TestResult.PASS
       except:
           return TestResult.FAIL
   ```

2. **Register the test case**:
   ```python
   TestCase("new_feature", "category", "Description", self._test_new_feature)
   ```

3. **Update this documentation** with the new test information

### Updating Test Categories

When adding new features, update the test categories and ensure the comprehensive test suite covers all functionality.

### Configuration Updates

When changing server configuration, ensure the test configuration remains permissive enough for testing while still validating security features.

## Troubleshooting

### Common Issues

1. **Rate Limiting Blocking Tests**:
   - Increase `max_requests_per_window` in `config/elemta.toml`
   - Restart Docker container: `docker compose restart elemta`

2. **Connection Refused**:
   - Verify Docker container is running: `docker compose ps`
   - Check service logs: `docker compose logs elemta`

3. **Authentication Failures**:
   - Verify LDAP service is running: `docker compose ps elemta-ldap`
   - Check authentication configuration in `config/elemta.toml`

4. **Test Timeouts**:
   - Increase timeout values in test script
   - Check server performance and resource usage

### Debug Mode

For debugging specific tests, you can modify the test script to add more verbose output or run individual test functions directly.

## Integration with Development Workflow

### Pre-commit Testing

Run the comprehensive test suite before committing changes:

```bash
# Run all tests
./run_tests.sh

# Run only security tests for security-related changes
./run_tests.sh --category security
```

### CI/CD Integration

The test suite can be integrated into CI/CD pipelines:

```bash
# In CI/CD pipeline
docker compose up -d
sleep 30  # Wait for services to start
./run_tests.sh --category security
```

### Feature Validation

When implementing new features, add corresponding tests and run the relevant test categories to ensure functionality works correctly.

## Future Enhancements

- **Performance Testing**: Add performance benchmarks
- **Load Testing**: Add concurrent user simulation
- **Integration Testing**: Add tests for external service integration
- **Automated Reporting**: Generate test reports and metrics
- **Test Data Management**: Centralized test data and fixtures
