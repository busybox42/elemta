# Elemta Test Suite

This directory contains various test scripts for validating Elemta functionality.

## Test Files

### Authentication Tests
- `test_smtp_auth.py` - Tests SMTP authentication with LDAP
- `test_ldap_success.py` - Validates LDAP connection and user authentication
- `test_auth_chain.sh` - Shell script for testing the complete authentication chain

### SMTP Protocol Tests
- `test_smtp_complete.py` - Complete SMTP session testing
- `test_smtp_docker.py` - SMTP tests specifically for Docker environment

### Relay Control Tests
- `test_relay_control.py` - Tests internal network relay without authentication
- `test_external_relay.py` - Tests external relay behavior and authentication requirements

### Delivery Tests
- `test_lmtp_direct.py` - Direct LMTP delivery testing to Dovecot

## Running Tests

### Prerequisites
1. Ensure Elemta stack is running: `docker-compose up -d`
2. Wait for all services to be ready (LDAP, Dovecot, etc.)

### Individual Tests
```bash
# Test SMTP authentication
python3 tests/test_smtp_auth.py

# Test relay control
python3 tests/test_relay_control.py

# Test complete SMTP pipeline
python3 tests/test_smtp_complete.py
```

### Authentication Chain Test
```bash
# Full authentication chain test
bash tests/test_auth_chain.sh
```

## Test Requirements

- Python 3 with `smtplib` and `email` modules
- Access to Elemta SMTP server (localhost:2525)
- LDAP server with test users configured
- Dovecot LMTP server running

## Notes

These tests were developed during the implementation of:
- LDAP authentication integration
- Network-based relay control
- LMTP delivery pipeline
- Antivirus/antispam header insertion 