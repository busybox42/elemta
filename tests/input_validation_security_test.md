# SMTP Input Validation Security Test Suite

## Overview
This document tests the comprehensive input validation system implemented in Elemta SMTP server to prevent injection attacks and ensure RFC compliance.

## Security Enhancements Implemented

### 1. RFC 5322 Email Address Validation
- **Enhanced Function**: `validateEmailAddressDetailed()`
- **Features**:
  - Strict RFC 5322 compliance with length limits (320 chars total, 64 local, 255 domain)
  - Command injection prevention (shell metacharacters, path traversal)
  - SQL injection pattern detection
  - Domain spoofing protection
  - Comprehensive character validation

### 2. SMTP Command Validation
- **Function**: `validateSMTPCommand()`
- **Features**:
  - RFC 5321 length limits (512 octets per command)
  - Control character filtering
  - Command injection prevention
  - SQL injection detection
  - SMTP command format validation
  - Input sanitization

### 3. Authentication Input Validation
- **Functions**: `validateBase64Input()`, `validateAuthenticationData()`
- **Features**:
  - Base64 format validation
  - Decoded data length limits
  - Injection pattern detection in credentials
  - Support for AUTH PLAIN, LOGIN, and CRAM-MD5

## Test Cases

### Email Address Validation Tests

#### Valid Addresses (Should Accept)
```
test@example.com
user.name@domain.org
valid+tag@sub.domain.com
```

#### Invalid Addresses (Should Reject with Security Logging)

**Command Injection Attempts:**
```
test@example.com; rm -rf /
user@domain.com | cat /etc/passwd
test@example.com && whoami
user@domain.com$(cat /etc/shadow)
```
Expected: `command_injection_attempt` security violation

**SQL Injection Attempts:**
```
admin'--@example.com
test@example.com'; DROP TABLE users; --
user@domain.com UNION SELECT * FROM passwords
```
Expected: `sql_injection_attempt` security violation

**Buffer Overflow Attempts:**
```
[Very long email over 320 characters]
```
Expected: `potential_buffer_overflow` security violation

**Domain Spoofing:**
```
test@..example.com
user@example..com
admin@.example.com
```
Expected: `domain_spoofing_attempt` security violation

### SMTP Command Validation Tests

#### Valid Commands (Should Accept)
```
EHLO example.com
MAIL FROM:<test@example.com>
RCPT TO:<user@domain.com>
DATA
AUTH PLAIN
```

#### Invalid Commands (Should Reject with Security Logging)

**Command Injection Attempts:**
```
EHLO example.com; ls -la
MAIL FROM:<test@example.com> | cat /etc/passwd
RCPT TO:<user@domain.com> && rm file.txt
AUTH PLAIN $(whoami)
```
Expected: `command_injection_attempt` security violation

**SQL Injection Attempts:**
```
EHLO example.com'; DROP TABLE sessions; --
MAIL FROM:<test@example.com> UNION SELECT password FROM users
```
Expected: `sql_injection_attempt` security violation

**Buffer Overflow Attempts:**
```
[Command over 512 characters]
```
Expected: `buffer_overflow_attempt` security violation

### Authentication Validation Tests

#### Valid Authentication (Should Accept)
```
AUTH PLAIN dGVzdAB0ZXN0AHBhc3N3b3Jk  (test\0test\0password)
AUTH LOGIN
334 VXNlcm5hbWU6
dGVzdA==  (test)
334 UGFzc3dvcmQ6
cGFzc3dvcmQ=  (password)
```

#### Invalid Authentication (Should Reject with Security Logging)

**Base64 Injection Attempts:**
```
AUTH PLAIN dGVzdAB0ZXN0AGBybSAtcmYgL2A=  (test\0test\0`rm -rf /`)
AUTH PLAIN dGVzdABhZG1pbictLQBwYXNz  (test\0admin'--\0pass)
```
Expected: `command_injection_attempt` or `sql_injection_attempt`

**Invalid Base64:**
```
AUTH PLAIN invalid@base64!
AUTH PLAIN dGVzdA===  (invalid padding)
```
Expected: `base64_decode_error`

**Buffer Overflow:**
```
AUTH PLAIN [very long base64 string over 4096 chars]
```
Expected: `buffer_overflow_attempt`

## Security Logging Events

The system logs detailed security events for monitoring:

### Event Types
- `invalid_command_input` - Malformed SMTP commands
- `invalid_mail_from_address` - Malicious sender addresses
- `invalid_rcpt_to_address` - Malicious recipient addresses
- `invalid_auth_plain_input` - AUTH PLAIN injection attempts
- `invalid_auth_username_input` - AUTH LOGIN username attacks
- `invalid_auth_password_input` - AUTH LOGIN password attacks

### Threat Classifications
- `command_injection_attempt` - Shell command injection
- `sql_injection_attempt` - SQL injection patterns
- `buffer_overflow_attempt` - Excessive length inputs
- `domain_spoofing_attempt` - Malformed domains

### Log Fields
- `error_type` - Specific validation failure
- `error_message` - Human-readable description
- `security_threat` - Threat classification
- `remote_addr` - Client IP address
- `raw_command` - Original input (truncated)

## Response Codes

The server sends appropriate SMTP error responses:

- `554 5.7.1` - Security violations (injection attempts)
- `501 5.1.7` - Invalid address format
- `501 5.5.2` - Invalid command syntax/encoding
- `500 5.5.2` - Command too long

## Monitoring Integration

Security events are structured for easy integration with:
- SIEM systems (Elasticsearch/Kibana)
- Log aggregation platforms
- Security monitoring tools
- Alerting systems

## Compliance

This implementation ensures:
- **RFC 5321** SMTP command compliance
- **RFC 5322** email address format compliance  
- **OWASP** injection prevention best practices
- **CWE-74** command injection prevention
- **CWE-89** SQL injection prevention
- **CWE-120** buffer overflow prevention

## Performance Impact

The validation system is designed for minimal performance impact:
- Early validation prevents processing malicious inputs
- Efficient pattern matching algorithms
- Structured logging for security analysis
- Graceful error handling

This comprehensive input validation system transforms Elemta into a hardened, security-focused SMTP server suitable for production environments.
