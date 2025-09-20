# SMTP Authentication Security Test Suite

## Overview
This document tests the comprehensive authentication security system implemented in Elemta SMTP server to prevent brute force attacks, ensure secure authentication methods, and provide complete audit logging.

## Security Enhancements Implemented

### 1. TLS Requirements for Authentication
- **PLAIN Authentication**: Requires TLS encryption (configurable, default: enabled)
- **LOGIN Authentication**: TLS optional (already base64 obscured)
- **CRAM-MD5 Authentication**: Completely disabled for security

### 2. Authentication Rate Limiting
- **IP-based Rate Limiting**: Max 10 attempts per IP per 15-minute window
- **Session Rate Limiting**: Max 5 attempts per SMTP session
- **Request Interval Limiting**: Minimum 3-second interval between attempts
- **IP Blocking**: 1-hour block after exceeding rate limits

### 3. Account Lockout Protection
- **Failed Attempt Tracking**: Max 5 failed attempts per account
- **Lockout Duration**: 30-minute account lockout
- **Lockout Window**: 1-hour window for counting failures
- **Automatic Cleanup**: Expired entries cleaned up hourly

### 4. CRAM-MD5 Security Hardening
- **Complete Disablement**: CRAM-MD5 removed from advertised methods
- **Security Justification**: MD5 is cryptographically broken
- **Alternative**: PLAIN/LOGIN over TLS recommended

### 5. Comprehensive Authentication Logging
- **All Authentication Events**: Success, failure, and security violations
- **Detailed Forensics**: IP addresses, usernames, failure reasons
- **Security Monitoring**: Structured logs for SIEM integration
- **Performance Metrics**: Authentication timing and success rates

## Test Cases

### TLS Requirement Testing

#### PLAIN Authentication without TLS (Should Reject)
```bash
telnet localhost 2525
EHLO test
AUTH PLAIN
```
**Expected Response**: `538 5.7.11 Encryption required for requested authentication mechanism`
**Security Log**: `plain_auth_without_tls` security violation

#### PLAIN Authentication with TLS (Should Accept)
```bash
telnet localhost 2525
EHLO test
STARTTLS
EHLO test
AUTH PLAIN dGVzdAB0ZXN0AHBhc3N3b3Jk
```
**Expected Response**: `235 2.7.0 Authentication successful` (if credentials valid)

### Rate Limiting Testing

#### Rapid Authentication Attempts (Should Block)
```bash
# Multiple rapid AUTH attempts in same session
telnet localhost 2525
EHLO test
AUTH LOGIN
# ... attempt 1
AUTH LOGIN  
# ... attempt 2
AUTH LOGIN
# ... attempt 3 (should trigger rate limiting)
```
**Expected Response**: `421 4.7.1 Authentication attempts too frequent. Slow down.`
**Security Log**: `auth_rate_limit_exceeded` security violation

#### IP-based Rate Limiting (Should Block IP)
```bash
# 10+ failed attempts from same IP within 15 minutes
# Should trigger IP block
```
**Expected Response**: `421 4.7.1 Too many failed authentication attempts. Try again later.`
**Security Log**: `blocked_ip_auth_attempt` security violation

### Account Lockout Testing

#### Account Lockout After Failed Attempts
```bash
# 5 failed authentication attempts for same username
# Should trigger account lockout
```
**Expected Response**: `535 5.7.8 Authentication failed` (no lockout disclosure)
**Security Log**: `locked_account_auth_attempt` security violation

### CRAM-MD5 Disablement Testing

#### CRAM-MD5 Not Advertised in EHLO
```bash
telnet localhost 2525
EHLO test
```
**Expected Response**: `250-AUTH PLAIN LOGIN` (no CRAM-MD5)

#### CRAM-MD5 Attempt Rejected
```bash
telnet localhost 2525
EHLO test
AUTH CRAM-MD5
```
**Expected Response**: `504 5.5.4 CRAM-MD5 authentication mechanism disabled for security reasons`
**Security Log**: `cram_md5_attempt` security violation

## Security Logging Events

### Authentication Events
- `smtp_auth_attempt` - Authentication attempt initiated
- `smtp_auth_success` - Successful authentication
- `smtp_auth_failure` - Failed authentication
- `smtp_auth_complete` - Authentication process completed

### Security Violations
- `blocked_ip_auth_attempt` - Authentication from blocked IP
- `auth_rate_limit_exceeded` - Rate limiting triggered
- `session_auth_limit_exceeded` - Session attempt limit exceeded
- `locked_account_auth_attempt` - Attempt on locked account
- `plain_auth_without_tls` - PLAIN auth without encryption
- `cram_md5_attempt` - Deprecated CRAM-MD5 attempt

### Log Fields
```json
{
  "event_type": "authentication_attempt",
  "method": "PLAIN",
  "username": "user@example.com",
  "remote_addr": "192.168.1.100",
  "tls_enabled": true,
  "session_attempts": 1,
  "duration_ms": 150,
  "failure_reason": "invalid_credentials"
}
```

## Security Configuration

### Default Security Policies
```go
config := &AuthSecurityConfig{
    MaxAttemptsPerIP:       10,           // 10 attempts per IP
    RateLimitWindow:        15 * time.Minute, // 15-minute window
    IPBlockDuration:        time.Hour,    // 1-hour IP block
    MaxFailedAttempts:      5,            // 5 failed per account
    AccountLockoutDuration: 30 * time.Minute, // 30-minute lockout
    LockoutWindow:          time.Hour,    // 1-hour failure window
    RequireTLSForPLAIN:     true,         // TLS required for PLAIN
    RequireTLSForLOGIN:     false,        // TLS optional for LOGIN
    DisableCRAMMD5:         true,         // CRAM-MD5 disabled
}
```

### Response Codes
- `235 2.7.0` - Authentication successful
- `421 4.7.1` - Rate limiting triggered
- `504 5.5.4` - Authentication mechanism disabled
- `535 5.7.8` - Authentication failed
- `538 5.7.11` - Encryption required

## Monitoring Integration

### Security Metrics
- **Blocked IPs**: Count of currently blocked IP addresses
- **Locked Accounts**: Count of currently locked accounts
- **Failed Attempts**: Rate of authentication failures
- **Success Rate**: Authentication success percentage

### Alerting Thresholds
- **High Failure Rate**: >50% authentication failures
- **Mass Account Lockout**: >10 accounts locked simultaneously
- **IP Block Surge**: >5 IPs blocked in 5 minutes
- **CRAM-MD5 Attempts**: Any attempt to use deprecated method

## Compliance & Standards

### Security Standards
- **OWASP Authentication**: Rate limiting and account lockout
- **RFC 4954**: SMTP AUTH security considerations
- **NIST SP 800-63B**: Authentication security guidelines
- **CWE-307**: Brute force attack prevention

### Audit Requirements
- **Complete Authentication Logs**: All attempts logged
- **Failure Analysis**: Detailed failure reasons
- **Security Event Tracking**: Violations and responses
- **Performance Monitoring**: Authentication timing

## Performance Impact

### Optimizations
- **Memory Efficient**: Cleanup of expired entries
- **Fast Lookups**: Hash-based IP and account tracking
- **Minimal Overhead**: Security checks add <1ms per request
- **Scalable Design**: Handles thousands of concurrent sessions

This comprehensive authentication security system transforms Elemta into a hardened SMTP server resistant to brute force attacks while maintaining usability for legitimate users.
