# SMTP Command Injection Prevention Test Suite

## Overview

This document describes comprehensive testing for SMTP command injection prevention in Elemta MTA. The tests validate that the new `CommandSecurityManager` properly prevents various types of injection attacks.

## Test Categories

### 1. SQL Injection Prevention

Tests that SQL injection patterns are blocked in SMTP commands:

```bash
# Test SQL injection in HELO command
echo "HELO example.com; DROP TABLE users" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test UNION SELECT injection
echo "HELO example.com UNION SELECT * FROM users" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test INSERT injection
echo "HELO example.com; INSERT INTO users VALUES ('hacker', 'password')" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation
```

### 2. Command Injection Prevention

Tests that shell command injection is blocked:

```bash
# Test semicolon injection
echo "HELO example.com; cat /etc/passwd" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test pipe injection
echo "HELO example.com | whoami" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test logical operator injection
echo "HELO example.com && rm -rf /" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test backtick injection
echo "HELO example.com\`id\`" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test command substitution
echo "HELO example.com\$(whoami)" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation
```

### 3. Script Injection Prevention

Tests that script injection is blocked:

```bash
# Test JavaScript injection
echo "HELO example.com<script>alert('xss')</script>" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test VBScript injection
echo "HELO example.com<vbscript>msgbox('xss')</vbscript>" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test event handler injection
echo "HELO example.com onload=alert('xss')" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation
```

### 4. Path Traversal Prevention

Tests that path traversal attacks are blocked:

```bash
# Test directory traversal
echo "HELO ../../../etc/passwd" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation

# Test Windows path traversal
echo "HELO ..\\..\\..\\windows\\system32\\config\\sam" | telnet localhost 2525
# Expected: 554 5.7.1 Command rejected: security violation
```

### 5. Control Character Prevention

Tests that control characters are blocked:

```bash
# Test null byte injection
echo -e "HELO example.com\x00" | telnet localhost 2525
# Expected: 500 5.5.2 Invalid control character

# Test other control characters
echo -e "HELO example.com\x01" | telnet localhost 2525
# Expected: 500 5.5.2 Invalid control character

# Test DEL character
echo -e "HELO example.com\x7F" | telnet localhost 2525
# Expected: 500 5.5.2 Invalid control character
```

### 6. CRLF Injection Prevention

Tests that CRLF injection is blocked:

```bash
# Test CRLF injection
echo -e "HELO example.com\r\nMAIL FROM:<test@example.com>" | telnet localhost 2525
# Expected: 554 5.7.1 Parameters rejected: security violation

# Test LF injection
echo -e "HELO example.com\nMAIL FROM:<test@example.com>" | telnet localhost 2525
# Expected: 554 5.7.1 Parameters rejected: security violation

# Test CR injection
echo -e "HELO example.com\rMAIL FROM:<test@example.com>" | telnet localhost 2525
# Expected: 554 5.7.1 Parameters rejected: security violation
```

### 7. Buffer Overflow Prevention

Tests that buffer overflow attacks are blocked:

```bash
# Test command line too long
python3 -c "print('HELO ' + 'A' * 600)" | telnet localhost 2525
# Expected: 500 5.5.2 Line too long

# Test parameter too long
python3 -c "print('MAIL FROM:<' + 'A' * 400 + '@example.com>')" | telnet localhost 2525
# Expected: 500 5.5.2 Parameters too long
```

### 8. Valid Commands

Tests that valid commands still work:

```bash
# Test valid HELO
echo "HELO example.com" | telnet localhost 2525
# Expected: 250 mail.example.com Hello example.com

# Test valid EHLO
echo "EHLO example.com" | telnet localhost 2525
# Expected: 250-mail.example.com Hello example.com (with extensions)

# Test valid MAIL FROM
echo "MAIL FROM:<test@example.com>" | telnet localhost 2525
# Expected: 250 2.1.0 Sender OK

# Test valid RCPT TO
echo "RCPT TO:<user@example.com>" | telnet localhost 2525
# Expected: 250 2.1.5 Recipient OK
```

## Automated Testing

### Unit Tests

Run the comprehensive unit test suite:

```bash
cd /home/alan/repos/elemta
go test -v ./internal/smtp -run TestCommandSecurityManager
```

### Fuzzing Tests

Run the fuzzing tests for comprehensive coverage:

```bash
cd /home/alan/repos/elemta
go test -fuzz FuzzCommandValidation ./internal/smtp
```

### Benchmark Tests

Run performance benchmarks:

```bash
cd /home/alan/repos/elemta
go test -bench=BenchmarkCommandValidation ./internal/smtp
```

## Expected Results

### Security Validation

All injection attempts should be blocked with appropriate error messages:

- **SQL Injection**: `554 5.7.1 Command rejected: security violation`
- **Command Injection**: `554 5.7.1 Command rejected: security violation`
- **Script Injection**: `554 5.7.1 Command rejected: security violation`
- **Path Traversal**: `554 5.7.1 Command rejected: security violation`
- **Control Characters**: `500 5.5.2 Invalid control character`
- **CRLF Injection**: `554 5.7.1 Parameters rejected: security violation`
- **Buffer Overflow**: `500 5.5.2 Line too long` or `500 5.5.2 Parameters too long`

### Valid Commands

All valid SMTP commands should work normally:

- **HELO**: `250 mail.example.com Hello example.com`
- **EHLO**: `250-mail.example.com Hello example.com` (with extensions)
- **MAIL FROM**: `250 2.1.0 Sender OK`
- **RCPT TO**: `250 2.1.5 Recipient OK`
- **DATA**: `354 Start mail input; end with <CRLF>.<CRLF>`
- **QUIT**: `221 2.0.0 mail.example.com closing connection`

### Performance

The security validation should not significantly impact performance:

- **Valid Command Processing**: < 1ms per command
- **Invalid Command Rejection**: < 2ms per command
- **Memory Usage**: Minimal overhead (< 1MB)

## Security Features

### Command Security Manager

The `CommandSecurityManager` provides:

1. **Comprehensive Validation**: 10-step validation process
2. **Pattern Blocking**: 25+ blocked patterns for various attack types
3. **Control Character Filtering**: Blocks all dangerous control characters
4. **Command Canonicalization**: Normalizes commands for consistent processing
5. **Parameter Validation**: Validates all command parameters
6. **Safe Logging**: Sanitizes commands for secure logging
7. **Performance Monitoring**: Tracks security statistics

### Configuration

Security can be configured via `CommandSecurityConfig`:

- **Max Command Length**: 512 characters (RFC 5321 compliant)
- **Max Parameter Length**: 320 characters (RFC 5321 compliant)
- **Strict Mode**: Enabled by default
- **Suspicious Command Logging**: Enabled by default
- **Blocked Patterns**: Comprehensive set of attack patterns

## Integration

The security system is integrated into:

1. **CommandHandler**: All commands validated before processing
2. **Session Management**: Security context maintained per session
3. **Logging System**: Commands sanitized for safe logging
4. **Error Handling**: Proper SMTP error codes returned
5. **Performance Monitoring**: Security metrics tracked

## Compliance

The implementation complies with:

- **RFC 5321**: SMTP protocol standards
- **OWASP Top 10**: A03:2021 Injection
- **CWE-89**: SQL Injection
- **CWE-78**: OS Command Injection
- **CWE-79**: Cross-site Scripting
- **CWE-22**: Path Traversal
- **NIST SP 800-53**: SI-10 Information Input Validation

## Conclusion

The SMTP command injection prevention system provides comprehensive protection against all major types of injection attacks while maintaining full SMTP protocol compliance and performance. All tests should pass, demonstrating that Elemta MTA is secure against command injection vulnerabilities.
