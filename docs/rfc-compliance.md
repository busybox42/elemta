# RFC Compliance Documentation

This document outlines the SMTP server's compliance with relevant RFC standards, including implementation status, known limitations, and planned improvements.

## Supported RFC Standards

### Core SMTP Protocol

#### RFC 5321 - Simple Mail Transfer Protocol
**Status: ✅ Fully Implemented**

| Section | Feature | Implementation | Code Location |
|---------|---------|----------------|---------------|
| §2.3.7 | Line Ending Validation | ✅ CRLF validation | `session_data.go:155` |
| §2.4 | SMTP Commands | ✅ HELO, EHLO, MAIL, RCPT, DATA, RSET, NOOP, QUIT | `session_commands.go` |
| §3.3 | Mail Transactions | ✅ Complete transaction flow | `session_data.go` |
| §4.1.3 | Hostname Validation | ✅ Domain name validation | `session_commands.go:1327` |
| §4.5.2 | Dot-Stuffing Transparency | ✅ Transparent dot-stuffing | `session_data.go:251` |
| §4.5.3.1.6 | Line Length Limits | ✅ 1000 octet limit | `session_data.go:585` |
| §4.5.4 | Reply Codes | ✅ Standard SMTP reply codes | `session_commands.go` |

#### RFC 5322 - Internet Message Format
**Status: ✅ Mostly Implemented**

| Section | Feature | Implementation | Code Location |
|---------|---------|----------------|---------------|
| §2.2 | Header Fields | ✅ Header parsing and validation | `session_data.go:993` |
| §3.6 | Required Headers | ✅ From, Date, etc. validation | `session_data.go:993` |
| §2.1.1 | Line Length Limits | ✅ 998 characters per line | `session_data.go:596` |

### Extended SMTP Features

#### RFC 1870 - SMTP Service Extension for Message Size
**Status: ✅ Fully Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| SIZE parameter in MAIL FROM | ✅ Parsing and validation | `session_commands.go` |
| Size limit enforcement | ✅ Message size checking | `session_data.go` |
| Buffer optimization | ✅ Pre-allocation based on SIZE | `session_data.go` |

#### RFC 2034 - SMTP Service Extension for Returning Enhanced Error Codes
**Status: ✅ Fully Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| ENHANCEDSTATUSCODES in EHLO | ✅ Advertised | `session_commands.go` |
| Enhanced status codes in replies | ✅ All replies use `X.Y.Z` format | `session_commands.go` |

#### RFC 3030 - SMTP Service Extension for Chunking (BDAT)
**Status: ✅ Fully Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| CHUNKING in EHLO | ✅ Advertised | `session_commands.go` |
| BDAT command handler | ✅ Single/multi-chunk transfer | `session_commands.go` |
| BDAT LAST processing | ✅ Final chunk triggers delivery | `session_commands.go` |
| BDAT 0 LAST (zero-size finalize) | ✅ Supported | `session_commands.go` |
| MaxSize enforcement for BDAT | ✅ Accumulated size checking | `session_data.go` |
| BDAT/DATA desync prevention | ✅ DATA rejected during BDAT | `session_state.go` |
| RSET clears BDAT state | ✅ Buffer and counters reset | `session_data.go` |

#### RFC 3461 - SMTP DSN (Delivery Status Notifications)
**Status: 🔄 Partially Implemented (Parsing Only)**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| DSN in EHLO | ✅ Advertised | `session_commands.go` |
| MAIL FROM RET=FULL\|HDRS | ✅ Parsed and stored | `session_commands.go` |
| MAIL FROM ENVID | ✅ Parsed and stored | `session_commands.go` |
| RCPT TO NOTIFY | ✅ Parsed and validated | `session_commands.go` |
| RCPT TO ORCPT | ✅ Parsed and stored | `session_commands.go` |
| DSN params stored as queue annotations | ✅ Via SetAnnotation | `session_data.go` |
| Bounce generation | ❌ Deferred to future phase | - |

#### RFC 6531 - SMTPUTF8 Extension
**Status: 🔄 Partially Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| SMTPUTF8 parameter | ✅ Supported in EHLO | `session_commands.go` |
| UTF-8 address handling | 🔄 Limited support | `session_commands.go` |
| Internationalized headers | ❌ Not implemented | - |

#### RFC 2920 - SMTP Service Extension for Command Pipelining
**Status: ✅ Fully Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| PIPELINING in EHLO | ✅ Advertised | `session_commands.go` |
| Response batching | ✅ Flush only when reader buffer empty | `session.go` |
| Special command handling | ✅ STARTTLS/AUTH/QUIT/DATA flush immediately | `session_commands.go`, `session_auth.go` |

### Security and Authentication

#### RFC 4954 - SMTP Service Extension for Authentication
**Status: ✅ Fully Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| AUTH command | ✅ PLAIN, LOGIN | `session_auth.go` |
| Authentication mechanisms | ✅ PLAIN, LOGIN | `session_auth.go:201` |
| TLS requirement | ✅ AUTH over TLS enforcement | `session_auth.go:205` |

#### RFC 3207 - SMTP Service Extension for Secure SMTP over TLS
**Status: ✅ Fully Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| STARTTLS command | ✅ TLS upgrade | `session_commands.go:414` |
| Certificate validation | ✅ X.509 validation | `tls.go` |
| Cipher suite configuration | ✅ Configurable ciphers | `tls.go:319` |

#### RFC 8689 - SMTP REQUIRETLS Extension
**Status: 🔄 Partially Implemented (Parsing Only)**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| REQUIRETLS in EHLO (TLS only) | ✅ Conditionally advertised | `session_commands.go` |
| REQUIRETLS in MAIL FROM | ✅ Parsed and stored | `session_commands.go` |
| TLS requirement enforcement (530 if no TLS) | ✅ Rejects without TLS | `session_commands.go` |
| Stored as queue annotation | ✅ Via SetAnnotation | `session_data.go` |
| Delivery-side TLS enforcement | ❌ Deferred to future phase | - |

### Network and Delivery

#### RFC 1918 - Private Address Allocation
**Status: ✅ Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| Private network detection | ✅ RFC 1918 ranges | `network.go:8` |
| Internal/external classification | ✅ Network type detection | `network.go` |

#### RFC 4193 - IPv6 Unique Local Addresses
**Status: ✅ Implemented**

| Feature | Implementation | Code Location |
|---------|----------------|---------------|
| IPv6 ULA detection | ✅ RFC 4193 ranges | `network.go:8` |
| IPv6 address validation | ✅ IPv6 literal handling | `session_commands.go:614` |

## Known Limitations

### Protocol Limitations

1. **DSN Bounce Generation**
   - DSN parameters (RET, ENVID, NOTIFY, ORCPT) are parsed and stored as queue annotations
   - Actual bounce/notification message generation is not yet implemented

2. **REQUIRETLS Delivery Enforcement**
   - REQUIRETLS is parsed at submission time and stored as a queue annotation
   - Delivery-side enforcement (requiring TLS for outbound connections) is not yet implemented

3. **SMTPUTF8 Limitations**
   - Internationalized email addresses have limited support
   - UTF-8 header validation not fully implemented
   - IDN (Internationalized Domain Names) limited support

### Security Considerations

1. **Enhanced Validation**
   - Some security checks are conservative and may reject valid edge cases
   - Memory limits are enforced but may be too restrictive for large legitimate emails

2. **Rate Limiting**
   - Basic rate limiting implemented but not per-RFC specifications
   - Connection throttling not fully compliant with RFC 5321 timing requirements

## Planned Compliance Improvements

### Short Term

1. **DSN Bounce Generation (RFC 3461)**
   - Generate bounce/delay/success notification messages based on stored DSN parameters
   - Deliver notifications to envelope sender

2. **REQUIRETLS Delivery Enforcement (RFC 8689)**
   - Check REQUIRETLS annotation before outbound delivery
   - Require TLS for downstream connections when set

3. **Complete SMTPUTF8 Implementation (RFC 6531)**
   - Full UTF-8 address validation
   - Internationalized header support
   - IDN (Internationalized Domain Names) support

### Medium Term

1. **Enhanced Security Extensions**
   - MTA-STS (RFC 8461) validation
   - DANE (RFC 7671) certificate validation

2. **Advanced Message Handling**
   - Message submission (RFC 6409) separation
   - BURL extension (RFC 4468) for message retrieval

### Long Term

1. **Full Internationalization**
   - Complete SMTPUTF8 ecosystem
   - Unicode normalization
   - Internationalized error messages

2. **Advanced Protocol Features**
   - Future SMTP extensions
   - Experimental protocol features
   - Performance optimizations

## Testing and Validation

### Automated Testing

- **SMTP Unit Tests**: `internal/smtp/*_test.go` - Core protocol compliance
- **BDAT Tests**: `internal/smtp/session_bdat_test.go` - CHUNKING/BDAT compliance
- **DSN Tests**: `internal/smtp/session_dsn_test.go` - DSN and REQUIRETLS compliance
- **Pipelining Tests**: `internal/smtp/session_pipelining_test.go` - RFC 2920 pipelining compliance
- **Integration Tests**: `tests/` - End-to-end validation via Docker

### Manual Testing

- **Protocol Validation**: Manual testing with various SMTP clients
- **Compliance Testing**: Third-party SMTP compliance tools
- **Interoperability Testing**: Testing with different mail servers

### Continuous Integration

- **Automated RFC Tests**: CI pipeline includes RFC compliance checks
- **Regression Testing**: Automated tests prevent compliance regressions
- **Performance Testing**: Load testing with RFC compliance validation

## Reference Implementation

This SMTP server aims to be a reference implementation for:

1. **Modern Go SMTP Servers**: Demonstrating best practices for SMTP implementation
2. **RFC Compliance**: Showing proper interpretation and implementation of SMTP standards
3. **Security**: Implementing secure defaults and modern security practices
4. **Performance**: Optimizing for high-throughput email processing

## Contributing to RFC Compliance

When contributing to the SMTP server:

1. **Reference RFC Sections**: Always cite specific RFC sections for protocol changes
2. **Add Tests**: Include tests for new RFC-compliant features
3. **Update Documentation**: Keep this document current with implementation changes
4. **Consider Security**: Ensure new features maintain security standards

## Additional Resources

- [IANA SMTP Service Extensions Registry](https://www.iana.org/assignments/smtp-extensions/)
- [RFC Index - Mail and Directory Services](https://www.rfc-editor.org/rfc/std-index.html)
- [SMTP Protocol Overview](https://tools.ietf.org/html/rfc5321)
- [Internet Message Format](https://tools.ietf.org/html/rfc5322)

---

*Last Updated: 2026-02-06*
*Version: 1.1*
