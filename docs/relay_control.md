# SMTP Relay Control

Elemta implements intelligent relay control that distinguishes between internal and external network connections, providing secure email relay while maintaining ease of use for internal applications.

## Overview

The relay control system implements the following security model:

1. **Local Domain Delivery**: Always allowed from any source
2. **Internal Network Relay**: Allowed without authentication
3. **External Network Relay**: Requires authentication

This approach prevents open relay abuse while allowing internal applications and services to send email freely.

## Network Classification

### Internal/Private Networks

Elemta automatically recognizes the following private network ranges as internal:

- **IPv4 Private Networks**:
  - `10.0.0.0/8` (Class A private)
  - `172.16.0.0/12` (Class B private) 
  - `192.168.0.0/16` (Class C private)
  - `127.0.0.0/8` (Loopback)
  - `169.254.0.0/16` (Link-local)

- **IPv6 Private Networks**:
  - `::1/128` (IPv6 loopback)
  - `fc00::/7` (IPv6 unique local addresses)
  - `fe80::/10` (IPv6 link-local)
  - `::ffff:0:0/96` (IPv4-mapped IPv6 addresses)

### External/Public Networks

All other IP addresses are considered external and require authentication for relay operations.

## Configuration

### Basic Configuration

```toml
[server]
hostname = "mail.example.com"
listen = ":25"

# Local domains for which we accept mail directly
local_domains = ["example.com", "localhost", "mail.example.com"]

# Additional IP addresses/networks allowed to relay (optional)
allowed_relays = ["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

[auth]
enabled = true
required = false  # Authentication required for external connections only
```

### Local Domains

Configure domains that your server handles locally:

```toml
local_domains = [
    "example.com",
    "mail.example.com", 
    "internal.company.com"
]
```

Messages to these domains are always accepted regardless of the source.

### Allowed Relays (Optional)

You can explicitly allow additional IP addresses or networks:

```toml
allowed_relays = [
    "127.0.0.1",           # Localhost
    "::1",                 # IPv6 localhost
    "10.0.0.0/8",          # Class A private
    "172.16.0.0/12",       # Class B private
    "192.168.0.0/16",      # Class C private
    "203.0.113.0/24"       # Specific external network
]
```

Note: Private networks are automatically allowed, so you typically don't need to list them explicitly.

## Relay Decision Logic

When a client attempts to send email, Elemta follows this decision tree:

```
1. Is the recipient domain local?
   ├─ YES → ALLOW (local delivery)
   └─ NO → Continue to step 2

2. Is the client IP from a private network?
   ├─ YES → ALLOW (internal relay)
   └─ NO → Continue to step 3

3. Is the client IP in allowed_relays?
   ├─ YES → ALLOW (explicitly allowed)
   └─ NO → Continue to step 4

4. Is the client authenticated?
   ├─ YES → ALLOW (authenticated relay)
   └─ NO → DENY (relay access denied)
```

## Security Benefits

### Prevents Open Relay Abuse

- External connections cannot relay without authentication
- Protects against spam and abuse
- Maintains email reputation

### Enables Internal Applications

- Internal services can send email without configuration
- No need to manage credentials for every application
- Simplifies deployment and maintenance

### Flexible Authentication

- External users can authenticate to send email
- Supports multiple authentication backends (LDAP, file, database)
- Maintains security boundaries

## Example Scenarios

### Scenario 1: Internal Application Sending Email

```
Source: 192.168.1.100 (internal)
From: app@example.com
To: user@external.com
Auth: None
Result: ✓ ALLOWED (internal network relay)
```

### Scenario 2: External User Sending Email

```
Source: 203.0.113.50 (external)
From: user@external.com  
To: recipient@another-domain.com
Auth: None
Result: ✗ DENIED (relay access denied)
```

### Scenario 3: Authenticated External User

```
Source: 203.0.113.50 (external)
From: user@external.com
To: recipient@another-domain.com  
Auth: user@example.com / password
Result: ✓ ALLOWED (authenticated relay)
```

### Scenario 4: Local Domain Delivery

```
Source: 203.0.113.50 (external)
From: sender@anywhere.com
To: user@example.com
Auth: None
Result: ✓ ALLOWED (local domain delivery)
```

## Testing Relay Control

Use the provided test scripts to verify relay behavior:

```bash
# Test basic relay functionality
python3 test_relay_control.py

# Test and explain relay behavior
python3 test_external_relay.py
```

## Monitoring and Logging

Elemta logs relay decisions for monitoring and debugging:

```json
{
  "level": "DEBUG",
  "msg": "allowing internal network relay",
  "client_ip": "192.168.1.100",
  "domain": "external.com"
}
```

```json
{
  "level": "WARN", 
  "msg": "relay denied",
  "recipient": "user@external.com",
  "client_ip": "203.0.113.50",
  "authenticated": false,
  "is_internal": false
}
```

## Best Practices

### Network Security

1. **Firewall Configuration**: Ensure SMTP ports are properly firewalled
2. **Network Segmentation**: Use VLANs to control internal network access
3. **Monitoring**: Monitor relay attempts and authentication failures

### Authentication

1. **Strong Passwords**: Enforce strong password policies
2. **Rate Limiting**: Implement rate limiting for authentication attempts
3. **Account Management**: Regularly audit user accounts

### Configuration

1. **Minimal Local Domains**: Only configure domains you actually handle
2. **Explicit Allowed Relays**: Be specific about additional allowed networks
3. **Regular Review**: Periodically review and update configuration

## Troubleshooting

### Common Issues

**Internal applications can't send email**:
- Verify the application is on a private network
- Check firewall rules
- Review server logs for relay decisions

**External users can't send email**:
- Ensure authentication is properly configured
- Verify user credentials
- Check authentication backend connectivity

**Unexpected relay denials**:
- Verify network classification (private vs public)
- Check allowed_relays configuration
- Review local_domains settings

### Debug Logging

Enable debug logging to see relay decisions:

```toml
[logging]
level = "debug"
```

This will show detailed information about each relay decision in the logs.

## Migration from Simple Relay Lists

If migrating from a simple `allowed_relays` configuration:

1. **Identify Internal Networks**: List your private network ranges
2. **Configure Local Domains**: Define domains you handle locally  
3. **Enable Authentication**: Set up authentication for external users
4. **Test Thoroughly**: Use test scripts to verify behavior
5. **Monitor**: Watch logs during initial deployment

The new system is backward compatible - existing `allowed_relays` entries continue to work alongside the automatic private network detection. 