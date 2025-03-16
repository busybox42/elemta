# Email Authentication in Elemta

Elemta provides comprehensive email authentication support through its plugin system, implementing all major email authentication standards: SPF, DKIM, DMARC, and ARC. This document explains how these standards work, how they're implemented in Elemta, and how to configure them.

## Overview of Email Authentication Standards

Email authentication standards help verify the authenticity of email messages and protect against email spoofing, phishing, and other forms of email-based attacks.

### Authentication Flow

In Elemta, email authentication follows this general flow:

1. **Connection**: When an email is received, the connection is established
2. **SPF Check**: Verify that the sending server is authorized to send mail for the domain
3. **DKIM Verification**: Verify the digital signature to ensure the message wasn't altered
4. **DMARC Evaluation**: Apply domain policies based on SPF and DKIM results
5. **ARC Verification**: If the message was forwarded, verify the authentication chain
6. **Action**: Based on the results, accept, reject, or flag the message

## SPF (Sender Policy Framework)

SPF allows domain owners to specify which mail servers are authorized to send email on behalf of their domain.

### How SPF Works

1. The receiving server checks the domain in the `MAIL FROM` command
2. It looks up the SPF record in the domain's DNS
3. It verifies that the sending IP address is listed in the SPF record
4. Based on the result, it applies the policy specified in the SPF record

### Configuring SPF in Elemta

```yaml
plugins:
  spf:
    enabled: true
    enforce: false  # Set to true to reject emails that fail SPF validation
    timeout: 5s     # DNS lookup timeout
    cache_size: 1000  # Size of the SPF record cache
    cache_ttl: 3600   # Time-to-live for cached records (in seconds)
```

```toml
[plugins.spf]
enabled = true
enforce = false  # Set to true to reject emails that fail SPF validation
timeout = "5s"   # DNS lookup timeout
cache_size = 1000  # Size of the SPF record cache
cache_ttl = 3600   # Time-to-live for cached records (in seconds)
```

### SPF Results

SPF checks can return several results:

- **Pass**: The sending IP is authorized by the domain's SPF record
- **Fail**: The sending IP is not authorized
- **SoftFail**: The sending IP is not authorized, but the domain owner is testing SPF
- **Neutral**: The domain owner makes no assertion about the IP
- **None**: No SPF record was found, or the record is invalid
- **TempError**: A temporary error occurred during SPF processing
- **PermError**: A permanent error occurred during SPF processing

## DKIM (DomainKeys Identified Mail)

DKIM adds a digital signature to outgoing messages and validates incoming messages, allowing the receiver to verify that the message was not altered in transit.

### How DKIM Works

1. The sending server adds a DKIM-Signature header to the email
2. The signature contains a cryptographic hash of selected headers and the message body
3. The receiving server retrieves the public key from the sender's DNS
4. It verifies the signature using the public key
5. If the signature is valid, the message is considered authentic

### Configuring DKIM in Elemta

```yaml
plugins:
  dkim:
    enabled: true
    verify: true    # Verify DKIM signatures on incoming messages
    sign: true      # Sign outgoing messages
    domain: "example.com"
    selector: "mail"
    key_file: "/etc/elemta/dkim/example.com.private"
    headers_to_sign:
      - "From"
      - "To"
      - "Subject"
      - "Date"
    canonicalization: "relaxed/simple"  # header/body canonicalization
    signature_expiration: 604800  # 7 days in seconds
```

```toml
[plugins.dkim]
enabled = true
verify = true    # Verify DKIM signatures on incoming messages
sign = true      # Sign outgoing messages
domain = "example.com"
selector = "mail"
key_file = "/etc/elemta/dkim/example.com.private"
headers_to_sign = ["From", "To", "Subject", "Date"]
canonicalization = "relaxed/simple"  # header/body canonicalization
signature_expiration = 604800  # 7 days in seconds
```

### Generating DKIM Keys

To generate DKIM keys for your domain:

```bash
# Generate private key
openssl genrsa -out example.com.private 2048

# Generate public key in DNS format
openssl rsa -in example.com.private -pubout -outform PEM | \
  sed -e '1d; $d' | tr -d '\n' > example.com.public.txt
```

Add the public key to your DNS as a TXT record:
```
mail._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=[content of example.com.public.txt]"
```

## DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC builds on SPF and DKIM to provide domain-level authentication and reporting.

### How DMARC Works

1. The receiving server performs SPF and DKIM checks
2. It looks up the DMARC record in the sender's DNS
3. Based on the SPF and DKIM results, it applies the policy specified in the DMARC record
4. It can generate reports about authentication results and send them to the domain owner

### Configuring DMARC in Elemta

```yaml
plugins:
  dmarc:
    enabled: true
    enforce: false  # Set to true to enforce DMARC policies
    report_to: "dmarc-reports@example.com"  # Where to send aggregate reports
    report_interval: 86400  # 24 hours in seconds
    failure_reports: "all"  # Options: none, all, or specific failure types
```

```toml
[plugins.dmarc]
enabled = true
enforce = false  # Set to true to enforce DMARC policies
report_to = "dmarc-reports@example.com"  # Where to send aggregate reports
report_interval = 86400  # 24 hours in seconds
failure_reports = "all"  # Options: none, all, or specific failure types
```

### DMARC Policies

DMARC policies specify what to do with messages that fail authentication:

- **none**: Take no action, just monitor
- **quarantine**: Treat the message as suspicious (e.g., mark as spam)
- **reject**: Reject the message

## ARC (Authenticated Received Chain)

ARC preserves email authentication results across forwarding services, solving the email forwarding problem that affects SPF, DKIM, and DMARC.

### How ARC Works

1. When a message is forwarded, the original SPF and DKIM may fail at the final destination
2. ARC creates a chain of signatures that preserve the authentication results at each hop
3. The final receiver can verify the ARC chain to determine if the message was authentic at its origin

### Configuring ARC in Elemta

```yaml
plugins:
  arc:
    enabled: true
    verify: true    # Verify ARC chains on incoming messages
    seal: true      # Add ARC seals to outgoing messages
    domain: "example.com"
    selector: "arc"
    key_file: "/etc/elemta/arc/example.com.private"
    headers_to_sign:
      - "From"
      - "To"
      - "Subject"
      - "Date"
    max_chain_length: 50  # Maximum number of ARC sets to process
```

```toml
[plugins.arc]
enabled = true
verify = true    # Verify ARC chains on incoming messages
seal = true      # Add ARC seals to outgoing messages
domain = "example.com"
selector = "arc"
key_file = "/etc/elemta/arc/example.com.private"
headers_to_sign = ["From", "To", "Subject", "Date"]
max_chain_length = 50  # Maximum number of ARC sets to process
```

### ARC Chain Validation Results

ARC validation can return several results:

- **none**: No ARC sets found
- **pass**: The ARC chain is valid
- **fail**: The ARC chain is invalid
- **invalid**: The ARC chain contains invalid data

## Integration with Other Systems

Elemta's email authentication plugins can integrate with other systems:

### ClamAV and Rspamd

Authentication results can be passed to ClamAV and Rspamd for additional processing:

```yaml
plugins:
  rspamd:
    enabled: true
    host: "rspamd"
    port: 11334
    pass_auth_results: true  # Pass authentication results to Rspamd
```

### Logging and Monitoring

Authentication results are logged and exposed as metrics:

- **Logs**: Detailed authentication results are logged for each message
- **Metrics**: Authentication success/failure rates are exposed as Prometheus metrics
- **Grafana**: Pre-configured dashboards show authentication statistics

## Troubleshooting

### Common Issues

- **SPF Failures**: Check that your SPF record is valid and includes all sending IPs
- **DKIM Failures**: Verify that your DKIM keys are correctly configured and the selector exists in DNS
- **DMARC Failures**: Ensure that your DMARC record is valid and properly formatted
- **ARC Failures**: Check that your ARC keys are correctly configured

### Debugging Tools

Elemta provides several tools for debugging authentication issues:

```bash
# Check SPF record for a domain
./elemta-cli spf check example.com

# Verify DKIM signature for a message
./elemta-cli dkim verify -f message.eml

# Test DMARC policy for a domain
./elemta-cli dmarc check example.com

# Validate ARC chain in a message
./elemta-cli arc verify -f message.eml
```

## Best Practices

- **Start in monitoring mode**: Enable authentication plugins but set `enforce: false` initially
- **Analyze reports**: Review authentication reports before enforcing policies
- **Gradually increase enforcement**: Move from monitoring to quarantine to reject as confidence increases
- **Keep keys secure**: Protect your private keys and rotate them periodically
- **Monitor authentication metrics**: Watch for unexpected changes in authentication success rates 