# SMTP Server

Elemta provides a lightweight SMTP server for handling email traffic. This document explains how to configure and use the SMTP server.

## Configuration

The SMTP server is configured using a YAML or TOML configuration file (see [Configuration Reference](configuration.md) for full details):

```yaml
hostname: "mail.example.com"
listen_addr: ":2525"
queue_dir: "./queue"
max_message_size: 26214400
dev_mode: true
allowed_relays:
  - "127.0.0.1"
  - "::1"
  - "192.168.65.1"

auth:
  enabled: true
  required: false
  methods:
    - "plain"
    - "login"

tls:
  enabled: true
  cert_file: "/etc/elemta/certs/cert.pem"
  key_file: "/etc/elemta/certs/key.pem"

queue:
  max_workers: 5
  max_retries: 3
  max_queue_time: 3600
  retry_schedule: [60, 300, 900]
```

### Configuration Options

- `hostname`: The hostname to use in SMTP responses
- `listen_addr`: The address and port to listen on (e.g., `:2525` for all interfaces on port 2525)
- `queue_dir`: Directory to store the email queue
- `max_size`: Maximum message size in bytes (default: 25MB)
- `dev_mode`: Enable development mode (emails are not actually sent)
- `allowed_relays`: IP addresses allowed to relay emails
- `max_workers`: Maximum number of worker goroutines for processing the queue
- `max_retries`: Maximum number of delivery attempts
- `max_queue_time`: Maximum time (in seconds) a message can stay in the queue
- `retry_schedule`: Array of retry intervals (in seconds)
- `auth`: Authentication configuration (see Authentication section)

## Starting the Server

### Using Docker

```bash
docker-compose up -d
```

### Running the Binary

```bash
./elemta
```

## SMTP Commands

Elemta supports the following SMTP commands:

- `HELO/EHLO`: Identify the client to the server
- `MAIL FROM`: Specify the sender of the email (supports SIZE, DSN RET/ENVID, REQUIRETLS parameters)
- `RCPT TO`: Specify the recipient of the email (supports DSN NOTIFY/ORCPT parameters)
- `DATA`: Send the email content (dot-stuffed format)
- `BDAT`: Send message data in chunks (RFC 3030 CHUNKING alternative to DATA)
- `STARTTLS`: Upgrade connection to TLS
- `QUIT`: End the session
- `RSET`: Reset the session
- `NOOP`: No operation (keep-alive)
- `HELP`: Display help information
- `AUTH`: Authenticate the client (if enabled)
- `XDEBUG`: Custom command for debugging (only available in development mode)

## Authentication

Elemta supports SMTP authentication using the following methods:

- `PLAIN`: Plain text authentication (username and password)
- `LOGIN`: Login authentication (username and password sent separately)

Authentication is configured in the `auth` section of the configuration file:

```yaml
auth:
  enabled: true
  required: false
  methods:
    - "plain"
    - "login"
  backend: "file"
  file_path: "/etc/elemta/users.json"
```

### Authentication Options

- `enabled`: Enable or disable authentication
- `required`: Require authentication for all connections
- `methods`: Authentication methods to offer (`plain`, `login`)
- `backend`: Authentication backend (`file`, `ldap`, etc.)
- `file_path`: Path to authentication data file

## Development Mode

When `dev_mode` is set to `true`, the server operates in development mode:

- Emails are not actually sent
- The `XDEBUG` command is available for debugging
- Messages are logged but not queued for delivery

This is useful for testing email functionality without sending actual emails.

## Testing the Server

You can test the SMTP server using telnet or the provided Python scripts:

### Using Telnet

```bash
telnet localhost 2525
```

Example session:

```
Trying ::1...
Connected to localhost.
Escape character is '^]'.
220 elemta ESMTP ready
EHLO example.com
250-mail.example.com Hello example.com
250-SIZE 26214400
250-8BITMIME
250-SMTPUTF8
250-ENHANCEDSTATUSCODES
250-CHUNKING
250-DSN
250-STARTTLS
250 HELP
MAIL FROM:<sender@example.com>
250 2.1.0 OK
RCPT TO:<recipient@example.com>
250 2.1.5 OK
DATA
354 Start mail input; end with <CRLF>.<CRLF>
Subject: Test Email

This is a test email.
.
250 2.0.0 Message accepted for delivery
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

**Note:** Additional extensions may appear depending on configuration:
- `REQUIRETLS` — shown only when TLS is active (after STARTTLS)
- `AUTH PLAIN LOGIN` — shown when authentication is enabled

### Using Python Scripts

Elemta includes Python scripts for testing the SMTP server:

```bash
# Test basic SMTP functionality
python3 test_smtp.py

# Test SMTP authentication
python3 test_smtp_auth.py
```

## Relay Configuration

By default, Elemta only allows relaying from localhost (`127.0.0.1` and `::1`) and the Docker network. To allow relaying from other IP addresses, add them to the `allowed_relays` array in the configuration file:

```yaml
allowed_relays:
  - "127.0.0.1"
  - "::1"
  - "192.168.1.100"
```

## Debugging

Elemta provides a custom `XDEBUG` command for debugging the SMTP server. This command is only available when `dev_mode` is set to `true`:

```
XDEBUG
250-Debug information:
250-Session ID: 00d88aa8-90bf-46d7-aac8-d73292a47e02
250-Client IP: 192.168.65.1:64147
250-Hostname: mail.example.com
250-State: INIT
250-Mail From:
250-Rcpt To:
250 Context:
```

## Logging

The SMTP server logs all activity to the configured logging outputs. You can view the logs to troubleshoot issues:

```bash
# View Docker logs
docker logs elemta

# View log file
cat logs/elemta.log
```

## Security Considerations

- **TLS**: For secure SMTP, configure the TLS section in the configuration file or use a reverse proxy with TLS termination.
- **Authentication**: Enable authentication to prevent unauthorized use of your SMTP server.
- **Relay Restrictions**: Only allow relaying from trusted IP addresses to prevent spam.

## Performance Tuning

- **Queue Directory**: Use a fast storage device for the queue directory
- **Max Size**: Adjust the maximum message size based on your needs
- **Max Workers**: Adjust the number of worker goroutines based on your system resources
- **Retry Schedule**: Customize the retry schedule based on your delivery requirements 