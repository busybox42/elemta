# SMTP Server

Elemta provides a lightweight SMTP server for handling email traffic. This document explains how to configure and use the SMTP server.

## Configuration

The SMTP server is configured using the configuration file located at `config/elemta.conf`:

```json
{
    "hostname": "mail.example.com",
    "listen_addr": ":2525",
    "queue_dir": "./queue",
    "max_size": 26214400,
    "dev_mode": false,
    "allowed_relays": ["127.0.0.1", "::1"]
}
```

### Configuration Options

- `hostname`: The hostname to use in SMTP responses
- `listen_addr`: The address and port to listen on (e.g., `:2525` for all interfaces on port 2525)
- `queue_dir`: Directory to store the email queue
- `max_size`: Maximum message size in bytes (default: 25MB)
- `dev_mode`: Enable development mode (emails are not actually sent)
- `allowed_relays`: IP addresses allowed to relay emails

## Starting the Server

### Using Docker

```bash
docker-compose up -d
```

### Running the Binary

```bash
./bin/elemta
```

## SMTP Commands

Elemta supports the following SMTP commands:

- `HELO/EHLO`: Identify the client to the server
- `MAIL FROM`: Specify the sender of the email
- `RCPT TO`: Specify the recipient of the email
- `DATA`: Send the email content
- `QUIT`: End the session
- `RSET`: Reset the session
- `NOOP`: No operation (keep-alive)
- `HELP`: Display help information
- `XDEBUG`: Custom command for debugging (only available in development mode)

## Development Mode

When `dev_mode` is set to `true`, the server operates in development mode:

- Emails are not actually sent
- The `XDEBUG` command is available for debugging
- Messages are logged but not queued for delivery

This is useful for testing email functionality without sending actual emails.

## Testing the Server

You can test the SMTP server using telnet or the provided test scripts:

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
250-mail.example.com
250-SIZE 26214400
250-8BITMIME
250-PIPELINING
250-ENHANCEDSTATUSCODES
250 HELP
MAIL FROM:<sender@example.com>
250 Ok
RCPT TO:<recipient@example.com>
250 Ok
DATA
354 Start mail input; end with <CRLF>.<CRLF>
Subject: Test Email

This is a test email.
.
250 Ok: message queued
QUIT
221 Bye
Connection closed by foreign host.
```

### Using Test Scripts

Elemta includes test scripts for testing the SMTP server:

```bash
# Test local SMTP
./test_smtp.sh

# Test sending to Gmail
./test_gmail.sh
```

## Relay Configuration

By default, Elemta only allows relaying from localhost (`127.0.0.1` and `::1`). To allow relaying from other IP addresses, add them to the `allowed_relays` array in the configuration file:

```json
{
    "allowed_relays": ["127.0.0.1", "::1", "192.168.1.100"]
}
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
docker-compose logs -f

# View log file
cat logs/elemta.log
```

## Security Considerations

- **TLS**: Elemta does not currently support TLS directly. For secure SMTP, use a reverse proxy with TLS termination.
- **Authentication**: Elemta does not currently support SMTP authentication. Use IP-based restrictions instead.
- **Relay Restrictions**: Only allow relaying from trusted IP addresses to prevent spam.

## Performance Tuning

- **Queue Directory**: Use a fast storage device for the queue directory
- **Max Size**: Adjust the maximum message size based on your needs
- **Concurrency**: Elemta handles multiple connections concurrently, but you may need to adjust system limits for high-volume deployments 