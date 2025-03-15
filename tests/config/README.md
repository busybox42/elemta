# Test Configuration Files

This directory contains configuration files used for testing the Elemta SMTP server.

## Available Files

- **test-elemta.conf**: Test configuration for the Elemta server

## Using Test Configurations

To run Elemta with a test configuration:

```bash
./build/elemta server --config tests/config/test-elemta.conf
```

## Configuration Details

The test configuration includes:

- Custom hostname: mail.evil-admin.com
- Listening on port 2525
- Maximum message size: 25MB
- Development mode disabled
- Allowed relays: 127.0.0.1, ::1, 192.168.65.1
- Worker and retry settings for testing 