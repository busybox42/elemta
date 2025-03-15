# Python Test Scripts

This directory contains Python scripts for testing the Elemta SMTP server.

## Available Scripts

- **test_smtp.py**: Basic SMTP test that sends an email through the Elemta server
- **test_smtp_auth.py**: Tests SMTP authentication functionality
- **test_security.py**: Tests security features like antivirus and antispam

## Running Tests

To run a test script:

```bash
python3 tests/python/test_smtp.py
```

### test_security.py Options

The security test script has several command-line options:

```bash
python3 tests/python/test_security.py --server localhost --port 2525 --test all
```

Options:
- `--server`: SMTP server address (default: localhost)
- `--port`: SMTP server port (default: 25)
- `--sender`: Sender email address (default: sender@example.com)
- `--recipient`: Recipient email address (default: recipient@example.com)
- `--test`: Test to run (choices: virus, spam, all; default: all)
- `--debug`: Enable debug output 