# Testing Elemta

This document describes how to test the Elemta SMTP server, including test mode, queue testing, and SMTP testing.

## Test Mode

Elemta provides a test mode that allows you to verify the functionality of the server without sending actual emails. This is useful for development, testing, and debugging.

### Running Test Mode

You can run Elemta in test mode using the provided script:

```bash
# Run the test mode script
./scripts/test-mode.sh

# Run with specific options
./scripts/test-mode.sh --type all      # Test everything
./scripts/test-mode.sh --type smtp     # Test only SMTP
./scripts/test-mode.sh --type queue    # Test only queue
./scripts/test-mode.sh --type python   # Test only Python functionality
```

### Test Mode Options

The test mode script supports several options:

- `--type, -t`: Test type (all, smtp, queue, python)
- `--server, -s`: SMTP server address (default: localhost)
- `--port, -p`: SMTP server port (default: 2526)
- `--count, -c`: Number of emails to send (default: 3)
- `--clear, -C`: Clear the queue before testing
- `--help, -h`: Show help message

## Queue Testing

Elemta provides several scripts for testing the queue functionality:

### Basic Queue Test

```bash
# Run the basic queue test
make test-queue-only
```

This script:
1. Checks the queue before creating entries
2. Creates several test messages in the queue
3. Checks the queue after creating entries
4. Lists all messages in the queue

### Queue Simulation

```bash
# Run the queue simulation
./scripts/simulate-queue.sh

# Specify the number of messages to create
./scripts/simulate-queue.sh 5 3 2 1  # 5 active, 3 deferred, 2 held, 1 failed
```

This script:
1. Checks the queue before creating messages
2. Creates messages in different queue states (active, deferred, held, failed)
3. Checks the queue after creating messages
4. Lists all messages in the queue

### Queue Management

After running the tests, you can manage the queue using the CLI:

```bash
# List all messages in the queue
./scripts/elemta-cli.sh queue list

# Show queue statistics
./scripts/elemta-cli.sh queue stats

# View details of a specific message
./scripts/elemta-cli.sh queue view <message-id>

# Retry a message
./scripts/elemta-cli.sh queue retry <message-id>

# Delete a message
./scripts/elemta-cli.sh queue delete <message-id>
```

## SMTP Testing

Elemta provides a script for testing SMTP functionality:

```bash
# Run the SMTP test
./scripts/test-smtp.sh

# Run with specific options
./scripts/test-smtp.sh --server localhost --port 2526 --count 5
```

This script:
1. Checks the queue before sending emails
2. Sends test emails using swaks
3. Checks the queue after sending emails
4. Lists all messages in the queue

### SMTP Test Options

The SMTP test script supports several options:

- `--server, -s`: SMTP server address (default: localhost)
- `--port, -p`: SMTP server port (default: 2526)
- `--from, -f`: Sender email address (default: sender@example.com)
- `--to, -t`: Recipient email address (default: recipient@example.com)
- `--subject, -S`: Email subject (default: Test Email)
- `--body, -b`: Email body (default: This is a test email sent by swaks.)
- `--count, -c`: Number of emails to send (default: 3)
- `--delay, -d`: Delay between emails in seconds (default: 1)
- `--help, -h`: Show help message

## Comprehensive Testing

For a comprehensive test that includes deployment, SMTP testing, queue testing, and test mode:

```bash
# Run the deploy and test script
./scripts/deploy-and-test.sh
```

This script:
1. Undeploys any existing containers
2. Builds the Docker images
3. Deploys with Docker Compose
4. Waits for containers to be ready
5. Runs the SMTP test
6. Runs the queue simulation
7. Checks the queue
8. Runs the test mode

## Automated Testing

Elemta also includes automated tests that can be run using Go's testing framework:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific tests
go test ./internal/smtp/...
go test ./internal/plugin/...
```

For more information about automated testing, see the [Development Guide](development.md). 