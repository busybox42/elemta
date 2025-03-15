# Elemta Unit Tests

This directory contains Go unit tests for the Elemta Mail Transfer Agent (MTA).

## Directory Structure

- `smtp/`: Tests for the SMTP server implementation
  - `xdebug_test.go`: Tests for the XDEBUG command
- `context/`: Tests for the context package
  - `context_test.go`: Tests for the context implementation

## Running Tests

To run all tests:

```bash
go test ./...
```

To run tests for a specific package:

```bash
go test ./internal/smtp
```

To run a specific test:

```bash
go test ./internal/smtp -run TestSessionBasic
```

To run tests with verbose output:

```bash
go test -v ./...
```

## Adding New Tests

When adding new unit tests:

1. Create them in the appropriate subdirectory
2. Follow Go testing conventions (test files should end with `_test.go`)
3. Update this README if you add a new category of tests 