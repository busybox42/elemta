# Elemta Tests

This directory contains tests for the Elemta Mail Transfer Agent (MTA).

## Directory Structure

- `unit/`: Unit tests for various components
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