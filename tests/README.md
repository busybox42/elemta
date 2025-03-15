# Elemta MTA Tests

This directory contains tests for the Elemta MTA.

## Directory Structure

- `scripts/`: Contains test scripts for various features
  - `test-email.go`: Basic email sending test
  - `spam-test.go`: Test for spam detection using GTUBE pattern
  - `virus-test.go`: Test for virus detection using EICAR pattern
  - `toggle_test_mode.sh`: Script to enable/disable test mode for Rspamd

- `data/`: Contains test data files
  - `eicar.txt`: EICAR test virus pattern
  - `gtube.txt`: GTUBE spam test pattern

- `config/`: Contains test-specific configuration files

- `docker/`: Contains Docker-specific tests

- `python/`: Contains Python-based tests

- `k8s/`: Contains Kubernetes-specific tests

- `unit/`: Contains unit tests

## Test Mode

Elemta supports a test mode that disables certain features for testing purposes. This is particularly useful for testing in environments where external services like DNS may not be available or reliable.

### Enabling Test Mode

To enable test mode:

```bash
./scripts/toggle_test_mode.sh enable
```

This will:
1. Back up your current Rspamd configuration
2. Apply test-specific settings that:
   - Disable DNS checks
   - Disable RBL checks
   - Set higher spam thresholds

### Disabling Test Mode

To disable test mode and restore your previous configuration:

```bash
./scripts/toggle_test_mode.sh disable
```

### Test Mode Configuration

The test mode configuration is defined in `config/rspamd/test-mode.conf`. You can modify this file to adjust the test mode settings.

## Running Tests

### Basic Email Test

```bash
go run scripts/test-email.go
```

### Spam Detection Test

```bash
go run scripts/spam-test.go
```

### Virus Detection Test

```bash
go run scripts/virus-test.go
```

### Docker Tests

```bash
make docker-test
```

### Python Tests

```bash
make python-test
```

### Kubernetes Tests

```bash
make k8s-test
``` 