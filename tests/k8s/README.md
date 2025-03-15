# Kubernetes Test Scripts

This directory contains test scripts for the Elemta Kubernetes deployment.

## Available Tests

- **test-elemta.sh**: Main test script that checks the SMTP, ClamAV, and Rspamd services
- **simple-test.sh**: A simplified test script that checks basic connectivity
- **test-clamav.sh**: Specific tests for the ClamAV service
- **test-rspamd.sh**: Specific tests for the Rspamd service
- **test-k8s-email.sh**: End-to-end email flow tests

## Running Tests

You can run the main test script using the Makefile target:

```bash
make k8s-test
```

Or run individual test scripts directly:

```bash
./tests/k8s/test-elemta.sh
./tests/k8s/simple-test.sh
./tests/k8s/test-clamav.sh
./tests/k8s/test-rspamd.sh
./tests/k8s/test-k8s-email.sh
```

## Test Requirements

- A running Kubernetes cluster
- The Elemta deployment must be active (`make k8s-up`)
- `kubectl` must be configured to access your cluster
- Network access to the NodePort services (30025 for SMTP, 30334 for Rspamd)

## Troubleshooting

If tests fail, check:

1. Pod status: `kubectl get pods`
2. Service status: `kubectl get services`
3. Pod logs: `kubectl logs -l app=elemta -c [container-name]`

## Adding New Tests

When adding new test scripts:

1. Place them in this directory
2. Make them executable (`chmod +x script.sh`)
3. Document them in this README.md
4. Consider adding a Makefile target for convenience 