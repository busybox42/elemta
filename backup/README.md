# Elemta Backup

This directory contains backup copies of files from the nested `elemta` directory in the repository.

The repository had two separate Go modules:
1. The root module at `/home/alan/repos/elemta` with import path `github.com/busybox42/elemta`
2. A nested module at `/home/alan/repos/elemta/elemta` with import path `github.com/elemta/elemta`

This caused confusion with where files should be placed. The files in this backup directory are from the nested module and may contain unique code that should be preserved.

## Directory Structure

- `elemta/internal/smtp/server.go` and `elemta/internal/smtp/state.go`: Different implementations of the SMTP server
- `elemta/internal/rule/engine.go`: Rule engine implementation
- `elemta/internal/config/config.go`: Configuration implementation
- `elemta/internal/common/session.go`: Common session implementation
- `elemta/internal/context/context.go`: Context implementation
- `elemta/pkg/`: Various packages for DMARC, RBL, SPF, ARC, DKIM, and utilities
- `elemta/cmd/elemta/main.go`: Main entry point for the Elemta application
- `elemta/examples/context_example.go`: Example code for using the context package
- `elemta/go.mod` and `elemta/go.sum`: Go module files for the nested module
- `elemta/README.md`: README file for the nested module 