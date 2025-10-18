# Secure Plugins Example

This directory contains an **example of secure plugin development** using Elemta's security-focused plugin manager.

## What's Here

- `example-antivirus/` - Example antivirus plugin with security features
- `Makefile` - Build configuration for secure plugins

## Status: Example Only

This is an **example/proof-of-concept** for secure plugin development patterns. It is **not used in production**.

## Relationship to Main Plugin System

Elemta uses **built-in plugins** for production (see `internal/plugin/`). This directory demonstrates:
- Plugin sandboxing techniques
- Security validation
- Secure plugin loading patterns

## See Also

- `docs/plugin-architecture.md` - Main plugin architecture
- `internal/plugin/secure_manager.go` - Secure plugin manager implementation
- `examples/external-plugins/` - Archived external plugins

