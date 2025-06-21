# Elemta Project Overview

## Project Purpose
Elemta is a high-performance, carrier-grade Mail Transfer Agent (MTA) written in Go with a modular plugin architecture. It's designed to handle enterprise-level email processing with comprehensive security features.

## Current Status
- **Maturity Level**: 95% production-ready (P0 and P1 tasks completed)
- **Codebase Size**: ~41,336 lines of Go code
- **Architecture**: Sophisticated modular design with clean separation of concerns
- **Last Updated**: 2025-06-21 - All critical blockers resolved

## Key Features
- **High Performance**: Built with Go for excellent concurrency
- **Pluggable Architecture**: Extensible plugin system for security components
- **Security-First**: Built-in SPF, DKIM, DMARC, ARC validation
- **Cloud-Native**: Docker and Kubernetes ready
- **Enterprise Features**: Authentication, queue management, delivery tracking
- **Modern Stack**: Go 1.23+, Prometheus metrics, web management interface

## Core Architecture Components

### SMTP Server (`internal/smtp/`)
- Protocol implementation with TLS support
- Authentication and session management
- Message processing pipeline

### Queue System (`internal/queue/`)
- Multi-queue message management (active, deferred, hold, failed)
- Retry logic and priority handling
- Message persistence and recovery

### Plugin System (`internal/plugin/`)
- Dynamic plugin loading with hot-reload
- Security plugins (antivirus, antispam)
- Authentication plugins (SPF, DKIM, DMARC, ARC)
- Custom filter capabilities

### Delivery Manager (`internal/delivery/`)
- Connection pooling and routing
- DNS caching and MX record handling
- Delivery tracking and retry management

### Authentication System (`internal/auth/`)
- Session and API key authentication
- RBAC (Role-Based Access Control)
- Multiple datasource support (LDAP, MySQL, PostgreSQL, SQLite)

### API Server (`internal/api/`)
- REST API for management operations
- Web interface for monitoring and administration
- Queue management endpoints

## Technology Stack
- **Language**: Go 1.23+
- **Configuration**: TOML/YAML (needs standardization)
- **Databases**: SQLite, MySQL, PostgreSQL support
- **LDAP**: Integration for user authentication
- **Monitoring**: Prometheus metrics, Grafana dashboards
- **Containerization**: Docker, Kubernetes
- **Security**: TLS, Let's Encrypt integration

## Development Standards
- **Go Style**: Follow `gofmt`, `goimports`, use `golangci-lint`
- **Error Handling**: Always handle errors explicitly, use `fmt.Errorf` with `%w` for wrapping
- **Context**: Pass `context.Context` as first parameter, use for timeouts/cancellation
- **Logging**: Use structured logging with `slog`, include relevant context
- **Testing**: Table-driven tests, 80%+ coverage, mock external dependencies

## Resolved Critical Issues (2025-06-21)
1. ✅ **Main entry point created** - `cmd/elemta/main.go` with full Cobra CLI
2. ✅ **Configuration standardized** - TOML format with comprehensive validation
3. ✅ **Production authentication** - Mock datasources removed, environment-based auth
4. ✅ **Build system aligned** - All build targets working, Docker deployments verified
5. ✅ **Error handling standardized** - Comprehensive error wrapping and structured logging

## Remaining Tasks (P2 Priority)
- Plugin system hardening and sandboxing
- Performance optimization and load testing
- Advanced monitoring and alerting features
- Documentation updates and security audit

## Project Goals
- **Reliability**: Handle high-volume email processing
- **Security**: Comprehensive email security through plugins
- **Performance**: Low-latency, high-throughput processing
- **Maintainability**: Clean, well-tested, documented code
- **Extensibility**: Easy plugin development and integration

## Deployment Options
- **Docker Compose**: Full development environment
- **Kubernetes**: Production-ready cluster deployment
- **From Source**: Development and customization

## Success Criteria
- All binaries build and run without errors
- Docker compose environment starts successfully
- Can send/receive emails through SMTP server
- Web UI accessible and functional
- Authentication works in production mode
- All tests pass consistently
- Documentation is complete and accurate 