# Elemta Project Overview

## Project Purpose
Elemta is a high-performance, carrier-grade Mail Transfer Agent (MTA) written in Go with a modular plugin architecture. It's designed to handle enterprise-level email processing with comprehensive security features.

## Current Status
- **Maturity Level**: 97% production-ready (P0, P1, and P2 tasks completed)
- **Codebase Size**: ~44,000+ lines of Go code
- **Architecture**: Sophisticated modular design with enterprise-grade security
- **Last Updated**: 2025-06-21 - All critical blockers and P2 performance/security tasks completed

## Key Features
- **High Performance**: Built with Go for excellent concurrency
- **Pluggable Architecture**: Extensible plugin system for security components
- **Security-First**: Built-in SPF, DKIM, DMARC, ARC validation
- **Cloud-Native**: Docker and Kubernetes ready
- **Enterprise Features**: Authentication, queue management, delivery tracking
- **Modern Stack**: Go 1.23+, Prometheus metrics, web management interface

## Core Architecture Components

### SMTP Server (`internal/smtp/`)
- Protocol implementation with enterprise-grade TLS security hardening
- 4-level TLS security configuration (Minimum, Recommended, Strict, Maximum)
- Real-time TLS monitoring and alerting system
- Authentication and session management
- Message processing pipeline

### Queue System (`internal/queue/`)
- Unified queue architecture with clean interface separation
- Multi-queue message management (active, deferred, hold, failed)
- High-performance optimization with configurable worker pools
- Retry logic with exponential backoff and priority handling
- Message persistence and recovery with atomic operations

### Plugin System (`internal/plugin/`)
- Enterprise-grade plugin hardening with validation and sandboxing
- Dynamic plugin loading with hot-reload capabilities
- Resource limits and security isolation
- Security plugins (antivirus, antispam)
- Authentication plugins (SPF, DKIM, DMARC, ARC)
- Custom filter capabilities with comprehensive development guide

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

## Completed P2 Tasks (2025-06-21)
- ✅ **Plugin system hardening and sandboxing** - Comprehensive validation, resource limits, hot-reload
- ✅ **Queue system optimization** - Unified architecture, performance improvements, worker pools
- ✅ **TLS security hardening** - 4-level security system, real-time monitoring, comprehensive testing

## Remaining Tasks (P3 Priority)
- Advanced monitoring dashboard enhancements
- Load testing and performance benchmarking
- Documentation updates and security audit
- Enterprise feature development

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