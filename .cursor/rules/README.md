# Elemta MTA - Cursor AI Assistant Rules

This directory contains configuration files for AI coding assistants working on the Elemta MTA project. These files provide comprehensive context about the project architecture, coding standards, and development workflows.

## Files Overview

### 📋 `elemta_architecture.mdc`
Comprehensive overview of the Elemta MTA architecture including:
- Command structure and entry points
- Internal package organization
- Plugin system design
- Key design patterns and data flow
- Security features and deployment options

### 🎯 `coding_standards.mdc`
Coding standards and best practices covering:
- Go coding style guidelines
- Error handling patterns
- Context usage and logging standards
- Interface design principles
- Testing standards and security considerations
- Performance guidelines and documentation requirements

### 🔄 `development_workflow.mdc`
Development workflow guidelines including:
- Environment setup procedures
- Feature development process
- Testing strategies (unit, integration, plugin)
- Code review process
- Debugging workflows and performance testing
- Release preparation and troubleshooting

## Purpose

These files ensure that AI assistants have deep understanding of:

1. **Project Context**: The overall architecture and how components interact
2. **Code Quality**: Standards for writing maintainable, secure, and performant code
3. **Development Process**: How to properly develop, test, and deploy changes

## For AI Assistants

When working on the Elemta project:

1. **Read the architecture guide** to understand the overall system design
2. **Follow coding standards** for all code modifications
3. **Use the development workflow** for testing and validation processes
4. **Reference specific patterns** mentioned in these files when implementing features

## Key Principles

- **Security First**: Always consider security implications
- **Plugin Architecture**: Leverage the modular plugin system
- **Performance**: Consider performance impact of changes
- **Testing**: Comprehensive testing for all modifications
- **Documentation**: Keep documentation updated with changes

## Quick Reference

### Common Commands
```bash
# Build and test
make build && make test

# Run linter
golangci-lint run

# Start development environment
docker-compose up -d

# Run with debug logging
./elemta server --debug
```

### Key Packages
- `internal/smtp/`: SMTP server implementation
- `internal/queue/`: Message queue management
- `internal/delivery/`: Message delivery system
- `internal/plugin/`: Plugin system core
- `internal/auth/`: Authentication & authorization

### Testing Patterns
- Use table-driven tests
- Mock external dependencies
- Include integration tests for workflows
- Aim for 80%+ test coverage

This configuration ensures consistent, high-quality development assistance for the Elemta MTA project. 