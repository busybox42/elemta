# Elemta Project - Cursor AI Rules

## Project Overview
This is Elemta, a high-performance SMTP server written in Go. Always consult the documentation in `.notes/` before starting work.

## Required Reading Before Starting
- **ALWAYS** read `.notes/project_overview.md` for project context
- **ALWAYS** check `.notes/task_list.md` for current priorities and task status
- **ALWAYS** review `.notes/decision_log.md` for architectural decisions
- Check `.notes/directory_structure.md` to understand file organization

## Critical Project Issues (P0 Priority)
1. **Missing Main Entry Point**: `cmd/elemta/main.go` doesn't exist - this blocks all development
2. **Configuration Chaos**: Multiple config formats (YAML/TOML/JSON) need standardization
3. **Mock Authentication**: Production code uses mock datasources - security risk

## Development Standards

### Go Code Style
- Follow `gofmt` and `goimports` formatting
- Use `golangci-lint` for code quality
- Error handling: Always use `fmt.Errorf("operation failed: %w", err)` for wrapping
- Context: Pass `context.Context` as first parameter for all operations
- Logging: Use structured logging with `slog` package

### File Structure Rules - STRICTLY ENFORCE
**Core Directories:**
- `internal/` - Core implementation, internal packages
- `cmd/` - Application entry points (main.go files)
- `config/` - Configuration files and examples
- `docs/` - User-facing documentation
- `.notes/` - Project notes (gitignored)

**Organized Subdirectories:**
- `deployments/compose/` - ALL docker-compose*.yml files
- `tests/` - Test code and test fixtures
- `tests/fixtures/` - Test data (ldif, json, xml, etc.)
- `scripts/` - Production scripts
- `scripts/dev/` - Development-only scripts (rebuild, restart, etc.)
- `monitoring/` - Prometheus, Grafana, Alertmanager configs
- `monitoring/grafana/dashboards/` - Grafana dashboard JSON files
- `examples/` - Code examples and sample integrations
- `docker/` - Dockerfiles and service configs
- `k8s/` - Kubernetes manifests
- `install/` - Installation and upgrade scripts

**Rules for New Files:**
1. **NEVER** add scripts to project root - use `scripts/` or `scripts/dev/`
2. **NEVER** add test fixtures to project root - use `tests/fixtures/<type>/`
3. **NEVER** add config examples to project root - use `config/` or `examples/`
4. **NEVER** add LDIF files to project root - use `tests/fixtures/ldap/`
5. **NEVER** add docker-compose variants to project root - use `deployments/compose/`
6. **NEVER** commit compiled binaries - they belong in `bin/` (gitignored)
7. **NEVER** commit AI work files (*_WORK.md, *_TODO.md) - they're gitignored

**Before Creating a New File:**
- Ask: "Where does this logically belong in the directory structure?"
- Check if a similar directory already exists
- Add a README.md to new directories explaining their purpose

### Testing Requirements
- Write table-driven tests for all new functionality
- Maintain 80%+ test coverage for critical paths
- Mock external dependencies
- Include integration tests for complex workflows

## Task Management Rules
1. **Before starting any task**: Update `.notes/task_list.md` status to 🔄 In Progress
2. **After completing a task**: Update status to ✅ Completed with completion date
3. **If blocked**: Update status to 🚫 Blocked with reason
4. **For decisions**: Log in `.notes/decision_log.md` with rationale

## Configuration Standards
- **Target Format**: TOML (decision pending in `.notes/decision_log.md`)
- **Validation**: All configs must have validation with clear error messages
- **Examples**: Provide working examples for all configuration options
- **Documentation**: Update docs when config changes

## Architecture Patterns

### Module Structure
Each module should follow this pattern:
```
internal/module/
├── module.go      # Main implementation
├── types.go       # Type definitions
├── config.go      # Configuration
└── module_test.go # Tests
```

### Interface Design
- Keep interfaces small and focused
- Define interfaces where they're used, not where they're implemented
- Use composition over inheritance

### Error Handling
- Return errors, don't panic
- Wrap errors with context: `fmt.Errorf("failed to process message: %w", err)`
- Log errors at appropriate levels
- Provide actionable error messages

## Security Requirements
- **Authentication**: Never use mock datasources in production code paths
- **TLS**: Always validate certificates in production
- **Input Validation**: Validate all external inputs
- **Logging**: Don't log sensitive information (passwords, keys)

## Performance Guidelines
- Use goroutines for concurrent operations
- Implement proper connection pooling
- Stream large messages, don't load entirely into memory
- Include context for cancellation and timeouts

## Docker and Deployment
- **MANDATORY**: Always test changes in Docker environment first
- **MANDATORY**: Rebuild Docker deployment and verify all services start correctly
- **MANDATORY**: Run end-to-end tests in Docker before committing any changes
- Update Docker configurations when changing build process
- Verify Kubernetes deployments work
- Test all docker-compose services start correctly
- **NO COMMITS** without successful Docker deployment testing

## Documentation Rules
- Update `.notes/` documentation when making architectural changes
- Keep README.md aligned with actual functionality
- Document all public APIs
- Include examples for complex operations

## Git Workflow
- Create feature branches for major changes
- Write descriptive commit messages
- Include issue references where applicable
- Update documentation in same commit as code changes

## Build and Testing Commands
```bash
# Standard build
make build

# Run all tests
go test -v ./...

# Docker environment
docker-compose up -d

# Format code
gofmt -w .
goimports -w .

# Lint code
golangci-lint run
```

## Priority Order for Development
1. **P0 (Critical)**: Fix main entry point, config standardization, remove mocks
2. **P1 (High)**: Build system, configuration validation, error handling
3. **P2 (Medium)**: Plugin hardening, documentation, testing
4. **P3 (Low)**: Performance optimization, enterprise features

## Common File Locations
- Main server: `cmd/elemta/main.go` (❌ MISSING - CREATE THIS FIRST)
- SMTP server: `internal/smtp/server.go`
- Queue system: `internal/queue/manager.go`
- Plugin system: `internal/plugin/manager.go`
- Configuration: `internal/config/config.go`
- Build config: `Makefile`, `Dockerfile`

## Module-Specific Guidelines

### SMTP Module (`internal/smtp/`)
- See `.notes/smtp_module.md` for detailed documentation
- Focus on protocol compliance and performance
- Implement proper session handling

### Queue Module (`internal/queue/`)
- See `.notes/queue_module.md` for detailed documentation
- Ensure message persistence and recovery
- Implement robust retry logic

### Plugin Module (`internal/plugin/`)
- See `.notes/plugin_module.md` for detailed documentation
- Plugin failures must not crash server
- Implement proper plugin isolation

## Emergency Contacts
- Check `.notes/milestones.md` for timeline and deadlines
- Review `.notes/decision_log.md` for pending decisions
- Escalate architectural decisions to project lead

## Git and Linear MCP Integration

### Required Workflow
1. **Before starting any work**: 
   - Use `@linear list my issues` to see assigned issues
   - Use `@linear get issue ELE-X` to get issue details
   - **MANDATORY**: Update Linear issue status to "In Progress" using `@linear update issue ELE-X --state "In Progress"`
   - Create branch: `git checkout -b type/description-ELE-X`

2. **During development**:
   - Make incremental commits with Linear issue references
   - Use `@linear create comment ELE-X` to update progress
   - Reference issue ID in commit messages: `Fixes: ELE-7`

3. **After completing work**:
   - Create PR with Linear issue link in description
   - **MANDATORY**: Use `@linear update issue ELE-X --state "Done"` when merged and pushed
   - Delete feature branch after merge

### Linear Issue Status Management
- **ALWAYS** mark issues as "In Progress" when starting work
- **ALWAYS** mark issues as "Done" when work is complete and merged
- **NEVER** leave issues in "In Progress" state after completion
- Use Linear MCP commands to maintain proper issue tracking

### Linear MCP Commands
```bash
# Issue management
@linear list my issues
@linear get issue ELE-7
@linear update issue ELE-7 --state "In Progress"
@linear create comment ELE-7 --body "Progress update"

# Team and project management
@linear list teams
@linear list projects
@linear get team "Elemta"
```

### Git Integration Standards
- **Branch naming**: `type/description-ELE-X` (e.g., `fix/queue-security-ELE-7`)
- **Commit messages**: Include Linear issue ID (`Fixes: ELE-7`)
- **PR descriptions**: Link to Linear issue with full context
- **Issue tracking**: Always update Linear status and add comments

### Workflow Documentation
- See `.notes/git_linear_workflow.md` for complete integration guide
- Follow standard development operations with both Git and Linear
- Maintain full traceability between code changes and issue tracking

### Example Workflow (ELE-41 Completed)
1. **Start**: `@linear update issue ELE-41 --state "In Progress"`
2. **Branch**: `git checkout -b fix/rate-limiting-plugin-ELE-41`
3. **Develop**: Implement features, commit with `Fixes: ELE-41`
4. **Test**: Verify in Docker deployment
5. **Merge**: `git merge fix/rate-limiting-plugin-ELE-41`
6. **Push**: `git push origin main`
7. **Complete**: `@linear update issue ELE-41 --state "Done"`
8. **Cleanup**: Delete feature branch

## Remember
- **Quality over speed**: This is production email infrastructure
- **Security first**: Email servers are high-value attack targets  
- **Test everything**: Email reliability is critical
- **Document decisions**: Future developers need context
- **Track everything**: Use Linear MCP for issue management and Git for version control