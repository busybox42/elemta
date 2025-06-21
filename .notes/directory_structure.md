# Elemta Directory Structure

## Root Level

### Application Entry Points
```
cmd/
├── elemta-cli/          # Command-line interface tool
│   ├── main.go         # CLI entry point
│   └── commands/       # CLI subcommands (queue, status, version)
├── elemta-queue/       # Queue processor utility
│   └── main.go        # Queue processor entry point
└── elemta/            # ❌ MISSING - Main server entry point
    └── main.go        # ❌ TODO: Create main server binary
```

### Core Implementation
```
internal/
├── smtp/              # Core SMTP server implementation
│   ├── server.go      # Main SMTP server
│   ├── session.go     # SMTP session handling
│   ├── auth.go        # SMTP authentication
│   ├── tls.go         # TLS/SSL handling
│   ├── tls_security.go # TLS security hardening (4-level configuration)
│   ├── tls_monitoring.go # TLS monitoring and alerting
│   ├── tls_security_test.go # TLS security tests
│   ├── tls_monitoring_test.go # TLS monitoring tests
│   └── queue.go       # SMTP queue integration
├── queue/             # Message queue system
│   ├── interfaces.go  # Unified queue interfaces
│   ├── storage.go     # Pluggable storage backend
│   ├── constructors.go # Modular delivery/processing managers
│   ├── manager.go     # Queue manager (multi-queue)
│   ├── processor.go   # Queue processing logic
│   ├── delivery_handler.go # Delivery handling
│   └── unified_test.go # Comprehensive queue system tests
├── plugin/            # Plugin system architecture
│   ├── manager.go     # Plugin loading and management
│   ├── types.go       # Plugin interfaces and types
│   ├── validator.go   # Plugin validation and security checks
│   ├── sandbox.go     # Plugin sandboxing and resource limits
│   ├── hotreload.go   # Hot-reload capabilities
│   ├── validator_test.go # Plugin validation tests
│   ├── antivirus.go   # Antivirus plugin interface
│   ├── antispam.go    # Antispam plugin interface
│   ├── dkim.go        # DKIM plugin interface
│   ├── spf.go         # SPF plugin interface
│   ├── dmarc.go       # DMARC plugin interface
│   └── arc.go         # ARC plugin interface
├── delivery/          # Message delivery system
│   ├── manager.go     # Delivery coordination
│   ├── pool.go        # Connection pooling
│   ├── router.go      # Routing logic
│   └── dns_cache.go   # DNS caching
├── auth/              # Authentication system
│   ├── auth.go        # Core authentication
│   ├── session.go     # Session management
│   ├── apikey.go      # API key authentication
│   └── rbac.go        # Role-based access control
├── api/               # REST API server
│   ├── server.go      # API server implementation
│   └── middleware.go  # Authentication middleware
├── config/            # Configuration management
│   └── config.go      # Config loading and validation
├── datasource/        # Data source abstractions
│   ├── datasource.go  # Interface definitions
│   ├── ldap.go        # LDAP implementation
│   ├── mysql.go       # MySQL implementation
│   ├── postgres.go    # PostgreSQL implementation
│   └── sqlite.go      # SQLite implementation
├── cache/             # Caching system
│   ├── cache.go       # Cache interface
│   ├── memory.go      # In-memory cache
│   ├── redis.go       # Redis cache
│   └── memcached.go   # Memcached implementation
├── antivirus/         # Antivirus integration
│   ├── scanner.go     # Scanner interface
│   └── clamav.go      # ClamAV implementation
└── antispam/          # Antispam integration
    ├── scanner.go     # Scanner interface
    └── rspamd.go      # RSpamd implementation
```

### Plugin Implementations
```
plugins/
├── spf/               # SPF validation plugin
├── dkim/              # DKIM validation plugin
├── dmarc/             # DMARC validation plugin
├── arc/               # ARC validation plugin
├── clamav/            # ClamAV antivirus plugin
├── rspamd/            # RSpamd antispam plugin
└── example_greylisting.go # Example greylisting plugin
```

### Configuration Files
```
config/
├── elemta.yaml        # Main YAML configuration
├── elemta.toml        # Main TOML configuration
├── elemta.conf        # Legacy configuration format
├── dev.yaml           # Development configuration
├── users.json         # User authentication data
└── rspamd/            # RSpamd-specific configuration
    └── local.d/       # RSpamd local configuration
```

### Documentation
```
docs/
├── README.md          # Documentation index
├── installation.md    # Installation instructions
├── configuration.md   # Configuration reference
├── email_authentication.md # Authentication setup
├── plugins.md         # Plugin development guide
├── queue_management.md # Queue operations
├── monitoring/        # Monitoring and metrics docs
├── delivery/          # Delivery system docs
└── docker/            # Docker deployment guides
```

### Deployment & Operations
```
docker/
├── dovecot/           # Dovecot IMAP/LMTP configuration
├── ldap/              # OpenLDAP configuration and schemas
├── roundcube/         # Roundcube webmail configuration
└── rspamd/            # RSpamd configuration

k8s/                   # Kubernetes deployment manifests
├── deployment.yaml    # Main deployment
├── service.yaml       # Service definitions
├── configmap.yaml     # Configuration maps
└── secret.yaml        # Secrets

scripts/
├── docker/            # Docker management scripts
├── ssl/               # TLS/SSL certificate scripts
├── monitoring/        # Monitoring setup scripts
└── test/              # Testing utilities

monitoring/
├── prometheus/        # Prometheus configuration
├── grafana/           # Grafana dashboards and config
└── alertmanager/      # Alert configuration
```

### Testing
```
tests/
├── unit/              # Unit tests
├── python/            # Python-based integration tests
├── k8s/               # Kubernetes testing
├── config/            # Test configurations
└── scripts/           # Test utilities and scripts
```

### Web Interface
```
web/
└── static/
    └── index.html     # Web management interface
```

### Build & Deployment Files
```
├── Makefile           # Build automation
├── Dockerfile         # Main container build
├── Dockerfile.cli     # CLI container build
├── docker-compose.yml # Development environment
├── go.mod             # Go module dependencies
└── go.sum             # Go module checksums
```

### Runtime Directories
```
queue/                 # Message queue storage (created at runtime)
├── active/            # Messages ready for delivery
├── deferred/          # Messages scheduled for retry
├── hold/              # Messages held for review
├── failed/            # Messages that failed delivery
└── data/              # Message content storage

logs/                  # Application logs (created at runtime)
bin/                   # Compiled binaries (created at build)
```

## Key File Purposes

### Critical Files
- `internal/smtp/server.go` - Core SMTP server implementation
- `internal/queue/manager.go` - Queue management system
- `internal/plugin/manager.go` - Plugin loading and execution
- `internal/config/config.go` - Configuration management
- `docker-compose.yml` - Development environment setup

### Configuration Files
- `config/elemta.yaml` - Primary configuration (YAML format)
- `config/elemta.toml` - Primary configuration (TOML format)  
- `config/dev.yaml` - Development-specific settings

### Entry Points
- `cmd/elemta-cli/main.go` - CLI tool for management
- `cmd/elemta-queue/main.go` - Queue processor utility
- **MISSING**: `cmd/elemta/main.go` - Main server binary

### Build Files
- `Makefile` - Build targets and automation
- `Dockerfile` - Container image build
- `go.mod` - Go dependencies and version

## Notes
- ❌ **CRITICAL**: Missing `cmd/elemta/main.go` prevents building main server
- ⚠️ **CONFIG**: Multiple config formats need standardization
- ✅ **STRUCTURE**: Well-organized modular architecture
- ✅ **TESTING**: Comprehensive test coverage across multiple environments 