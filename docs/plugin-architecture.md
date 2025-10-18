# Elemta Plugin Architecture

## Current Design: Built-in Plugins Only

Elemta uses a **built-in plugin architecture** where all plugins are compiled directly into the main binary. This design was chosen for reliability, performance, and simplicity.

## Directory Structure

```
internal/plugin/          # All plugin code (21 Go files)
├── manager.go            # Plugin manager and loader
├── enhanced_manager.go   # Advanced plugin features  
├── secure_manager.go     # Security-focused plugin management
├── hotreload.go          # Hot reload system (for development)
├── hooks.go              # Hook interfaces (Connection, SMTP, Mail, etc.)
├── types.go              # Core plugin types and enums
├── plugin.go             # Base Plugin interface
│
├── rate_limiter.go       # Rate limiting implementation (703 lines)
├── rate_limiter_plugin.go # Rate limiting plugin wrapper
├── redis_client.go       # Valkey/Redis client for distributed state
│
├── antispam.go           # Antispam plugin base
├── antivirus.go          # Antivirus plugin base
│
├── spf.go                # SPF (Sender Policy Framework)
├── dkim.go               # DKIM signing/verification
├── dmarc.go              # DMARC policy enforcement
├── arc.go + arc_impl.go  # ARC (Authenticated Received Chain)
│
└── ...test.go files      # Comprehensive test coverage

examples/external-plugins-archive/  # Archived .so plugins (not used in production)
```

## Plugin Types

### 1. **Built-in Plugins** (Active)
Located in `internal/plugin/`, these are compiled into the main binary:

- **Rate Limiting**: `rate_limiter.go` + `rate_limiter_plugin.go`
  - Uses Valkey for distributed rate limiting across nodes
  - Integrated directly into ResourceManager
  - 703 lines of production code

- **Authentication Plugins**:
  - SPF validation (`spf.go`)
  - DKIM signing/verification (`dkim.go`)
  - DMARC policy checks (`dmarc.go`)
  - ARC chain validation (`arc.go`, `arc_impl.go`)

- **Scanning Plugins**:
  - Antispam integration (`antispam.go`) - interfaces with Rspamd
  - Antivirus integration (`antivirus.go`) - interfaces with ClamAV

### 2. **External .so Plugins** (Archived)
Previously located in `plugins/`, now in `examples/external-plugins-archive/`.

**Status**: Not used in production

**Why Archived**:
- Go's `plugin` package is **Linux-only**
- Requires **exact Go version match** between plugin and main binary
- Found to be **"too fragile"** during Valkey integration (user feedback)
- Rate limiting was moved from .so to built-in for reliability

**What's Archived**:
- `rate_limiter.go` (wrapper for internal version)
- `allowdeny/` (complex allow/deny rules engine)  
- `example_greylisting.go` (greylisting example)
- `spf/`, `dkim/`, `dmarc/`, `arc/` (wrappers for internal versions)
- `rspamd/`, `clamav/` (external service integrations)
- `*.so` files (compiled plugins)

## Plugin Loading

### Current System (Production)
```go
// Direct instantiation - no .so loading
resourceMgr := NewResourceManager(...)
rateLimiter := NewRateLimiterPlugin()  // Built-in
```

### Legacy System (Not Used)
```go
// .so file loading - DISABLED
pluginManager.LoadPlugin("rate_limiter")  // Would load rate_limiter.so
```

Configuration shows this:
```toml
[plugins]
directory = "/app/plugins"
enabled = []  # ← EMPTY! No .so plugins loaded
```

## Plugin Hooks

Plugins can implement various hook interfaces:

- `ConnectionHook` - Handle connection events
- `SMTPCommandHook` - Intercept SMTP commands (HELO, AUTH, etc.)
- `MailTransactionHook` - Mail transaction events (MAIL FROM, RCPT TO, DATA)
- `MessageProcessingHook` - Message content processing
- `QueueHook` - Queue operations
- `DeliveryHook` - Delivery attempts
- `SecurityHook` - Security events (rate limits, reputation checks)

## Why Built-in Only?

### Performance
- **Zero overhead**: No inter-process communication or .so loading
- **Direct function calls**: Nanosecond latency for plugin hooks
- **Momentum-style**: User wants "Momentum-like" performance (their workplace MTA)

### Reliability
- **No version mismatches**: Plugin and main binary always compatible
- **No load failures**: Plugins can't fail to load at runtime
- **Easier testing**: All code in one binary

### Simplicity
- **Single binary deployment**: Just `elemta` executable
- **Cross-platform**: Works on Linux, macOS, BSD (not just Linux)
- **Easier debugging**: All code in same process space

## Future Extensibility

If third-party plugin support is needed, the recommended approach is **gRPC-based plugins** (HashiCorp style):

### Proposed gRPC Plugin System
```
internal/plugin/
├── grpc/             # gRPC plugin system
│   ├── protocol.proto
│   ├── server.go
│   └── client.go
├── builtin/          # In-process plugins (current code)
└── manager.go        # Unified manager

external-plugins/     # Out-of-process plugins
├── custom_filter/    # Go plugin via gRPC
└── python_filter/    # Python plugin via gRPC
```

**Benefits**:
- ✅ No Go version compatibility issues
- ✅ Plugin crashes don't crash main server
- ✅ Supports non-Go plugins (Python, Rust, etc.)
- ✅ Production-proven (Terraform, Vault use this)

**Drawbacks**:
- ❌ gRPC overhead (microseconds, not nanoseconds)
- ❌ More complex implementation
- ❌ Best for low-frequency hooks (not per-message processing)

## Development Guidelines

### Adding a New Built-in Plugin

1. **Create plugin file**: `internal/plugin/my_plugin.go`
2. **Implement interfaces**: `Plugin` + relevant hooks
3. **Register in manager**: Update `enhanced_manager.go` if needed
4. **Add tests**: `internal/plugin/my_plugin_test.go`
5. **Update docs**: This file

### Plugin Organization

Current organization (flat structure):
```
internal/plugin/
├── manager.go
├── rate_limiter.go
├── spf.go
└── ...
```

**Future consideration**: Could organize into subdirectories:
```
internal/plugin/
├── system/         # manager.go, hooks.go, types.go
├── rate_limiting/  # rate_limiter.go, redis_client.go
├── authentication/ # spf.go, dkim.go, dmarc.go, arc.go
├── antispam/       # antispam.go
└── antivirus/      # antivirus.go
```

**However**: This requires changing all files to subpackages, which is invasive. Current flat structure works fine for now.

## Configuration

### Plugin System Config
```toml
[plugins]
directory = "/app/plugins"        # Not used (.so plugins disabled)
enabled = []                      # No external plugins

# Built-in plugins configured elsewhere:

[rate_limiter]                    # Rate limiting config
enabled = true
max_connections_per_ip = 5
connection_rate_per_minute = 10

[authentication]                  # SPF/DKIM/DMARC config  
spf_enabled = true
dkim_enabled = true
dmarc_policy = "quarantine"
```

## Testing

All plugins have comprehensive test coverage:
- Unit tests: `*_test.go` files
- Integration tests: `tests/test_elemta_centralized.py`
- Security tests: `hotreload_security_test.go` (ELE-36)

Run tests:
```bash
make test           # Unit tests
make test-docker    # Integration tests (21/21 passing)
```

## Summary

- ✅ **Built-in plugins**: All production code in `internal/plugin/`
- ❌ **External .so plugins**: Archived, not used
- 🚀 **Performance**: Direct function calls, zero overhead
- 🔒 **Reliability**: Single binary, no version mismatches
- 📈 **Scalability**: Rate limiting via Valkey for multinode deployments

For questions, see `.notes/plugin_module.md` or ask the team.

