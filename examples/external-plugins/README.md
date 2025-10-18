# External Plugins (Archive)

This directory contains **archived external plugins** that are **not used in production**.

## Why Archived?

1. **Go Plugin Fragility**: Go's `plugin` package requires exact Go version matches and is Linux-only
2. **Performance**: Built-in plugins are faster (no .so loading overhead)
3. **Reliability**: All production code is compiled into main binary
4. **User Feedback**: Found to be "too fragile" during Valkey integration

## What's Here

- `rate_limiter.go` - Wrapper for internal rate limiter (now built-in)
- `allowdeny/` - Complex allow/deny rules engine  
- `example_greylisting.go` - Greylisting plugin example
- `spf/`, `dkim/`, `dmarc/`, `arc/` - Wrappers for internal auth plugins
- `rspamd/`, `clamav/` - External service integrations
- `*.so` files - Compiled plugin binaries

## Current Production Architecture

**All plugins are built-in** in `internal/plugin/`:

```go
// Production code uses direct instantiation
resourceMgr := NewResourceManager(...)
rateLimiter := NewRateLimiterPlugin()  // Built-in, not loaded from .so
```

See `docs/plugin-architecture.md` for full details.

## These Files Are

- ✅ Useful as **examples** of plugin development
- ✅ Reference for **future gRPC plugin system** (if needed)
- ❌ **Not loaded** at runtime
- ❌ **Not maintained** for current Elemta version

## If You Need External Plugins

Consider **gRPC-based plugins** (HashiCorp style):
- No Go version compatibility issues
- Plugin crashes don't crash main server
- Supports non-Go plugins (Python, Rust, etc.)

See `docs/plugin-architecture.md` → "Future Extensibility" section.

