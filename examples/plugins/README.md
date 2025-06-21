# Elemta Plugin Development Guide

This guide provides comprehensive information for developing secure, robust plugins for the Elemta SMTP server.

## Table of Contents
1. [Overview](#overview)
2. [Plugin Architecture](#plugin-architecture)
3. [Development Best Practices](#development-best-practices)
4. [Security Guidelines](#security-guidelines)
5. [Plugin Types](#plugin-types)
6. [Configuration Handling](#configuration-handling)
7. [Testing Your Plugin](#testing-your-plugin)
8. [Example Plugins](#example-plugins)
9. [API Reference](#api-reference)

## Overview

Elemta plugins are Go shared objects (.so files) that extend the functionality of the SMTP server. They can process emails at various stages of the pipeline, implement authentication mechanisms, perform content filtering, and more.

### Key Features

- **Hot Reload**: Plugins can be reloaded without restarting the server
- **Sandboxing**: Resource limits and security restrictions prevent plugins from affecting the host system
- **Validation**: Comprehensive validation ensures plugins meet security and compatibility requirements
- **Error Isolation**: Plugin failures don't crash the main server

## Plugin Architecture

### Core Interfaces

Every plugin must implement the base `Plugin` interface:

```go
type Plugin interface {
    GetInfo() PluginInfo
    Init(config map[string]interface{}) error
    Close() error
}
```

### Plugin Metadata

Each plugin must export a `PluginInfo` variable:

```go
var PluginInfo = plugin.PluginInfo{
    Name:        "myplugin",
    Description: "Description of what the plugin does",
    Version:     "1.0.0",
    Type:        plugin.PluginTypeFilter,
    Author:      "Your Name",
}
```

### Plugin Instance

Export a plugin instance that implements the required interfaces:

```go
var Plugin MyPlugin
```

## Development Best Practices

### 1. Error Handling

Always wrap errors with context:

```go
func (p *MyPlugin) ProcessMessage(msg *message.Message) (*plugin.PluginResult, error) {
    result, err := p.doSomething()
    if err != nil {
        return nil, fmt.Errorf("processing failed: %w", err)
    }
    return result, nil
}
```

### 2. Resource Management

Use context for timeout and cancellation:

```go
func (p *MyPlugin) Init(cfg map[string]interface{}) error {
    ctx, cancel := context.WithCancel(context.Background())
    p.ctx = ctx
    p.cancel = cancel
    return nil
}

func (p *MyPlugin) Close() error {
    if p.cancel != nil {
        p.cancel()
    }
    return nil
}
```

### 3. Configuration Validation

Always validate configuration:

```go
func (p *MyPlugin) validateConfig() error {
    if p.config.Timeout <= 0 {
        return fmt.Errorf("timeout must be positive")
    }
    if p.config.MaxSize < 1024 {
        return fmt.Errorf("max_size must be at least 1024 bytes")
    }
    return nil
}
```

### 4. Thread Safety

Use mutexes for shared state:

```go
type MyPlugin struct {
    mu    sync.RWMutex
    stats map[string]int64
}

func (p *MyPlugin) updateStats(key string) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.stats[key]++
}
```

### 5. Logging

Use structured logging:

```go
p.logger.Info("Processing message", 
    "message_id", msg.ID,
    "size", len(msg.Data),
    "from", msg.From)
```

## Security Guidelines

### 1. Input Validation

Always validate input data:

```go
func (p *MyPlugin) ProcessMessage(msg *message.Message) (*plugin.PluginResult, error) {
    if msg == nil {
        return nil, fmt.Errorf("message cannot be nil")
    }
    if len(msg.Data) > p.config.MaxSize {
        return &plugin.PluginResult{
            Action: plugin.ActionReject,
            Message: "Message too large",
        }, nil
    }
    // Process message...
}
```

### 2. Resource Limits

Respect resource limits in the sandbox:

```go
func (p *MyPlugin) processLargeData(data []byte) error {
    // Process data in chunks to avoid memory spikes
    chunkSize := 64 * 1024 // 64KB chunks
    for i := 0; i < len(data); i += chunkSize {
        end := i + chunkSize
        if end > len(data) {
            end = len(data)
        }
        if err := p.processChunk(data[i:end]); err != nil {
            return err
        }
    }
    return nil
}
```

### 3. Avoid Global State

Don't use global variables for mutable state:

```go
// BAD - Global mutable state
var globalCounter int64

// GOOD - Plugin instance state
type MyPlugin struct {
    counter int64
    mu      sync.Mutex
}
```

### 4. External Dependencies

Be cautious with external network calls:

```go
func (p *MyPlugin) callExternalService(data []byte) error {
    ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
    defer cancel()
    
    client := &http.Client{
        Timeout: 5 * time.Second,
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", p.config.ServiceURL, bytes.NewReader(data))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("external service call failed: %w", err)
    }
    defer resp.Body.Close()
    
    // Process response...
    return nil
}
```

## Plugin Types

### Content Filter Plugins

Process message content:

```go
func (p *FilterPlugin) ProcessMessage(msg *message.Message) (*plugin.PluginResult, error) {
    // Analyze message content
    if p.containsSpam(msg.Data) {
        return &plugin.PluginResult{
            Action:  plugin.ActionReject,
            Message: "Spam detected",
        }, nil
    }
    
    return &plugin.PluginResult{
        Action: plugin.ActionContinue,
    }, nil
}
```

### Authentication Plugins

Implement custom authentication:

```go
type AuthPlugin interface {
    plugin.Plugin
    Authenticate(username, password string, clientAddr net.Addr) (*AuthResult, error)
}
```

### Antivirus Plugins

Scan for malware:

```go
type AntivirusPlugin interface {
    plugin.Plugin
    ScanMessage(msg *message.Message) (*plugin.Result, error)
}
```

### Antispam Plugins

Detect spam:

```go
type AntispamPlugin interface {
    plugin.Plugin
    ScanMessage(msg *message.Message) (*plugin.Result, error)
}
```

## Configuration Handling

### Configuration Structure

Define a clear configuration structure:

```go
type PluginConfig struct {
    Enabled     bool          `toml:"enabled" json:"enabled"`
    LogLevel    string        `toml:"log_level" json:"log_level"`
    Timeout     time.Duration `toml:"timeout" json:"timeout"`
    MaxSize     int64         `toml:"max_size" json:"max_size"`
    ServiceURL  string        `toml:"service_url" json:"service_url"`
    APIKey      string        `toml:"api_key" json:"api_key"`
}
```

### Safe Configuration Parsing

Handle type conversions safely:

```go
func (p *MyPlugin) parseConfig(cfg map[string]interface{}) error {
    if v, ok := cfg["enabled"].(bool); ok {
        p.config.Enabled = v
    }
    
    if v, ok := cfg["timeout"].(string); ok {
        if d, err := time.ParseDuration(v); err == nil {
            p.config.Timeout = d
        }
    }
    
    if v, ok := cfg["max_size"].(float64); ok {
        p.config.MaxSize = int64(v)
    }
    
    return nil
}
```

## Testing Your Plugin

### Unit Tests

Create comprehensive unit tests:

```go
func TestMyPlugin_ProcessMessage(t *testing.T) {
    plugin := &MyPlugin{}
    
    // Test normal message
    msg := &message.Message{
        ID:   "test-1",
        Data: []byte("Normal message content"),
    }
    
    result, err := plugin.ProcessMessage(msg)
    assert.NoError(t, err)
    assert.Equal(t, plugin.ActionContinue, result.Action)
}

func TestMyPlugin_ConfigValidation(t *testing.T) {
    tests := []struct {
        name    string
        config  map[string]interface{}
        wantErr bool
    }{
        {
            name: "valid config",
            config: map[string]interface{}{
                "enabled": true,
                "timeout": "30s",
            },
            wantErr: false,
        },
        {
            name: "invalid timeout",
            config: map[string]interface{}{
                "timeout": "invalid",
            },
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            plugin := &MyPlugin{}
            err := plugin.Init(tt.config)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Integration Tests

Test with the actual plugin system:

```go
func TestPluginIntegration(t *testing.T) {
    // Load plugin
    manager := plugin.NewManager("./test_plugins")
    err := manager.LoadPlugin("myplugin")
    require.NoError(t, err)
    
    // Get plugin instance
    p, err := manager.GetPlugin("myplugin")
    require.NoError(t, err)
    
    // Test plugin functionality
    result, err := p.ProcessMessage(testMessage)
    assert.NoError(t, err)
    assert.NotNil(t, result)
}
```

## Example Plugins

See the following example implementations:

- `simple_filter.go` - Basic content filtering
- `rate_limiter.go` - Rate limiting based on sender
- `reputation_checker.go` - IP reputation checking
- `content_scanner.go` - Advanced content analysis

## API Reference

### Core Types

#### PluginInfo
```go
type PluginInfo struct {
    Name        string // Unique plugin name
    Description string // Human-readable description  
    Version     string // Semantic version
    Type        string // Plugin type
    Author      string // Plugin author
}
```

#### PluginResult
```go
type PluginResult struct {
    Action      PluginAction
    Message     string
    Score       float64
    Annotations map[string]string
}
```

#### PluginAction
```go
const (
    ActionContinue   PluginAction = iota // Continue processing
    ActionReject                         // Reject the message
    ActionDiscard                        // Silently discard
    ActionQuarantine                     // Quarantine the message
    ActionDefer                          // Defer/retry later
    ActionModify                         // Modify and continue
)
```

### Processing Stages

```go
const (
    StageConnect      ProcessingStage = iota
    StageHelo
    StageAuth
    StageMailFrom
    StageRcptTo
    StageDataBegin
    StageDataHeaders
    StageDataBody
    StageDataComplete
    StageQueued
    StagePreDelivery
    StagePostDelivery
    StageDisconnect
    StageError
)
```

### Plugin Types

```go
const (
    PluginTypeAntivirus  = "antivirus"
    PluginTypeAntispam   = "antispam"
    PluginTypeDKIM       = "dkim"
    PluginTypeSPF        = "spf"
    PluginTypeDMARC      = "dmarc"
    PluginTypeARC        = "arc"
    PluginTypeFilter     = "filter"
    PluginTypeAuth       = "auth"
    PluginTypeRouting    = "routing"
    PluginTypeMetrics    = "metrics"
)
```

## Troubleshooting

### Common Issues

1. **Plugin not loading**: Check that `PluginInfo` and `Plugin` variables are exported
2. **Validation errors**: Ensure plugin implements required interfaces correctly
3. **Runtime panics**: Use proper error handling and avoid nil pointer dereferences
4. **Memory leaks**: Always clean up resources in the `Close()` method
5. **Timeout errors**: Respect context cancellation and timeouts

### Debugging

Enable debug logging:

```go
p.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
```

### Performance Tips

1. **Minimize allocations** in hot paths
2. **Use object pooling** for frequently allocated objects
3. **Implement caching** for expensive operations
4. **Profile your plugin** with `go tool pprof`
5. **Use goroutines carefully** - respect the sandbox limits

## Contributing

When contributing plugins to the Elemta ecosystem:

1. Follow the coding standards in this guide
2. Include comprehensive tests
3. Provide clear documentation
4. Consider security implications
5. Test with the plugin sandbox enabled

For more information, see the main Elemta documentation and the plugin system source code in `internal/plugin/`. 