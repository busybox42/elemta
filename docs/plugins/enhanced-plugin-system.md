# Enhanced Plugin System

The Enhanced Plugin System in Elemta provides a comprehensive, production-ready framework for extending email server functionality with robust hook points, lifecycle management, error isolation, and monitoring capabilities.

## Overview

The Enhanced Plugin System builds upon Elemta's existing plugin architecture to provide:

- **Comprehensive Hook Points**: 11 different hook types covering all SMTP processing stages
- **Error Isolation**: Plugin crashes and timeouts won't affect the main server
- **Lifecycle Management**: Graceful loading, initialization, and shutdown of plugins
- **Performance Monitoring**: Detailed metrics and execution statistics
- **Thread Safety**: All operations are safe for concurrent execution
- **Configuration Management**: Flexible configuration with hot-reload support

## Architecture

### Core Components

1. **EnhancedManager**: Central orchestrator for plugin lifecycle and execution
2. **HookRegistry**: Manages registration and retrieval of plugin hooks
3. **Executor**: Provides safe, isolated execution with panic recovery and timeouts
4. **HookContext**: Rich context information passed to plugin hooks

## Hook Types

### 1. Connection Hooks (`ConnectionHook`)

Executed when connections are established or closed.

```go
type ConnectionHook interface {
    OnConnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error)
    OnDisconnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error)
}
```

**Use Cases**: IP blocking, connection limiting, logging

### 2. SMTP Command Hooks (`SMTPCommandHook`)

Executed for SMTP protocol commands.

```go
type SMTPCommandHook interface {
    OnHelo(ctx *HookContext, hostname string) (*PluginResult, error)
    OnEhlo(ctx *HookContext, hostname string) (*PluginResult, error)
    OnAuth(ctx *HookContext, mechanism, username string) (*PluginResult, error)
    OnStartTLS(ctx *HookContext) (*PluginResult, error)
}
```

**Use Cases**: Authentication validation, TLS enforcement, hostname verification

### 3. Mail Transaction Hooks (`MailTransactionHook`)

Executed during mail envelope processing.

```go
type MailTransactionHook interface {
    OnMailFrom(ctx *HookContext, sender string, params map[string]string) (*PluginResult, error)
    OnRcptTo(ctx *HookContext, recipient string, params map[string]string) (*PluginResult, error)
    OnData(ctx *HookContext) (*PluginResult, error)
}
```

**Use Cases**: Sender/recipient validation, policy enforcement

### 4. Message Processing Hooks (`MessageProcessingHook`)

Executed during message content processing.

```go
type MessageProcessingHook interface {
    OnHeaders(ctx *HookContext, headers map[string][]string) (*PluginResult, error)
    OnBody(ctx *HookContext, body []byte) (*PluginResult, error)
    OnMessageComplete(ctx *HookContext, rawMessage []byte) (*PluginResult, error)
}
```

**Use Cases**: Content filtering, header manipulation, virus/spam scanning

### 5. Queue Hooks (`QueueHook`)

Executed during queue operations.

```go
type QueueHook interface {
    OnEnqueue(ctx *HookContext, queueID string) (*PluginResult, error)
    OnDequeue(ctx *HookContext, queueID string) (*PluginResult, error)
    OnQueueRetry(ctx *HookContext, queueID string, attempt int) (*PluginResult, error)
}
```

**Use Cases**: Queue monitoring, retry logic customization

### 6. Delivery Hooks (`DeliveryHook`)

Executed during message delivery.

```go
type DeliveryHook interface {
    OnPreDelivery(ctx *HookContext, recipient string) (*PluginResult, error)
    OnDeliveryAttempt(ctx *HookContext, recipient string, attempt int) (*PluginResult, error)
    OnDeliverySuccess(ctx *HookContext, recipient string) (*PluginResult, error)
    OnDeliveryFailure(ctx *HookContext, recipient string, err error) (*PluginResult, error)
}
```

**Use Cases**: Delivery notifications, bounce handling, statistics

### 7. Security Hooks (`SecurityHook`)

Executed for security-related checks.

```go
type SecurityHook interface {
    OnRateLimitCheck(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error)
    OnGreylistCheck(ctx *HookContext, sender, recipient string, remoteAddr net.Addr) (*PluginResult, error)
    OnReputationCheck(ctx *HookContext, remoteAddr net.Addr, domain string) (*PluginResult, error)
}
```

**Use Cases**: Rate limiting, greylisting, reputation management

### 8. Content Filter Hooks (`ContentFilterHook`)

Executed for content analysis.

```go
type ContentFilterHook interface {
    OnAntivirusScan(ctx *HookContext, content []byte) (*PluginResult, error)
    OnAntispamScan(ctx *HookContext, content []byte) (*PluginResult, error)
    OnContentFilter(ctx *HookContext, content []byte) (*PluginResult, error)
}
```

**Use Cases**: Virus scanning, spam detection, content analysis

### 9. Authentication Hooks (`AuthenticationHook`)

Executed for email authentication protocols.

```go
type AuthenticationHook interface {
    OnSPFCheck(ctx *HookContext, sender string, remoteAddr net.IP) (*PluginResult, error)
    OnDKIMVerify(ctx *HookContext, content []byte) (*PluginResult, error)
    OnDMARCCheck(ctx *HookContext, sender string, spfResult, dkimResult string) (*PluginResult, error)
}
```

**Use Cases**: SPF/DKIM/DMARC validation, authentication scoring

### 10. Metrics Hooks (`MetricsHook`)

Executed for metrics collection.

```go
type MetricsHook interface {
    OnMetricsCollect(ctx *HookContext, event string, data map[string]interface{}) error
}
```

**Use Cases**: Custom metrics, monitoring, analytics

### 11. Error Hooks (`ErrorHook`)

Executed when errors occur.

```go
type ErrorHook interface {
    OnError(ctx *HookContext, err error, phase ProcessingStage) (*PluginResult, error)
    OnRecovery(ctx *HookContext, recovered interface{}, phase ProcessingStage) (*PluginResult, error)
}
```

**Use Cases**: Error logging, alerting, recovery actions

## Configuration

### Enhanced Manager Configuration

```toml
[plugins]
enabled = true
plugin_path = "./plugins"
plugins = ["enhanced-security", "custom-filter"]
auto_reload = false
reload_interval = "5m"
health_check_interval = "30s"

[plugins.executor]
timeout = "30s"
max_concurrent = 10
enable_panic_recovery = true

[plugins.plugin_config.enhanced-security]
max_connections_per_minute = 60
greylist_ttl_minutes = 15

[plugins.plugin_config.custom-filter]
block_patterns = ["spam", "virus"]
scan_attachments = true
```

### YAML Configuration

```yaml
plugins:
  enabled: true
  plugin_path: "./plugins"
  plugins:
    - enhanced-security
    - custom-filter
  auto_reload: false
  reload_interval: 5m
  health_check_interval: 30s
  
  executor:
    timeout: 30s
    max_concurrent: 10
    enable_panic_recovery: true
  
  plugin_config:
    enhanced-security:
      max_connections_per_minute: 60
      greylist_ttl_minutes: 15
    custom-filter:
      block_patterns: ["spam", "virus"]
      scan_attachments: true
```

## Creating Enhanced Plugins

### Basic Plugin Structure

```go
package main

import (
    "github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo exported variable
var PluginInfo = &plugin.PluginInfo{
    Name:        "my-enhanced-plugin",
    Description: "My enhanced plugin with multiple hooks",
    Version:     "1.0.0",
    Type:        plugin.PluginTypeSecurity,
    Author:      "Your Name",
}

// Plugin exported variable
var Plugin = &MyEnhancedPlugin{}

// MyEnhancedPlugin implements multiple hook interfaces
type MyEnhancedPlugin struct {
    config map[string]interface{}
}

// Plugin interface implementation
func (p *MyEnhancedPlugin) GetInfo() plugin.PluginInfo {
    return *PluginInfo
}

func (p *MyEnhancedPlugin) Init(config map[string]interface{}) error {
    p.config = config
    // Initialize plugin resources
    return nil
}

func (p *MyEnhancedPlugin) Close() error {
    // Clean up plugin resources
    return nil
}

// ConnectionHook implementation
func (p *MyEnhancedPlugin) OnConnect(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
    // Implement connection logic
    return &plugin.PluginResult{
        Action:  plugin.ActionContinue,
        Message: "Connection allowed",
    }, nil
}

// SecurityHook implementation
func (p *MyEnhancedPlugin) OnRateLimitCheck(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
    // Implement rate limiting logic
    return &plugin.PluginResult{
        Action:  plugin.ActionContinue,
        Message: "Rate limit OK",
    }, nil
}
```

### Advanced Plugin with Multiple Hooks

See `examples/plugins/example_enhanced_security.go` for a comprehensive example implementing:
- Connection hooks for IP-based access control
- Security hooks for rate limiting, greylisting, and reputation
- Metrics hooks for statistics collection
- Configurable behavior through plugin configuration

## Error Isolation and Recovery

### Panic Recovery

The executor automatically recovers from plugin panics:

```go
// Plugin that panics
func (p *BadPlugin) OnConnect(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
    panic("Something went wrong")
}

// Executor handles the panic and continues processing
result := executor.ExecutePlugin("bad-plugin", pluginFunc)
if result.Recovered {
    log.Printf("Plugin panicked: %v", result.RecoverData)
}
```

### Timeout Handling

Plugins that run too long are automatically terminated:

```go
config := plugin.ExecutorConfig{
    Timeout: 30 * time.Second, // Kill plugins after 30 seconds
}
```

### Concurrency Control

Limit the number of concurrent plugin executions:

```go
config := plugin.ExecutorConfig{
    MaxConcurrent: 10, // Max 10 plugins running simultaneously
}
```

## Monitoring and Metrics

### Executor Metrics

The executor tracks comprehensive metrics:

```go
metrics := executor.GetMetrics()
fmt.Printf("Total executions: %d\n", metrics.TotalExecutions)
fmt.Printf("Successful: %d\n", metrics.SuccessfulExecutions)
fmt.Printf("Failed: %d\n", metrics.FailedExecutions)
fmt.Printf("Panic recoveries: %d\n", metrics.PanicRecoveries)
fmt.Printf("Timeouts: %d\n", metrics.TimeoutErrors)
```

### Plugin-Specific Metrics

Individual plugin performance is tracked:

```go
for name, stats := range metrics.PluginStats {
    fmt.Printf("Plugin %s:\n", name)
    fmt.Printf("  Executions: %d\n", stats.Executions)
    fmt.Printf("  Success rate: %.2f%%\n", 
        float64(stats.Successes)/float64(stats.Executions)*100)
    fmt.Printf("  Average time: %v\n", stats.AverageTime)
}
```

## Integration with SMTP Server

### Using Enhanced Manager

```go
// Initialize enhanced plugin manager
config := plugin.DefaultEnhancedConfig()
config.PluginPath = "./plugins"
config.Plugins = []string{"enhanced-security", "content-filter"}

pluginManager := plugin.NewEnhancedManager(config)
if err := pluginManager.Start(); err != nil {
    log.Fatalf("Failed to start plugin manager: %v", err)
}
defer pluginManager.Stop()

// Get hook executor
hookExecutor := pluginManager.ExecuteHooks()

// Execute hooks during SMTP processing
results := hookExecutor.OnConnect(sessionID, messageID, remoteAddr, localAddr)
for _, result := range results {
    if result.Result.Action == plugin.ActionReject {
        // Reject the connection
        return fmt.Errorf("Connection rejected: %s", result.Result.Message)
    }
}
```

### Hook Context Usage

```go
// Create rich context for hooks
hookCtx := plugin.NewHookContext(
    ctx,
    sessionID,
    messageID,
    remoteAddr,
    localAddr,
    plugin.StageConnect,
)

// Add custom data
hookCtx.Set("client_hostname", hostname)
hookCtx.Set("tls_enabled", tlsEnabled)

// Execute hooks with context
results := hookExecutor.OnConnect(sessionID, messageID, remoteAddr, localAddr)
```

## Best Practices

### Plugin Development

1. **Implement Multiple Hooks**: Use appropriate hook types for your functionality
2. **Handle Errors Gracefully**: Return meaningful error messages
3. **Be Performance Conscious**: Hooks are called frequently, optimize accordingly
4. **Use Configuration**: Make plugins configurable for different environments
5. **Log Appropriately**: Use structured logging for debugging

### Production Deployment

1. **Test Thoroughly**: Test all hook implementations under load
2. **Monitor Performance**: Watch plugin execution metrics
3. **Configure Timeouts**: Set appropriate timeouts for your environment
4. **Enable Panic Recovery**: Always enable panic recovery in production
5. **Use Health Checks**: Implement health check functions for critical plugins

### Security Considerations

1. **Validate Input**: Always validate data passed to hooks
2. **Limit Resource Usage**: Prevent plugins from consuming excessive resources
3. **Isolate Plugins**: Use the provided isolation mechanisms
4. **Regular Updates**: Keep plugins updated for security fixes
5. **Audit Plugin Code**: Review plugin code for security vulnerabilities

## Migration from Legacy System

### Compatibility

The enhanced system maintains compatibility with existing plugins while providing new capabilities:

```go
// Legacy plugin still works
type LegacyPlugin struct {
    plugin.AntivirusPluginBase
}

// Enhanced plugin with hooks
type EnhancedPlugin struct {
    plugin.AntivirusPluginBase
    // Additional hook implementations
}

func (p *EnhancedPlugin) OnConnect(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
    // New hook functionality
}
```

### Migration Steps

1. **Update Configuration**: Add enhanced manager configuration
2. **Update Initialization**: Replace old manager with enhanced manager
3. **Add Hook Support**: Implement new hook interfaces in existing plugins
4. **Test Integration**: Verify compatibility with existing functionality
5. **Enable New Features**: Gradually enable enhanced features

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**: Check plugin path and permissions
2. **Hooks Not Executing**: Verify plugin implements correct interfaces
3. **Performance Issues**: Check executor metrics and adjust timeouts
4. **Panic Recovery**: Review stack traces in panic recovery logs
5. **Configuration Errors**: Validate configuration syntax and values

### Debug Mode

Enable debug logging for detailed plugin execution information:

```go
config := plugin.ExecutorConfig{
    LogLevel: slog.LevelDebug,
}
```

### Health Monitoring

Check plugin manager status:

```go
status := pluginManager.GetStatus()
fmt.Printf("Lifecycle state: %s\n", status["lifecycle_state"])
fmt.Printf("Loaded plugins: %d\n", status["loaded_plugins"])
```

## Examples

See the `examples/plugins/` directory for complete plugin implementations:

- `example_enhanced_security.go`: Comprehensive security plugin with multiple hooks
- `example_policy.go`: Policy enforcement plugin
- `example_antivirus.go`: Basic antivirus plugin
- `example_antispam.go`: Basic antispam plugin

## API Reference

For detailed API documentation, see:
- `internal/plugin/hooks.go` - Hook interfaces and context
- `internal/plugin/executor.go` - Plugin executor and metrics
- `internal/plugin/enhanced_manager.go` - Enhanced manager and lifecycle
- `internal/plugin/types.go` - Core types and constants 