# Plugin Module Documentation

**Location**: `internal/plugin/`
**Purpose**: Extensible plugin system for email security and processing

## Overview
The Plugin module provides a flexible architecture for extending Elemta with custom functionality, including email security features, content filtering, and processing enhancements.

## Key Components

### Manager (`manager.go`)
**Responsibilities**:
- Plugin discovery and loading
- Plugin lifecycle management
- Plugin execution coordination
- Error handling and isolation

**Key Functions**:
- `NewManager(pluginPath string)` - Creates plugin manager
- `LoadPlugin(name string)` - Loads individual plugin
- `LoadPlugins()` - Loads all plugins from directory
- `ExecuteStage(stage, context)` - Executes plugins for processing stage

### Plugin Types (`types.go`)
**Defines interfaces for**:
- Antivirus plugins
- Antispam plugins
- Authentication plugins (DKIM, SPF, DMARC, ARC)
- Custom processing plugins

## Plugin Types

### Security Plugins

#### Antivirus (`antivirus.go`)
```go
type AntivirusPlugin interface {
    ScanMessage(ctx context.Context, message *Message) (*ScanResult, error)
    GetInfo() *PluginInfo
}
```
- **Purpose**: Virus and malware detection
- **Examples**: ClamAV integration
- **Result**: Clean, Infected, or Error

#### Antispam (`antispam.go`)
```go
type AntispamPlugin interface {
    ScanMessage(ctx context.Context, message *Message) (*ScanResult, error)
    GetScore(ctx context.Context, message *Message) (float64, error)
}
```
- **Purpose**: Spam detection and scoring
- **Examples**: RSpamd integration
- **Result**: Spam score and classification

### Authentication Plugins

#### DKIM (`dkim.go`)
```go
type DKIMPlugin interface {
    VerifySignature(ctx context.Context, message *Message) (*DKIMResult, error)
    SignMessage(ctx context.Context, message *Message, domain string) error
}
```
- **Purpose**: DKIM signature verification and signing
- **Operations**: Verify incoming, sign outgoing

#### SPF (`spf.go`)
```go
type SPFPlugin interface {
    CheckSPF(ctx context.Context, ip string, domain string) (*SPFResult, error)
}
```
- **Purpose**: Sender Policy Framework validation
- **Operations**: IP authorization checking

#### DMARC (`dmarc.go`)
```go
type DMARCPlugin interface {
    CheckDMARC(ctx context.Context, message *Message) (*DMARCResult, error)
}
```
- **Purpose**: DMARC policy evaluation
- **Operations**: Policy lookup and alignment checking

#### ARC (`arc.go`)
```go
type ARCPlugin interface {
    VerifyChain(ctx context.Context, message *Message) (*ARCResult, error)
    SealMessage(ctx context.Context, message *Message) error
}
```
- **Purpose**: Authenticated Received Chain processing
- **Operations**: Chain verification and sealing

## Plugin Loading

### Discovery Process
1. **Directory Scan**: Scan plugin directory for `.so` files
2. **Symbol Lookup**: Find required plugin symbols
3. **Interface Validation**: Verify plugin implements required interface
4. **Registration**: Register plugin with appropriate type manager

### Loading Mechanism
```go
// Load plugin from shared library
p, err := plugin.Open(pluginPath)
if err != nil {
    return err
}

// Look up plugin symbol
sym, err := p.Lookup("Plugin")
if err != nil {
    return err
}

// Cast to appropriate interface
antivirusPlugin, ok := sym.(AntivirusPlugin)
```

## Processing Stages

### Message Processing Pipeline
1. **Pre-Reception**: Before message acceptance
2. **Post-Reception**: After message received
3. **Pre-Queue**: Before queuing for delivery
4. **Pre-Delivery**: Before delivery attempt
5. **Post-Delivery**: After delivery completion

### Stage Execution
```go
// Execute all plugins for a stage
result, err := pluginManager.ExecuteStage(
    PreReception,
    &ProcessingContext{
        Message: message,
        Session: session,
    },
)
```

## Inputs
- **Email Messages**: Raw email data for processing
- **Processing Context**: Session information, metadata
- **Configuration**: Plugin-specific settings

## Outputs
- **Processing Results**: Accept, reject, or modify decisions
- **Scores and Classifications**: Spam scores, threat levels
- **Modified Messages**: Headers added or content modified
- **Metrics**: Plugin performance and effectiveness data

## Dependencies
- Go plugin system (`plugin` package)
- Context for cancellation and timeouts
- Logging system for plugin activities

## Configuration
```toml
[plugins]
enabled = true
directory = "/app/plugins"
plugins = [
    "clamav",
    "rspamd", 
    "dkim",
    "spf",
    "dmarc"
]

[plugins.clamav]
socket = "/var/run/clamav/clamd.ctl"
timeout = 30

[plugins.rspamd]
url = "http://rspamd:11333"
timeout = 10

[plugins.dkim]
selector = "default"
private_key = "/app/keys/dkim.key"
```

## Example Usage

### Plugin Development
```go
package main

import (
    "context"
    "github.com/busybox42/elemta/internal/plugin"
)

type MyAntivirusPlugin struct {
    config *Config
}

func (p *MyAntivirusPlugin) ScanMessage(ctx context.Context, msg *plugin.Message) (*plugin.ScanResult, error) {
    // Implement virus scanning logic
    return &plugin.ScanResult{
        Status: plugin.StatusClean,
        Details: "No threats detected",
    }, nil
}

func (p *MyAntivirusPlugin) GetInfo() *plugin.PluginInfo {
    return &plugin.PluginInfo{
        Name:    "MyAntivirus",
        Version: "1.0.0",
        Type:    plugin.PluginTypeAntivirus,
    }
}

// Export plugin symbol
var Plugin MyAntivirusPlugin
```

### Plugin Usage
```go
// Load plugin manager
manager := plugin.NewManager("/app/plugins")

// Load all plugins
err := manager.LoadPlugins()

// Get specific plugin
antivirusPlugin, err := manager.GetAntivirusPlugin("clamav")

// Scan message
result, err := antivirusPlugin.ScanMessage(ctx, message)
if result.Status == plugin.StatusInfected {
    // Handle infected message
}
```

## Security Considerations
- **Plugin Isolation**: Plugins run in separate address space
- **Resource Limits**: Timeout and memory limits for plugin execution
- **Input Validation**: All plugin inputs validated
- **Error Handling**: Plugin failures don't crash main server

## Performance Notes
- **Hot Loading**: Plugins can be loaded without server restart
- **Caching**: Plugin results cached when appropriate
- **Parallel Execution**: Multiple plugins can run concurrently
- **Metrics**: Plugin execution time and success rates monitored

## Plugin Development Guidelines

### Interface Implementation
- Implement all required interface methods
- Handle context cancellation properly
- Return meaningful error messages
- Provide plugin information metadata

### Error Handling
- Use context for timeout handling
- Return specific error types when possible
- Log errors appropriately
- Fail gracefully without crashing

### Performance Best Practices
- Minimize processing time
- Use connection pooling for external services
- Cache expensive operations
- Respect context deadlines

## Available Plugins

### Built-in Plugins
- **ClamAV**: Antivirus scanning via ClamAV daemon
- **RSpamd**: Spam detection via RSpamd service
- **DKIM**: DKIM signature verification and signing
- **SPF**: SPF policy validation
- **DMARC**: DMARC policy enforcement
- **ARC**: ARC chain processing

### Example Plugins
- **Greylisting**: Temporary rejection for unknown senders
- **Rate Limiting**: Connection and message rate limiting
- **Content Filter**: Custom content-based filtering

## Troubleshooting

### Common Issues
1. **Plugin Not Loading**: Check file permissions and dependencies
2. **Symbol Not Found**: Verify plugin exports correct symbols
3. **Interface Mismatch**: Ensure plugin implements required interface
4. **Runtime Errors**: Check plugin logs and error handling

### Debugging
```bash
# List loaded plugins
elemta-cli plugins list

# Test plugin loading
elemta-cli plugins test <plugin-name>

# View plugin metrics
elemta-cli plugins metrics

# Plugin-specific logs
tail -f /app/logs/plugins/<plugin-name>.log
```

## Future Enhancements
- Plugin marketplace and distribution
- Plugin configuration UI
- Advanced plugin orchestration
- Plugin performance optimization
- Plugin security sandboxing 