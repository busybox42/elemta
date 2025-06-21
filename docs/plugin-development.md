# Elemta Plugin Development Guide

This guide covers developing custom plugins for Elemta's extensible architecture.

## Plugin System Overview

Elemta's plugin system allows you to extend functionality through:
- **Antivirus plugins**: Virus and malware scanning
- **Antispam plugins**: Spam detection and scoring
- **Authentication plugins**: SPF, DKIM, DMARC, ARC validation
- **Content filters**: Custom message processing
- **Delivery handlers**: Custom delivery mechanisms

## Plugin Architecture

### Plugin Types

All plugins implement specific interfaces defined in `internal/plugin/types.go`:

```go
type Plugin interface {
    GetInfo() *PluginInfo
    Initialize(config map[string]interface{}) error
    Cleanup() error
}

type PluginInfo struct {
    Name        string
    Version     string
    Description string
    Author      string
    License     string
}
```

### Plugin Loading

Plugins are Go shared libraries (`.so` files) that are loaded dynamically:

1. **Discovery**: Plugin manager scans plugin directory
2. **Symbol lookup**: Finds exported `Plugin` symbol
3. **Type assertion**: Casts to appropriate interface
4. **Initialization**: Calls `Initialize()` with configuration
5. **Registration**: Registers with appropriate hooks

## Developing a Simple Plugin

### 1. Basic Plugin Structure

Create a new directory for your plugin:
```bash
mkdir -p plugins/myplugin
cd plugins/myplugin
```

**main.go**:
```go
package main

import (
    "context"
    "fmt"
    
    "github.com/busybox42/elemta/internal/plugin"
)

// MyPlugin implements the Plugin interface
type MyPlugin struct {
    config map[string]interface{}
}

// GetInfo returns plugin metadata
func (p *MyPlugin) GetInfo() *plugin.PluginInfo {
    return &plugin.PluginInfo{
        Name:        "MyPlugin",
        Version:     "1.0.0",
        Description: "Example plugin for demonstration",
        Author:      "Your Name",
        License:     "MIT",
    }
}

// Initialize sets up the plugin with configuration
func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    p.config = config
    fmt.Println("MyPlugin initialized")
    return nil
}

// Cleanup performs any necessary cleanup
func (p *MyPlugin) Cleanup() error {
    fmt.Println("MyPlugin cleanup")
    return nil
}

// Plugin is the exported symbol that Elemta looks for
var Plugin MyPlugin
```

### 2. Build the Plugin

**Makefile**:
```makefile
PLUGIN_NAME=myplugin
PLUGIN_SO=$(PLUGIN_NAME).so

.PHONY: build clean install

build:
	go build -buildmode=plugin -o $(PLUGIN_SO) .

clean:
	rm -f $(PLUGIN_SO)

install: build
	cp $(PLUGIN_SO) ../../bin/plugins/

test:
	go test -v ./...
```

Build the plugin:
```bash
make build
```

## Antivirus Plugin Example

### Interface Implementation

```go
package main

import (
    "context"
    "fmt"
    "os/exec"
    "strings"
    "time"
    
    "github.com/busybox42/elemta/internal/plugin"
)

type ClamAVPlugin struct {
    socketPath string
    timeout    time.Duration
}

// Implement AntivirusPlugin interface
func (p *ClamAVPlugin) ScanMessage(ctx context.Context, message *plugin.Message) (*plugin.ScanResult, error) {
    // Create temporary file with message content
    tempFile, err := p.writeMessageToTempFile(message)
    if err != nil {
        return nil, fmt.Errorf("failed to write temp file: %w", err)
    }
    defer os.Remove(tempFile)
    
    // Run ClamAV scan
    ctx, cancel := context.WithTimeout(ctx, p.timeout)
    defer cancel()
    
    cmd := exec.CommandContext(ctx, "clamdscan", "--fdpass", tempFile)
    output, err := cmd.Output()
    
    result := &plugin.ScanResult{
        PluginName: "ClamAV",
        ScanTime:   time.Now(),
        Clean:      true,
    }
    
    if err != nil {
        // Check if it's a detection (exit code 1) or real error
        if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
            result.Clean = false
            result.ThreatName = p.extractThreatName(string(output))
            result.Action = plugin.ActionReject
        } else {
            return nil, fmt.Errorf("clamav scan failed: %w", err)
        }
    }
    
    return result, nil
}

func (p *ClamAVPlugin) extractThreatName(output string) string {
    lines := strings.Split(output, "\n")
    for _, line := range lines {
        if strings.Contains(line, "FOUND") {
            parts := strings.Split(line, ":")
            if len(parts) >= 2 {
                return strings.TrimSpace(parts[1])
            }
        }
    }
    return "Unknown threat"
}

func (p *ClamAVPlugin) writeMessageToTempFile(message *plugin.Message) (string, error) {
    tempFile, err := os.CreateTemp("", "elemta-scan-*")
    if err != nil {
        return "", err
    }
    
    _, err = tempFile.Write(message.RawData)
    if err != nil {
        tempFile.Close()
        os.Remove(tempFile.Name())
        return "", err
    }
    
    tempFile.Close()
    return tempFile.Name(), nil
}

// GetInfo returns plugin information
func (p *ClamAVPlugin) GetInfo() *plugin.PluginInfo {
    return &plugin.PluginInfo{
        Name:        "ClamAV",
        Version:     "1.0.0",
        Description: "ClamAV antivirus scanner",
        Author:      "Elemta Team",
        License:     "MIT",
    }
}

// Initialize configures the plugin
func (p *ClamAVPlugin) Initialize(config map[string]interface{}) error {
    // Set default socket path
    p.socketPath = "/var/run/clamav/clamd.ctl"
    p.timeout = 30 * time.Second
    
    // Override with configuration if provided
    if socketPath, ok := config["socket_path"].(string); ok {
        p.socketPath = socketPath
    }
    
    if timeout, ok := config["timeout"].(int); ok {
        p.timeout = time.Duration(timeout) * time.Second
    }
    
    // Test ClamAV connectivity
    if err := p.testConnection(); err != nil {
        return fmt.Errorf("failed to connect to ClamAV: %w", err)
    }
    
    return nil
}

func (p *ClamAVPlugin) testConnection() error {
    cmd := exec.Command("clamdscan", "--version")
    return cmd.Run()
}

func (p *ClamAVPlugin) Cleanup() error {
    return nil
}

// Export the plugin
var Plugin ClamAVPlugin
```

## Antispam Plugin Example

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
    
    "github.com/busybox42/elemta/internal/plugin"
)

type RSpamdPlugin struct {
    url        string
    timeout    time.Duration
    httpClient *http.Client
}

// RSpamd API response structure
type RSpamdResponse struct {
    Score   float64 `json:"score"`
    Action  string  `json:"action"`
    Symbols map[string]struct {
        Score       float64 `json:"score"`
        Description string  `json:"description"`
    } `json:"symbols"`
}

func (p *RSpamdPlugin) ScanMessage(ctx context.Context, message *plugin.Message) (*plugin.ScanResult, error) {
    // Create request to RSpamd
    req, err := http.NewRequestWithContext(ctx, "POST", p.url+"/symbols", bytes.NewReader(message.RawData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    req.Header.Set("Content-Type", "text/plain")
    
    // Send request
    resp, err := p.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("rspamd request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("rspamd returned status %d", resp.StatusCode)
    }
    
    // Parse response
    var rspamdResp RSpamdResponse
    if err := json.NewDecoder(resp.Body).Decode(&rspamdResp); err != nil {
        return nil, fmt.Errorf("failed to parse rspamd response: %w", err)
    }
    
    // Create scan result
    result := &plugin.ScanResult{
        PluginName: "RSpamd",
        ScanTime:   time.Now(),
        Score:      rspamdResp.Score,
        Clean:      rspamdResp.Action == "no action",
    }
    
    // Determine action based on score and RSpamd action
    switch rspamdResp.Action {
    case "reject":
        result.Action = plugin.ActionReject
    case "soft reject":
        result.Action = plugin.ActionTempFail
    case "greylist":
        result.Action = plugin.ActionGreylist
    case "add header", "rewrite subject":
        result.Action = plugin.ActionAddHeader
    default:
        result.Action = plugin.ActionAccept
    }
    
    // Add detected symbols as metadata
    if len(rspamdResp.Symbols) > 0 {
        symbols := make([]string, 0, len(rspamdResp.Symbols))
        for symbol := range rspamdResp.Symbols {
            symbols = append(symbols, symbol)
        }
        result.Metadata = map[string]interface{}{
            "symbols": symbols,
        }
    }
    
    return result, nil
}

func (p *RSpamdPlugin) GetScore(ctx context.Context, message *plugin.Message) (float64, error) {
    result, err := p.ScanMessage(ctx, message)
    if err != nil {
        return 0, err
    }
    return result.Score, nil
}

func (p *RSpamdPlugin) GetInfo() *plugin.PluginInfo {
    return &plugin.PluginInfo{
        Name:        "RSpamd",
        Version:     "1.0.0",
        Description: "RSpamd spam detection and scoring",
        Author:      "Elemta Team",
        License:     "MIT",
    }
}

func (p *RSpamdPlugin) Initialize(config map[string]interface{}) error {
    // Set defaults
    p.url = "http://localhost:11333"
    p.timeout = 10 * time.Second
    
    // Override with configuration
    if url, ok := config["url"].(string); ok {
        p.url = url
    }
    
    if timeout, ok := config["timeout"].(int); ok {
        p.timeout = time.Duration(timeout) * time.Second
    }
    
    // Create HTTP client
    p.httpClient = &http.Client{
        Timeout: p.timeout,
    }
    
    // Test connectivity
    if err := p.testConnection(); err != nil {
        return fmt.Errorf("failed to connect to RSpamd: %w", err)
    }
    
    return nil
}

func (p *RSpamdPlugin) testConnection() error {
    req, err := http.NewRequest("GET", p.url+"/stat", nil)
    if err != nil {
        return err
    }
    
    resp, err := p.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("rspamd health check failed: status %d", resp.StatusCode)
    }
    
    return nil
}

func (p *RSpamdPlugin) Cleanup() error {
    return nil
}

var Plugin RSpamdPlugin
```

## DKIM Plugin Example

```go
package main

import (
    "context"
    "crypto/rsa"
    "fmt"
    "strings"
    "time"
    
    "github.com/emersion/go-msgauth/dkim"
    "github.com/busybox42/elemta/internal/plugin"
)

type DKIMPlugin struct {
    privateKey *rsa.PrivateKey
    selector   string
    domain     string
}

func (p *DKIMPlugin) VerifySignature(ctx context.Context, message *plugin.Message) (*plugin.DKIMResult, error) {
    // Parse DKIM signature from headers
    headers := p.parseHeaders(message.RawData)
    dkimHeader, exists := headers["DKIM-Signature"]
    if !exists {
        return &plugin.DKIMResult{
            Valid:   false,
            Reason:  "No DKIM signature found",
            SignedBy: "",
        }, nil
    }
    
    // Verify the signature
    verifier, err := dkim.NewVerifier()
    if err != nil {
        return nil, fmt.Errorf("failed to create DKIM verifier: %w", err)
    }
    
    result, err := verifier.Verify(strings.NewReader(string(message.RawData)))
    if err != nil {
        return &plugin.DKIMResult{
            Valid:   false,
            Reason:  err.Error(),
            SignedBy: p.extractDomain(dkimHeader),
        }, nil
    }
    
    return &plugin.DKIMResult{
        Valid:     true,
        Reason:    "Signature valid",
        SignedBy:  result.Domain,
        Selector:  result.Selector,
        Algorithm: result.Algo,
    }, nil
}

func (p *DKIMPlugin) SignMessage(ctx context.Context, message *plugin.Message, domain string) error {
    if p.privateKey == nil {
        return fmt.Errorf("no private key configured for signing")
    }
    
    // Create DKIM signer
    options := &dkim.SignOptions{
        Domain:   domain,
        Selector: p.selector,
        Signer:   p.privateKey,
        Hash:     "sha256",
        HeaderKeys: []string{
            "from", "to", "subject", "date", "message-id",
        },
    }
    
    signer, err := dkim.NewSigner(options)
    if err != nil {
        return fmt.Errorf("failed to create DKIM signer: %w", err)
    }
    
    // Sign the message
    var signedMessage strings.Builder
    if err := signer.Sign(&signedMessage, strings.NewReader(string(message.RawData))); err != nil {
        return fmt.Errorf("failed to sign message: %w", err)
    }
    
    // Update message with signed version
    message.RawData = []byte(signedMessage.String())
    
    return nil
}

func (p *DKIMPlugin) parseHeaders(rawMessage []byte) map[string]string {
    headers := make(map[string]string)
    lines := strings.Split(string(rawMessage), "\n")
    
    var currentHeader, currentValue string
    for _, line := range lines {
        line = strings.TrimRight(line, "\r")
        if line == "" {
            // End of headers
            if currentHeader != "" {
                headers[currentHeader] = currentValue
            }
            break
        }
        
        if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
            // Continuation of previous header
            currentValue += " " + strings.TrimSpace(line)
        } else {
            // New header
            if currentHeader != "" {
                headers[currentHeader] = currentValue
            }
            
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 {
                currentHeader = strings.TrimSpace(parts[0])
                currentValue = strings.TrimSpace(parts[1])
            }
        }
    }
    
    return headers
}

func (p *DKIMPlugin) extractDomain(dkimHeader string) string {
    // Simple extraction of d= parameter
    parts := strings.Split(dkimHeader, ";")
    for _, part := range parts {
        trimmed := strings.TrimSpace(part)
        if strings.HasPrefix(trimmed, "d=") {
            return strings.TrimSpace(trimmed[2:])
        }
    }
    return ""
}

func (p *DKIMPlugin) GetInfo() *plugin.PluginInfo {
    return &plugin.PluginInfo{
        Name:        "DKIM",
        Version:     "1.0.0",
        Description: "DKIM signature verification and signing",
        Author:      "Elemta Team",
        License:     "MIT",
    }
}

func (p *DKIMPlugin) Initialize(config map[string]interface{}) error {
    // Set defaults
    p.selector = "default"
    
    // Load configuration
    if selector, ok := config["selector"].(string); ok {
        p.selector = selector
    }
    
    if domain, ok := config["domain"].(string); ok {
        p.domain = domain
    }
    
    // Load private key for signing (optional)
    if keyPath, ok := config["private_key_path"].(string); ok {
        if err := p.loadPrivateKey(keyPath); err != nil {
            return fmt.Errorf("failed to load private key: %w", err)
        }
    }
    
    return nil
}

func (p *DKIMPlugin) loadPrivateKey(keyPath string) error {
    // Implementation would load RSA private key from file
    // This is a simplified version
    return nil
}

func (p *DKIMPlugin) Cleanup() error {
    return nil
}

var Plugin DKIMPlugin
```

## Plugin Configuration

### Configuration Format

Plugins are configured in the main `elemta.toml` file:

```toml
[plugins]
enabled = true
directory = "/app/plugins"
plugins = ["clamav", "rspamd", "dkim", "spf", "dmarc"]

# Plugin-specific configuration
[plugins.clamav]
socket_path = "/var/run/clamav/clamd.ctl"
timeout = 30

[plugins.rspamd]
url = "http://rspamd:11333"
timeout = 10
score_threshold = 5.0

[plugins.dkim]
selector = "elemta"
domain = "example.com"
private_key_path = "/app/keys/dkim.key"
```

### Environment-Based Configuration

```go
func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    // Load from config first
    timeout := 30
    if t, ok := config["timeout"].(int); ok {
        timeout = t
    }
    
    // Override with environment variable
    if envTimeout := os.Getenv("MYPLUGIN_TIMEOUT"); envTimeout != "" {
        if t, err := strconv.Atoi(envTimeout); err == nil {
            timeout = t
        }
    }
    
    p.timeout = time.Duration(timeout) * time.Second
    return nil
}
```

## Testing Plugins

### Unit Testing

**plugin_test.go**:
```go
package main

import (
    "context"
    "testing"
    "time"
    
    "github.com/busybox42/elemta/internal/plugin"
)

func TestMyPluginInitialization(t *testing.T) {
    p := &MyPlugin{}
    
    config := map[string]interface{}{
        "timeout": 30,
        "enabled": true,
    }
    
    if err := p.Initialize(config); err != nil {
        t.Fatalf("Failed to initialize plugin: %v", err)
    }
    
    // Test that configuration was applied
    if p.timeout != 30*time.Second {
        t.Errorf("Expected timeout 30s, got %v", p.timeout)
    }
}

func TestScanMessage(t *testing.T) {
    p := &ClamAVPlugin{}
    
    // Initialize with test config
    config := map[string]interface{}{
        "socket_path": "/tmp/test-clamd.ctl",
        "timeout":     10,
    }
    
    if err := p.Initialize(config); err != nil {
        t.Skipf("ClamAV not available: %v", err)
    }
    
    // Test message
    message := &plugin.Message{
        From:    "test@example.com",
        To:      []string{"user@example.com"},
        Subject: "Test Message",
        RawData: []byte("This is a test message"),
    }
    
    ctx := context.Background()
    result, err := p.ScanMessage(ctx, message)
    if err != nil {
        t.Fatalf("Scan failed: %v", err)
    }
    
    if !result.Clean {
        t.Errorf("Expected clean message, got threat: %s", result.ThreatName)
    }
}
```

### Integration Testing

```bash
# Test plugin loading
./bin/elemta plugin test /app/plugins/myplugin.so

# Test with real message
echo "Test message" | ./bin/elemta plugin scan myplugin

# Performance testing
./bin/elemta plugin benchmark myplugin --duration 60s
```

## Best Practices

### Error Handling

```go
func (p *MyPlugin) ScanMessage(ctx context.Context, message *plugin.Message) (*plugin.ScanResult, error) {
    // Always check context cancellation
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
    }
    
    // Use timeouts for external calls
    ctx, cancel := context.WithTimeout(ctx, p.timeout)
    defer cancel()
    
    // Wrap errors with context
    result, err := p.performScan(ctx, message)
    if err != nil {
        return nil, fmt.Errorf("scan failed for message %s: %w", message.ID, err)
    }
    
    return result, nil
}
```

### Resource Management

```go
type MyPlugin struct {
    pool      *connectionPool
    semaphore chan struct{} // Limit concurrent operations
}

func (p *MyPlugin) Initialize(config map[string]interface{}) error {
    // Limit concurrent scans
    maxConcurrent := 10
    if mc, ok := config["max_concurrent"].(int); ok {
        maxConcurrent = mc
    }
    p.semaphore = make(chan struct{}, maxConcurrent)
    
    return nil
}

func (p *MyPlugin) ScanMessage(ctx context.Context, message *plugin.Message) (*plugin.ScanResult, error) {
    // Acquire semaphore
    select {
    case p.semaphore <- struct{}{}:
        defer func() { <-p.semaphore }()
    case <-ctx.Done():
        return nil, ctx.Err()
    }
    
    // Perform scan...
    return result, nil
}
```

### Logging

```go
import "log/slog"

func (p *MyPlugin) ScanMessage(ctx context.Context, message *plugin.Message) (*plugin.ScanResult, error) {
    logger := slog.With(
        "plugin", "myplugin",
        "message_id", message.ID,
        "from", message.From,
    )
    
    logger.Info("Starting message scan")
    
    result, err := p.performScan(ctx, message)
    if err != nil {
        logger.Error("Scan failed", "error", err)
        return nil, err
    }
    
    logger.Info("Scan completed", 
        "clean", result.Clean,
        "score", result.Score,
        "duration", time.Since(result.ScanTime))
    
    return result, nil
}
```

## Deployment

### Plugin Installation

```bash
# Build plugin
make build

# Install to plugin directory
sudo cp myplugin.so /opt/elemta/plugins/

# Update configuration
sudo vim /etc/elemta/elemta.toml
# Add plugin to plugins.plugins array

# Restart Elemta
sudo systemctl restart elemta
```

### Docker Deployment

**Dockerfile.plugin**:
```dockerfile
FROM golang:1.23-alpine AS builder

WORKDIR /build
COPY . .
RUN go mod download
RUN go build -buildmode=plugin -o myplugin.so .

FROM alpine:latest
COPY --from=builder /build/myplugin.so /plugins/
```

### Plugin Versioning

Use semantic versioning and plugin metadata:

```go
func (p *MyPlugin) GetInfo() *plugin.PluginInfo {
    return &plugin.PluginInfo{
        Name:         "MyPlugin",
        Version:      "1.2.3",
        Description:  "Enhanced plugin with new features",
        Author:       "Your Name",
        License:      "MIT",
        APIVersion:   "1.0",  // Elemta plugin API version
        Dependencies: []string{"clamav>=0.103"},
    }
}
```

## Security Considerations

1. **Input Validation**: Always validate message data
2. **Resource Limits**: Implement timeouts and concurrency limits
3. **Error Handling**: Don't expose sensitive information in errors
4. **Dependencies**: Keep external dependencies updated
5. **Sandboxing**: Use the plugin sandbox features for isolation

## Performance Tips

1. **Connection Pooling**: Reuse connections to external services
2. **Caching**: Cache results when appropriate
3. **Async Processing**: Use goroutines for I/O operations
4. **Memory Management**: Stream large messages, don't load entirely
5. **Profiling**: Use Go's profiling tools to identify bottlenecks

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**:
   - Check file permissions
   - Verify plugin symbol export
   - Check Go version compatibility

2. **Configuration Not Working**:
   - Verify TOML syntax
   - Check configuration keys
   - Enable debug logging

3. **Performance Issues**:
   - Monitor resource usage
   - Check external service latency
   - Review concurrency settings

### Debug Tools

```bash
# Test plugin functionality
./bin/elemta plugin test myplugin.so

# Debug plugin loading
./bin/elemta --log-level debug plugin load myplugin.so

# Profile plugin performance
go tool pprof http://localhost:8081/debug/pprof/profile
``` 