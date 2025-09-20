# Secure Plugin System Test Suite

## Overview
This document tests the comprehensive secure plugin system implemented in Elemta SMTP server to eliminate CGO security vulnerabilities, provide proper sandboxing, input/output validation, resource limits, and process isolation.

## Security Enhancements Implemented

### 1. CGO-Free Plugin Architecture
- **Process-Based Isolation**: Plugins run in separate processes, not shared libraries
- **No CGO Dependencies**: Eliminates memory safety risks and attack surface
- **Static Linking**: All plugins are statically linked with no dynamic dependencies
- **JSON Communication**: Secure inter-process communication via stdin/stdout
- **Binary Validation**: Comprehensive plugin binary and checksum verification

### 2. Plugin Sandboxing and Isolation
- **Process Sandboxing**: Each plugin runs in isolated process with restricted environment
- **Resource Limits**: Memory, CPU, execution time, and file descriptor limits
- **Capability Restrictions**: Granular control over filesystem, network, and system access
- **Secure Environment**: Minimal environment variables and restricted PATH
- **Sandbox Cleanup**: Automatic cleanup of plugin sandbox environments

### 3. Input/Output Validation and Sanitization
- **Comprehensive Input Validation**: Email addresses, headers, body, metadata validation
- **Output Sanitization**: Plugin output validation and threat detection
- **Injection Prevention**: SQL injection, command injection, header injection protection
- **Size Limits**: Message size, header count, metadata limits
- **UTF-8 Validation**: Character encoding validation and suspicious pattern detection

### 4. Resource Management and Monitoring
- **Resource Monitoring**: Real-time tracking of memory, CPU, and execution time
- **Resource Limits Enforcement**: Configurable limits with violation detection
- **Health Monitoring**: Continuous plugin health checks and status tracking
- **Performance Metrics**: Request counts, error rates, and response times
- **Automatic Cleanup**: Resource cleanup on plugin shutdown or failure

### 5. Plugin Lifecycle Management
- **Secure Loading**: Plugin validation, checksum verification, and capability checks
- **Graceful Shutdown**: Proper plugin shutdown with resource cleanup
- **Error Recovery**: Plugin failure isolation without server crash
- **Hot Reloading**: Safe plugin reloading with validation
- **Statistics Tracking**: Comprehensive plugin usage and performance statistics

## Secure Plugin Architecture

### Plugin Communication Protocol
```json
{
  "type": "process_message",
  "id": "msg-12345",
  "data": {
    "message_id": "msg-abc123",
    "from": "sender@example.com",
    "to": ["recipient@example.com"],
    "subject": "Test Message",
    "headers": {"X-Test": "value"},
    "body": "base64-encoded-content",
    "metadata": {"key": "value"},
    "timestamp": "2025-09-20T05:55:40Z",
    "remote_addr": "192.168.1.100:12345",
    "tls_enabled": true
  },
  "timestamp": "2025-09-20T05:55:40Z"
}
```

### Plugin Response Format
```json
{
  "type": "response",
  "id": "msg-12345",
  "data": {
    "action": "continue",
    "score": 25.5,
    "message": "Suspicious content detected",
    "headers": {"X-Scan-Result": "suspicious"},
    "modified_body": null,
    "metadata": {"threat_level": "low"},
    "errors": [],
    "warnings": ["Suspicious subject pattern"]
  },
  "timestamp": "2025-09-20T05:55:40Z"
}
```

### Resource Limits Configuration
```go
type PluginResourceLimits struct {
    MaxMemoryMB      int64         // 50MB default
    MaxCPUPercent    float64       // 10% default
    MaxExecutionTime time.Duration // 30 seconds default
    MaxFileSize      int64         // 10MB default
    MaxNetworkOps    int           // 100 operations default
    AllowedPaths     []string      // ["/tmp/elemta-plugin"]
    BlockedSyscalls  []string      // ["execve", "fork", "clone", ...]
}
```

## Test Cases

### CGO Elimination Testing

#### Static Linking Verification (Should Pass)
```bash
# Test: Verify plugins are statically linked
cd secure-plugins
make build-example-antivirus
file example-antivirus/plugin
ldd example-antivirus/plugin 2>/dev/null || echo "No dynamic dependencies - PASS"
```
**Expected Result**: Plugin is statically linked with no dynamic dependencies
**Security Benefit**: Eliminates shared library attack vectors
**Verification**: `file` shows "statically linked", `ldd` shows "not a dynamic executable"

#### CGO Usage Detection (Should Fail)
```bash
# Test: Detect any CGO usage in plugin code
cd secure-plugins
grep -r "import.*\"C\"" */ && echo "FAIL: CGO detected" || echo "PASS: No CGO usage"
grep -r "#cgo" */ && echo "FAIL: CGO directives found" || echo "PASS: No CGO directives"
```
**Expected Result**: No CGO usage detected in any plugin
**Security Benefit**: Eliminates memory safety vulnerabilities
**Verification**: No `import "C"` or `#cgo` directives found

#### Binary Security Analysis
```bash
# Test: Analyze plugin binary for security issues
cd secure-plugins/example-antivirus
objdump -x plugin | grep -E "(NEEDED|INTERP)" || echo "PASS: No dynamic dependencies"
strings plugin | grep -E "(libc|libssl|libcrypto)" || echo "PASS: No library references"
```
**Expected Result**: No references to dynamic libraries or interpreters
**Security Benefit**: Reduces attack surface and dependency vulnerabilities

### Plugin Sandboxing Testing

#### Process Isolation Verification (Should Isolate)
```bash
# Test: Verify plugin runs in separate process
cd secure-plugins/example-antivirus
timeout 5 ./plugin &
PLUGIN_PID=$!
ps -p $PLUGIN_PID -o pid,ppid,comm,args
kill $PLUGIN_PID
```
**Expected Result**: Plugin runs as separate process with restricted environment
**Security Benefit**: Process isolation prevents main server compromise
**Verification**: Plugin has different PID and process group

#### Resource Limits Testing (Should Enforce Limits)
```bash
# Test: Plugin resource limit enforcement
# This would be tested through the main server's resource monitoring
```
**Expected Result**: Plugin resource usage stays within configured limits
**Resource Limits**: Memory < 50MB, CPU < 10%, Execution < 30s
**Enforcement**: Plugin terminated or throttled if limits exceeded

#### Sandbox Environment Verification
```bash
# Test: Verify plugin runs in restricted environment
cd secure-plugins/example-antivirus
echo '{"type":"command","command":"initialize","data":{}}' | timeout 5 ./plugin | grep "ready"
```
**Expected Result**: Plugin initializes successfully in sandbox
**Security Benefit**: Restricted environment prevents system access
**Verification**: Plugin responds with ready message

### Input/Output Validation Testing

#### Email Address Validation (Should Validate)
```go
// Test: Comprehensive email validation
input := &SecurePluginInput{
    From: "test@example.com",
    To: []string{"valid@example.com", "invalid-email"},
    // ... other fields
}
err := validator.ValidateInput(input)
// Should detect invalid email in To field
```
**Expected Result**: Invalid email addresses detected and rejected
**Security Benefit**: Prevents email injection attacks
**Validation**: RFC 5322 compliance, length limits, suspicious patterns

#### Header Injection Prevention (Should Block)
```go
// Test: Header injection detection
input := &SecurePluginInput{
    Headers: map[string]string{
        "X-Test": "value\r\nX-Injected: malicious",
    },
}
err := validator.ValidateInput(input)
```
**Expected Result**: Header injection attempt detected and blocked
**Security Benefit**: Prevents SMTP header injection attacks
**Detection**: Line break characters in header values

#### Message Size Limits (Should Enforce)
```go
// Test: Message size limit enforcement
largeBody := make([]byte, 100*1024*1024) // 100MB
input := &SecurePluginInput{
    Body: largeBody,
}
err := validator.ValidateInput(input)
```
**Expected Result**: Oversized message rejected
**Security Benefit**: Prevents memory exhaustion attacks
**Limit**: 50MB maximum message size

#### Suspicious Pattern Detection (Should Detect)
```go
// Test: Suspicious pattern detection
input := &SecurePluginInput{
    Subject: "URGENT: Click here to win $1000000",
    Body: []byte("SELECT * FROM users WHERE password=''"),
}
err := validator.ValidateInput(input)
```
**Expected Result**: Suspicious patterns detected and flagged
**Security Benefit**: Detects potential phishing and SQL injection
**Patterns**: Script tags, SQL keywords, suspicious phrases

### Resource Management Testing

#### Memory Usage Monitoring (Should Monitor)
```bash
# Test: Plugin memory usage tracking
# Start plugin and monitor memory usage
ps -o pid,vsz,rss,comm -p $PLUGIN_PID
```
**Expected Result**: Memory usage tracked and within limits
**Monitoring**: Real-time VSZ and RSS tracking
**Limits**: 50MB maximum memory usage

#### CPU Usage Monitoring (Should Monitor)
```bash
# Test: Plugin CPU usage tracking
top -p $PLUGIN_PID -n 1 | grep plugin
```
**Expected Result**: CPU usage tracked and within limits
**Monitoring**: Real-time CPU percentage tracking
**Limits**: 10% maximum CPU usage

#### Execution Time Limits (Should Timeout)
```go
// Test: Plugin execution timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

output, err := plugin.ProcessMessage(ctx, input)
// Should timeout if plugin takes too long
```
**Expected Result**: Long-running plugin operations timeout
**Security Benefit**: Prevents plugin hang and resource exhaustion
**Timeout**: 30 seconds maximum execution time

#### Health Check Monitoring (Should Monitor)
```go
// Test: Plugin health monitoring
err := plugin.HealthCheck(context.Background())
```
**Expected Result**: Plugin health status tracked and reported
**Health Indicators**: Initialization status, pattern loading, scan statistics
**Monitoring**: Regular health checks with status reporting

### Plugin Lifecycle Testing

#### Secure Plugin Loading (Should Validate)
```go
// Test: Plugin loading with validation
manager := NewSecurePluginManager(config, logger)
err := manager.LoadPlugin("example-antivirus")
```
**Expected Result**: Plugin loaded successfully after validation
**Validation Steps**: Binary validation, checksum verification, capability checks
**Security**: Only trusted plugins with valid checksums loaded

#### Plugin Checksum Verification (Should Verify)
```bash
# Test: Plugin integrity verification
cd secure-plugins
make checksums
# Modify plugin binary
echo "tampered" >> example-antivirus/plugin
# Try to load plugin - should fail checksum verification
```
**Expected Result**: Tampered plugin rejected due to checksum mismatch
**Security Benefit**: Prevents loading of modified or corrupted plugins
**Verification**: SHA256 checksum comparison

#### Graceful Plugin Shutdown (Should Cleanup)
```go
// Test: Plugin shutdown and cleanup
err := manager.UnloadPlugin("example-antivirus")
// Verify sandbox cleanup
_, err = os.Stat("/tmp/elemta-plugin-sandbox/example-antivirus")
// Should return "no such file or directory"
```
**Expected Result**: Plugin shuts down gracefully with complete cleanup
**Cleanup**: Process termination, sandbox removal, resource release
**Verification**: No remaining processes or files

#### Plugin Error Recovery (Should Isolate)
```go
// Test: Plugin failure isolation
// Simulate plugin crash
plugin.process.Kill()
// Main server should continue operating
```
**Expected Result**: Plugin failure doesn't crash main server
**Isolation**: Plugin failures contained within process boundaries
**Recovery**: Failed plugin marked as unhealthy, server continues

### Performance and Security Analysis

#### Plugin Processing Performance
```bash
# Test: Plugin processing throughput
time for i in {1..100}; do
  echo '{"type":"process_message","data":{...}}' | ./plugin
done
```
**Expected Result**: Consistent processing performance within limits
**Performance**: <100ms average processing time per message
**Scalability**: Performance maintained under load

#### Memory Safety Verification
```bash
# Test: Memory safety analysis
valgrind --tool=memcheck --leak-check=full ./plugin < test_input.json
```
**Expected Result**: No memory leaks or safety violations
**Security Benefit**: Memory safety without CGO vulnerabilities
**Tools**: Static linking eliminates dynamic library memory issues

#### Security Audit Results
```bash
# Test: Comprehensive security audit
cd secure-plugins
make security-audit
```
**Expected Result**: All security checks pass
**Audit Items**: CGO usage, system calls, dynamic dependencies, permissions
**Security Score**: 100% compliance with security requirements

## Plugin Development Guidelines

### Secure Plugin Template
```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "time"
)

type SecurePlugin struct {
    initialized bool
    // Plugin-specific fields
}

func (p *SecurePlugin) ProcessMessage(ctx context.Context, input *SecurePluginInput) (*SecurePluginOutput, error) {
    // Implement secure message processing
    // - Validate all inputs
    // - Respect context timeouts
    // - Return structured output
    // - Handle errors gracefully
}

func main() {
    // Plugin communication loop
    // - JSON-based stdin/stdout communication
    // - Proper error handling
    // - Graceful shutdown
}
```

### Security Requirements
1. **No CGO Usage**: Plugins must be CGO-free with `CGO_ENABLED=0`
2. **Static Linking**: All dependencies must be statically linked
3. **Input Validation**: All inputs must be validated before processing
4. **Resource Awareness**: Plugins must respect resource limits
5. **Error Handling**: All errors must be handled gracefully
6. **Timeout Compliance**: Plugins must respect context timeouts
7. **Clean Shutdown**: Plugins must shutdown gracefully on signals

### Plugin Capabilities
```json
{
  "capabilities": [
    "scan_message",    // Can scan message content
    "modify_headers",  // Can modify email headers
    "modify_body",     // Can modify message body
    "quarantine",      // Can quarantine messages
    "network_access",  // Requires network access
    "file_access",     // Requires file system access
    "external_api"     // Requires external API access
  ]
}
```

## Integration Testing

### SMTP Server Integration
```bash
# Test: Plugin integration with SMTP server
cd /home/alan/repos/elemta
docker-compose up -d elemta
# Send test email through SMTP server
echo "Test message" | mail -s "Plugin Test" test@example.com
# Verify plugin processing in logs
docker logs elemta-node0 | grep "plugin"
```
**Expected Result**: Plugin processes messages seamlessly
**Integration**: Plugin called during message processing pipeline
**Logging**: Plugin processing events logged with security details

### Performance Under Load
```bash
# Test: Plugin performance under load
for i in {1..1000}; do
  echo "Test email $i" | mail -s "Load Test $i" test@example.com &
done
wait
```
**Expected Result**: System maintains performance under load
**Resource Management**: Plugin resource limits prevent system overload
**Scalability**: Multiple plugin instances handle concurrent requests

### Security Event Logging
```bash
# Test: Security event logging
# Attempt various attacks through plugins
# - Malicious input injection
# - Resource exhaustion attempts
# - Invalid plugin loading
# Verify all security events are logged
```
**Expected Result**: All security events properly logged
**Security Monitoring**: Comprehensive logging of security violations
**Incident Response**: Detailed logs for security analysis

## Migration from CGO Plugins

### Legacy Plugin Conversion
1. **Identify CGO Dependencies**: Scan existing plugins for CGO usage
2. **Replace CGO Calls**: Convert CGO calls to pure Go implementations
3. **Update Build Process**: Change from shared library to static binary
4. **Implement Communication**: Add JSON-based IPC protocol
5. **Add Security Features**: Implement input validation and resource limits

### Compatibility Testing
```bash
# Test: Verify converted plugins work correctly
cd secure-plugins
make build-example-antivirus
# Compare output with legacy plugin
diff <(legacy_plugin < test_input) <(./example-antivirus/plugin < test_input)
```
**Expected Result**: Converted plugins produce equivalent results
**Compatibility**: Same functionality without security vulnerabilities
**Performance**: Comparable or better performance than CGO versions

This comprehensive secure plugin system eliminates CGO security vulnerabilities while providing enhanced sandboxing, validation, and resource management. The system ensures that plugin failures cannot compromise the main SMTP server while maintaining high performance and functionality.
