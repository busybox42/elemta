# Resource Management and Rate Limiting Test Suite

## Overview
This document tests the comprehensive resource management and rate limiting system implemented in Elemta SMTP server to protect against resource exhaustion, provide connection limits, goroutine pool management, circuit breaker protection, and real-time resource monitoring.

## Resource Management Enhancements Implemented

### 1. Connection Limits and Rate Limiting
- **Global Connection Limits**: Maximum concurrent connections (default: 1000)
- **Per-IP Connection Limits**: Maximum connections per IP address (default: 50)
- **Global Rate Limiting**: Token bucket algorithm with window-based limiting
- **Per-IP Rate Limiting**: Individual rate limits for each IP address
- **Connection Timeout Management**: Configurable connection and session timeouts
- **Idle Connection Cleanup**: Automatic cleanup of idle connections

### 2. Goroutine Pool Management
- **Worker Pool**: Fixed-size pool of worker goroutines (default: 100)
- **Task Queue**: Buffered channel for pending tasks
- **Pool Utilization Monitoring**: Real-time tracking of active/available workers
- **Graceful Degradation**: Direct goroutine creation when pool is full
- **Resource Cleanup**: Proper shutdown and cleanup of worker goroutines

### 3. Circuit Breaker Protection
- **External Service Protection**: Circuit breakers for SMTP delivery, LDAP, database
- **State Management**: Closed, Open, Half-Open states with automatic transitions
- **Failure Threshold**: Configurable failure count before opening (default: 5)
- **Recovery Timeout**: Automatic transition to half-open after timeout (default: 30s)
- **Request Blocking**: Immediate failure when circuit is open

### 4. Resource Monitoring and Alerting
- **Real-time Metrics**: Active connections, request rates, resource utilization
- **Performance Statistics**: Connection duration, request counts, throughput
- **Resource Health**: Memory usage, goroutine counts, connection pools
- **Automatic Alerting**: Threshold-based alerts for resource exhaustion
- **Comprehensive Logging**: Structured logging for all resource events

## Resource Management Architecture

### Resource Limits Configuration
```go
type ResourceLimits struct {
    MaxConnections         int           // Maximum concurrent connections
    MaxConnectionsPerIP    int           // Maximum connections per IP
    MaxGoroutines          int           // Maximum goroutines
    ConnectionTimeout      time.Duration // Connection timeout
    SessionTimeout         time.Duration // Session timeout
    IdleTimeout           time.Duration // Idle connection timeout
    RateLimitWindow       time.Duration // Rate limiting window
    MaxRequestsPerWindow  int           // Max requests per window
    MaxMemoryUsage        int64         // Maximum memory usage
    GoroutinePoolSize     int           // Worker pool size
    CircuitBreakerEnabled bool          // Enable circuit breakers
    ResourceMonitoringEnabled bool      // Enable monitoring
}
```

### Connection Tracking System
```go
type ConnectionInfo struct {
    RemoteAddr    string    // Client IP address
    ConnectedAt   time.Time // Connection establishment time
    LastActivity  time.Time // Last activity timestamp
    RequestCount  int32     // Number of requests processed
    BytesSent     int64     // Bytes sent to client
    BytesReceived int64     // Bytes received from client
    SessionID     string    // Unique session identifier
}
```

### IP Connection Tracker
```go
type IPConnectionTracker struct {
    connections map[string]int32 // IP -> connection count
    mutex       sync.RWMutex     // Thread-safe access
    maxPerIP    int32            // Maximum connections per IP
}
```

### Resource Rate Limiter
```go
type ResourceRateLimiter struct {
    tokens         int32         // Available tokens
    maxTokens      int32         // Maximum tokens
    refillRate     int32         // Tokens per second
    lastRefill     int64         // Last refill timestamp
    windowStart    time.Time     // Window start time
    windowCount    int32         // Requests in current window
    windowLimit    int32         // Window request limit
    windowDuration time.Duration // Window duration
}
```

## Test Cases

### Connection Limit Testing

#### Global Connection Limit (Should Block)
```bash
# Test: Exceed global connection limit
for i in {1..1100}; do
  telnet localhost 2525 &
done
```
**Expected Result**: First 1000 connections accepted, remaining 100 rejected
**Resource Log**: `Connection rejected: global limit reached`
**Metrics**: `active_connections: 1000, rejected_requests: 100`

#### Per-IP Connection Limit (Should Block)
```bash
# Test: Exceed per-IP connection limit from single IP
for i in {1..60}; do
  telnet localhost 2525 &
done
```
**Expected Result**: First 50 connections accepted, remaining 10 rejected
**Resource Log**: `Connection rejected: IP limit reached`
**Metrics**: `ip_connections: 50, max_per_ip: 50`

#### Connection Timeout Protection
```bash
# Test: Connection idle timeout
telnet localhost 2525
# Wait for idle timeout (default: 2 minutes)
```
**Expected Result**: Connection closed after idle timeout
**Resource Log**: `Connection released due to idle timeout`
**Cleanup**: Connection removed from tracking

### Rate Limiting Testing

#### Global Rate Limiting (Should Block)
```bash
# Test: Exceed global rate limit
for i in {1..150}; do
  echo "EHLO test" | nc localhost 2525 &
done
```
**Expected Result**: First 100 requests in window accepted, remaining 50 rejected
**Resource Log**: `Connection rejected: global rate limit exceeded`
**Rate Limiter**: Token bucket depleted

#### Per-IP Rate Limiting (Should Block)
```bash
# Test: Exceed per-IP rate limit
for i in {1..20}; do
  echo "EHLO test" | nc localhost 2525 &
done
```
**Expected Result**: First 10 requests (1/10th of global) accepted, remaining 10 rejected
**Resource Log**: `Connection rejected: IP rate limit exceeded`
**Rate Limiter**: Per-IP tokens depleted

#### Rate Limit Recovery
```bash
# Test: Rate limit recovery after window
# Exceed rate limit, wait for window reset, retry
```
**Expected Result**: Requests accepted after window reset
**Rate Limiter**: Tokens refilled, window counter reset

### Goroutine Pool Management Testing

#### Pool Utilization Monitoring
```go
// Test: Monitor pool utilization under load
poolStats := resourceManager.GetStats()["goroutine_pool"]
```
**Expected Result**: Real-time utilization statistics
**Metrics**: `utilization: 0.85, available_workers: 15, pending_tasks: 5`

#### Pool Overflow Handling
```bash
# Test: Submit more tasks than pool capacity
# Submit 150 tasks to 100-worker pool
```
**Expected Result**: First 100 tasks use pool, remaining 50 create direct goroutines
**Resource Log**: `Goroutine pool full, handling connection directly`
**Graceful Degradation**: System continues to function

#### Pool Cleanup on Shutdown
```go
// Test: Proper pool cleanup
resourceManager.Close()
```
**Expected Result**: All workers terminated gracefully
**Resource Log**: `Goroutine pool closed`
**Memory**: No goroutine leaks

### Circuit Breaker Protection Testing

#### SMTP Delivery Circuit Breaker
```go
// Test: SMTP delivery failures trigger circuit breaker
// Simulate 5 consecutive delivery failures
for i := 0; i < 5; i++ {
    err := deliveryManager.deliverToHost("nonexistent.example.com", 25, ...)
}
```
**Expected Result**: Circuit breaker opens after 5 failures
**Circuit Breaker Log**: `Circuit breaker opened due to failures`
**State**: `CircuitBreakerOpen`

#### Circuit Breaker Recovery
```go
// Test: Circuit breaker recovery after timeout
// Wait 30 seconds, attempt delivery
time.Sleep(30 * time.Second)
err := deliveryManager.deliverToHost("working.example.com", 25, ...)
```
**Expected Result**: Circuit transitions to half-open, then closed on success
**Circuit Breaker Log**: `Circuit breaker closed after successful request`
**State**: `CircuitBreakerClosed`

#### Circuit Breaker Request Blocking
```go
// Test: Requests blocked when circuit is open
circuitBreaker := resourceManager.GetCircuitBreaker("test-service")
// Open the circuit manually
circuitBreaker.state = CircuitBreakerOpen
err := circuitBreaker.Execute(func() error { return nil })
```
**Expected Result**: Request immediately fails without execution
**Error**: `circuit breaker test-service is open`

### Resource Monitoring Testing

#### Connection Activity Tracking
```bash
# Test: Connection activity updates
telnet localhost 2525
EHLO test.example.com
MAIL FROM: <test@example.com>
RCPT TO: <user@example.com>
```
**Expected Result**: Activity timestamp updated with each command
**Resource Log**: `Connection activity updated`
**Metrics**: `last_activity` timestamp updated

#### Resource Statistics Collection
```go
// Test: Comprehensive resource statistics
stats := resourceManager.GetStats()
```
**Expected Statistics**:
```json
{
  "active_connections": 45,
  "max_connections": 1000,
  "total_requests": 12847,
  "rejected_requests": 23,
  "rejection_rate": 0.18,
  "connection_utilization": 4.5,
  "goroutine_pool": {
    "max_workers": 100,
    "available_workers": 78,
    "active_workers": 22,
    "pending_tasks": 3,
    "utilization": 0.22
  },
  "circuit_breakers": {
    "smtp-delivery-example.com": {
      "state": "closed",
      "failure_count": 0,
      "max_failures": 5
    }
  },
  "rate_limiters": {
    "global_tokens": 87,
    "ip_limiters": 15
  }
}
```

#### Resource Health Monitoring
```go
// Test: Automated resource health monitoring
// Monitor runs every 30 seconds
```
**Expected Result**: Regular health reports logged
**Resource Log**: `Resource statistics` with utilization metrics
**Cleanup**: Idle connections and old rate limiters cleaned up

## Performance Impact Analysis

### Connection Processing Performance
```bash
# Baseline: Without resource management
# Load test: 1000 concurrent connections
ab -n 10000 -c 1000 http://localhost:2525/

# With resource management enabled
# Same load test with resource controls
```
**Expected Impact**: <5% performance overhead
**Resource Management**: Connection limits prevent resource exhaustion
**Stability**: System remains stable under high load

### Memory Usage Analysis
```bash
# Monitor memory usage during load test
ps aux | grep elemta
top -p $(pgrep elemta)
```
**Expected Result**: Controlled memory growth with resource limits
**Connection Tracking**: ~1KB per tracked connection
**Goroutine Pool**: Fixed memory footprint regardless of load
**Rate Limiters**: Minimal memory overhead per IP

### Throughput Analysis
```bash
# Measure SMTP throughput with resource management
# Send 1000 emails through SMTP
time for i in {1..1000}; do
  echo "Test email $i" | mail -s "Test $i" user@example.com
done
```
**Expected Result**: Consistent throughput with resource protection
**Rate Limiting**: Smooth traffic flow, prevents spikes
**Circuit Breakers**: Fail-fast for unavailable services

## Resource Management Configuration

### Default Resource Limits
```toml
[resources]
max_connections = 1000
max_connections_per_ip = 50
max_goroutines = 2000
connection_timeout = 30
session_timeout = 300
idle_timeout = 120
rate_limit_window = 60
max_requests_per_window = 1000
max_memory_usage = 524288000  # 500MB
goroutine_pool_size = 100
circuit_breaker_enabled = true
resource_monitoring_enabled = true
```

### Production Resource Limits
```toml
[resources]
max_connections = 10000
max_connections_per_ip = 100
max_goroutines = 20000
connection_timeout = 60
session_timeout = 600
idle_timeout = 300
rate_limit_window = 60
max_requests_per_window = 10000
max_memory_usage = 2147483648  # 2GB
goroutine_pool_size = 500
circuit_breaker_enabled = true
resource_monitoring_enabled = true
```

## Security and Stability Features

### DDoS Protection
- **Connection Rate Limiting**: Prevents connection flooding
- **Per-IP Limits**: Prevents single-source attacks
- **Resource Exhaustion Protection**: Global limits prevent system overload
- **Graceful Degradation**: System continues operating under attack

### Resource Leak Prevention
- **Connection Tracking**: All connections monitored and cleaned up
- **Goroutine Pool**: Fixed pool prevents goroutine leaks
- **Idle Connection Cleanup**: Automatic cleanup of abandoned connections
- **Circuit Breaker Cleanup**: Failed services don't consume resources

### Monitoring and Alerting
- **Real-time Metrics**: Continuous resource monitoring
- **Threshold Alerts**: Automatic alerts for resource exhaustion
- **Performance Tracking**: Connection duration and request rates
- **Health Reporting**: System health status and trends

## Integration Points

### SMTP Server Integration
- **Connection Acceptance**: Resource checks before accepting connections
- **Session Management**: Activity tracking and timeout management
- **Command Processing**: Rate limiting and resource monitoring
- **Connection Cleanup**: Proper resource release on disconnect

### Delivery Manager Integration
- **Circuit Breaker Protection**: External SMTP delivery protection
- **Connection Pooling**: Resource-aware connection management
- **Failure Handling**: Circuit breaker state management
- **Performance Monitoring**: Delivery success/failure tracking

### Queue System Integration
- **Processing Limits**: Resource-aware message processing
- **Worker Pool**: Goroutine pool for queue processing
- **Circuit Breaker**: Protection for external queue services
- **Resource Monitoring**: Queue performance metrics

This comprehensive resource management system transforms Elemta into a production-ready, scalable SMTP server capable of handling high loads while maintaining system stability and preventing resource exhaustion attacks.
