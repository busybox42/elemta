# Memory Configuration Guide

## Overview

Elemta includes comprehensive memory management to prevent resource exhaustion attacks and ensure stable operation under load.

## Configuration

Memory limits are fully configurable via the `[memory]` section in `elemta.toml`:

```toml
[memory]
max_memory_usage = 2147483648               # 2GB total memory limit (bytes)
per_connection_memory_limit = 52428800     # 50MB per session (bytes)
memory_warning_threshold = 0.75            # 75% warning threshold
memory_critical_threshold = 0.90           # 90% critical threshold  
gc_threshold = 0.80                        # 80% force garbage collection
monitoring_interval = "5s"                 # Memory check interval
max_goroutines = 2000                      # Maximum concurrent goroutines
goroutine_leak_detection = true
memory_exhaustion_protection = true
```

## Configuration Parameters

### Memory Limits

**`max_memory_usage`** (default: 2GB)
- Total memory limit for the entire SMTP server process
- When exceeded, new connections are rejected with temporary failure
- Recommended: 2-4GB for production, 1GB for development

**`per_connection_memory_limit`** (default: 50MB)
- Maximum memory per SMTP session/connection
- Prevents single connections from exhausting server memory
- Automatically calculated from max_memory_usage / max_connections

### Thresholds

**`memory_warning_threshold`** (default: 0.75)
- Warning logged when memory usage exceeds this percentage
- Does not reject connections, just logs for monitoring
- Range: 0.0-1.0 (0% to 100%)

**`memory_critical_threshold`** (default: 0.90)
- Critical threshold - new connections rejected above this
- Returns SMTP 452 (temporary failure) to clients
- Clients should retry later

**`gc_threshold`** (default: 0.80)
- Automatically triggers garbage collection at this threshold
- Helps prevent reaching critical threshold
- Reduces memory pressure proactively

### Monitoring

**`monitoring_interval`** (default: "5s")
- How often to check memory usage
- Lower values = more overhead but faster detection
- Higher values = less overhead but slower response

**`max_goroutines`** (default: 2000)
- Maximum number of concurrent goroutines
- Prevents goroutine leaks from exhausting resources
- Should be >= max_connections * 2

**`goroutine_leak_detection`** (default: true)
- Enable automatic goroutine leak detection
- Logs warnings when goroutine count grows unexpectedly
- Helps identify resource leaks early

**`memory_exhaustion_protection`** (default: true)
- Enable comprehensive memory exhaustion protection
- Activates circuit breakers on memory pressure
- Recommended to always keep enabled

## SMTP Response Codes

### Temporary Failures (4xx) - Client Should Retry

**452 4.3.1 Insufficient system storage**
- Returned when memory limits are exceeded
- Client should retry later (temporary condition)
- Used in: command processing, connection acceptance

**552 5.3.4 Message exceeds fixed maximum message size**
- Returned when per-session memory limit exceeded during DATA
- Also indicates temporary resource constraint
- Used during message data reading

### When Limits Are Exceeded

1. **During Connection**: 452 returned, connection rejected
2. **During MAIL/RCPT**: 452 returned, command rejected
3. **During DATA**: 552 returned, message rejected
4. **Global Limit**: Circuit breaker activated, all new connections rejected

## Monitoring Memory Usage

### Via API

```bash
# Get memory statistics
curl http://localhost:8080/api/stats

# Check health status
curl http://localhost:8080/health
```

### Via Prometheus

```bash
# Memory usage metrics
curl http://localhost:8080/metrics | grep memory

# Example metrics:
# elemta_memory_usage_bytes
# elemta_memory_utilization_percent
# elemta_gc_runs_total
# elemta_goroutines_current
```

### Via Logs

Memory events are logged with structured logging:

```json
{
  "level": "WARN",
  "msg": "Memory critical threshold exceeded",
  "current_usage": 1932735283,
  "max_usage": 2147483648,
  "utilization_percent": 90.0,
  "threshold": 0.90
}
```

## Tuning Recommendations

### Small Deployments (< 100 connections)
```toml
[memory]
max_memory_usage = 1073741824        # 1GB
per_connection_memory_limit = 10485760  # 10MB
```

### Medium Deployments (100-1000 connections)
```toml
[memory]
max_memory_usage = 4294967296        # 4GB
per_connection_memory_limit = 52428800  # 50MB
```

### Large Deployments (> 1000 connections)
```toml
[memory]
max_memory_usage = 8589934592        # 8GB
per_connection_memory_limit = 104857600  # 100MB
max_goroutines = 5000
```

### Load Testing / Development
```toml
[memory]
max_memory_usage = 536870912         # 512MB
per_connection_memory_limit = 10485760  # 10MB
memory_critical_threshold = 0.95     # More tolerant
```

## Troubleshooting

### Too Many 452 Errors

**Symptoms**: Clients getting "452 Insufficient system storage" frequently

**Solutions**:
1. Increase `max_memory_usage` limit
2. Increase `memory_critical_threshold` (0.90 → 0.95)
3. Reduce `per_connection_memory_limit` to allow more connections
4. Enable more aggressive garbage collection (lower `gc_threshold`)

### Memory Grows Continuously

**Symptoms**: Memory usage increases over time without dropping

**Solutions**:
1. Enable `goroutine_leak_detection = true`
2. Check logs for goroutine leak warnings
3. Generate heap profile: `curl http://localhost:8080/debug/pprof/heap > heap.prof`
4. Analyze: `go tool pprof heap.prof`
5. Lower `gc_threshold` for more frequent GC

### Frequent Garbage Collections

**Symptoms**: High CPU usage, logs show frequent GC runs

**Solutions**:
1. Increase `max_memory_usage` to reduce GC pressure
2. Increase `gc_threshold` (0.80 → 0.85)
3. Optimize memory-intensive operations
4. Use object pooling for frequently allocated objects

## Best Practices

1. **Start Conservative**: Begin with lower limits, increase based on monitoring
2. **Monitor Trends**: Track memory usage over time via Prometheus/Grafana
3. **Load Test**: Verify limits with realistic traffic before production
4. **Set Alerts**: Configure alerts at 75% and 90% thresholds
5. **Profile Regularly**: Generate heap profiles to identify memory leaks
6. **Plan Capacity**: Ensure physical RAM > max_memory_usage * 1.5

## Related Documentation

- [Performance and Scaling](performance_and_scaling.md)
- [Resource Management](../README.md#resource-management)
- [Production Deployment](production-deployment.md)

