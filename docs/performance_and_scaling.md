# Performance and Scaling Guide

This guide covers Elemta's advanced performance optimization and horizontal scaling features.

## Table of Contents

- [Connection Pooling](#connection-pooling)
- [Clustering](#clustering)
- [Distributed Queue](#distributed-queue)
- [Memory Optimization](#memory-optimization)
- [Performance Monitoring](#performance-monitoring)
- [Load Testing](#load-testing)

## Connection Pooling

Elemta includes an advanced connection pool for efficient resource management.

### Features

- **Adaptive sizing**: Min/max idle and active connection limits
- **Health checking**: Test connections on borrow, return, and while idle
- **Lifecycle management**: Automatic creation, validation, and destruction
- **Lease management**: Connection lifetime and idle timeout tracking
- **Performance monitoring**: Comprehensive statistics and metrics

### Configuration

```go
import "github.com/busybox42/elemta/internal/smtp"

config := smtp.PoolConfig{
    MinIdle:       10,
    MaxIdle:       50,
    MaxActive:     200,
    MaxLifetime:   1 * time.Hour,
    IdleTimeout:   15 * time.Minute,
    WaitTimeout:   30 * time.Second,
    TestOnBorrow:  true,
    TestOnReturn:  true,
    TestWhileIdle: true,
    Factory:       myConnectionFactory,
    Validator:     myConnectionValidator,
}

pool, err := smtp.NewConnectionPool(config, logger)
if err != nil {
    log.Fatal(err)
}
defer pool.Close()
```

### Usage

```go
// Acquire connection
conn, err := pool.Acquire(ctx)
if err != nil {
    return err
}
defer conn.Close()

// Use connection
underlying := conn.Conn()
// ... perform operations

// Connection automatically returns to pool on Close()
```

### Monitoring

```go
// Get pool statistics
info := pool.GetPoolInfo()
fmt.Printf("Active: %d, Idle: %d, Total: %d\n",
    info["active_connections"],
    info["idle_connections"],
    info["total_connections"])

// Get detailed statistics
stats := pool.GetStatistics()
fmt.Printf("Created: %d, Reused: %d, Destroyed: %d\n",
    stats.Created.Load(),
    stats.Reused.Load(),
    stats.Destroyed.Load())
```

## Clustering

Elemta supports horizontal scaling with automatic cluster discovery and leader election.

### Architecture

- **Node discovery**: Automatic discovery using Valkey
- **Leader election**: Distributed leader election with automatic failover
- **Health monitoring**: Continuous health checks and status tracking
- **Metrics aggregation**: Cluster-wide statistics and monitoring

### Configuration

```toml
[cluster]
enabled = true
node_id = "elemta-node-1"
address = "10.0.1.10:2525"
role = "worker"  # master, worker, or standby
valkey_url = "valkey://localhost:6379"
valkey_keyspace = "elemta:cluster"
heartbeat_interval = "5s"
node_ttl = "30s"
```

### Usage

```go
import "github.com/busybox42/elemta/internal/cluster"

config := cluster.ClusterConfig{
    NodeID:         "elemta-node-1",
    Address:        "10.0.1.10:2525",
    Role:           cluster.RoleWorker,
    ValkeyURL:      "valkey://localhost:6379",
    ValkeyKeyspace: "elemta:cluster",
    Logger:         logger,
    OnMasterChange: func(old, new string) {
        log.Printf("Master changed: %s -> %s", old, new)
    },
}

c, err := cluster.NewCluster(config)
if err != nil {
    log.Fatal(err)
}
defer c.Close()

// Check if this node is the leader
if c.IsLeader() {
    // Perform leader-only operations
}

// Get cluster statistics
stats := c.GetClusterStats()
```

### Node Roles

**Master**: Participates in leader election, can become cluster leader
**Worker**: Processes work items, does not participate in leadership
**Standby**: Hot standby, can become master if needed

### Health Monitoring

```go
config.HealthCheckFunc = func(ctx context.Context) bool {
    // Return true if node is healthy
    return checkSystemHealth()
}

config.OnHealthChange = func(node *cluster.Node, old, new cluster.NodeStatus) {
    log.Printf("Node %s health changed: %s -> %s", node.ID, old, new)
}
```

## Distributed Queue

The distributed queue enables work distribution across cluster nodes.

### Features

- **Priority-based**: Items processed by priority
- **Scheduled processing**: Delay item processing to specific times
- **Lease management**: Automatic lease expiration and recovery
- **Retry logic**: Configurable retry with exponential backoff
- **Dead letter queue**: Failed items tracked separately

### Usage

```go
import "github.com/busybox42/elemta/internal/cluster"

queue, err := cluster.NewDistributedQueue(
    "valkey://localhost:6379",
    "elemta:queue",
    "node-1",
    logger,
)
if err != nil {
    log.Fatal(err)
}
defer queue.Close()

// Enqueue work item
item := &cluster.QueueItem{
    Type:     "email_delivery",
    Priority: 5,
    Data: map[string]interface{}{
        "from":    "sender@example.com",
        "to":      "recipient@example.com",
        "subject": "Test",
    },
    MaxAttempts: 3,
}

if err := queue.Enqueue(ctx, item); err != nil {
    log.Fatal(err)
}

// Worker loop
for {
    item, err := queue.Dequeue(ctx, 5*time.Minute)
    if err != nil {
        log.Printf("Dequeue error: %v", err)
        continue
    }
    if item == nil {
        time.Sleep(1 * time.Second)
        continue
    }

    // Process item
    if err := processItem(item); err != nil {
        // Retry with backoff
        queue.Fail(ctx, item.ID, true, time.Minute*time.Duration(item.Attempts))
    } else {
        // Mark complete
        queue.Complete(ctx, item.ID)
    }
}

// Lease recovery (run periodically)
recovered, _ := queue.RecoverExpiredLeases(ctx)
log.Printf("Recovered %d expired leases", recovered)
```

## Memory Optimization

Advanced memory management and optimization.

### Features

- **Automatic GC triggering**: Based on memory thresholds
- **Object pooling**: Reusable buffers and message structures
- **Memory profiling**: Continuous memory monitoring
- **Leak detection**: Track allocation patterns

### Configuration

```go
import "github.com/busybox42/elemta/internal/performance"

config := performance.MemoryOptimizerConfig{
    MaxMemory:     2 * 1024 * 1024 * 1024, // 2GB
    GCThreshold:   0.85,                    // 85%
    CheckInterval: 30 * time.Second,
    Logger:        logger,
}

optimizer := performance.NewMemoryOptimizer(config)
defer optimizer.Close()
```

### Object Pools

```go
// Buffer pool
bufPool := optimizer.GetBufferPool()
buf := bufPool.Get(4096)
defer bufPool.Put(buf)

// Use buffer
copy(*buf, data)

// Message pool
msgPool := optimizer.GetMessagePool()
msg := msgPool.Get()
defer msgPool.Put(msg)

// Use message
msg.Headers["From"] = "sender@example.com"
msg.Body = append(msg.Body, content...)
```

### Monitoring

```go
stats := optimizer.GetStats()
fmt.Printf("Heap: %dMB, GC runs: %d, Live objects: %d\n",
    stats["heap_alloc_mb"],
    stats["gc_runs"],
    stats["live_objects"])
```

## Performance Monitoring

Comprehensive performance profiling and monitoring.

### Features

- **CPU profiling**: Track CPU usage patterns
- **Memory profiling**: Heap and allocation profiles
- **Goroutine profiling**: Track goroutine creation and leaks
- **Execution tracing**: Detailed execution traces
- **Automatic profiling**: Scheduled profile generation

### Configuration

```go
import "github.com/busybox42/elemta/internal/performance"

config := performance.ProfilerConfig{
    Enabled:     true,
    ProfileDir:  "./profiles",
    AutoProfile: true,
    ProfileInt:  5 * time.Minute,
    Logger:      logger,
}

profiler := performance.NewProfiler(config)
defer profiler.Close()
```

### Manual Profiling

```go
// CPU profiling
profiler.StartCPUProfile()
// ... run workload
profiler.StopCPUProfile()

// Generate profiles
profiler.GenerateHeapProfile()
profiler.GenerateGoroutineProfile()
profiler.GenerateBlockProfile()
profiler.GenerateMutexProfile()

// Execution tracing
profiler.StartTrace()
// ... run workload
profiler.StopTrace()

// Generate all profiles
profiler.GenerateAllProfiles()
```

### Analyzing Profiles

```bash
# CPU profile
go tool pprof profiles/cpu-20250122-150405.prof

# Heap profile
go tool pprof profiles/heap-20250122-150405.prof

# Goroutine profile
go tool pprof profiles/goroutine-20250122-150405.prof

# Execution trace
go tool trace profiles/trace-20250122-150405.out
```

## Load Testing

Comprehensive load testing suite.

### Running Tests

```bash
# Basic load test
python3 tests/performance/smtp_load_test.py

# Comprehensive test suite
python3 tests/performance/comprehensive_load_test.py
```

### Test Scenarios

1. **Baseline Performance**: Sequential email sending
2. **Concurrent Connections**: Multiple simultaneous connections
3. **Large Messages**: Handling of large email bodies
4. **Sustained Load**: Long-duration steady traffic
5. **Spike Traffic**: Sudden bursts of connections
6. **Connection Pooling**: Rapid connection creation/destruction
7. **Resource Limits**: Behavior at maximum capacity

### Interpreting Results

```json
{
  "test_name": "Concurrent Connections",
  "emails_sent": 500,
  "emails_per_second": 45.2,
  "avg_response_time": 0.342,
  "p95_response_time": 0.891,
  "p99_response_time": 1.234,
  "cpu_usage": 65.3,
  "memory_usage_mb": 512
}
```

## Best Practices

### Connection Pooling

1. Set `MinIdle` to handle baseline traffic
2. Set `MaxActive` below system limits
3. Enable health checks in production
4. Monitor pool statistics regularly
5. Tune lifetimes based on workload

### Clustering

1. Use odd number of master nodes (3, 5, 7)
2. Monitor node health continuously
3. Plan for node failures
4. Use standby nodes for high availability
5. Implement proper health checks

### Memory Optimization

1. Use object pools for frequently allocated objects
2. Monitor memory trends
3. Set appropriate GC thresholds
4. Profile regularly to detect leaks
5. Use memory limits to prevent OOM

### Performance Monitoring

1. Enable automatic profiling in production
2. Collect profiles during incidents
3. Monitor goroutine counts
4. Track allocation patterns
5. Analyze profiles regularly

## Troubleshooting

### High Memory Usage

```bash
# Generate heap profile
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Check for leaks
go tool pprof -alloc_space heap.prof
```

### Goroutine Leaks

```bash
# Generate goroutine profile
curl http://localhost:8080/debug/pprof/goroutine > goroutine.prof
go tool pprof goroutine.prof

# List goroutines
(pprof) list .
```

### Slow Performance

```bash
# CPU profile for 30 seconds
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Find hot spots
(pprof) top10
(pprof) list functionName
```

### Cluster Issues

```bash
# Check cluster status
curl http://localhost:8080/api/cluster/stats

# View node health
curl http://localhost:8080/api/cluster/nodes

# Check queue depth
curl http://localhost:8080/api/queue/stats
```

## Production Deployment

### Recommended Configuration

```toml
[performance]
max_connections = 1000
max_connections_per_ip = 50
goroutine_pool_size = 200
connection_timeout = "30s"
session_timeout = "5m"

[cluster]
enabled = true
heartbeat_interval = "5s"
node_ttl = "30s"

[memory]
max_memory = "4GB"
gc_threshold = 0.85
check_interval = "30s"

[profiling]
enabled = true
auto_profile = true
profile_interval = "5m"
```

### Monitoring Setup

1. Enable Prometheus metrics
2. Set up Grafana dashboards
3. Configure alerting rules
4. Monitor cluster health
5. Track performance trends

## Further Reading

- [SMTP Server Configuration](smtp_server.md)
- [Queue Management](queue_management.md)
- [Production Deployment](production-deployment.md)
- [Troubleshooting](troubleshooting.md)

