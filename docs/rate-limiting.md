# Rate Limiting Architecture

## Overview

Elemta implements distributed rate limiting using Valkey (Redis-compatible) for multinode deployments. This provides cluster-wide request tracking and prevents abuse across horizontally scaled instances.

## Implementation

### Sliding Window Algorithm

Elemta uses a **sorted set-based sliding window** for accurate rate limiting:

```
Time:  0s      1s      2s      3s      4s      5s
       ├───────┼───────┼───────┼───────┼───────┤
Requests: 3       2       1       4       2

Window (5s): Counts all requests in the last 5 seconds
Current time: 5s → Count = 3+2+1+4+2 = 12 requests
```

### Valkey Data Structure

**Key Format:**
```
elemta:ratelimit:ip:<client_ip>
```

**Value**: Sorted set (ZSET) where:
- **Score**: Unix timestamp (seconds)
- **Member**: Unique request ID

**Example:**
```bash
$ valkey-cli ZRANGE elemta:ratelimit:ip:172.20.0.1 0 -1 WITHSCORES
1) "req_1729210954_001"
2) "1729210954"
3) "req_1729210955_002"
4) "1729210955"
```

## Rate Limit Checks

### Algorithm Flow

```go
func (rm *ResourceManager) CanAcceptConnection(remoteAddr string) (bool, error) {
    // 1. Extract IP from address
    ip := extractIP(remoteAddr)
    
    // 2. Local check (fast path)
    if !rm.checkLocalLimits(ip) {
        return false, ErrRateLimited
    }
    
    // 3. Distributed check via Valkey
    if rm.valkeyClient != nil && rm.valkeyClient.enabled {
        allowed, err := rm.valkeyClient.CheckRateLimit(ctx, ip, limit, window)
        if err != nil {
            // Fail open on Valkey errors
            rm.logger.Warn("Valkey rate limit check failed", "error", err)
            return true, nil
        }
        return allowed, nil
    }
    
    return true, nil
}
```

### Valkey Operations

**Check Rate Limit:**
```
1. ZREMRANGEBYSCORE elemta:ratelimit:ip:<IP> 0 <now - window>  # Remove old entries
2. ZCARD elemta:ratelimit:ip:<IP>                              # Count current entries
3. If count < limit:
     ZADD elemta:ratelimit:ip:<IP> <now> <request_id>          # Add new entry
     EXPIRE elemta:ratelimit:ip:<IP> <window>                  # Set TTL
     return ALLOWED
   Else:
     return DENIED
```

## Configuration

### TOML Configuration

```toml
[resources]
max_connections = 1000
max_connections_per_ip = 50

# Valkey distributed rate limiting
valkey_url = "valkey://elemta-valkey:6379"
valkey_key_prefix = "elemta:ratelimit:"
```

### Environment Variables

```bash
# Override via environment
export VALKEY_URL="valkey://valkey.example.com:6379"
export VALKEY_KEY_PREFIX="elemta:ratelimit:"
```

## Performance

### Benchmarks

**Single Node (Local Only):**
- Latency: ~50μs per rate limit check
- Throughput: ~20,000 checks/sec

**Multinode (Valkey):**
- Latency: ~1ms per rate limit check (includes network RTT)
- Throughput: ~10,000 checks/sec per node
- **Cluster throughput**: Scales linearly with nodes

### Optimization

**Failover Strategy:**
- If Valkey is unreachable, **fail open** (allow connections)
- Local limits still apply as first line of defense
- Log warnings for monitoring

**Connection Pooling:**
- Valkey client maintains connection pool
- Automatic reconnection on failure
- Health checks every 10 seconds

## Monitoring

### Prometheus Metrics

```promql
# Rate limit rejections per node
rate(smtp_rate_limit_rejections_total[1m])

# Valkey check latency
histogram_quantile(0.99, rate(valkey_check_duration_seconds_bucket[5m]))

# Valkey availability
up{job="valkey"}
```

### Valkey Monitoring

```bash
# Real-time request tracking
watch -n 1 'docker exec elemta-valkey valkey-cli --scan --pattern "elemta:ratelimit:*" | xargs -I {} docker exec elemta-valkey valkey-cli ZCARD {}'

# Memory usage
docker exec elemta-valkey valkey-cli INFO memory | grep used_memory_human

# Hit rate
docker exec elemta-valkey valkey-cli INFO stats | grep keyspace_hits
```

## Rate Limit Policies

### Default Limits

```go
const (
    MaxConnectionsPerIP     = 50    // Per IP across cluster
    MaxConnectionsGlobal    = 1000  // Total cluster capacity
    RateLimitWindow         = 60    // Seconds
    RateLimitMaxRequests    = 100   // Per window per IP
)
```

### Custom Policies

Add to `config/elemta-generated.toml`:

```toml
[resources]
max_connections = 2000              # Increase cluster capacity
max_connections_per_ip = 100        # Per-IP limit

# Rate limiting window (not yet configurable, hardcoded to 60s)
```

## Failure Modes

### Valkey Unavailable

**Behavior:**
- Nodes continue accepting connections
- Fall back to local-only rate limiting
- Log warnings: `Valkey rate limit check failed`

**Recovery:**
- Automatic reconnection every health check
- No manual intervention required
- State resumes when Valkey returns

### Node Failure

**Behavior:**
- Other nodes continue serving traffic
- Shared queue ensures no message loss
- Rate limit state remains consistent

**Recovery:**
- Restart failed node
- Automatically rejoins cluster
- Picks up shared state from Valkey

### Split Brain (Network Partition)

**Behavior:**
- Nodes can't communicate with Valkey
- Each operates independently with local limits
- More permissive than cluster mode

**Mitigation:**
- Monitor Valkey connectivity
- Set alerts for Valkey errors
- Use network redundancy

## Security Considerations

### Valkey Authentication

For production, enable AUTH:

```yaml
valkey:
  command: >
    valkey-server
    --requirepass your-secure-password
    --appendonly yes
```

Update nodes:
```bash
export VALKEY_URL="valkey://:your-secure-password@elemta-valkey:6379"
```

### Network Isolation

```yaml
networks:
  internal_network:
    internal: true  # No external access
```

### Rate Limit Bypass Prevention

- Valkey keys include IP address (can't be spoofed at L4)
- X-Forwarded-For headers ignored (use connection IP)
- No user-controllable components in rate limit keys

## Scaling Guidelines

### Horizontal Scaling

**2-10 Nodes:**
- Single Valkey instance sufficient
- Shared volumes for queue
- Standard configuration

**10-50 Nodes:**
- Valkey cluster (3-5 primary nodes)
- Distributed queue (per-node with relay)
- Consider queue service separation

**50+ Nodes:**
- Valkey cluster with replicas
- Separate queue services
- Geographic distribution
- Dedicated monitoring

### Vertical Scaling

**Valkey Resources:**
- **CPU**: 1-2 cores sufficient for most workloads
- **Memory**: 512MB-4GB depending on tracked IPs
- **Disk**: SSD for AOF persistence

**Elemta Node Resources:**
- **CPU**: 2-4 cores per node
- **Memory**: 1-2GB per node
- **Disk**: Shared queue volume (SSD recommended)

## Testing

### Multinode Test Suite

```bash
# Full multinode validation
python3 tests/test-multinode-valkey.py
```

Tests include:
1. ✅ Round-robin node distribution
2. ✅ Distributed rate limiting (cluster-wide)
3. ✅ Valkey shared state verification

### Manual Testing

```bash
# Send emails to different nodes
for i in {0..2}; do
  port=$((2525 + i))
  echo "EHLO test" | nc localhost $port
done

# Check Valkey state
docker exec elemta-valkey valkey-cli KEYS "elemta:ratelimit:*"
```

## Comparison to Momentum MTA

Elemta's multinode architecture is inspired by Momentum (now SparkPost):

| Feature                  | Momentum      | Elemta        |
|--------------------------|---------------|---------------|
| Shared State             | Cassandra     | Valkey        |
| Rate Limiting            | Distributed   | Distributed ✅ |
| Queue Model              | Per-node      | Shared volume |
| Config Management        | Centralized   | Per-node      |
| Metrics                  | SNMP/HTTP     | Prometheus    |
| Clustering               | Native        | Compose/K8s   |

## Future Enhancements

- [ ] Valkey Sentinel for HA
- [ ] Valkey Cluster for > 10 nodes
- [ ] Per-domain rate limiting
- [ ] Authenticated user rate limiting
- [ ] Dynamic rate limit adjustment
- [ ] Geographic distribution support
- [ ] Message routing across nodes

## References

- [Valkey Getting Started](https://valkey.io/docs/get-started/)
- [Resource Manager Implementation](../internal/smtp/resource_manager.go)
- [Docker Compose Multinode](../deployments/compose/docker-compose-multinode.yml)
- [Multinode Test Suite](../tests/test-multinode-valkey.py)

