# Multinode Deployment Guide

## Overview

Elemta supports horizontal scaling across multiple nodes with shared state managed through Valkey (Redis-compatible). This enables:

- **Distributed rate limiting** - Cluster-wide request tracking
- **High availability** - No single point of failure
- **Load balancing** - Distribute traffic across nodes
- **Shared queue** - Unified message queue across nodes

## Architecture

```
                    ┌─────────────┐
                    │   Valkey    │
                    │  (Shared)   │
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
       ┌────▼────┐    ┌────▼────┐   ┌────▼────┐
       │ Node 0  │    │ Node 1  │   │ Node 2  │
       │ :2525   │    │ :2526   │   │ :2527   │
       └────┬────┘    └────┬────┘   └────┬────┘
            │              │              │
            └──────────────┼──────────────┘
                           │
                    ┌──────▼──────┐
                    │Shared Queue │
                    │  & Storage  │
                    └─────────────┘
```

## Quick Start

### 1. Start Multinode Deployment

```bash
# From project root
make docker-setup  # Start base services

# Add additional nodes
docker compose -f deployments/compose/docker-compose.yml \
               -f deployments/compose/docker-compose-multinode.yml up -d
```

### 2. Verify Nodes

```bash
# Check all nodes are running
docker ps | grep elemta-node

# Should show:
# elemta-node0  :2525  (metrics :8080)
# elemta-node1  :2526  (metrics :8081)
# elemta-node2  :2527  (metrics :8082)
```

### 3. Test Distributed Rate Limiting

```bash
# Run multinode test suite
python3 tests/test-multinode-valkey.py
```

Expected output:
```
✅ All multinode Valkey tests passed!
   Distributed rate limiting is working correctly.
```

## Configuration

### Node-Specific Settings

Each node can have custom settings via environment variables:

```yaml
environment:
  NODE_ID: node1                                      # Unique node identifier
  ELEMTA_CONFIG_PATH: /app/config/elemta-generated.toml
  VALKEY_URL: valkey://elemta-valkey:6379             # Shared Valkey instance
  VALKEY_KEY_PREFIX: "elemta:ratelimit:"              # Key namespace
```

### Valkey Configuration

The shared Valkey instance is configured for high availability:

```yaml
valkey:
  image: valkey/valkey:8.0-alpine
  command: >
    valkey-server
    --appendonly yes                 # Persistence enabled
    --appendfsync everysec          # Sync every second
    --maxmemory 512mb               # Memory limit
    --maxmemory-policy allkeys-lru  # Eviction policy
```

## Rate Limiting Behavior

### How It Works

1. **Request arrives** at any node (node0, node1, or node2)
2. **Node checks Valkey** for `elemta:ratelimit:ip:<client_ip>`
3. **Valkey returns count** of requests from that IP across ALL nodes
4. **Decision made** based on cluster-wide count
5. **State updated** in Valkey with sliding window algorithm

### Validation

```bash
# Check rate limit data in Valkey
docker exec elemta-valkey valkey-cli --scan --pattern "elemta:ratelimit:*"

# Example output:
# elemta:ratelimit:ip:172.20.0.1  (11 requests)
# elemta:ratelimit:ip:::1         (7 requests)
```

### Metrics Per Node

Each node exposes Prometheus metrics:

- **Node 0**: `http://localhost:8080/metrics`
- **Node 1**: `http://localhost:8081/metrics`
- **Node 2**: `http://localhost:8082/metrics`

## Load Balancing

### Option 1: HAProxy

```haproxy
frontend smtp_front
    bind *:25
    mode tcp
    default_backend smtp_servers

backend smtp_servers
    mode tcp
    balance leastconn
    server node0 localhost:2525 check
    server node1 localhost:2526 check
    server node2 localhost:2527 check
```

### Option 2: Nginx Stream

```nginx
stream {
    upstream smtp_cluster {
        least_conn;
        server localhost:2525 max_fails=3 fail_timeout=30s;
        server localhost:2526 max_fails=3 fail_timeout=30s;
        server localhost:2527 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 25;
        proxy_pass smtp_cluster;
        proxy_connect_timeout 60s;
    }
}
```

### Option 3: DNS Round-Robin

Configure multiple A records for your MX domain pointing to different nodes.

## Scaling Guidelines

### Adding More Nodes

1. Copy node definition in `docker-compose-multinode.yml`
2. Change `NODE_ID`, `container_name`, and ports
3. Ensure `VALKEY_URL` points to the same shared instance
4. Run `docker compose up -d`

### Removing Nodes

```bash
docker compose -f deployments/compose/docker-compose.yml \
               -f deployments/compose/docker-compose-multinode.yml \
               stop elemta-node2
docker compose rm elemta-node2
```

## Performance Characteristics

### Tested Configuration (3 Nodes)

- **Throughput**: 3x single node capacity
- **Latency**: ~1ms Valkey overhead per request
- **Failover**: Automatic (healthy nodes continue)
- **State sync**: Real-time via Valkey

### Valkey Overhead

Based on testing:
- **Command latency**: < 1ms for rate limit checks
- **Memory usage**: ~10KB per 1000 tracked IPs
- **Network**: Minimal (only counters, not message data)

## Monitoring

### Valkey Health Check

```bash
# Check Valkey is responding
docker exec elemta-valkey valkey-cli PING

# Check memory usage
docker exec elemta-valkey valkey-cli INFO memory | grep used_memory_human

# Check connection count
docker exec elemta-valkey valkey-cli INFO clients | grep connected_clients
```

### Node Health Checks

```bash
# Check all nodes
for port in 2525 2526 2527; do
  nc -zv localhost $port && echo "Port $port: ✅" || echo "Port $port: ❌"
done
```

### Metrics Aggregation

Use Prometheus to aggregate metrics across all nodes:

```promql
# Total SMTP connections across cluster
sum(smtp_connections_total)

# Rate limit hits per node
sum by (node_id) (rate_limit_hits_total)

# Valkey operations per second
rate(valkey_commands_total[1m])
```

## Troubleshooting

### Nodes Can't Connect to Valkey

```bash
# Check Valkey is running
docker ps | grep valkey

# Test connectivity from node
docker exec elemta-node1 ping -c 2 elemta-valkey

# Check Valkey logs
docker logs elemta-valkey
```

### Rate Limiting Not Synchronized

```bash
# Verify all nodes use same Valkey
docker exec elemta-node0 env | grep VALKEY
docker exec elemta-node1 env | grep VALKEY

# Check Valkey data
docker exec elemta-valkey valkey-cli KEYS "elemta:ratelimit:*"
```

### Performance Degradation

```bash
# Check Valkey latency
docker exec elemta-valkey valkey-cli --latency

# Check Valkey slow log
docker exec elemta-valkey valkey-cli SLOWLOG GET 10
```

## Production Recommendations

1. **Valkey Clustering**: For > 10 nodes, use Valkey cluster mode
2. **Persistent Storage**: Mount Valkey data volume to persistent disk
3. **Monitoring**: Set up alerts for Valkey connection failures
4. **Backup**: Regular AOF/RDB backups of Valkey data
5. **Network**: Use private network for Valkey communication
6. **Security**: Enable Valkey AUTH for production

## References

- [Valkey Documentation](https://valkey.io/docs/)
- [Docker Compose Multi-file](https://docs.docker.com/compose/multiple-compose-files/)
- [Elemta Rate Limiting Architecture](./rate-limiting.md)

