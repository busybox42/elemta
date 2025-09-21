# Memory Exhaustion Protection Test Suite

This document describes comprehensive tests for the memory exhaustion protection system implemented in ELE-21.

## Test Overview

The memory exhaustion protection system includes:
- Per-connection memory tracking and limits
- Configurable memory limits with production-appropriate defaults
- Memory usage monitoring and alerting system
- Forced garbage collection under memory pressure
- Goroutine leak detection and cleanup
- Memory exhaustion protection circuit breakers
- Comprehensive memory stress testing
- Gradual connection rejection under memory pressure

## Test Categories

### 1. Memory Limit Enforcement Tests

#### Test 1.1: Basic Memory Limit Check
```bash
# Test normal memory usage within limits
curl -X GET http://localhost:8080/api/resources/stats
# Expected: Memory utilization < 75% (warning threshold)
```

#### Test 1.2: Memory Warning Threshold
```bash
# Simulate memory pressure to trigger warning
# Expected: Warning logged when memory usage > 75%
```

#### Test 1.3: Memory Critical Threshold
```bash
# Simulate high memory usage to trigger critical threshold
# Expected: Critical alert logged when memory usage > 90%
```

#### Test 1.4: Memory Circuit Breaker
```bash
# Trigger memory circuit breaker
# Expected: Circuit breaker opens when critical threshold exceeded multiple times
```

### 2. Per-Connection Memory Tracking Tests

#### Test 2.1: Connection Memory Limit
```bash
# Test per-connection memory limit enforcement
telnet localhost 2525
# Send large email content to test per-connection limits
# Expected: Connection rejected if memory usage exceeds per-connection limit
```

#### Test 2.2: Connection Memory Tracking
```bash
# Monitor memory usage per connection
curl -X GET http://localhost:8080/api/resources/stats
# Expected: Memory usage tracked per connection
```

### 3. Garbage Collection Tests

#### Test 3.1: Forced Garbage Collection
```bash
# Trigger memory pressure to force GC
# Expected: GC triggered when memory usage > 80%
```

#### Test 3.2: Memory Recovery After GC
```bash
# Monitor memory usage before and after GC
# Expected: Memory usage decreases after forced GC
```

### 4. Goroutine Management Tests

#### Test 4.1: Goroutine Limit Enforcement
```bash
# Test goroutine limit enforcement
# Expected: New connections rejected when goroutine limit reached
```

#### Test 4.2: Goroutine Leak Detection
```bash
# Simulate goroutine leak scenario
# Expected: Warning logged when goroutine count exceeds expected levels
```

### 5. Memory Stress Tests

#### Test 5.1: Connection Flooding
```bash
# Rapidly establish many connections
for i in {1..1000}; do
  (echo "HELO test.com"; sleep 0.1) | telnet localhost 2525 &
done
# Expected: Connections rejected when memory limits exceeded
```

#### Test 5.2: Large Message Processing
```bash
# Send large email messages
telnet localhost 2525
HELO test.com
MAIL FROM:<test@example.com>
RCPT TO:<user@example.com>
DATA
# Send large message content (10MB+)
# Expected: Memory limits enforced, large messages handled appropriately
```

#### Test 5.3: Memory Exhaustion Attack Simulation
```bash
# Simulate memory exhaustion attack
# Expected: Circuit breaker activates, connections rejected
```

### 6. Monitoring and Alerting Tests

#### Test 6.1: Memory Statistics API
```bash
# Test memory statistics endpoint
curl -X GET http://localhost:8080/api/resources/memory
# Expected: Comprehensive memory statistics returned
```

#### Test 6.2: Memory Alerts
```bash
# Monitor logs for memory alerts
docker logs elemta-node0 | grep -i "memory"
# Expected: Memory warnings and critical alerts logged
```

### 7. Configuration Tests

#### Test 7.1: Memory Configuration Validation
```bash
# Test memory configuration loading
elemta config validate
# Expected: Memory configuration validated successfully
```

#### Test 7.2: Memory Limit Adjustment
```bash
# Test dynamic memory limit adjustment
# Expected: Memory limits can be adjusted via configuration
```

## Test Implementation

### Manual Testing Commands

#### Memory Usage Monitoring
```bash
# Monitor memory usage in real-time
watch -n 1 'curl -s http://localhost:8080/api/resources/stats | jq .memory_manager'
```

#### Connection Stress Test
```bash
# Create connection stress test script
cat > stress_test.sh << 'EOF'
#!/bin/bash
for i in {1..100}; do
  (
    echo "HELO test$i.com"
    echo "MAIL FROM:<test$i@example.com>"
    echo "RCPT TO:<user@example.com>"
    echo "DATA"
    echo "Subject: Test $i"
    echo ""
    echo "This is test message $i"
    echo "."
    echo "QUIT"
  ) | telnet localhost 2525 &
done
wait
EOF
chmod +x stress_test.sh
./stress_test.sh
```

#### Memory Pressure Test
```bash
# Create memory pressure test
cat > memory_pressure_test.sh << 'EOF'
#!/bin/bash
# Allocate memory to create pressure
python3 -c "
import time
import sys

# Allocate memory in chunks
memory_blocks = []
for i in range(100):
    try:
        # Allocate 10MB chunks
        block = 'x' * (10 * 1024 * 1024)
        memory_blocks.append(block)
        print(f'Allocated {len(memory_blocks) * 10}MB')
        time.sleep(0.1)
    except MemoryError:
        print('Memory allocation failed')
        break

# Hold memory for a while
time.sleep(10)

# Release memory
memory_blocks.clear()
print('Memory released')
"
EOF
chmod +x memory_pressure_test.sh
./memory_pressure_test.sh
```

### Automated Testing

#### Unit Tests
```bash
# Run memory manager unit tests
go test -v ./internal/smtp -run TestMemoryManager
```

#### Integration Tests
```bash
# Run resource manager integration tests
go test -v ./internal/smtp -run TestResourceManager
```

#### Stress Tests
```bash
# Run memory stress tests
go test -v ./internal/smtp -run TestMemoryStress
```

## Expected Results

### Memory Protection Features
- ✅ Memory limits enforced at 75% warning, 90% critical
- ✅ Per-connection memory tracking and limits
- ✅ Forced garbage collection under memory pressure
- ✅ Goroutine leak detection and limits
- ✅ Memory exhaustion circuit breakers
- ✅ Comprehensive memory monitoring and alerting

### Performance Characteristics
- ✅ Memory monitoring overhead < 1%
- ✅ Connection acceptance latency < 1ms
- ✅ Memory limit checks < 0.1ms
- ✅ Garbage collection triggered appropriately
- ✅ Circuit breaker activation within 5 seconds

### Security Protection
- ✅ Memory exhaustion attacks blocked
- ✅ Connection flooding protection
- ✅ Large message handling with limits
- ✅ Goroutine leak prevention
- ✅ Resource exhaustion prevention

## Monitoring and Metrics

### Key Metrics to Monitor
- Memory utilization percentage
- Peak memory usage
- Goroutine count and peak
- GC collection frequency
- Memory warnings and critical alerts
- Connection rejection rate due to memory limits
- Circuit breaker activation frequency

### Alerting Thresholds
- Memory warning: > 75% utilization
- Memory critical: > 90% utilization
- Goroutine warning: > 80% of max goroutines
- Circuit breaker: > 5 triggers in 30 seconds

### Dashboard Integration
- Prometheus metrics for memory usage
- Grafana dashboards for memory monitoring
- Alert manager integration for memory alerts
- Log aggregation for memory events

## Troubleshooting

### Common Issues
1. **Memory limits too low**: Adjust `MaxMemoryUsage` in configuration
2. **Frequent GC**: Increase `GCThreshold` or `MaxMemoryUsage`
3. **Circuit breaker activation**: Check for memory leaks or increase limits
4. **Goroutine leaks**: Enable goroutine leak detection and monitoring

### Debug Commands
```bash
# Check memory statistics
curl -s http://localhost:8080/api/resources/stats | jq .memory_manager

# Monitor memory usage
docker stats elemta-node0

# Check goroutine count
curl -s http://localhost:8080/api/resources/stats | jq .memory_manager.goroutine_count

# View memory alerts
docker logs elemta-node0 | grep -i "memory"
```

## Conclusion

The memory exhaustion protection system provides comprehensive protection against memory-related attacks and resource exhaustion. The system includes multiple layers of protection:

1. **Prevention**: Memory limits and per-connection tracking
2. **Detection**: Real-time monitoring and alerting
3. **Response**: Forced GC and circuit breakers
4. **Recovery**: Automatic cleanup and resource management

This implementation ensures that the SMTP server can handle high loads and memory pressure while maintaining service availability and preventing memory exhaustion attacks.
