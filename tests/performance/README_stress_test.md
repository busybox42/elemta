# SMTP Stress Test Tool

A comprehensive SMTP stress testing utility that goes far beyond basic load testing. This tool can push your SMTP server to its limits with configurable duration, advanced testing scenarios, and detailed performance analysis.

## Features

### Core Functionality
- **Time-based testing**: Run tests for configurable duration (default: 5 minutes)
- **Dynamic connection management**: Ramp-up from min to max concurrent connections
- **Real-time monitoring**: CPU, memory, network I/O, file descriptors
- **Comprehensive metrics**: Response time percentiles, throughput, error analysis
- **JSON output**: Detailed results for further analysis

### Advanced Testing Scenarios
- **Connection reuse**: Test keep-alive behavior and connection pooling
- **TLS/STARTTLS**: Test encrypted connection overhead
- **Slow client simulation**: Test timeout handling with configurable delays
- **Malformed commands**: Test SMTP protocol robustness
- **SMTP pipelining**: Test command batching performance
- **Burst patterns**: Simulate real-world traffic spikes
- **Authentication stress**: Test auth system under load

## Installation

```bash
# Install required dependencies
pip install psutil

# Make the script executable
chmod +x smtp_stress_test.py
```

## Basic Usage

### Simple Stress Test
```bash
# 5-minute test with 50 concurrent connections
python smtp_stress_test.py --duration 300 --max-connections 50 --host localhost --port 2525
```

### High-Intensity Test
```bash
# 10-minute test with 200 connections, burst mode enabled
python smtp_stress_test.py \
  --duration 600 \
  --max-connections 200 \
  --min-connections 20 \
  --ramp-up 60 \
  --burst-mode \
  --burst-interval 30 \
  --burst-duration 10 \
  --output stress_results.json
```

## Advanced Testing Scenarios

### 1. Test Connection Pooling
```bash
# Test connection reuse efficiency
python smtp_stress_test.py \
  --duration 300 \
  --max-connections 100 \
  --connection-reuse \
  --messages-per-connection 20 \
  --output connection_pool_results.json
```

### 2. Test TLS/STARTTLS Overhead
```bash
# Compare TLS vs non-TLS performance
python smtp_stress_test.py \
  --duration 300 \
  --max-connections 50 \
  --use-tls \
  --username test@example.com \
  --password testpass \
  --output tls_results.json
```

### 3. Test Slow Client Behavior
```bash
# Test timeout handling with slow clients
python smtp_stress_test.py \
  --duration 180 \
  --max-connections 30 \
  --slow-client \
  --slow-delay 0.5 \
  --output slow_client_results.json
```

### 4. Test Malformed Command Handling
```bash
# Test server robustness with invalid SMTP commands
python smtp_stress_test.py \
  --duration 120 \
  --max-connections 20 \
  --malformed \
  --output malformed_results.json
```

### 5. Test SMTP Pipelining
```bash
# Test pipelining performance
python smtp_stress_test.py \
  --duration 240 \
  --max-connections 40 \
  --pipelining \
  --output pipelining_results.json
```

### 6. Test Rate Limiting
```bash
# Test authentication rate limiting
python smtp_stress_test.py \
  --duration 300 \
  --max-connections 100 \
  --username test@example.com \
  --password testpass \
  --auth-failure-rate 0.3 \
  --output rate_limit_results.json
```

### 7. Comprehensive Production Test
```bash
# Full production scenario with multiple stress factors
python smtp_stress_test.py \
  --duration 1800 \
  --max-connections 500 \
  --min-connections 50 \
  --ramp-up 120 \
  --message-size 2048 \
  --burst-mode \
  --burst-interval 60 \
  --burst-duration 15 \
  --connection-reuse \
  --messages-per-connection 15 \
  --use-tls \
  --username prod@example.com \
  --password prodpass \
  --output production_stress_test.json
```

## Command Line Options

### Basic Options
- `--duration, -d`: Test duration in seconds (default: 300)
- `--max-connections, -c`: Maximum concurrent connections (default: 100)
- `--min-connections`: Minimum concurrent connections (default: 10)
- `--ramp-up`: Ramp-up time in seconds (default: 30)
- `--message-size`: Message size in bytes (default: 1024)
- `--host`: Target SMTP host (default: localhost)
- `--port, -p`: Target SMTP port (default: 2525)

### Authentication
- `--username`: SMTP username for authentication
- `--password`: SMTP password for authentication

### Traffic Patterns
- `--burst-mode`: Enable burst mode traffic patterns
- `--burst-interval`: Burst interval in seconds (default: 30)
- `--burst-duration`: Burst duration in seconds (default: 5)

### Advanced Testing
- `--use-tls`: Use TLS/STARTTLS for connections
- `--connection-reuse`: Use connection reuse (default: enabled)
- `--no-connection-reuse`: Disable connection reuse
- `--messages-per-connection`: Messages per connection when reuse enabled (default: 10)
- `--pipelining`: Enable SMTP pipelining testing
- `--slow-client`: Enable slow client behavior testing
- `--slow-delay`: Delay in seconds for slow client mode (default: 0.1)
- `--malformed`: Enable malformed SMTP command testing
- `--auth-failure-rate`: Rate of intentional auth failures (0.0-1.0, default: 0.0)

### Monitoring & Output
- `--no-monitor`: Disable system resource monitoring
- `--output, -o`: Output file for results (JSON format)

## Understanding Results

### Key Metrics
- **Success Rate**: Percentage of successful email deliveries
- **Throughput**: Messages per second
- **Response Times**: Min, max, average, and percentiles (50th, 95th, 99th)
- **System Resources**: CPU, memory, network I/O, file descriptors

### Interpreting Percentiles
- **50th percentile**: Median response time
- **95th percentile**: 95% of requests complete faster than this
- **99th percentile**: 99% of requests complete faster than this

### System Resource Analysis
- Monitor CPU usage for processing bottlenecks
- Track memory usage for memory leaks
- Watch file descriptors for connection leaks
- Network I/O indicates bandwidth utilization

## Test Scenarios and What They Test

| Scenario | Purpose | Key Metrics to Watch |
|----------|---------|----------------------|
| Basic Load | General performance | Throughput, response times |
| Connection Reuse | Connection efficiency | Connection count, success rate |
| TLS Testing | Encryption overhead | CPU usage, response times |
| Slow Client | Timeout handling | Error rates, connection timeouts |
| Malformed Commands | Protocol robustness | Error handling, server stability |
| Pipelining | Command batching | Throughput, response times |
| Burst Mode | Traffic spike handling | Resource spikes, recovery time |
| Auth Failures | Rate limiting | Auth success/failure rates |

## Best Practices

### Before Testing
1. **Monitor baseline**: Know your normal resource usage
2. **Check logs**: Ensure logging is at appropriate levels
3. **Backup configs**: Save current server configuration
4. **Alert monitoring**: Set up alerts for critical failures

### During Testing
1. **Monitor resources**: Watch CPU, memory, disk space
2. **Check logs**: Look for errors or warnings
3. **Observe behavior**: Note any unusual server behavior
4. **Have rollback plan**: Know how to quickly restore service

### After Testing
1. **Analyze results**: Review all metrics and error patterns
2. **Check system integrity**: Verify no lasting damage
3. **Document findings**: Record performance baselines and limits
4. **Plan improvements**: Address any discovered bottlenecks

## Troubleshooting

### Common Issues

**High Failure Rate**
- Check server logs for specific errors
- Verify network connectivity
- Ensure server isn't already overloaded
- Check authentication credentials

**Connection Timeouts**
- Increase timeout values in test
- Check firewall settings
- Verify server capacity
- Monitor network latency

**Resource Exhaustion**
- Reduce concurrent connections
- Check for memory leaks
- Monitor file descriptor limits
- Review server configuration

**Slow Performance**
- Check system resource usage
- Analyze network bandwidth
- Review server configuration
- Consider hardware limitations

### Debug Mode
Add verbose logging by modifying the script or use system monitoring tools:
```bash
# Monitor system resources during test
top -p $(pgrep -f smtp_stress_test)

# Monitor network connections
netstat -an | grep :2525

# Monitor file descriptors
lsof -p $(pgrep -f smtp_stress_test)
```

## Example Output

```json
{
  "config": {
    "duration_seconds": 300,
    "max_concurrent_connections": 100,
    "message_size_bytes": 1024
  },
  "total_emails_sent": 15000,
  "successful_emails": 14850,
  "failed_emails": 150,
  "success_rate": 99.0,
  "emails_per_second": 50.0,
  "percentile_95": 0.250,
  "percentile_99": 0.450,
  "system_metrics": [...]
}
```

## Contributing

To add new test scenarios:
1. Add configuration options to `StressTestConfig`
2. Implement new testing method following existing patterns
3. Add command-line arguments in `parse_arguments()`
4. Update configuration in `main()`
5. Add documentation and examples

## License

This stress testing tool is part of the Elemta project and follows the same licensing terms.
