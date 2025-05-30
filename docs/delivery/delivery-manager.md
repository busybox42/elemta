# Delivery Manager

The Delivery Manager is a comprehensive system for handling outbound email delivery in Elemta. It provides advanced features like connection pooling, DNS caching, intelligent routing, delivery tracking, and TLS support.

## Overview

The Delivery Manager consists of several integrated components:

- **Manager**: Central coordinator that orchestrates delivery operations
- **Connection Pool**: Efficient connection management with reuse and health monitoring
- **DNS Cache**: High-performance DNS resolution with TTL-based caching
- **Router**: Intelligent message routing based on configurable rules
- **Delivery Tracker**: Comprehensive tracking and metrics collection

## Key Features

### 🔗 Connection Pooling
- **Connection Reuse**: Minimizes connection overhead by reusing existing connections
- **Health Monitoring**: Automatic detection and removal of unhealthy connections
- **Concurrency Control**: Per-host connection limits to prevent server overload
- **Connection Metrics**: Detailed statistics on connection usage and performance

### 🌐 DNS Caching
- **Multi-Record Support**: Caches MX, A, and TXT records with appropriate TTLs
- **LRU Eviction**: Intelligent cache management to optimize memory usage
- **Retry Logic**: Robust error handling with exponential backoff
- **Performance Metrics**: Hit rates, latency tracking, and cache statistics

### 🚦 Intelligent Routing
- **Rule-Based Routing**: Flexible routing rules based on various message criteria
- **Local Domain Detection**: Automatic local delivery for configured domains
- **Relay Support**: Smart relay routing with authentication
- **Priority Handling**: Message prioritization for optimal delivery order

### 📊 Delivery Tracking
- **Real-Time Monitoring**: Track delivery status and progress in real-time
- **Comprehensive Metrics**: Success rates, error categorization, timing statistics
- **Historical Data**: Hourly and daily delivery statistics
- **Error Analysis**: Detailed error tracking and categorization

### 🔒 Security & TLS
- **Opportunistic TLS**: Automatic TLS upgrade when available
- **TLS Version Control**: Configurable minimum TLS versions
- **Certificate Validation**: Proper certificate chain validation
- **Secure Authentication**: Support for various SMTP authentication methods

## Configuration

### Basic Configuration

```go
config := delivery.DefaultConfig()
config.MaxConnectionsPerHost = 10
config.ConnectionTimeout = 30 * time.Second
config.DeliveryTimeout = 5 * time.Minute
config.MaxConcurrentDeliveries = 50
config.TLSMinVersion = "1.2"
```

### Advanced Configuration

```go
config := &delivery.Config{
    // Connection settings
    MaxConnectionsPerHost:    10,
    ConnectionTimeout:        30 * time.Second,
    IdleTimeout:             5 * time.Minute,
    KeepAliveInterval:       1 * time.Minute,
    
    // Delivery settings
    DeliveryTimeout:         5 * time.Minute,
    MaxConcurrentDeliveries: 50,
    MaxRetries:              3,
    RetryDelay:              30 * time.Second,
    
    // DNS settings
    DNSCacheSize:            1000,
    DNSCacheTTL:            5 * time.Minute,
    DNSTimeout:             10 * time.Second,
    DNSRetries:             3,
    
    // TLS settings
    TLSMinVersion:           "1.2",
    TLSCipherSuites:        []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    
    // Local domains
    LocalDomains:           []string{"localhost", "example.local"},
    
    // Relay settings (optional)
    RelayHost:              "smtp.relay.com",
    RelayPort:              587,
    RelayAuth:              true,
    RelayUsername:          "username",
    RelayPassword:          "password",
}
```

## Usage

### Basic Usage

```go
// Create and start delivery manager
manager, err := delivery.NewManager(config)
if err != nil {
    log.Fatal(err)
}

if err := manager.Start(); err != nil {
    log.Fatal(err)
}
defer manager.Stop()

// Deliver a message
msg := &delivery.Message{
    ID:       "msg-123",
    From:     "sender@example.com",
    To:       []string{"recipient@example.com"},
    Data:     []byte("Subject: Test\r\n\r\nMessage body"),
    Priority: delivery.PriorityNormal,
}

ctx := context.Background()
result, err := manager.DeliverMessage(ctx, msg)
if err != nil {
    log.Printf("Delivery failed: %v", err)
} else {
    log.Printf("Delivered to %d recipients", result.SuccessfulRecipients)
}
```

### Routing Rules

Configure custom routing rules for different scenarios:

```go
router := delivery.NewRouter(config)

// High-priority relay rule
highPriorityRule := &delivery.RoutingRule{
    ID:          "high-priority-relay",
    Name:        "High Priority Messages",
    Enabled:     true,
    Priority:    1,
    Headers:     map[string][]string{"X-Priority": {"1"}},
    RouteType:   delivery.RouteTypeRelay,
    RelayHost:   "premium-relay.com",
    RelayPort:   587,
    ForceTLS:    true,
}
router.AddRoutingRule(highPriorityRule)

// Bulk email rule
bulkRule := &delivery.RoutingRule{
    ID:               "bulk-emails",
    Name:             "Bulk Email Routing",
    Enabled:          true,
    Priority:         10,
    FromDomain:       []string{"newsletter.company.com"},
    RouteType:        delivery.RouteTypeRelay,
    RelayHost:        "bulk-relay.com",
    RelayPort:        25,
    DeliveryPriority: delivery.PriorityBulk,
}
router.AddRoutingRule(bulkRule)

// Time-based routing
offHoursRule := &delivery.RoutingRule{
    ID:       "off-hours",
    Name:     "Off Hours Delivery",
    Enabled:  true,
    Priority: 20,
    TimeRange: &delivery.TimeRange{
        Start: "18:00",
        End:   "08:00",
        Days:  []int{1, 2, 3, 4, 5}, // Monday-Friday
    },
    DeliveryPriority: delivery.PriorityLow,
}
router.AddRoutingRule(offHoursRule)
```

## Monitoring and Statistics

### Connection Pool Statistics

```go
stats := manager.GetConnectionStats()
fmt.Printf("Total connections: %d\n", stats["total_connections"])
fmt.Printf("Active connections: %d\n", stats["active_connections"])
fmt.Printf("Pool utilization: %.1f%%\n", stats["pool_utilization"])
fmt.Printf("Connection hits: %d\n", stats["connection_hits"])
fmt.Printf("Connection misses: %d\n", stats["connection_misses"])
```

### DNS Cache Statistics

```go
stats := manager.GetDNSStats()
fmt.Printf("Cache hits: %d\n", stats["cache_hits"])
fmt.Printf("Cache misses: %d\n", stats["cache_misses"])
fmt.Printf("Hit ratio: %.1f%%\n", stats["hit_ratio"])
fmt.Printf("Cache size: %d\n", stats["cache_size"])
fmt.Printf("DNS errors: %d\n", stats["errors"])
```

### Delivery Statistics

```go
stats := manager.GetDeliveryStats()
fmt.Printf("Total deliveries: %d\n", stats["total_deliveries"])
fmt.Printf("Success rate: %.1f%%\n", stats["success_rate"])
fmt.Printf("Average delivery time: %v\n", stats["average_delivery_time"])
fmt.Printf("Failed deliveries: %d\n", stats["failed_deliveries"])
```

## Message Priorities

The delivery manager supports multiple priority levels:

- **Critical** (`PriorityCritical = 0`): Immediate delivery, highest priority
- **High** (`PriorityHigh = 100`): High priority, processed before normal
- **Normal** (`PriorityNormal = 200`): Standard priority for regular emails
- **Low** (`PriorityLow = 300`): Lower priority, processed when resources available
- **Bulk** (`PriorityBulk = 400`): Lowest priority for bulk/marketing emails

## Error Handling

The delivery manager provides comprehensive error handling:

### Error Types

- **Connection Errors**: Network connectivity issues
- **DNS Errors**: Domain resolution failures
- **SMTP Errors**: Server response errors (5xx, 4xx codes)
- **TLS Errors**: SSL/TLS negotiation failures
- **Timeout Errors**: Operation timeouts

### Error Recovery

- **Automatic Retries**: Configurable retry logic with exponential backoff
- **Circuit Breaker**: Temporary suspension of problematic destinations
- **Fallback Routing**: Alternative delivery paths for failed routes
- **Error Metrics**: Detailed error tracking and categorization

## Performance Optimization

### Connection Pooling Best Practices

1. **Right-size Pool Limits**: Set `MaxConnectionsPerHost` based on target server capacity
2. **Monitor Pool Utilization**: Keep utilization below 80% for optimal performance
3. **Tune Timeouts**: Balance between responsiveness and resource usage
4. **Regular Cleanup**: Ensure expired connections are properly cleaned up

### DNS Caching Optimization

1. **Cache Size**: Set appropriate cache size based on domain diversity
2. **TTL Management**: Respect DNS TTL values for accuracy
3. **Prewarming**: Pre-populate cache with common domains
4. **Monitoring**: Track hit rates and adjust cache size accordingly

### Delivery Optimization

1. **Concurrency Tuning**: Balance between speed and resource usage
2. **Priority Management**: Use appropriate priorities for different message types
3. **Routing Efficiency**: Design routing rules for optimal path selection
4. **Resource Monitoring**: Monitor CPU, memory, and network usage

## Integration Examples

### Queue Integration

```go
// Custom delivery handler for queue integration
type QueueDeliveryHandler struct {
    deliveryManager *delivery.Manager
}

func (h *QueueDeliveryHandler) DeliverMessage(ctx context.Context, msg *queue.Message) error {
    deliveryMsg := &delivery.Message{
        ID:       msg.ID,
        From:     msg.From,
        To:       msg.To,
        Data:     msg.Data,
        Priority: convertPriority(msg.Priority),
    }
    
    result, err := h.deliveryManager.DeliverMessage(ctx, deliveryMsg)
    if err != nil {
        return err
    }
    
    if !result.Success && result.FailedRecipients > 0 {
        return fmt.Errorf("delivery failed for %d recipients", result.FailedRecipients)
    }
    
    return nil
}
```

### Plugin Integration

```go
// Example delivery plugin hook
func (p *MyPlugin) OnBeforeDelivery(ctx *plugin.HookContext) plugin.HookResult {
    // Custom pre-delivery logic
    if shouldDelay(ctx) {
        return plugin.HookResult{
            Action:  plugin.ActionDelay,
            Message: "Message delayed due to rate limiting",
        }
    }
    
    return plugin.HookResult{Action: plugin.ActionContinue}
}
```

## Troubleshooting

### Common Issues

1. **High Connection Errors**
   - Check network connectivity
   - Verify firewall settings
   - Monitor target server health

2. **DNS Resolution Failures**
   - Verify DNS server configuration
   - Check domain validity
   - Monitor DNS cache hit rates

3. **TLS Negotiation Failures**
   - Check TLS version compatibility
   - Verify certificate validity
   - Review cipher suite configuration

4. **Performance Issues**
   - Monitor connection pool utilization
   - Check DNS cache efficiency
   - Review concurrency settings

### Debugging Tools

- **Connection Pool Stats**: Monitor connection usage patterns
- **DNS Cache Contents**: Inspect cached DNS records
- **Delivery Tracking**: Analyze delivery attempts and failures
- **Error Categorization**: Identify common failure patterns

## Best Practices

1. **Configuration Management**
   - Use environment-specific configurations
   - Regularly review and tune settings
   - Monitor performance metrics

2. **Security**
   - Always use TLS when available
   - Implement proper authentication
   - Regular security audits

3. **Monitoring**
   - Set up alerting for critical metrics
   - Regular health checks
   - Performance baseline tracking

4. **Maintenance**
   - Regular log analysis
   - Performance tuning
   - Resource optimization

The Delivery Manager provides a robust, scalable foundation for email delivery in production environments. Its modular design allows for easy customization and integration with existing systems while maintaining high performance and reliability. 