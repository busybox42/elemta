# ELK Stack Integration for Elemta SMTP Server

## Overview

The ELK (Elasticsearch, Logstash, Kibana) stack provides comprehensive log analysis capabilities for the Elemta SMTP server. This integration enables real-time monitoring, search, and visualization of SMTP server logs, queue processing, and message delivery metrics.

## Architecture

```
Elemta SMTP Server → Filebeat → Logstash → Elasticsearch → Kibana
                                    ↓
                            Log Processing & Parsing
```

### Components

1. **Elasticsearch**: Stores and indexes log data
2. **Logstash**: Processes and transforms logs
3. **Kibana**: Provides visualization and dashboard interface
4. **Filebeat**: Ships logs from containers and files

## Quick Start

### 1. Deploy ELK Stack

```bash
# Start the ELK stack services
./scripts/setup-elk.sh
```

### 2. Access Interfaces

- **Kibana Dashboard**: http://localhost:5601
- **Elasticsearch API**: http://localhost:9200
- **Logstash Monitoring**: http://localhost:9600

### 3. View Logs

1. Open Kibana: http://localhost:5601
2. Go to **Discover** to search logs
3. Go to **Dashboard** to view pre-built visualizations

## Log Processing

### Log Types Parsed

The Logstash pipeline automatically parses and categorizes the following log types:

#### SMTP Connection Logs
```
SMTP: 2024-01-15 10:30:45 new connection: 192.168.1.100:54321
```
- **Event Type**: `smtp_connection`
- **Fields**: `client_ip`, `client_port`, `timestamp`

#### SMTP Command Logs
```
SMTP: 2024-01-15 10:30:46 EHLO client.example.com
SMTP: 2024-01-15 10:30:47 MAIL FROM:<sender@example.com>
```
- **Event Type**: `smtp_command`
- **Fields**: `smtp_command`, `command_data`

#### Queue Processing Logs
```
component=queue-processor message_id=abc123 from=sender@example.com to=[recipient@example.com]
```
- **Event Type**: `queue_processing`
- **Fields**: `message_id`, `sender`, `recipient`

#### Message Delivery Logs
```
component=lmtp-delivery message_id=abc123 from=sender@example.com to=[recipient@example.com]
```
- **Event Type**: `message_delivery`
- **Fields**: `message_id`, `sender`, `recipient`

#### Error Logs
```
2024-01-15 10:30:48 ERROR Failed to deliver message: connection refused
```
- **Event Type**: `error`
- **Fields**: `level`, `is_error`, `log_message`

## Kibana Dashboards

### Pre-built Visualizations

1. **SMTP Connections Timeline**
   - Shows connection patterns over time
   - Helps identify traffic spikes

2. **SMTP Commands Distribution**
   - Pie chart of command usage
   - Identifies common protocol operations

3. **Message Flow Visualization**
   - Queue processing → Delivery pipeline
   - Shows message throughput

4. **Error Log Table**
   - Recent error messages
   - Sorted by timestamp

5. **Top Senders/Recipients**
   - Most active email addresses
   - Helps identify high-volume users

6. **Client IP Analysis**
   - Connection sources
   - Geographic distribution (if GeoIP enabled)

### Custom Queries

#### Common Search Patterns

```bash
# Find all SMTP connections from specific IP
client_ip:"192.168.1.100"

# Find all error messages
level:"ERROR"

# Find messages from specific sender
sender:"user@example.com"

# Find queue processing events
event_type:"queue_processing"

# Find failed deliveries
event_type:"message_delivery" AND level:"ERROR"

# Find authentication events
event_type:"authentication"
```

#### Time-based Queries

```bash
# Last hour errors
level:"ERROR" AND @timestamp:[now-1h TO now]

# Today's connections
event_type:"smtp_connection" AND @timestamp:[now/d TO now]

# Peak hour analysis
@timestamp:[now-1h TO now] AND event_type:"smtp_connection"
```

## Configuration

### Logstash Pipeline

The main configuration is in `elk/logstash/pipeline/elemta.conf`:

- **Input**: Filebeat (port 5044) and direct file monitoring
- **Filter**: Grok patterns for log parsing
- **Output**: Elasticsearch with daily indices

### Elasticsearch Indices

- **Pattern**: `elemta-logs-YYYY.MM.dd`
- **Retention**: Configurable (default: no limit)
- **Shards**: 1 (suitable for single-node deployment)

### Filebeat Configuration

- **Container logs**: `/var/lib/docker/containers/*/*.log`
- **File logs**: `/var/log/elemta/*.log`
- **Multiline**: Handles stack traces and multi-line messages

## Monitoring and Alerting

### Health Checks

```bash
# Check Elasticsearch cluster health
curl http://localhost:9200/_cluster/health

# Check Logstash pipeline stats
curl http://localhost:9600/_node/stats/pipelines

# Check Kibana status
curl http://localhost:5601/api/status
```

### Performance Metrics

Monitor these key metrics:

1. **Log ingestion rate** (events/second)
2. **Elasticsearch index size** (GB)
3. **Query response time** (ms)
4. **Pipeline processing time** (ms)

### Alerting Setup

Configure alerts for:

- High error rates (>10 errors/minute)
- Connection failures
- Queue processing delays
- Disk space usage (>80%)

## Troubleshooting

### Common Issues

#### 1. No Logs Appearing

```bash
# Check Filebeat is running
docker logs elemta-filebeat

# Check Logstash processing
docker logs elemta-logstash

# Verify log files exist
ls -la logs/
```

#### 2. Elasticsearch Connection Issues

```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Check network connectivity
docker network ls
docker network inspect elemta_monitoring_network
```

#### 3. Kibana Dashboard Empty

```bash
# Check index pattern exists
curl http://localhost:5601/api/saved_objects/index-pattern

# Verify data in Elasticsearch
curl "http://localhost:9200/elemta-logs-*/_search?size=10&pretty"
```

#### 4. High Memory Usage

```bash
# Adjust JVM heap sizes in docker-compose.yml
ES_JAVA_OPTS: "-Xms512m -Xmx512m"
LS_JAVA_OPTS: "-Xmx256m -Xms256m"
```

### Log Levels

Set appropriate log levels for debugging:

```bash
# Increase Logstash debug logging
docker-compose exec elemta-logstash bin/logstash --log.level=debug

# Enable Elasticsearch slow query logging
curl -X PUT "localhost:9200/_settings" -H 'Content-Type: application/json' -d'
{
  "index.search.slowlog.threshold.query.debug": "1s"
}'
```

## Advanced Configuration

### Custom Grok Patterns

Add custom patterns in `elk/logstash/pipeline/elemta.conf`:

```ruby
# Custom pattern for application-specific logs
grok {
  match => { 
    "message" => "%{TIMESTAMP_ISO8601:timestamp} %{WORD:component} %{GREEDYDATA:custom_message}" 
  }
}
```

### Index Lifecycle Management

Configure automatic index cleanup:

```bash
# Set up ILM policy for log retention
curl -X PUT "localhost:9200/_ilm/policy/elemta-logs-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "delete": {
        "min_age": "30d"
      }
    }
  }
}'
```

### Security Considerations

For production deployments:

1. Enable X-Pack security
2. Configure TLS/SSL
3. Set up user authentication
4. Implement role-based access control
5. Enable audit logging

## Performance Tuning

### Elasticsearch Optimization

```yaml
# In docker-compose.yml
environment:
  - "ES_JAVA_OPTS=-Xms2g -Xmx2g"  # Increase heap size
  - indices.memory.index_buffer_size=30%
  - thread_pool.write.queue_size=1000
```

### Logstash Optimization

```yaml
# Pipeline settings
pipeline.workers: 4
pipeline.batch.size: 1000
pipeline.batch.delay: 50
```

## Integration with Monitoring Stack

The ELK stack integrates with the existing Prometheus/Grafana monitoring:

- **Elasticsearch metrics** → Prometheus
- **Logstash pipeline metrics** → Prometheus  
- **Cross-reference** log events with metrics
- **Unified alerting** across logs and metrics

## Backup and Recovery

### Data Backup

```bash
# Create Elasticsearch snapshot
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/backups"
  }
}'
```

### Configuration Backup

Important files to backup:

- `elk/` directory (all configurations)
- `docker-compose.yml` (ELK service definitions)
- Kibana saved objects and dashboards

## Conclusion

The ELK stack provides powerful log analysis capabilities for Elemta SMTP server operations. Use this integration to:

- Monitor SMTP server performance
- Troubleshoot delivery issues
- Analyze traffic patterns
- Detect security threats
- Optimize server configuration

For advanced use cases, consider integrating with external tools like Beats modules, machine learning features, or custom alerting systems. 