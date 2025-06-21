# Queue Module Documentation

**Location**: `internal/queue/`
**Purpose**: Message queue system for email processing and delivery

## Overview
The Queue module manages email messages through their lifecycle from reception to delivery, providing robust retry logic, priority handling, and operational visibility.

## Key Components

### Manager (`manager.go`)
**Responsibilities**:
- Multi-queue message management
- Queue statistics and monitoring
- Message lifecycle operations
- Background processing coordination

**Key Functions**:
- `NewManager(queueDir string)` - Creates new queue manager
- `EnqueueMessage(from, to, subject, data, priority)` - Adds message to queue
- `GetMessage(id string)` - Retrieves message by ID
- `MoveMessage(id, targetQueue, reason)` - Moves message between queues

### Processor (`processor.go`)
**Responsibilities**:
- Background queue processing
- Retry logic implementation
- Delivery attempt coordination
- Error handling and recovery

**Key Functions**:
- `NewProcessor(config *Config)` - Creates queue processor
- `Start()` - Begins background processing
- `ProcessQueue(queueType)` - Processes specific queue

### Delivery Handler (`delivery_handler.go`)
**Responsibilities**:
- Actual message delivery
- SMTP client operations
- Delivery status tracking
- Error categorization

## Queue Types

### Active Queue
- **Purpose**: Messages ready for immediate delivery
- **Processing**: Continuous processing by delivery workers
- **Retry Logic**: Immediate retry on temporary failures

### Deferred Queue
- **Purpose**: Messages scheduled for later retry
- **Processing**: Periodic processing based on retry schedule
- **Retry Logic**: Exponential backoff with configurable intervals

### Hold Queue
- **Purpose**: Messages manually held for review
- **Processing**: Manual processing only
- **Use Cases**: Suspicious messages, compliance review

### Failed Queue
- **Purpose**: Messages that exhausted all retry attempts
- **Processing**: Manual intervention required
- **Analysis**: Permanent failure analysis and reporting

## Message Structure
```go
type Message struct {
    ID          string            `json:"id"`
    QueueType   QueueType         `json:"queue_type"`
    From        string            `json:"from"`
    To          []string          `json:"to"`
    Subject     string            `json:"subject"`
    Size        int64             `json:"size"`
    Priority    Priority          `json:"priority"`
    CreatedAt   time.Time         `json:"created_at"`
    RetryCount  int               `json:"retry_count"`
    NextRetry   time.Time         `json:"next_retry"`
    LastError   string            `json:"last_error"`
    Attempts    []Attempt         `json:"attempts"`
}
```

## Inputs
- **Email Messages**: From SMTP server or API
- **Configuration**: Queue settings, retry schedules
- **Management Commands**: Queue operations via API

## Outputs
- **Delivered Messages**: Successfully sent emails
- **Failed Messages**: Permanently failed deliveries
- **Queue Statistics**: Operational metrics
- **Delivery Reports**: Status and tracking information

## Dependencies
- `internal/delivery` - Message delivery system
- `internal/config` - Configuration management
- Standard library: `os`, `path/filepath`, `encoding/json`

## Configuration
```toml
[queue]
dir = "/app/queue"
max_retries = 5
retry_schedule = [300, 600, 1800, 3600]  # seconds
max_queue_time = 86400  # 24 hours
cleanup_interval = 3600  # 1 hour

[queue.priorities]
critical = 4
high = 3
normal = 2
low = 1
```

## Example Usage

### Basic Queue Operations
```go
// Create queue manager
manager := queue.NewManager("/app/queue")

// Enqueue message
messageID, err := manager.EnqueueMessage(
    "sender@example.com",
    []string{"recipient@example.org"},
    "Test Subject",
    []byte("Message body"),
    queue.PriorityNormal,
)

// Check message status
message, err := manager.GetMessage(messageID)
fmt.Printf("Status: %s, Retries: %d\n", message.QueueType, message.RetryCount)

// Move to hold queue
err = manager.MoveMessage(messageID, queue.Hold, "Manual review required")
```

### Queue Processing
```go
// Create processor
processor := queue.NewProcessor(config)

// Start background processing
go processor.Start()

// Process specific queue
err := processor.ProcessQueue(queue.Active)
```

## Retry Logic

### Retry Schedule
- **Attempt 1**: Immediate (0 seconds)
- **Attempt 2**: 5 minutes (300 seconds)
- **Attempt 3**: 10 minutes (600 seconds)
- **Attempt 4**: 30 minutes (1800 seconds)
- **Attempt 5**: 1 hour (3600 seconds)
- **Final**: Move to failed queue

### Error Classification
- **Temporary Errors**: Network issues, temporary failures (retry)
- **Permanent Errors**: Invalid recipients, policy violations (fail)
- **Unknown Errors**: Treated as temporary with limited retries

## Performance Characteristics
- **Throughput**: 1000+ messages/minute processing capacity
- **Scalability**: Multiple workers for parallel processing
- **Storage**: Efficient file-based storage with metadata
- **Memory Usage**: Streaming processing for large messages

## Monitoring and Metrics
- Queue depths by type
- Processing rates and throughput
- Retry attempt distributions
- Error rates and classifications
- Processing latencies

## Operational Commands

### Queue Management
```bash
# List all messages
elemta-cli queue list

# Show queue statistics
elemta-cli queue stats

# Move message to different queue
elemta-cli queue move <message-id> <target-queue>

# Flush entire queue
elemta-cli queue flush <queue-type>

# Retry specific message
elemta-cli queue retry <message-id>
```

## Security Considerations
- **File Permissions**: Queue directories protected with appropriate permissions
- **Message Isolation**: Each message stored in separate files
- **Access Control**: Queue operations require authentication
- **Audit Trail**: All queue operations logged

## Troubleshooting

### Common Issues
1. **Queue Directory Permissions**: Ensure write access to queue directories
2. **Disk Space**: Monitor disk usage for queue storage
3. **Processing Delays**: Check processor worker configuration
4. **Stuck Messages**: Investigate delivery handler issues

### Diagnostic Commands
```bash
# Check queue health
elemta-cli queue health

# View message details
elemta-cli queue show <message-id>

# Process queue manually
elemta-cli queue process --queue active

# Clean up old messages
elemta-cli queue cleanup --older-than 7d
```

## Future Enhancements
- Database-backed queue storage option
- Advanced scheduling capabilities
- Queue prioritization algorithms
- Distributed queue processing
- Real-time queue monitoring dashboard 