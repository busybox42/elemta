# Queue Management in Elemta

Elemta includes a robust queue management system for reliable email handling. This document describes the queue architecture, message processing, and CLI commands for managing the queue.

## Queue Architecture

The queue system consists of four types of queues:

1. **Active Queue**: Contains messages that are actively being processed or waiting to be processed.
2. **Deferred Queue**: Contains messages that have failed delivery but will be retried later according to the retry schedule.
3. **Held Queue**: Contains messages that have been manually placed on hold by an administrator.
4. **Failed Queue**: Contains messages that have permanently failed delivery after exhausting all retry attempts.

## Queue Processing

Messages are processed by the queue processor, which runs as part of the SMTP server. The queue processor is responsible for:

1. Scanning the active queue for new messages
2. Attempting delivery of messages in the active queue
3. Moving messages to the appropriate queue based on delivery status
4. Retrying delivery of messages according to the retry schedule

### Per-Domain Delivery Concurrency

Elemta applies a per-domain concurrency limit when delivering messages (e.g. via LMTP to Dovecot). Each queued message is tagged with a primary routing domain derived from the first recipient address. The delivery layer enforces a maximum number of in-flight deliveries per domain;
additional messages for that domain will temporarily fail and be retried via the deferred queue according to the retry schedule.

The limit is controlled by the SMTP configuration option:

```toml
# SMTP configuration (elemta.conf / elemta.toml)
max_connections_per_domain = 10  # Maximum concurrent deliveries per domain
```

When `max_connections_per_domain` is not set or is <= 0, Elemta uses a safe default (currently 10). This protects remote domains from overload and prevents a single domain from monopolizing delivery workers.

### Queue Processor Configuration

The queue processor can be configured with the following options:

```yaml
queue_processor:
  enabled: true             # Enable/disable queue processing
  interval: 10              # Scanning interval in seconds
  workers: 5                # Number of concurrent delivery workers
  debug: false              # Enable debug logging for queue processor
```

Or in TOML format:

```toml
[queue_processor]
enabled = true              # Enable/disable queue processing
interval = 10               # Scanning interval in seconds
workers = 5                 # Number of concurrent delivery workers
debug = false               # Enable debug logging for queue processor
```

## Message Prioritization

Elemta supports message prioritization with four priority levels:

1. **Critical** (Priority 4): Highest priority, processed first
2. **High** (Priority 3): Processed after Critical messages
3. **Normal** (Priority 2): Default priority level
4. **Low** (Priority 1): Lowest priority, processed last

Messages with higher priority are always processed before messages with lower priority.

## Retry Logic

When a message delivery fails, Elemta will retry delivery according to the configured retry schedule. The default retry schedule uses an exponential backoff:

1. 1 minute (60 seconds)
2. 5 minutes (300 seconds)
3. 15 minutes (900 seconds)
4. 1 hour (3600 seconds)
5. 3 hours (10800 seconds)
6. 6 hours (21600 seconds)
7. 12 hours (43200 seconds)

You can configure a custom retry schedule in the configuration file:

```yaml
queue:
  retry_schedule:
    - 60     # 1 minute
    - 300    # 5 minutes
    - 900    # 15 minutes
    - 3600   # 1 hour
    - 10800  # 3 hours
    - 21600  # 6 hours
    - 43200  # 12 hours
```

## Queue Management CLI

Elemta provides a command-line interface for managing the queue. The CLI commands are available through the `elemta queue` command.

### List Messages

```bash
# List all messages in the active queue
elemta queue list active

# List all messages in the deferred queue
elemta queue list deferred

# List all messages in the held queue
elemta queue list held

# List all messages in the failed queue
elemta queue list failed

# List all messages in all queues
elemta queue list all
```

### View Message Details

```bash
# View details of a specific message
elemta queue view <message-id>

# View message content
elemta queue content <message-id>
```

### Retry Message

```bash
# Retry a specific message
elemta queue retry <message-id>

# Retry all messages in the failed queue
elemta queue retry-all failed

# Retry all messages in the deferred queue
elemta queue retry-all deferred
```

### Hold Message

```bash
# Hold a specific message
elemta queue hold <message-id>

# Hold all messages in the active queue
elemta queue hold-all active

# Hold all messages in the deferred queue
elemta queue hold-all deferred
```

### Release Message

```bash
# Release a held message
elemta queue release <message-id>

# Release all messages in the held queue
elemta queue release-all
```

### Delete Message

```bash
# Delete a specific message
elemta queue delete <message-id>

# Delete all messages in the failed queue
elemta queue delete-all failed
```

### Flush Queue

```bash
# Flush the active queue
elemta queue flush active

# Flush the deferred queue
elemta queue flush deferred

# Flush the held queue
elemta queue flush held

# Flush the failed queue
elemta queue flush failed

# Flush all queues
elemta queue flush all
```

### Queue Statistics

```bash
# Show queue statistics
elemta queue stats
```

## Queue Directory Structure

The queue is stored in the file system with the following directory structure:

```
queue/
├── active/
├── deferred/
├── held/
└── failed/
```

Each message is stored as two files:
1. `<message-id>.json`: Contains message metadata
2. `<message-id>.eml`: Contains the raw message content

## Queue Integration with SMTP Server

When the SMTP server receives a message, it:

1. Creates a new message in the active queue
2. Stores the message metadata and content
3. Returns success to the SMTP client

The queue processor then:

1. Scans the active queue for new messages
2. Attempts delivery of each message
3. Updates the message status based on delivery result
4. Moves the message to the appropriate queue if needed

This decoupled approach ensures that the SMTP server can quickly accept messages without waiting for delivery to complete.

## Configuration Options

The queue system can be configured with the following options:

### YAML Format

```yaml
# Queue configuration
queue:
  queue_dir: "/var/spool/elemta/queue"   # Queue storage directory
  max_workers: 10                        # Maximum delivery workers
  max_retries: 5                         # Maximum delivery attempts
  max_queue_time: 172800                 # Maximum time in queue (seconds)
  retry_schedule:                        # Custom retry schedule
    - 60     # 1 minute
    - 300    # 5 minutes
    - 900    # 15 minutes
    - 3600   # 1 hour
    - 10800  # 3 hours
    - 21600  # 6 hours
    - 43200  # 12 hours
  keep_delivered_messages: false         # Keep delivered messages
  keep_message_data: true                # Keep message data after delivery
  queue_priority_enabled: true           # Enable message prioritization

# Queue processor configuration
queue_processor:
  enabled: true                          # Enable queue processing
  interval: 10                           # Queue processing interval (seconds)
  workers: 5                             # Number of concurrent workers
  debug: false                           # Enable debug logging
```

### TOML Format

```toml
# Queue configuration
[queue]
queue_dir = "/var/spool/elemta/queue"    # Queue storage directory
max_workers = 10                         # Maximum delivery workers
max_retries = 5                          # Maximum delivery attempts
max_queue_time = 172800                  # Maximum time in queue (seconds)
retry_schedule = [60, 300, 900, 3600, 10800, 21600, 43200]  # Custom retry schedule
keep_delivered_messages = false          # Keep delivered messages
keep_message_data = true                 # Keep message data after delivery
queue_priority_enabled = true            # Enable message prioritization

# Queue processor configuration
[queue_processor]
enabled = true                           # Enable queue processing
interval = 10                            # Queue processing interval (seconds)
workers = 5                              # Number of concurrent workers
debug = false                            # Enable debug logging
```

## Monitoring

Elemta exposes queue metrics for monitoring. See [Monitoring](monitoring.md) for more information. 