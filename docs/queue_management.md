# Queue Management System

The Elemta MTA includes a robust queue management system for reliable email delivery. This document describes the queue system architecture, configuration options, and usage.

## Overview

The queue management system is responsible for:

1. Storing incoming messages for later delivery
2. Prioritizing messages based on importance
3. Managing retry attempts for failed deliveries
4. Cleaning up old messages that exceed the maximum queue time

## Architecture

The queue system consists of the following components:

- **QueueManager**: Manages the queue processing, prioritization, and worker pool
- **QueuedMessage**: Extends MessageInfo with additional queue-specific fields
- **Priority Levels**: Messages can be assigned different priority levels

### Priority Levels

Messages can be assigned one of the following priority levels:

- **Low (0)**: Non-urgent messages
- **Normal (1)**: Standard messages (default)
- **High (2)**: Important messages
- **Critical (3)**: Urgent messages that should be delivered as soon as possible

## Configuration

The queue system can be configured through the following settings in the configuration file:

```json
{
  "queue_dir": "./queue",
  "max_workers": 10,
  "max_retries": 10,
  "max_queue_time": 172800,
  "retry_schedule": [60, 300, 900, 3600, 10800, 21600, 43200]
}
```

### Configuration Options

- **queue_dir**: Directory where queued messages are stored
- **max_workers**: Maximum number of concurrent delivery workers
- **max_retries**: Maximum number of delivery attempts before giving up
- **max_queue_time**: Maximum time (in seconds) a message can stay in the queue
- **retry_schedule**: Array of retry intervals (in seconds) for each retry attempt

## Queue Storage Format

Each queued message consists of two files:

1. **Message File**: Contains the raw message data (filename is the message ID)
2. **Metadata File**: JSON file with message metadata (filename is the message ID + ".json")

### Metadata Format

```json
{
  "id": "message-uuid",
  "from": "sender@example.com",
  "to": ["recipient1@example.com", "recipient2@example.com"],
  "status": "queued",
  "created_at": "2023-03-14T12:34:56Z",
  "updated_at": "2023-03-14T12:34:56Z",
  "priority": 1,
  "retry_count": 0,
  "next_retry": "2023-03-14T12:44:56Z",
  "last_error": "",
  "attempts": []
}
```

## Queue Processing

The queue manager processes messages in the following order:

1. Messages are sorted by priority (highest first)
2. Within each priority level, messages are sorted by next retry time
3. Messages are processed by a pool of worker goroutines
4. Failed deliveries are rescheduled based on the retry schedule

## Retry Logic

When a delivery attempt fails:

1. The retry count is incremented
2. The error message is stored
3. The next retry time is calculated based on the retry schedule
4. If the retry count exceeds the maximum, the message remains in the queue but is no longer processed

## Cleanup

The queue manager periodically cleans up:

1. Successfully delivered messages (removed immediately)
2. Messages that have exceeded the maximum queue time

## Usage in Code

To enqueue a message with a specific priority:

```go
qm := smtp.NewQueueManager(config)
msg := smtp.NewMessage()
// Set message properties...
err := qm.EnqueueMessage(msg, smtp.PriorityNormal)
```

## Command Line Tools

Elemta provides command-line tools for queue management:

```bash
# List queued messages
elemta queue list

# View a specific message
elemta queue view <message-id>

# Force retry of a failed message
elemta queue retry <message-id>

# Delete a message from the queue
elemta queue delete <message-id>

# Flush the entire queue
elemta queue flush
```

## Monitoring

The queue system provides metrics for monitoring:

- Total messages in queue
- Messages by priority
- Messages by status
- Delivery success/failure rates
- Average delivery time

These metrics can be accessed through the monitoring API or web interface. 