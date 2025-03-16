# Queue Management System

Elemta includes a robust queue management system for reliable email delivery. This document explains how the queue system works and how to use the queue management CLI tool.

## Queue Architecture

The queue system is designed with multiple tiers to handle different message states:

1. **Active Queue**: Messages that are actively being processed for delivery.
2. **Deferred Queue**: Messages that have failed delivery and are waiting for retry based on a backoff schedule.
3. **Held Queue**: Messages that have been manually held for review.
4. **Failed Queue**: Messages that have permanently failed after exceeding retry limits or other fatal errors.

## Message Prioritization

Messages can be assigned different priority levels:

- **Low**: For non-urgent messages.
- **Normal**: Default priority for most messages.
- **High**: For important messages that should be delivered before normal messages.
- **Critical**: For urgent messages that should be delivered as soon as possible.

## Retry Logic

When a message delivery fails, it is moved to the deferred queue with an exponential backoff schedule:

1. The first retry happens after 1 minute.
2. Subsequent retries follow an exponential backoff pattern (e.g., 5 minutes, 15 minutes, 30 minutes, 1 hour, etc.).
3. The backoff schedule is configurable in the configuration file.
4. After the maximum number of retries, the message is moved to the failed queue.

## Queue Management CLI

The `elemta-queue` command-line tool allows you to manage the queue system.

### Installation

The CLI tool is included with the Elemta installation. Make sure it's in your PATH.

### Basic Usage

```bash
elemta-queue [options] command [args]
```

### Options

- `-config <path>`: Path to the configuration file.
- `-queue <type>`: Queue type to operate on (active, deferred, held, failed, all). Default is "all".

### Commands

#### List Messages

List all messages in the queue:

```bash
elemta-queue list
```

List messages in a specific queue:

```bash
elemta-queue -queue active list
elemta-queue -queue deferred list
elemta-queue -queue held list
elemta-queue -queue failed list
```

#### View Message Details

View detailed information about a specific message:

```bash
elemta-queue view <message-id>
```

This shows:
- Message metadata (ID, from, to, status, priority, etc.)
- Delivery attempts
- Error information
- Message content

#### Retry a Message

Force immediate retry of a message from any queue:

```bash
elemta-queue retry <message-id>
```

This moves the message to the active queue for immediate delivery.

#### Hold a Message

Hold a message for manual review:

```bash
elemta-queue hold <message-id> [reason]
```

This moves the message to the held queue with an optional reason.

#### Release a Message

Release a held message back to the active queue:

```bash
elemta-queue release <message-id>
```

#### Delete a Message

Delete a message from any queue:

```bash
elemta-queue delete <message-id>
```

#### Flush Queue

Delete all messages from all queues:

```bash
elemta-queue flush
```

Delete all messages from a specific queue:

```bash
elemta-queue -queue active flush
elemta-queue -queue deferred flush
elemta-queue -queue held flush
elemta-queue -queue failed flush
```

#### Show Queue Statistics

Display statistics about the queue:

```bash
elemta-queue stats
```

This shows:
- Number of messages in each queue
- Total message count
- Data size

## Configuration

The queue system can be configured in the Elemta configuration file (YAML or TOML format):

### YAML Configuration

```yaml
queue:
  queue_dir: "./queue"
  max_workers: 10
  max_retries: 5
  max_queue_time: 172800
  retry_schedule:
    - 60
    - 300
    - 900
    - 3600
    - 10800
    - 21600
    - 43200
  keep_delivered_messages: true
  keep_message_data: true
  queue_priority_enabled: true
```

### TOML Configuration

```toml
[queue]
queue_dir = "./queue"
max_workers = 10
max_retries = 5
max_queue_time = 172800
retry_schedule = [60, 300, 900, 3600, 10800, 21600, 43200]
keep_delivered_messages = true
keep_message_data = true
queue_priority_enabled = true
```

### Configuration Options

- `queue_dir`: Directory where queue files are stored.
- `max_workers`: Maximum number of concurrent delivery workers.
- `max_retries`: Maximum number of delivery attempts before giving up.
- `max_queue_time`: Maximum time (in seconds) a message can stay in the queue before being moved to the failed queue.
- `retry_schedule`: Custom retry schedule in seconds. If empty, exponential backoff is used.
- `keep_delivered_messages`: Whether to keep delivered messages for archiving.
- `keep_message_data`: Whether to keep message data after delivery.
- `queue_priority_enabled`: Whether to enable queue prioritization.

## Programmatic API

The queue system can also be accessed programmatically through the Go API:

```go
import "github.com/busybox42/elemta/internal/smtp"

// Create a queue manager
qm := smtp.NewQueueManager(config)
qm.Start()
defer qm.Stop()

// Enqueue a message
msg := smtp.NewMessage()
msg.from = "sender@example.com"
msg.to = []string{"recipient@example.com"}
msg.data = []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.")
err := qm.EnqueueMessage(msg, smtp.PriorityNormal)

// Hold a message
err = qm.HoldMessage(messageID, "Manual review required")

// Release a message
err = qm.ReleaseMessage(messageID)

// Get queue statistics
stats := qm.GetQueueStats()
```

## Queue Directory Structure

The queue directory has the following structure:

```
queue/
├── active/       # Active queue messages
├── deferred/     # Deferred queue messages
├── held/         # Held queue messages
├── failed/       # Failed queue messages
├── data/         # Message content data
└── delivered/    # Archived delivered messages (if enabled)
```

Each message has:
1. A metadata file (JSON) in the appropriate queue directory
2. A data file in the data directory containing the raw message content

## Monitoring

The queue system logs detailed information about message processing, which can be used for monitoring and troubleshooting. The `elemta-queue stats` command provides a quick overview of the current queue state.

For more advanced monitoring, consider integrating with a monitoring system like Prometheus and Grafana to track queue metrics over time. 