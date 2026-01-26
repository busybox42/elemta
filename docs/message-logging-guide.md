# Message Lifecycle Logging Implementation Guide

## Overview

The new `logging.MessageLogger` provides structured logging for all message lifecycle events with comprehensive timing information.

## Log Types

### 1. Reception Log
Logged when a message is received and accepted into the queue.

**Fields:**
- All message context (from, to, subject, size, etc.)
- Client information (IP, hostname, auth status, TLS)
- `processing_delay_ms`: Time from SMTP reception to queue acceptance
- Virus/spam scan results

### 2. Delivery Log
Logged when a message is successfully delivered.

**Fields:**
- All message context
- `total_delay_ms`: Time from reception to delivery
- `queue_delay_ms`: Time from queue acceptance to delivery
- Retry count
- Delivery method (LMTP, SMTP, etc.)

### 3. Rejection Log
Logged when a message is rejected during SMTP reception (before queuing).

**Fields:**
- All message context
- Client information
- `processing_delay_ms`: Time spent processing before rejection
- Rejection reason (virus, spam, policy, etc.)

### 4. Deferral Log
Logged when a message encounters a temporary failure and is deferred for retry.

**Fields:**
- All message context
- `total_delay_ms`: Time from reception to deferral
- `queue_delay_ms`: Time in queue before deferral
- `next_retry_in_seconds`: When the next retry will occur
- Retry count
- Deferral reason

### 5. Bounce Log
Logged when a message permanently fails.

**Fields:**
- All message context
- `total_delay_ms`: Time from reception to bounce
- `queue_delay_ms`: Time in queue before bounce
- Retry count
- Bounce reason

## Integration Points

### In SMTP Session (session_data.go)

```go
import "github.com/busybox42/elemta/internal/logging"

// After message is accepted
msgLogger := logging.NewMessageLogger(dh.logger)
msgLogger.LogReception(logging.MessageContext{
    MessageID:      metadata.MessageID,
    QueueID:        queueID,
    From:           metadata.From,
    To:             metadata.To,
    Subject:        metadata.Subject,
    Size:           metadata.Size,
    ClientIP:       dh.state.GetClientIP(),
    ClientHostname: dh.state.GetClientHostname(),
    Username:       dh.state.GetUsername(),
    Authenticated:  dh.state.IsAuthenticated(),
    TLSActive:      dh.state.IsTLSActive(),
    ReceptionTime:  receptionStartTime,
    ProcessingTime: time.Now(),
    VirusScanned:   virusResult != nil,
    VirusFound:     virusResult != nil && virusResult.Infected,
    SpamScanned:    spamResult != nil,
    SpamScore:      spamScore,
})

// For rejections
msgLogger.LogRejection(logging.MessageContext{
    MessageID:      metadata.MessageID,
    From:           metadata.From,
    To:             metadata.To,
    Subject:        metadata.Subject,
    Size:           metadata.Size,
    ClientIP:       dh.state.GetClientIP(),
    ReceptionTime:  receptionStartTime,
    ProcessingTime: time.Now(),
    Error:          rejectionReason,
    VirusFound:     virusDetected,
    SpamScore:      spamScore,
})
```

### In Queue Processor (processor.go)

```go
import "github.com/busybox42/elemta/internal/logging"

// For successful delivery
msgLogger := logging.NewMessageLogger(p.logger)
msgLogger.LogDelivery(logging.MessageContext{
    MessageID:      msg.ID,
    QueueID:        msg.ID,
    From:           msg.From,
    To:             msg.To,
    Subject:        msg.Subject,
    Size:           msg.Size,
    ReceptionTime:  msg.CreatedAt,
    ProcessingTime: msg.CreatedAt, // When queued
    DeliveryTime:   time.Now(),
    RetryCount:     msg.RetryCount,
    DeliveryMethod: "lmtp",
})

// For deferrals
msgLogger.LogDeferral(logging.MessageContext{
    MessageID:      msg.ID,
    QueueID:        msg.ID,
    From:           msg.From,
    To:             msg.To,
    Subject:        msg.Subject,
    Size:           msg.Size,
    ReceptionTime:  msg.CreatedAt,
    ProcessingTime: msg.CreatedAt,
    NextRetry:      msg.NextRetry,
    RetryCount:     msg.RetryCount,
    Error:          deliveryErr.Error(),
    DeliveryMethod: "lmtp",
})

// For bounces
msgLogger.LogBounce(logging.MessageContext{
    MessageID:      msg.ID,
    QueueID:        msg.ID,
    From:           msg.From,
    To:             msg.To,
    Subject:        msg.Subject,
    Size:           msg.Size,
    ReceptionTime:  msg.CreatedAt,
    ProcessingTime: msg.CreatedAt,
    RetryCount:     msg.RetryCount,
    Error:          bounceReason,
    DeliveryMethod: "lmtp",
})
```

## Log Output Examples

### Reception Log
```json
{
  "time": "2026-01-26T04:30:15Z",
  "level": "INFO",
  "msg": "message_reception",
  "event_type": "reception",
  "message_id": "abc123",
  "queue_id": "abc123",
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "recipient_count": 1,
  "subject": "Test Message",
  "size": 1024,
  "client_ip": "192.168.1.100",
  "authenticated": true,
  "tls_active": true,
  "reception_time": "2026-01-26T04:30:15Z",
  "processing_delay_ms": 45,
  "virus_scanned": true,
  "virus_found": false,
  "spam_scanned": true,
  "spam_score": 2.5
}
```

### Delivery Log
```json
{
  "time": "2026-01-26T04:30:20Z",
  "level": "INFO",
  "msg": "message_delivery",
  "event_type": "delivery",
  "message_id": "abc123",
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "delivery_method": "lmtp",
  "reception_time": "2026-01-26T04:30:15Z",
  "delivery_time": "2026-01-26T04:30:20Z",
  "total_delay_ms": 5000,
  "queue_delay_ms": 4955,
  "retry_count": 0,
  "status": "delivered"
}
```

### Deferral Log
```json
{
  "time": "2026-01-26T04:30:25Z",
  "level": "WARN",
  "msg": "message_deferral",
  "event_type": "deferral",
  "message_id": "xyz789",
  "from": "sender@example.com",
  "to": ["user@example.com"],
  "reception_time": "2026-01-26T04:30:15Z",
  "deferral_time": "2026-01-26T04:30:25Z",
  "next_retry": "2026-01-26T04:31:25Z",
  "total_delay_ms": 10000,
  "queue_delay_ms": 9955,
  "next_retry_in_seconds": 60,
  "retry_count": 1,
  "deferral_reason": "452 Insufficient system storage",
  "status": "deferred"
}
```

### Bounce Log
```json
{
  "time": "2026-01-26T04:35:30Z",
  "level": "ERROR",
  "msg": "message_bounce",
  "event_type": "bounce",
  "message_id": "def456",
  "from": "sender@example.com",
  "to": ["invalid@example.com"],
  "reception_time": "2026-01-26T04:30:15Z",
  "bounce_time": "2026-01-26T04:35:30Z",
  "total_delay_ms": 315000,
  "queue_delay_ms": 314955,
  "retry_count": 5,
  "bounce_reason": "550 User doesn't exist",
  "status": "bounced"
}
```

## Querying Logs

### Find all deliveries
```bash
grep '"event_type":"delivery"' /var/log/elemta.log | jq .
```

### Find slow deliveries (>10s)
```bash
grep '"event_type":"delivery"' /var/log/elemta.log | jq 'select(.total_delay_ms > 10000)'
```

### Find all deferrals
```bash
grep '"event_type":"deferral"' /var/log/elemta.log | jq .
```

### Find all bounces
```bash
grep '"event_type":"bounce"' /var/log/elemta.log | jq .
```

### Calculate average delivery time
```bash
grep '"event_type":"delivery"' /var/log/elemta.log | jq -s 'map(.total_delay_ms) | add/length'
```

## Next Steps

To fully implement this logging:

1. Update `session_data.go` to track reception start time
2. Update `session_data.go` to use MessageLogger for reception/rejection
3. Update `processor.go` to use MessageLogger for delivery/deferral/bounce
4. Add reception_time to Message struct (or use CreatedAt)
5. Consider adding processing_time to track when message enters queue vs when received
