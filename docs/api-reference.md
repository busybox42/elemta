# API Reference

This document provides a comprehensive reference for Elemta's REST API endpoints.

## Base URL

```
http://localhost:8025/api
```

## Authentication

Most endpoints don't require authentication for monitoring and statistics. Administrative operations may require authentication depending on configuration.

## Response Format

All responses are in JSON format. Error responses include HTTP status codes and descriptive messages.

## Endpoints

### Delivery Statistics

#### GET /api/stats/delivery

Retrieves delivery statistics with configurable time scale aggregation.

**Parameters:**
- `timeScale` (optional): Time aggregation level
  - `hour` (default): Hourly statistics for the last 24 hours
  - `day`: Daily statistics for the last 30 days
  - `week`: Weekly statistics for the last 12 weeks
  - `month`: Monthly statistics for the last 12 months

**Example Requests:**

```bash
# Get hourly statistics (default)
curl http://localhost:8025/api/stats/delivery

# Get daily statistics
curl http://localhost:8025/api/stats/delivery?timeScale=day

# Get weekly statistics
curl http://localhost:8025/api/stats/delivery?timeScale=week

# Get monthly statistics
curl http://localhost:8025/api/stats/delivery?timeScale=month
```

**Response Structure:**

```json
{
  "total_delivered": 1250,
  "total_failed": 45,
  "total_deferred": 23,
  "success_rate": 94.8,
  "data": [
    {
      "label": "2026-01-28",
      "delivered": 52,
      "failed": 2,
      "deferred": 1
    },
    {
      "label": "2026-01-27",
      "delivered": 48,
      "failed": 1,
      "deferred": 0
    }
  ],
  "by_hour": [
    {
      "hour": "15:00",
      "delivered": 12,
      "failed": 0,
      "deferred": 0
    }
  ],
  "recent_errors": [
    {
      "message_id": "msg-12345",
      "recipient": "user@example.com",
      "error": "Connection timeout",
      "timestamp": "2026-01-28T12:00:00Z"
    }
  ]
}
```

**Field Descriptions:**

- `total_delivered`: Total number of successfully delivered messages
- `total_failed`: Total number of failed delivery attempts
- `total_deferred`: Total number of deferred messages
- `success_rate`: Overall delivery success rate percentage
- `data`: Array of time-scale aggregated statistics
- `by_hour`: Hourly statistics (maintained for backward compatibility)
- `recent_errors`: Array of recent delivery errors

### Queue Management

#### GET /api/queue/stats

Retrieves current queue statistics.

**Example Request:**
```bash
curl http://localhost:8025/api/queue/stats
```

**Response:**
```json
{
  "pending": 15,
  "deferred": 3,
  "failed": 1,
  "total": 19
}
```

#### GET /api/queue/{type}

Retrieves messages in a specific queue.

**Parameters:**
- `type`: Queue type (`pending`, `deferred`, `failed`)

**Example Request:**
```bash
curl http://localhost:8025/api/queue/pending
```

#### GET /api/queue/message/{id}

Retrieves details of a specific message.

**Parameters:**
- `id`: Message ID

**Example Request:**
```bash
curl http://localhost:8025/api/queue/message/msg-12345
```

#### DELETE /api/queue/message/{id}

Deletes a specific message from the queue.

**Parameters:**
- `id`: Message ID

**Example Request:**
```bash
curl -X DELETE http://localhost:8025/api/queue/message/msg-12345
```

#### POST /api/queue/{type}/flush

Flushes all messages from a specific queue.

**Parameters:**
- `type`: Queue type (`pending`, `deferred`, `failed`, `all`)

**Example Request:**
```bash
curl -X POST http://localhost:8025/api/queue/pending/flush
```

### Logging

#### GET /api/logs

Retrieves system logs.

**Parameters:**
- `level` (optional): Filter by log level (`debug`, `info`, `warn`, `error`, `fatal`)
- `limit` (optional): Maximum number of log entries to return (default: 100)

**Example Request:**
```bash
curl http://localhost:8025/api/logs?level=error&limit=50
```

#### GET /api/logs/messages

Retrieves message delivery logs with enhanced filtering.

**Parameters:**
- `event_type` (optional): Filter by event type (`delivery`, `rejection`, `tempfail`, `system`)
- `limit` (optional): Maximum number of entries to return (default: 100)

**Example Request:**
```bash
curl "http://localhost:8025/api/logs/messages?event_type=rejection&limit=50"
```

**Response Structure:**
```json
{
  "logs": [
    {
      "timestamp": "2026-01-28T12:00:00Z",
      "event_type": "rejection",
      "message_id": "msg-12345",
      "recipient": "user@example.com",
      "delivery_ip": "192.168.1.100",
      "delivery_host": "mail.example.com",
      "spam_score": 8.5,
      "threats": ["spam"],
      "message": "Message rejected due to spam score"
    }
  ]
}
```

### Health and Monitoring

#### GET /api/health

Retrieves server health status.

**Example Request:**
```bash
curl http://localhost:8025/api/health
```

**Response:**
```json
{
  "status": "healthy",
  "uptime": 86400,
  "uptime_formatted": "1 day",
  "started_at": "2026-01-27T12:00:00Z",
  "go_version": "1.21.0",
  "num_goroutines": 45,
  "memory": {
    "alloc": 10485760,
    "total_alloc": 52428800,
    "sys": 31457280
  }
}
```

#### GET /api/stats/delivery

Retrieves detailed delivery statistics (same as /api/stats/delivery above).

### Test Email

#### POST /api/send-test

Sends a test email for testing configuration.

**Request Body:**
```json
{
  "from": "test@example.com",
  "to": "recipient@example.com",
  "subject": "Test Email",
  "body": "This is a test email from Elemta."
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8025/api/send-test \
  -H "Content-Type: application/json" \
  -d '{
    "from": "test@example.com",
    "to": "recipient@example.com",
    "subject": "Test Email",
    "body": "This is a test email from Elemta."
  }'
```

## Error Handling

### HTTP Status Codes

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### Error Response Format

```json
{
  "error": "Error message description",
  "code": "ERROR_CODE",
  "details": "Additional error details"
}
```

## Rate Limiting

API endpoints may be rate limited to prevent abuse. When rate limits are exceeded, the server responds with HTTP 429 Too Many Requests.

## WebSocket Support

Some endpoints support WebSocket connections for real-time updates:

- `/api/logs/ws`: Real-time log streaming
- `/api/queue/ws`: Real-time queue status updates

## SDK Examples

### Go

```go
package main

import (
    "encoding/json"
    "net/http"
)

type DeliveryStats struct {
    TotalDelivered int64 `json:"total_delivered"`
    TotalFailed    int64 `json:"total_failed"`
    SuccessRate    float64 `json:"success_rate"`
    Data           []TimeScaleStats `json:"data"`
}

func getDeliveryStats(timeScale string) (*DeliveryStats, error) {
    resp, err := http.Get("http://localhost:8025/api/stats/delivery?timeScale=" + timeScale)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var stats DeliveryStats
    err = json.NewDecoder(resp.Body).Decode(&stats)
    return &stats, err
}
```

### JavaScript

```javascript
async function getDeliveryStats(timeScale = 'hour') {
    const response = await fetch(`/api/stats/delivery?timeScale=${timeScale}`);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return await response.json();
}

// Example usage
const hourlyStats = await getDeliveryStats('hour');
const dailyStats = await getDeliveryStats('day');
```

### Python

```python
import requests

def get_delivery_stats(time_scale='hour'):
    response = requests.get(f'http://localhost:8025/api/stats/delivery', 
                          params={'timeScale': time_scale})
    response.raise_for_status()
    return response.json()

# Example usage
hourly_stats = get_delivery_stats('hour')
daily_stats = get_delivery_stats('day')
```
