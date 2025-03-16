# Greylisting Plugin

The greylisting plugin implements a simple greylisting mechanism to help reduce spam. Greylisting is a method of defending against spam that temporarily rejects emails from unknown senders, expecting legitimate mail servers to retry after a delay.

## How Greylisting Works

1. When an email is received from a sender for the first time, the server temporarily rejects it with a 4xx SMTP error code.
2. Legitimate mail servers will retry delivery after a delay, typically within a few minutes or hours.
3. Spam software often doesn't retry, or doesn't follow proper retry procedures.
4. When the legitimate mail server retries after the configured delay, the email is accepted.

## Configuration

The greylisting plugin supports the following configuration options:

| Option | Description | Default |
|--------|-------------|---------|
| `delay` | The minimum time to wait before accepting a retry | `5m` (5 minutes) |

Example configuration in `elemta.yaml`:

```yaml
plugins:
  enabled: true
  plugin_path: "/path/to/plugins"
  plugins:
    - "greylisting"
  config:
    greylisting:
      delay: "15m"  # 15 minutes delay
```

## Technical Details

The plugin maintains an in-memory database of sender-recipient pairs with the timestamp of their first attempt. When a sender tries to deliver a message:

1. If the sender-recipient pair is not in the database, it's added with the current timestamp and the message is temporarily rejected.
2. If the pair is in the database but the configured delay hasn't passed since the first attempt, the message is still rejected.
3. If the pair is in the database and the delay has passed, the message is accepted.

The plugin automatically cleans up old entries (older than 36 hours) to prevent memory leaks.

## SMTP Response Codes

When greylisting is triggered, the plugin returns:

```
450 4.7.1 Please try again later (greylisting)
```

This is a temporary rejection code that tells the sending server to try again later.

## Limitations

- The greylisting database is stored in memory and will be lost when the server restarts.
- In a clustered environment, each server instance maintains its own separate greylisting database.
- Some legitimate mail servers might not retry, or might retry from different IP addresses, which can cause delays in email delivery.

## Metrics

The greylisting plugin reports the following Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `elemta_greylisting_total` | Counter | Total number of greylisted messages (first-time rejections) |
| `elemta_greylisting_passed` | Counter | Number of messages that passed greylisting (accepted after delay) |
| `elemta_greylisting_rejected` | Counter | Number of messages rejected due to not meeting the delay requirement |
| `elemta_greylisting_active` | Gauge | Current number of entries in the greylisting database |
| `elemta_greylisting_cleanup_total` | Counter | Number of cleanup operations performed |
| `elemta_greylisting_entries_removed` | Counter | Number of expired entries removed during cleanup |
| `elemta_greylisting_processing_time_seconds` | Histogram | Time taken to process a message through greylisting |

### Monitoring Greylisting

These metrics can be used to monitor the effectiveness of greylisting and tune the delay parameter. For example:

- A high ratio of `elemta_greylisting_total` to `elemta_greylisting_passed` might indicate that legitimate senders are not retrying properly.
- A continuously increasing `elemta_greylisting_active` could indicate a memory leak or insufficient cleanup.
- Spikes in `elemta_greylisting_processing_time_seconds` might indicate performance issues.

You can add these metrics to your Grafana dashboard to visualize greylisting effectiveness over time. 