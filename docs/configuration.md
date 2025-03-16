# Elemta Configuration

This document describes how to configure the Elemta SMTP server using either YAML or TOML configuration formats.

## Configuration Formats

Elemta supports two configuration formats:

1. **YAML**: Traditional configuration format
2. **TOML**: New configuration format with improved readability

Both formats support the same configuration options, so you can choose the one you prefer.

## Configuration File Location

By default, Elemta looks for a configuration file in the following locations:

1. Path specified with the `-config` flag
2. `./config/elemta.toml`
3. `./config/elemta.yaml`
4. `/etc/elemta/elemta.toml`
5. `/etc/elemta/elemta.yaml`

## Specifying a Configuration File

You can specify a configuration file using the `-config` flag:

```bash
# Run with YAML configuration
./elemta -config config/elemta.yaml

# Run with TOML configuration
./elemta -config config/elemta.toml
```

## Basic Configuration

Here's a basic configuration example in both formats:

### YAML Format

```yaml
# Basic server configuration
hostname: "mail.example.com"
listen_addr: "0.0.0.0:25"
queue_dir: "/var/spool/elemta/queue"
log_level: "info"

# TLS configuration
tls:
  enabled: true
  cert_file: "/etc/elemta/certs/cert.pem"
  key_file: "/etc/elemta/certs/key.pem"

# Authentication
auth:
  enabled: true
  methods:
    - "plain"
    - "login"
  backend: "file"
  file_path: "/etc/elemta/users.json"

# Queue configuration
queue:
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

### TOML Format

```toml
# Basic server configuration
hostname = "mail.example.com"
listen_addr = "0.0.0.0:25"
queue_dir = "/var/spool/elemta/queue"
log_level = "info"

# TLS configuration
[tls]
enabled = true
cert_file = "/etc/elemta/certs/cert.pem"
key_file = "/etc/elemta/certs/key.pem"

# Authentication
[auth]
enabled = true
methods = ["plain", "login"]
backend = "file"
file_path = "/etc/elemta/users.json"

# Queue configuration
[queue]
max_workers = 10
max_retries = 5
max_queue_time = 172800
retry_schedule = [60, 300, 900, 3600, 10800, 21600, 43200]
keep_delivered_messages = true
keep_message_data = true
queue_priority_enabled = true
```

## Configuration Options

### Server Options

| Option | Description | Default |
|--------|-------------|---------|
| `hostname` | Server hostname used in SMTP greeting | `localhost` |
| `listen_addr` | Address and port to listen on | `0.0.0.0:25` |
| `queue_dir` | Directory for queue storage | `./queue` |
| `log_level` | Logging level (debug, info, warn, error) | `info` |
| `max_message_size` | Maximum message size in bytes | `10485760` (10MB) |
| `max_recipients` | Maximum recipients per message | `100` |
| `banner` | SMTP banner text | `Elemta SMTP Server` |

### TLS Options

| Option | Description | Default |
|--------|-------------|---------|
| `tls.enabled` | Enable TLS support | `false` |
| `tls.cert_file` | Path to TLS certificate file | `""` |
| `tls.key_file` | Path to TLS key file | `""` |
| `tls.required` | Require TLS for all connections | `false` |
| `tls.client_auth` | Require client certificate authentication | `false` |

### Authentication Options

| Option | Description | Default |
|--------|-------------|---------|
| `auth.enabled` | Enable authentication | `false` |
| `auth.methods` | Authentication methods (plain, login) | `["plain", "login"]` |
| `auth.backend` | Authentication backend (file, ldap, etc.) | `"file"` |
| `auth.file_path` | Path to authentication file | `""` |

### Queue Options

| Option | Description | Default |
|--------|-------------|---------|
| `queue.max_workers` | Maximum delivery workers | `5` |
| `queue.max_retries` | Maximum delivery attempts | `5` |
| `queue.max_queue_time` | Maximum time in queue (seconds) | `172800` (2 days) |
| `queue.retry_schedule` | Custom retry schedule in seconds | Exponential backoff |
| `queue.keep_delivered_messages` | Keep delivered messages | `false` |
| `queue.keep_message_data` | Keep message data after delivery | `true` |
| `queue.queue_priority_enabled` | Enable message prioritization | `true` |

### Plugin Options

| Option | Description | Default |
|--------|-------------|---------|
| `plugins.enabled` | Enable plugin system | `true` |
| `plugins.directory` | Plugin directory | `./plugins` |
| `plugins.config_directory` | Plugin configuration directory | `./config/plugins` |

## Environment Variables

Configuration values can also be set using environment variables. The environment variable names are derived from the configuration keys by:

1. Converting to uppercase
2. Replacing dots with underscores
3. Prefixing with `ELEMTA_`

For example:
- `hostname` becomes `ELEMTA_HOSTNAME`
- `tls.enabled` becomes `ELEMTA_TLS_ENABLED`
- `queue.max_workers` becomes `ELEMTA_QUEUE_MAX_WORKERS`

Environment variables take precedence over configuration file values.

## Docker Configuration

When running Elemta in Docker, you can:

1. Mount a configuration file:
   ```bash
   docker run -v /path/to/config:/app/config elemta
   ```

2. Use environment variables:
   ```bash
   docker run -e ELEMTA_HOSTNAME=mail.example.com -e ELEMTA_TLS_ENABLED=true elemta
   ```

3. Use Docker Compose:
   ```yaml
   version: '3'
   services:
     elemta:
       image: elemta
       volumes:
         - ./config:/app/config
       environment:
         - ELEMTA_HOSTNAME=mail.example.com
         - ELEMTA_TLS_ENABLED=true
   ```

## Configuration Examples

For more configuration examples, see:
- [Basic SMTP Server](examples/config/basic.yaml)
- [TLS Configuration](examples/config/tls.yaml)
- [Authentication](examples/config/auth.yaml)
- [Queue Configuration](examples/config/queue.yaml)
- [Plugin Configuration](examples/config/plugins.yaml) 