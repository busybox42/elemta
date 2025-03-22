# Elemta CLI Tool

The Elemta CLI tool provides a command-line interface for interacting with the Elemta Mail Transfer Agent. It communicates with the API server to manage the mail queue and check server status.

## Installation

You can install the Elemta CLI tool by running:

```bash
make cli
```

This will build the CLI tool and place it in the `bin` directory. You can also install it to `/usr/local/bin` by running:

```bash
make install
```

## Usage

The Elemta CLI tool has the following commands:

### Queue Management

- `elemta-cli queue list [queue_type]` - List messages in the queue
- `elemta-cli queue show [message_id]` - Show details of a specific message
- `elemta-cli queue delete [message_id]` - Delete a specific message
- `elemta-cli queue flush [queue_type]` - Flush messages from the queue
- `elemta-cli queue stats` - Show queue statistics

### Server Status

- `elemta-cli status` - Show the current status of the Elemta MTA server
- `elemta-cli version` - Show version information

### Global Flags

- `-a, --api-url` - API server URL (default "http://localhost:8081")
- `-k, --api-key` - API key for authentication
- `-v, --verbose` - Enable verbose output
- `-f, --formatter` - Output format (table, json, csv)

## Configuration

By default, the Elemta CLI tool connects to the API server at `http://localhost:8081`. You can change this by using the `--api-url` flag or by setting the `ELEMTA_API_URL` environment variable.

## Examples

List all messages in the queue:

```bash
elemta-cli queue list
```

Show details of a specific message:

```bash
elemta-cli queue show abc123
```

Flush the active queue:

```bash
elemta-cli queue flush active
```

Check server status:

```bash
elemta-cli status
``` 