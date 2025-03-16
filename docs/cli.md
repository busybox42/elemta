# Elemta CLI Tools

This document describes how to use the Elemta CLI tools, both locally and in Docker.

## Local Usage

If you've built Elemta from source, you can use the CLI tools directly:

```bash
# Main Elemta CLI
./build/elemta [command]

# Queue management CLI
./build/elemta-queue [options] command [args]
```

## Docker Usage

We provide a convenient script to access the CLI tools in Docker:

```bash
# Use the main Elemta CLI
./scripts/elemta-cli.sh [command]

# Use the queue management CLI
./scripts/elemta-cli.sh queue [command]
```

### Available Commands

#### Main CLI

```bash
# Show help
./scripts/elemta-cli.sh --help

# Start the server
./scripts/elemta-cli.sh server

# Manage the queue
./scripts/elemta-cli.sh queue
```

#### Queue Management

```bash
# Show queue help
./scripts/elemta-cli.sh queue --help

# List messages in the queue
./scripts/elemta-cli.sh queue list

# View details of a specific message
./scripts/elemta-cli.sh queue view <message-id>

# Move a message to the active queue for immediate retry
./scripts/elemta-cli.sh queue retry <message-id>

# Delete a message from the queue
./scripts/elemta-cli.sh queue delete <message-id>

# Delete all messages from the queue
./scripts/elemta-cli.sh queue flush

# Hold a message for manual review
./scripts/elemta-cli.sh queue hold <message-id> [reason]

# Release a held message back to the active queue
./scripts/elemta-cli.sh queue release <message-id>

# Show queue statistics
./scripts/elemta-cli.sh queue stats
```

### Docker Container Details

The CLI tools are available in a separate Docker container (`elemta-cli`) that runs alongside the main Elemta container. This container:

- Exposes the same CLI interface as the local build
- Uses the same configuration as the main Elemta container
- Can be used to manage the queue and server

### Building the CLI Container

If you need to rebuild the CLI container:

```bash
# Build the container
docker build -t elemta-cli -f Dockerfile.cli .

# Run the container
docker run -d --name elemta-cli --network elemta_network -p 2526:25 -p 5871:587 -p 8083:8080 elemta-cli
```

### Kubernetes Usage

For Kubernetes deployments, you can access the CLI tools using:

```bash
# Get a list of pods
kubectl get pods

# Access the CLI in a pod
kubectl exec -it <pod-name> -- /app/elemta [command]

# Access the queue management CLI in a pod
kubectl exec -it <pod-name> -- /app/elemta-queue [options] command [args]
``` 