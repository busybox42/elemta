#!/bin/sh
set -e

# Print environment variables for debugging
echo "Environment variables:"
env

# Print working directory
echo "Working directory:"
pwd
ls -la

# Check if the binary exists
echo "Looking for server binary:"
find / -name elemta -type f 2>/dev/null || echo "Binary not found"

# Run the server in foreground mode
echo "Starting Elemta server..."
exec /app/elemta server

# The exec command replaces the shell process, so the code below will only run if exec fails
echo "Server failed to start properly"
exit 1

