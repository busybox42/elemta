#!/bin/sh
set -e

# Function to check if a service is ready
check_service() {
    local host=$1
    local port=$2
    local service=$3
    local max_attempts=$4
    local attempt=1

    echo "Waiting for $service to be ready..."
    while ! nc -z $host $port >/dev/null 2>&1; do
        if [ $attempt -ge $max_attempts ]; then
            echo "$service is not available after $max_attempts attempts, continuing anyway..."
            break
        fi
        echo "Attempt $attempt: $service is not ready yet, waiting..."
        sleep 5
        attempt=$((attempt + 1))
    done

    if [ $attempt -lt $max_attempts ]; then
        echo "$service is ready!"
    fi
}

# Wait for services to be ready
check_service elemta-clamav 3310 "ClamAV" 12  # Wait up to 1 minute
check_service elemta-rspamd 11333 "Rspamd" 12  # Wait up to 1 minute

# Start Elemta
echo "Starting Elemta..."
exec /app/elemta server

# The exec command replaces the shell process, so the code below will only run if exec fails
echo "Server failed to start properly"
exit 1

