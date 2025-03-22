#!/bin/bash

# Script to run Elemta CLI commands in Docker

# Check if the elemta_node0 container is running
if ! docker ps | grep -q "elemta_node0.*"; then
    echo "The elemta_node0 container is not running."
    echo "Starting it now..."
    
    # Check if the container exists but is stopped
    if docker ps -a | grep -q elemta_node0; then
        docker start elemta_node0
    else
        echo "The elemta_node0 container doesn't exist. Please run docker-compose up -d first."
        exit 1
    fi
    
    # Wait for the container to be ready
    echo "Waiting for the container to be ready..."
    for i in {1..10}; do
        if docker ps | grep -q "elemta_node0"; then
            break
        fi
        echo "Waiting... ($i/10)"
        sleep 3
    done
fi

# Run the command directly using the elemta binary
docker exec -it elemta_node0 /app/elemta "$@" 