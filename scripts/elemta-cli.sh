#!/bin/bash

# Script to run Elemta CLI commands in Docker

# Check if the elemta-cli container is running
if ! docker ps | grep -q elemta-cli; then
    echo "The elemta-cli container is not running."
    echo "Starting it now..."
    
    # Check if the container exists but is stopped
    if docker ps -a | grep -q elemta-cli; then
        docker start elemta-cli
    else
        # Check if the image exists
        if ! docker images | grep -q elemta-cli; then
            echo "Building the elemta-cli image..."
            docker-compose -f docker-compose-cli.yml build
        fi
        
        echo "Starting the elemta-cli container..."
        docker run -d --name elemta-cli --network elemta_elemta_network -p 2526:25 -p 5871:587 -p 8083:8080 elemta-cli
    fi
    
    # Wait for the container to be healthy
    echo "Waiting for the container to be ready..."
    for i in {1..10}; do
        if docker ps | grep -q "elemta-cli.*healthy"; then
            break
        fi
        echo "Waiting... ($i/10)"
        sleep 3
    done
fi

# Run the command
if [ "$1" == "queue" ]; then
    # Use elemta-queue for queue commands
    docker exec -it elemta-cli /app/elemta-queue -config /app/config/elemta.toml "${@:2}"
else
    # Use elemta for other commands
    docker exec -it elemta-cli /app/elemta "$@"
fi 