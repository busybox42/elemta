#!/bin/bash
set -e

echo "Building elemta binary..."
go build -o elemta cmd/elemta/main.go

echo "Building Docker image with updated code..."
docker build -t elemta_node:latest .

echo "Restarting containers..."
docker-compose down
docker-compose up -d

echo "Waiting for containers to start..."
sleep 5

echo "Checking elemta_node0 logs..."
docker logs elemta_node0 | grep -i "Queue processor"

echo "Done! The updated elemta with queue processor support is running." 