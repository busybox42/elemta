#!/bin/bash

# Define default port
PORT=2530

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -p|--port)
      PORT="$2"
      shift
      shift
      ;;
    *)
      # unknown option
      shift
      ;;
  esac
done

echo "Starting Elemta MTA server in development mode on port $PORT..."
go run cmd/elemta/main.go server --dev --no-auth-required --port "$PORT" 