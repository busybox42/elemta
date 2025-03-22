FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the elemta binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o elemta ./cmd/elemta
RUN CGO_ENABLED=0 GOOS=linux go build -o elemta-queue ./cmd/elemta-queue
RUN CGO_ENABLED=0 GOOS=linux go build -o elemta-cli ./cmd/elemta-cli

# Final image
FROM python:3.9-slim

WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /app/config /app/queue /app/logs /app/plugins

# Copy entrypoint script
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copy binaries from the builder stage
COPY --from=builder /build/elemta /app/elemta
COPY --from=builder /build/elemta-queue /app/elemta-queue
COPY --from=builder /build/elemta-cli /app/elemta-cli

# Expose ports
EXPOSE 2525 8080 8081

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"] 