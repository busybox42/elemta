# Multi-stage build for secure container deployment
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install Git and build tools for dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Clean up dependencies
RUN go mod tidy

# Build the elemta binaries (statically linked)
# All plugins are built-in to the main binary - no external .so files needed
RUN CGO_ENABLED=0 go build -o elemta ./cmd/elemta
RUN CGO_ENABLED=0 go build -o elemta-queue ./cmd/elemta-queue
RUN CGO_ENABLED=0 go build -o elemta-cli ./cmd/elemta-cli

# Security-hardened final image
FROM debian:bookworm-slim

# Create a non-root user with specific UID/GID for security
RUN groupadd -r elemta -g 1001 && \
    useradd -r -g elemta -u 1001 -d /app -s /bin/sh elemta

# Install required packages (no gosu - we don't need privilege dropping)
RUN apt-get update && apt-get install -y python3 python3-pip curl netcat-openbsd dos2unix libc6 && rm -rf /var/lib/apt/lists/*

# Create directories with proper ownership from the start
# Note: /app/plugins directory exists but is empty (all plugins are built-in)
RUN mkdir -p /app/config /app/queue /app/logs /app/plugins /app/certs && \
    chown -R elemta:elemta /app && \
    chmod 755 /app/config /app/logs /app/plugins /app/certs && \
    chmod 700 /app/queue

# Set working directory
WORKDIR /app

# Copy entrypoint script and set proper permissions
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN dos2unix /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chown elemta:elemta /app/entrypoint.sh

# Copy the binary and config files with proper ownership
COPY --from=builder --chown=elemta:elemta /build/elemta /app/elemta
COPY --from=builder --chown=elemta:elemta /build/elemta-queue /app/elemta-queue
COPY --from=builder --chown=elemta:elemta /build/elemta-cli /app/elemta-cli
# Note: No .so plugins copied - all plugins are built into the main binary

# Copy configuration files with proper ownership
COPY --chown=elemta:elemta config/elemta.toml /app/config/elemta.toml
COPY --chown=elemta:elemta config/dev.toml /app/config/dev.toml
# Note: Using LDAP authentication, no local database needed

# TLS certificates are expected to be mounted into /app/certs at runtime
# (CI builds do not embed test certificates.)

# Copy web files with proper ownership
COPY --chown=elemta:elemta web /app/web

# Copy images directory for logo
COPY --from=builder --chown=elemta:elemta /build/images /app/images

# Set proper permissions for executables
RUN chmod +x /app/elemta /app/elemta-queue /app/elemta-cli

# Create secure volume initialization script (runs as non-root)
RUN echo '#!/bin/sh' > /app/init-volumes.sh && \
    echo 'echo "Initializing volume directories as non-root user..."' >> /app/init-volumes.sh && \
    echo 'mkdir -p /app/queue/active /app/queue/deferred /app/queue/hold /app/queue/failed /app/logs' >> /app/init-volumes.sh && \
    echo 'chmod 700 /app/queue 2>/dev/null || true' >> /app/init-volumes.sh && \
    echo 'chmod 755 /app/logs 2>/dev/null || true' >> /app/init-volumes.sh && \
    echo 'echo "Volume initialization complete"' >> /app/init-volumes.sh && \
    chmod +x /app/init-volumes.sh && \
    chown elemta:elemta /app/init-volumes.sh

# Expose ports
EXPOSE 2525 8080 8081

# Switch to non-root user - NO PRIVILEGE ESCALATION
USER elemta

# Set entrypoint to the secure entrypoint script (runs as elemta user)
ENTRYPOINT ["/app/entrypoint.sh"]