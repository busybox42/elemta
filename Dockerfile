FROM golang:1.23-alpine AS builder

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
RUN CGO_ENABLED=0 go build -o elemta ./cmd/elemta
RUN CGO_ENABLED=0 go build -o elemta-queue ./cmd/elemta-queue
RUN CGO_ENABLED=0 go build -o elemta-cli ./cmd/elemta-cli

# Build the plugins (with CGO enabled for plugins)
WORKDIR /build/plugins
RUN CGO_ENABLED=1 go build -buildmode=plugin -o clamav.so ./clamav
RUN CGO_ENABLED=1 go build -buildmode=plugin -o rspamd.so ./rspamd
WORKDIR /build

# Final image
FROM debian:bookworm-slim

# Create a non-root user for security
RUN groupadd -r elemta -g 1001 && \
    useradd -r -g elemta -u 1001 -d /app -s /bin/sh elemta

# Install required packages
RUN apt-get update && apt-get install -y python3 python3-pip curl netcat-openbsd dos2unix libc6 && rm -rf /var/lib/apt/lists/*

# Create directories with proper ownership
RUN mkdir -p /app/config /app/queue /app/logs /app/plugins /app/certs && \
    chown -R elemta:elemta /app

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
COPY --from=builder --chown=elemta:elemta /build/plugins/clamav.so /app/plugins/clamav.so
COPY --from=builder --chown=elemta:elemta /build/plugins/rspamd.so /app/plugins/rspamd.so

# Copy configuration files with proper ownership
COPY --chown=elemta:elemta config/elemta.toml /app/config/elemta.toml
COPY --chown=elemta:elemta config/dev.toml /app/config/dev.toml
COPY --chown=elemta:elemta config/users.txt /app/config/users.txt

# Copy SQLite database with proper ownership
COPY --chown=elemta:elemta config/elemta.db /app/config/elemta.db

# Copy TLS cert and key with proper ownership and permissions
COPY --chown=elemta:elemta config/test.crt /app/certs/test.crt
COPY --chown=elemta:elemta config/test.key /app/certs/test.key
RUN chmod 644 /app/certs/test.crt && \
    chmod 600 /app/certs/test.key

# Copy web files with proper ownership
COPY --chown=elemta:elemta web /app/web

# Set proper permissions for executables
RUN chmod +x /app/elemta /app/elemta-queue /app/elemta-cli

# Set proper permissions for directories
RUN chmod 755 /app/config /app/queue /app/logs /app/plugins /app/certs && \
    chmod 700 /app/queue  # Queue directory should be private

# Create a startup script that fixes permissions as root, then drops privileges
RUN echo '#!/bin/sh' > /app/startup.sh && \
    echo 'echo "Fixing permissions for volume-mounted directories..."' >> /app/startup.sh && \
    echo 'chown -R elemta:elemta /app/queue /app/logs 2>/dev/null || true' >> /app/startup.sh && \
    echo 'chmod 700 /app/queue 2>/dev/null || true' >> /app/startup.sh && \
    echo 'chmod 755 /app/logs 2>/dev/null || true' >> /app/startup.sh && \
    echo 'echo "Dropping privileges to elemta user..."' >> /app/startup.sh && \
    echo 'exec gosu elemta /app/entrypoint.sh "$@"' >> /app/startup.sh && \
    chmod +x /app/startup.sh && \
    chown elemta:elemta /app/startup.sh

# Install gosu for privilege dropping
RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

# Expose ports
EXPOSE 2525 8080 8081

# Set entrypoint to the startup script
ENTRYPOINT ["/app/startup.sh"] 