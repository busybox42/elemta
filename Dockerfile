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

WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y python3 python3-pip curl netcat-openbsd dos2unix libc6 && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /app/config /app/queue /app/logs /app/plugins

# Copy entrypoint script
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN dos2unix /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Copy the binary and config files
COPY --from=builder /build/elemta /app/elemta
COPY --from=builder /build/elemta-queue /app/elemta-queue
COPY --from=builder /build/elemta-cli /app/elemta-cli
COPY --from=builder /build/plugins/clamav.so /app/plugins/clamav.so
COPY --from=builder /build/plugins/rspamd.so /app/plugins/rspamd.so

# Copy configuration files
COPY config/elemta.toml /app/config/elemta.toml
COPY config/dev.toml /app/config/dev.toml
COPY config/users.txt /app/config/users.txt

# Copy SQLite database
COPY config/elemta.db /app/config/elemta.db

# Copy TLS cert and key
COPY config/test.crt /app/certs/test.crt
COPY config/test.key /app/certs/test.key

# Expose ports
EXPOSE 2525 8080 8081

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"] 