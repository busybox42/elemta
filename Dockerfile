FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install Git for dependency downloads
RUN apk add --no-cache git

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o /app/elemta-bin ./cmd/elemta

# Create a minimal runtime image
FROM alpine:latest

# Add necessary packages
RUN apk --no-cache add ca-certificates tzdata

# Create a non-root user
RUN addgroup -S elemta && adduser -S elemta -G elemta

# Create necessary directories
RUN mkdir -p /app/queue /app/logs /app/config /app/plugins
RUN chown -R elemta:elemta /app

WORKDIR /app

# Copy the binary and config file
COPY --from=builder /app/elemta-bin /app/elemta
COPY --from=builder /app/config/test-elemta.conf /app/config/elemta.conf

# Copy example plugins
COPY --from=builder /app/examples/plugins /app/examples/plugins

# Create plugins directory
RUN mkdir -p /app/plugins

# Set the user to run the application
USER elemta

# Expose SMTP port
EXPOSE 2525

# Set the entry point
ENTRYPOINT ["/app/elemta"] 