FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /elemta ./cmd/elemta

# Create a minimal runtime image
FROM alpine:latest

# Add ca-certificates for secure connections
RUN apk --no-cache add ca-certificates tzdata

# Create a non-root user to run the application
RUN adduser -D -H -h /app elemta

# Create necessary directories
RUN mkdir -p /app/config /app/queue /app/logs /app/rules
RUN chown -R elemta:elemta /app

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /elemta /app/elemta

# Copy the default configuration
COPY config/elemta.conf /app/config/

# Set the user to run the application
USER elemta

# Expose SMTP port
EXPOSE 2525

# Set the entrypoint
ENTRYPOINT ["/app/elemta"] 