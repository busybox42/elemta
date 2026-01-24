package context

import (
	"context"
	"log/slog"
)

// contextKey provides type safety for context keys to prevent collisions
type contextKey string

const (
	// Core context keys
	sessionIDKey  contextKey = "session_id"
	remoteAddrKey contextKey = "remote_addr"
	usernameKey   contextKey = "username"
	loggerKey     contextKey = "logger"

	// Request/transaction context keys
	transactionIDKey contextKey = "transaction_id"
	messageIDKey     contextKey = "message_id"

	// Security context keys
	authMethodKey contextKey = "auth_method"
	tlsVersionKey contextKey = "tls_version"
	clientCertKey contextKey = "client_cert"

	// Performance context keys
	startTimeKey    contextKey = "start_time"
	requestCountKey contextKey = "request_count"
)

// Type-safe context value setters

// WithSessionID adds a session ID to the context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// WithRemoteAddr adds a remote address to the context
func WithRemoteAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, remoteAddrKey, addr)
}

// WithUsername adds an authenticated username to the context
func WithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username)
}

// WithLogger adds a structured logger to the context
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// WithTransactionID adds a transaction ID to the context
func WithTransactionID(ctx context.Context, transactionID string) context.Context {
	return context.WithValue(ctx, transactionIDKey, transactionID)
}

// WithMessageID adds a message ID to the context
func WithMessageID(ctx context.Context, messageID string) context.Context {
	return context.WithValue(ctx, messageIDKey, messageID)
}

// WithAuthMethod adds the authentication method to the context
func WithAuthMethod(ctx context.Context, authMethod string) context.Context {
	return context.WithValue(ctx, authMethodKey, authMethod)
}

// WithTLSVersion adds the TLS version to the context
func WithTLSVersion(ctx context.Context, tlsVersion string) context.Context {
	return context.WithValue(ctx, tlsVersionKey, tlsVersion)
}

// WithClientCert adds the client certificate to the context
func WithClientCert(ctx context.Context, clientCert string) context.Context {
	return context.WithValue(ctx, clientCertKey, clientCert)
}

// WithStartTime adds the start time to the context
func WithStartTime(ctx context.Context, startTime any) context.Context {
	return context.WithValue(ctx, startTimeKey, startTime)
}

// WithRequestCount adds the request count to the context
func WithRequestCount(ctx context.Context, count int) context.Context {
	return context.WithValue(ctx, requestCountKey, count)
}

// Type-safe context value getters

// SessionID retrieves the session ID from the context
func SessionID(ctx context.Context) string {
	if id, ok := ctx.Value(sessionIDKey).(string); ok {
		return id
	}
	return ""
}

// RemoteAddr retrieves the remote address from the context
func RemoteAddr(ctx context.Context) string {
	if addr, ok := ctx.Value(remoteAddrKey).(string); ok {
		return addr
	}
	return "unknown"
}

// Username retrieves the authenticated username from the context
func Username(ctx context.Context) string {
	if username, ok := ctx.Value(usernameKey).(string); ok {
		return username
	}
	return ""
}

// Logger retrieves the logger from the context, returning a default logger if none is set
func Logger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// TransactionID retrieves the transaction ID from the context
func TransactionID(ctx context.Context) string {
	if id, ok := ctx.Value(transactionIDKey).(string); ok {
		return id
	}
	return ""
}

// MessageID retrieves the message ID from the context
func MessageID(ctx context.Context) string {
	if id, ok := ctx.Value(messageIDKey).(string); ok {
		return id
	}
	return ""
}

// AuthMethod retrieves the authentication method from the context
func AuthMethod(ctx context.Context) string {
	if method, ok := ctx.Value(authMethodKey).(string); ok {
		return method
	}
	return ""
}

// TLSVersion retrieves the TLS version from the context
func TLSVersion(ctx context.Context) string {
	if version, ok := ctx.Value(tlsVersionKey).(string); ok {
		return version
	}
	return ""
}

// ClientCert retrieves the client certificate from the context
func ClientCert(ctx context.Context) string {
	if cert, ok := ctx.Value(clientCertKey).(string); ok {
		return cert
	}
	return ""
}

// StartTime retrieves the start time from the context
func StartTime(ctx context.Context) any {
	return ctx.Value(startTimeKey)
}

// RequestCount retrieves the request count from the context
func RequestCount(ctx context.Context) int {
	if count, ok := ctx.Value(requestCountKey).(int); ok {
		return count
	}
	return 0
}
