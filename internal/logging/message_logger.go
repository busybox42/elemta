package logging

import (
	"context"
	"log/slog"
	"time"
)

// MessageLogger provides structured logging for message lifecycle events
type MessageLogger struct {
	logger *slog.Logger
}

// NewMessageLogger creates a new message logger
func NewMessageLogger(logger *slog.Logger) *MessageLogger {
	return &MessageLogger{
		logger: logger.With("component", "message-lifecycle"),
	}
}

// MessageContext contains all context about a message for logging
type MessageContext struct {
	MessageID      string
	QueueID        string
	From           string
	To             []string
	Subject        string
	Size           int64
	ClientIP       string
	ClientHostname string
	Username       string
	Authenticated  bool
	TLSActive      bool
	ReceptionTime  time.Time
	ProcessingTime time.Time
	DeliveryTime   time.Time
	DeliveryIP     string
	DeliveryHost   string
	RetryCount     int
	NextRetry      time.Time
	Error          string
	VirusScanned   bool
	VirusFound     bool
	SpamScanned    bool
	SpamScore      float64
	DeliveryMethod string
}

// LogReception logs when a message is received and accepted
func (ml *MessageLogger) LogReception(ctx MessageContext) {
	// Calculate delay from reception to acceptance
	processingDelay := time.Duration(0)
	if !ctx.ProcessingTime.IsZero() && !ctx.ReceptionTime.IsZero() {
		processingDelay = ctx.ProcessingTime.Sub(ctx.ReceptionTime)
	}

	ml.logger.Info("message_reception",
		"event_type", "reception",
		"message_id", ctx.MessageID,
		"queue_id", ctx.QueueID,
		"from", ctx.From,
		"to", ctx.To,
		"recipient_count", len(ctx.To),
		"subject", ctx.Subject,
		"size", ctx.Size,
		"client_ip", ctx.ClientIP,
		"client_hostname", ctx.ClientHostname,
		"username", ctx.Username,
		"authenticated", ctx.Authenticated,
		"tls_active", ctx.TLSActive,
		"reception_time", ctx.ReceptionTime.Format(time.RFC3339),
		"processing_delay_ms", processingDelay.Milliseconds(),
		"virus_scanned", ctx.VirusScanned,
		"virus_found", ctx.VirusFound,
		"spam_scanned", ctx.SpamScanned,
		"spam_score", ctx.SpamScore,
	)
}

// LogDelivery logs successful message delivery
func (ml *MessageLogger) LogDelivery(ctx MessageContext) {
	// Calculate delays
	receptionToDelivery := time.Duration(0)
	processingToDelivery := time.Duration(0)

	if !ctx.DeliveryTime.IsZero() {
		if !ctx.ReceptionTime.IsZero() {
			receptionToDelivery = ctx.DeliveryTime.Sub(ctx.ReceptionTime)
		}
		if !ctx.ProcessingTime.IsZero() {
			processingToDelivery = ctx.DeliveryTime.Sub(ctx.ProcessingTime)
		}
	}

	// Build log fields
	fields := []any{
		"event_type", "delivery",
		"message_id", ctx.MessageID,
		"queue_id", ctx.QueueID,
		"from", ctx.From,
		"to", ctx.To,
		"recipient_count", len(ctx.To),
		"subject", ctx.Subject,
		"size", ctx.Size,
		"delivery_method", ctx.DeliveryMethod,
		"retry_count", ctx.RetryCount,
		"reception_time", ctx.ReceptionTime.Format(time.RFC3339),
		"delivery_time", ctx.DeliveryTime.Format(time.RFC3339),
		"total_delay_ms", receptionToDelivery.Milliseconds(),
		"queue_delay_ms", processingToDelivery.Milliseconds(),
		"status", "delivered",
	}

	// Add delivery IP and host if available
	if ctx.DeliveryIP != "" {
		fields = append(fields, "delivery_ip", ctx.DeliveryIP)
	}
	if ctx.DeliveryHost != "" {
		fields = append(fields, "delivery_host", ctx.DeliveryHost)
	}

	ml.logger.Info("message_delivery", fields...)
}

// LogRejection logs when a message is rejected during reception
func (ml *MessageLogger) LogRejection(ctx MessageContext) {
	// Calculate delay from reception to rejection
	processingDelay := time.Duration(0)
	if !ctx.ProcessingTime.IsZero() && !ctx.ReceptionTime.IsZero() {
		processingDelay = ctx.ProcessingTime.Sub(ctx.ReceptionTime)
	}

	ml.logger.Warn("message_rejection",
		"event_type", "rejection",
		"message_id", ctx.MessageID,
		"from", ctx.From,
		"to", ctx.To,
		"recipient_count", len(ctx.To),
		"subject", ctx.Subject,
		"size", ctx.Size,
		"client_ip", ctx.ClientIP,
		"client_hostname", ctx.ClientHostname,
		"username", ctx.Username,
		"authenticated", ctx.Authenticated,
		"tls_active", ctx.TLSActive,
		"reception_time", ctx.ReceptionTime.Format(time.RFC3339),
		"processing_delay_ms", processingDelay.Milliseconds(),
		"rejection_reason", ctx.Error,
		"virus_found", ctx.VirusFound,
		"spam_score", ctx.SpamScore,
		"status", "rejected",
	)
}

// LogDeferral logs when a message is deferred for retry
func (ml *MessageLogger) LogDeferral(ctx MessageContext) {
	// Calculate delays
	receptionToDefer := time.Duration(0)
	processingToDefer := time.Duration(0)
	nextRetryDelay := time.Duration(0)

	now := time.Now()
	if !ctx.ReceptionTime.IsZero() {
		receptionToDefer = now.Sub(ctx.ReceptionTime)
	}
	if !ctx.ProcessingTime.IsZero() {
		processingToDefer = now.Sub(ctx.ProcessingTime)
	}
	if !ctx.NextRetry.IsZero() {
		nextRetryDelay = ctx.NextRetry.Sub(now)
	}

	ml.logger.Warn("message_deferral",
		"event_type", "deferral",
		"message_id", ctx.MessageID,
		"queue_id", ctx.QueueID,
		"from", ctx.From,
		"to", ctx.To,
		"recipient_count", len(ctx.To),
		"subject", ctx.Subject,
		"size", ctx.Size,
		"delivery_method", ctx.DeliveryMethod,
		"retry_count", ctx.RetryCount,
		"reception_time", ctx.ReceptionTime.Format(time.RFC3339),
		"deferral_time", now.Format(time.RFC3339),
		"next_retry", ctx.NextRetry.Format(time.RFC3339),
		"total_delay_ms", receptionToDefer.Milliseconds(),
		"queue_delay_ms", processingToDefer.Milliseconds(),
		"next_retry_in_seconds", int(nextRetryDelay.Seconds()),
		"deferral_reason", ctx.Error,
		"status", "deferred",
	)
}

// LogBounce logs when a message permanently fails
func (ml *MessageLogger) LogBounce(ctx MessageContext) {
	// Calculate delays
	receptionToBounce := time.Duration(0)
	processingToBounce := time.Duration(0)

	now := time.Now()
	if !ctx.ReceptionTime.IsZero() {
		receptionToBounce = now.Sub(ctx.ReceptionTime)
	}
	if !ctx.ProcessingTime.IsZero() {
		processingToBounce = now.Sub(ctx.ProcessingTime)
	}

	ml.logger.Error("message_bounce",
		"event_type", "bounce",
		"message_id", ctx.MessageID,
		"queue_id", ctx.QueueID,
		"from", ctx.From,
		"to", ctx.To,
		"recipient_count", len(ctx.To),
		"subject", ctx.Subject,
		"size", ctx.Size,
		"delivery_method", ctx.DeliveryMethod,
		"retry_count", ctx.RetryCount,
		"reception_time", ctx.ReceptionTime.Format(time.RFC3339),
		"bounce_time", now.Format(time.RFC3339),
		"total_delay_ms", receptionToBounce.Milliseconds(),
		"queue_delay_ms", processingToBounce.Milliseconds(),
		"bounce_reason", ctx.Error,
		"status", "bounced",
	)
}

// LogTempFail logs temporary delivery failures
func (ml *MessageLogger) LogTempFail(ctx MessageContext) {
	// Calculate delays
	receptionToFail := time.Duration(0)
	processingToFail := time.Duration(0)

	now := time.Now()
	if !ctx.ReceptionTime.IsZero() {
		receptionToFail = now.Sub(ctx.ReceptionTime)
	}
	if !ctx.ProcessingTime.IsZero() {
		processingToFail = now.Sub(ctx.ProcessingTime)
	}

	ml.logger.Warn("message_tempfail",
		"event_type", "tempfail",
		"message_id", ctx.MessageID,
		"queue_id", ctx.QueueID,
		"from", ctx.From,
		"to", ctx.To,
		"recipient_count", len(ctx.To),
		"subject", ctx.Subject,
		"size", ctx.Size,
		"delivery_method", ctx.DeliveryMethod,
		"retry_count", ctx.RetryCount,
		"reception_time", ctx.ReceptionTime.Format(time.RFC3339),
		"failure_time", now.Format(time.RFC3339),
		"total_delay_ms", receptionToFail.Milliseconds(),
		"queue_delay_ms", processingToFail.Milliseconds(),
		"failure_reason", ctx.Error,
		"status", "temporary_failure",
	)
}

// AuthContext contains authentication-related information
type AuthContext struct {
	Username       string
	ClientIP       string
	ClientHostname string
	AuthMethod     string
	Success        bool
	FailureReason  string
	TLSActive      bool
	SessionID      string
	AttemptTime    time.Time
}

// LogAuthentication logs authentication attempts (success and failure)
func (ml *MessageLogger) LogAuthentication(ctx AuthContext) {
	level := slog.LevelInfo
	status := "success"
	if !ctx.Success {
		level = slog.LevelWarn
		status = "failure"
	}

	ml.logger.Log(context.Background(), level, "authentication",
		"event_type", "authentication",
		"session_id", ctx.SessionID,
		"username", ctx.Username,
		"client_ip", ctx.ClientIP,
		"client_hostname", ctx.ClientHostname,
		"auth_method", ctx.AuthMethod,
		"tls_active", ctx.TLSActive,
		"status", status,
		"success", ctx.Success,
		"failure_reason", ctx.FailureReason,
		"attempt_time", ctx.AttemptTime.Format(time.RFC3339),
	)
}
