// internal/smtp/session_data.go
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"log/slog"

	"github.com/busybox42/elemta/internal/logging"
	"github.com/busybox42/elemta/internal/plugin"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/google/uuid"
)

// DataReaderState represents the state of the data reader
type DataReaderState struct {
	InHeaders       bool
	LastLineEmpty   bool
	LineCount       int64
	BytesRead       int64
	HeadersComplete bool
}

// MessageMetadata contains metadata about a message
type MessageMetadata struct {
	MessageID string
	From      string
	To        []string
	Subject   string
	Date      time.Time
	Size      int64
	Headers   map[string]string
	Checksum  string
}

// SecurityScanResult represents the result of security scanning
type SecurityScanResult struct {
	Passed      bool
	Threats     []string
	SpamScore   float64
	VirusFound  bool
	Quarantined bool
}

// DataHandler manages message data processing for a session
type DataHandler struct {
	session           *Session
	state             *SessionState
	logger            *slog.Logger
	conn              net.Conn
	reader            *bufio.Reader
	config            *Config
	queueManager      queue.QueueManager
	builtinPlugins    *plugin.BuiltinPlugins
	enhancedValidator *EnhancedValidator
	msgLogger         *logging.MessageLogger
	receptionTime     time.Time
}

// NewDataHandler creates a new data handler
func NewDataHandler(session *Session, state *SessionState, conn net.Conn, reader *bufio.Reader,
	config *Config, queueManager queue.QueueManager, builtinPlugins *plugin.BuiltinPlugins, logger *slog.Logger) *DataHandler {
	baseLogger := logger.With("component", "session-data")

	// Use the existing global logger that writes to both stdout and file
	// The global logger is configured in logging_handler.go to write to /app/logs/elemta.log
	msgLogger := logging.NewMessageLogger(baseLogger)

	return &DataHandler{
		session:           session,
		state:             state,
		logger:            baseLogger,
		conn:              conn,
		reader:            reader,
		config:            config,
		queueManager:      queueManager,
		builtinPlugins:    builtinPlugins,
		enhancedValidator: NewEnhancedValidator(logger.With("component", "enhanced-validator")),
		msgLogger:         msgLogger,
		receptionTime:     time.Now(),
	}
}

// ReadData reads message data from the client with streaming and progressive memory tracking
func (dh *DataHandler) ReadData(ctx context.Context) ([]byte, error) {
	dh.logger.DebugContext(ctx, "Starting streaming message data reading with memory tracking")

	startTime := time.Now()
	var buffer bytes.Buffer
	state := &DataReaderState{
		InHeaders: true,
	}
	suspiciousPatterns := 0
	maxSize := dh.config.MaxSize

	// Get per-session memory limit (50MB default for ELE-16)
	sessionMemoryLimit := int64(50 * 1024 * 1024) // 50MB default
	if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
		sessionMemoryLimit = dh.session.resourceManager.memoryManager.config.PerConnectionMemoryLimit
	}

	// Set read timeout
	if deadline, ok := ctx.Deadline(); ok {
		_ = dh.conn.SetReadDeadline(deadline) // Best effort
	} else {
		_ = dh.conn.SetReadDeadline(time.Now().Add(30 * time.Minute)) // Best effort
	}
	defer func() { _ = dh.conn.SetReadDeadline(time.Time{}) }() // Best effort cleanup

	// Progressive memory tracking variables
	const memoryCheckInterval = 1024 * 1024 // Check every 1MB
	lastMemoryCheck := int64(0)

	for {
		line, err := dh.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				dh.logger.WarnContext(ctx, "Unexpected EOF while reading message data")
				return nil, fmt.Errorf("unexpected end of data")
			}
			dh.logger.ErrorContext(ctx, "Error reading message data", "error", err)
			return nil, fmt.Errorf("error reading data: %w", err)
		}

		state.LineCount++
		state.BytesRead += int64(len(line))

		// Check message size limit
		if state.BytesRead > maxSize {
			dh.logger.WarnContext(ctx, "Message size limit exceeded",
				"bytes_read", state.BytesRead,
				"max_size", maxSize,
			)
			return nil, fmt.Errorf("552 5.3.4 Message size exceeds maximum allowed")
		}

		// PROGRESSIVE MEMORY TRACKING (ELE-16 Critical Fix)
		// Check memory limits progressively during data reading
		if state.BytesRead-lastMemoryCheck >= memoryCheckInterval {
			lastMemoryCheck = state.BytesRead

			// Check per-session memory limit
			if state.BytesRead > sessionMemoryLimit {
				dh.logger.WarnContext(ctx, "Session memory limit exceeded during data reading",
					"bytes_read", state.BytesRead,
					"session_memory_limit", sessionMemoryLimit,
					"session_id", dh.session.sessionID,
				)
				return nil, fmt.Errorf("552 5.3.4 Session memory limit exceeded")
			}

			// Check global memory limits if resource manager is available
			if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
				if err := dh.session.resourceManager.memoryManager.CheckMemoryLimit(); err != nil {
					dh.logger.WarnContext(ctx, "Global memory limit exceeded during data reading",
						"error", err,
						"session_id", dh.session.sessionID,
					)
					return nil, fmt.Errorf("552 5.3.4 Server memory limit exceeded")
				}
			}
		}

		// Convert line to string for processing
		lineStr := string(line)

		// Check for end of data marker with enhanced security validation
		if dh.isValidEndOfData(lineStr, state, &suspiciousPatterns) {
			dh.logger.DebugContext(ctx, "Valid end-of-data marker detected")
			break
		}

		// Validate line content for security threats
		if err := dh.validateLineContent(ctx, lineStr, state); err != nil {
			dh.logger.WarnContext(ctx, "Line validation failed",
				"line_number", state.LineCount,
				"error", err,
			)
			return nil, fmt.Errorf("554 5.7.1 Message rejected: %s", err.Error())
		}

		// Track header completion
		if state.InHeaders {
			// Headers end with a single empty line (RFC 5322)
			if strings.TrimSpace(lineStr) == "" {
				state.InHeaders = false
				state.HeadersComplete = true
				dh.logger.DebugContext(ctx, "Headers section completed",
					"line_count", state.LineCount,
				)
			}
		}

		// Write line to buffer (streaming approach - could be optimized further)
		buffer.Write(line)

		// Periodic logging for large messages with memory tracking
		if state.LineCount%1000 == 0 {
			dh.logger.DebugContext(ctx, "Message reading progress with memory tracking",
				"lines_read", state.LineCount,
				"bytes_read", state.BytesRead,
				"session_memory_limit", sessionMemoryLimit,
				"memory_utilization_pct", float64(state.BytesRead)/float64(sessionMemoryLimit)*100,
				"duration", time.Since(startTime),
			)
		}
	}

	data := buffer.Bytes()
	dh.state.SetDataSize(ctx, int64(len(data)))

	// Final memory check before returning
	if int64(len(data)) > sessionMemoryLimit {
		dh.logger.WarnContext(ctx, "Final session memory limit check failed",
			"final_size", len(data),
			"session_memory_limit", sessionMemoryLimit,
			"session_id", dh.session.sessionID,
		)
		return nil, fmt.Errorf("552 5.3.4 Session memory limit exceeded")
	}

	dh.logger.InfoContext(ctx, "Streaming message data reading completed with memory tracking",
		"total_lines", state.LineCount,
		"total_bytes", len(data),
		"session_memory_limit", sessionMemoryLimit,
		"memory_utilization_pct", float64(len(data))/float64(sessionMemoryLimit)*100,
		"duration", time.Since(startTime),
		"suspicious_patterns", suspiciousPatterns,
	)

	return data, nil
}

// ProcessMessage processes the complete message with security scanning and validation
func (dh *DataHandler) ProcessMessage(ctx context.Context, data []byte) error {
	dh.logger.DebugContext(ctx, "Starting message processing with memory tracking", "size", len(data))

	startTime := time.Now()

	// PROGRESSIVE MEMORY TRACKING (ELE-16 Critical Fix)
	// Check memory limits before processing
	if dh.session.resourceManager != nil && dh.session.resourceManager.memoryManager != nil {
		// Check global memory limits
		if err := dh.session.resourceManager.memoryManager.CheckMemoryLimit(); err != nil {
			dh.logger.WarnContext(ctx, "Global memory limit exceeded before message processing",
				"error", err,
				"session_id", dh.session.sessionID,
				"message_size", len(data),
			)
			return fmt.Errorf("552 5.3.4 Server memory limit exceeded")
		}

		// Check per-session memory limits for the message
		estimatedProcessingMemory := int64(len(data) * 3) // Estimate 3x message size for processing
		if err := dh.session.resourceManager.memoryManager.CheckConnectionMemoryLimit(dh.session.sessionID, estimatedProcessingMemory); err != nil {
			dh.logger.WarnContext(ctx, "Session memory limit exceeded for message processing",
				"error", err,
				"session_id", dh.session.sessionID,
				"message_size", len(data),
				"estimated_processing_memory", estimatedProcessingMemory,
			)
			return fmt.Errorf("552 5.3.4 Session memory limit exceeded")
		}
	}

	// Extract message metadata
	metadata, err := dh.extractMessageMetadata(ctx, data)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to extract message metadata", "error", err)
		return fmt.Errorf("451 4.3.0 Message processing failed")
	}

	// Validate message headers
	if err := dh.validateMessageHeaders(ctx, metadata); err != nil {
		dh.logger.WarnContext(ctx, "Message header validation failed", "error", err)
		return fmt.Errorf("554 5.7.1 Message rejected: %s", err.Error())
	}

	// Perform security scanning
	scanResult, err := dh.performSecurityScan(ctx, data, metadata)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Security scan failed", "error", err)
		return fmt.Errorf("451 4.3.0 Security scan failed")
	}

	// Handle security scan results
	if !scanResult.Passed {
		return dh.handleSecurityThreat(ctx, scanResult, metadata)
	}

	// Add server headers before queuing
	enhancedData, err := dh.addServerHeaders(ctx, data, metadata, scanResult)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to add server headers", "error", err)
		return fmt.Errorf("451 4.3.0 Message processing failed")
	}

	// Save enhanced message to queue
	if err := dh.saveMessage(ctx, enhancedData, metadata); err != nil {
		dh.logger.ErrorContext(ctx, "Failed to save message", "error", err)
		return fmt.Errorf("451 4.3.0 Message processing failed")
	}

	// Reset session state for next transaction
	dh.state.Reset(ctx)
	dh.state.IncrementMessageCount(ctx)

	dh.logger.InfoContext(ctx, "Message processing completed successfully",
		"message_id", metadata.MessageID,
		"from", metadata.From,
		"recipients", len(metadata.To),
		"size", metadata.Size,
		"duration", time.Since(startTime),
	)

	return nil
}

// isValidEndOfData checks for valid end-of-data marker with security validation
func (dh *DataHandler) isValidEndOfData(line string, state *DataReaderState, suspiciousPatterns *int) bool {
	// RFC 5321 § 2.3.8: The sequence "\r\n.\r\n" indicates end of data
	// We must be strict about this to prevent SMTP smuggling attacks

	// Check for exact end-of-data sequence
	if line == ".\r\n" || line == ".\n" {
		dh.logger.DebugContext(context.Background(), "End-of-data marker detected",
			"line", fmt.Sprintf("%q", line),
			"line_count", state.LineCount,
		)
		return true
	}

	// Check for suspicious patterns that could indicate SMTP smuggling
	if strings.HasPrefix(line, ".") {
		*suspiciousPatterns++

		// Log suspicious patterns for security monitoring
		if line != ".\r\n" && line != ".\n" {
			dh.logger.WarnContext(context.Background(), "Suspicious dot-prefixed line detected",
				"line", fmt.Sprintf("%q", line),
				"line_count", state.LineCount,
				"pattern_type", "invalid_end_of_data",
			)
		}
	}

	return false
}

// validateLineContent validates individual lines for security threats using enhanced validation
func (dh *DataHandler) validateLineContent(ctx context.Context, line string, state *DataReaderState) error {
	// Check if this is an internal connection - be more permissive for internal connections
	isInternal := dh.isInternalConnection()

	// For internal connections, only do basic validation
	if isInternal {
		// Basic line length check
		if len(line) > 1000 {
			return fmt.Errorf("line too long")
		}

		// Only check for obvious security threats
		if strings.Contains(line, "'; DROP TABLE") ||
			strings.Contains(line, "\"; DROP TABLE") ||
			strings.Contains(line, "UNION SELECT") ||
			strings.Contains(line, "<script") {
			return fmt.Errorf("security violation detected")
		}

		dh.logger.DebugContext(ctx, "Using permissive validation for internal connection",
			"remote_addr", dh.conn.RemoteAddr().String(),
			"in_headers", state.InHeaders,
		)

		return nil
	}

	// For external connections, use enhanced validator for comprehensive line validation
	validationResult := dh.enhancedValidator.ValidateSMTPParameter("DATA_LINE", line)

	if !validationResult.Valid {
		// Log security event for failed validation
		LogSecurityEvent(dh.logger, "line_validation_failed", validationResult.SecurityThreat,
			validationResult.ErrorMessage, line, dh.conn.RemoteAddr().String())

		dh.logger.WarnContext(ctx, "Line validation failed",
			"error_type", validationResult.ErrorType,
			"error_message", validationResult.ErrorMessage,
			"security_threat", validationResult.SecurityThreat,
			"security_score", validationResult.SecurityScore,
			"line_number", state.LineCount,
		)

		return fmt.Errorf("security violation: %s", validationResult.ErrorMessage)
	}

	// Additional header-specific validation for external connections
	dh.logger.DebugContext(ctx, "Using enhanced validation for external connection",
		"remote_addr", dh.conn.RemoteAddr().String(),
		"in_headers", state.InHeaders,
		"security_score", validationResult.SecurityScore,
	)

	if state.InHeaders {
		dh.logger.DebugContext(ctx, "Applying strict header validation for external connection")
		return dh.validateHeaderLine(ctx, line)
	}

	return nil
}

// addServerHeaders adds server-generated headers to the message
func (dh *DataHandler) addServerHeaders(ctx context.Context, data []byte, metadata *MessageMetadata, scanResult *SecurityScanResult) ([]byte, error) {
	dataStr := string(data)

	// Find the end of headers
	headerEnd := strings.Index(dataStr, "\r\n\r\n")
	if headerEnd == -1 {
		// Try with just LF instead of CRLF
		headerEnd = strings.Index(dataStr, "\n\n")
		if headerEnd == -1 {
			// No clear header/body separation, add headers at the beginning
			headerEnd = 0
		}
	}

	var headers, body string
	if headerEnd > 0 {
		headers = dataStr[:headerEnd]
		body = dataStr[headerEnd:]
	} else {
		headers = ""
		body = dataStr
	}

	// Build additional headers
	var additionalHeaders []string

	// Add Received header (most important for email tracing)
	receivedTime := time.Now().Format(time.RFC1123Z)
	receivedHeader := fmt.Sprintf("Received: from %s (%s)\r\n\tby %s with ESMTP id %s\r\n\t(envelope-from <%s>)\r\n\tfor <%s>; %s",
		dh.config.Hostname,
		dh.conn.RemoteAddr().String(),
		dh.config.Hostname,
		metadata.MessageID,
		metadata.From,
		strings.Join(metadata.To, ", "),
		receivedTime,
	)
	additionalHeaders = append(additionalHeaders, receivedHeader)

	// Add security scan headers
	if scanResult != nil {
		if scanResult.VirusFound {
			additionalHeaders = append(additionalHeaders, "X-Virus-Scanned: Yes")
			additionalHeaders = append(additionalHeaders, "X-Virus-Status: INFECTED")
		} else {
			additionalHeaders = append(additionalHeaders, "X-Virus-Scanned: Clean (Elemta)")
		}

		spamStatus := "No"
		if scanResult.SpamScore > 5.0 {
			spamStatus = "Yes"
		}
		additionalHeaders = append(additionalHeaders, "X-Spam-Scanned: Yes")
		additionalHeaders = append(additionalHeaders, fmt.Sprintf("X-Spam-Status: %s, score=%.1f/10.0", spamStatus, scanResult.SpamScore))
		additionalHeaders = append(additionalHeaders, fmt.Sprintf("X-Spam-Score: %.1f", scanResult.SpamScore))
	}

	// Add server identification headers
	additionalHeaders = append(additionalHeaders, "X-Elemta-Version: 1.0")
	additionalHeaders = append(additionalHeaders, "X-Processed-By: Elemta MTA")
	additionalHeaders = append(additionalHeaders, fmt.Sprintf("X-Message-ID: %s", metadata.MessageID))

	// Combine headers
	var finalHeaders string
	if headers != "" {
		finalHeaders = headers + "\r\n" + strings.Join(additionalHeaders, "\r\n")
	} else {
		finalHeaders = strings.Join(additionalHeaders, "\r\n")
	}

	// Ensure proper header/body separation
	if body != "" {
		if !strings.HasPrefix(body, "\r\n\r\n") && !strings.HasPrefix(body, "\n\n") {
			finalHeaders += "\r\n"
		}
		return []byte(finalHeaders + body), nil
	} else {
		return []byte(finalHeaders + "\r\n\r\n"), nil
	}
}

// isInternalConnection checks if the connection is from internal Docker network
func (dh *DataHandler) isInternalConnection() bool {
	if dh.conn == nil {
		return false
	}

	remoteAddr := dh.conn.RemoteAddr().String()

	// Check for Docker internal networks (172.x.x.x range)
	if strings.HasPrefix(remoteAddr, "172.") {
		return true
	}

	// Check for localhost connections (IPv4 and IPv6)
	if strings.HasPrefix(remoteAddr, "127.") ||
		strings.HasPrefix(remoteAddr, "[::1]") ||
		strings.Contains(remoteAddr, "::1") {
		return true
	}

	// Check for Docker bridge network (10.x.x.x range)
	if strings.HasPrefix(remoteAddr, "10.") {
		return true
	}

	return false
}

// validateHeaderLine validates message header lines
func (dh *DataHandler) validateHeaderLine(ctx context.Context, line string) error {
	line = strings.TrimSpace(line)

	// Empty lines are allowed in headers
	if line == "" {
		return nil
	}

	// Check for header continuation (starts with whitespace)
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return nil // Valid header continuation
	}

	// Check for valid header format: "Name: Value"
	if !strings.Contains(line, ":") {
		dh.logger.DebugContext(ctx, "Header validation failed: no colon found", "line", line)
		return fmt.Errorf("invalid header format")
	}

	parts := strings.SplitN(line, ":", 2)
	headerName := strings.TrimSpace(parts[0])
	headerValue := strings.TrimSpace(parts[1])

	// Validate header name
	if headerName == "" {
		return fmt.Errorf("empty header name")
	}

	// Check for valid header name characters (RFC 5322)
	for _, char := range headerName {
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-') {
			return fmt.Errorf("invalid header name character")
		}
	}

	// Validate specific headers
	return dh.validateSpecificHeader(ctx, headerName, headerValue)
}

// validateSpecificHeader validates specific header types
func (dh *DataHandler) validateSpecificHeader(ctx context.Context, name, value string) error {
	name = strings.ToLower(name)

	switch name {
	case "content-type":
		return dh.validateContentTypeHeader(value)
	case "from", "to", "cc", "bcc", "reply-to":
		return dh.validateEmailHeaders(value)
	case "date":
		return dh.validateDateHeader(value)
	case "message-id":
		return dh.validateMessageIDHeader(value)
	}

	return nil
}

// validateContentTypeHeader validates Content-Type headers
func (dh *DataHandler) validateContentTypeHeader(value string) error {
	// Allow common content types and parameters
	if strings.Contains(value, ";") {
		// Handle parameters like charset, boundary
		parts := strings.Split(value, ";")
		contentType := strings.TrimSpace(parts[0])
		if contentType == "" {
			return fmt.Errorf("empty content type")
		}
	}
	return nil
}

// validateEmailHeaders validates email address headers
func (dh *DataHandler) validateEmailHeaders(value string) error {
	// Basic email header validation
	if len(value) > 1000 {
		return fmt.Errorf("email header too long")
	}
	return nil
}

// validateDateHeader validates Date headers
func (dh *DataHandler) validateDateHeader(value string) error {
	// Basic date header validation
	if len(value) > 100 {
		return fmt.Errorf("date header too long")
	}
	return nil
}

// validateMessageIDHeader validates Message-ID headers
func (dh *DataHandler) validateMessageIDHeader(value string) error {
	// Basic Message-ID validation
	if len(value) > 1000 {
		return fmt.Errorf("message-id too long")
	}
	return nil
}

// extractMessageMetadata extracts metadata from the message
func (dh *DataHandler) extractMessageMetadata(ctx context.Context, data []byte) (*MessageMetadata, error) {
	metadata := &MessageMetadata{
		MessageID: uuid.New().String(),
		From:      dh.state.GetMailFrom(),
		To:        dh.state.GetRecipients(),
		Date:      time.Now(),
		Size:      int64(len(data)),
		Headers:   make(map[string]string),
	}

	// Calculate checksum
	hash := md5.Sum(data)
	metadata.Checksum = fmt.Sprintf("%x", hash)

	// Extract headers
	headers := dh.extractHeaders(data)
	for name, value := range headers {
		metadata.Headers[strings.ToLower(name)] = value
	}

	// Extract specific fields
	if subject, exists := metadata.Headers["subject"]; exists {
		metadata.Subject = subject
	}

	if msgID, exists := metadata.Headers["message-id"]; exists {
		metadata.MessageID = msgID
	}

	dh.logger.DebugContext(ctx, "Message metadata extracted",
		"message_id", metadata.MessageID,
		"from", metadata.From,
		"recipients", len(metadata.To),
		"subject", metadata.Subject,
		"size", metadata.Size,
	)

	return metadata, nil
}

// extractHeaders extracts headers from message data
func (dh *DataHandler) extractHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	var currentHeader string
	var currentValue strings.Builder

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		// Empty line indicates end of headers
		if line == "" {
			if currentHeader != "" {
				headers[currentHeader] = currentValue.String()
			}
			break
		}

		// Check for header continuation
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentHeader != "" {
				currentValue.WriteString(" ")
				currentValue.WriteString(strings.TrimSpace(line))
			}
			continue
		}

		// Save previous header
		if currentHeader != "" {
			headers[currentHeader] = currentValue.String()
		}

		// Parse new header
		if colonIndex := strings.Index(line, ":"); colonIndex > 0 {
			currentHeader = strings.TrimSpace(line[:colonIndex])
			currentValue.Reset()
			currentValue.WriteString(strings.TrimSpace(line[colonIndex+1:]))
		} else {
			currentHeader = ""
			currentValue.Reset()
		}
	}

	return headers
}

// validateMessageHeaders validates message headers using enhanced validation
func (dh *DataHandler) validateMessageHeaders(ctx context.Context, metadata *MessageMetadata) error {
	// Skip strict header requirements for internal connections (like Roundcube) or if auth is not required
	isInternal := dh.isInternalConnection()
	authNotRequired := dh.config.Auth != nil && dh.config.Auth.Enabled && !dh.config.Auth.Required

	if !isInternal && !authNotRequired {
		// Check required headers only for external connections when auth is required
		requiredHeaders := []string{"from", "date"}
		for _, header := range requiredHeaders {
			if _, exists := metadata.Headers[header]; !exists {
				dh.logger.WarnContext(ctx, "Missing required header", "header", header)
				return fmt.Errorf("missing required header: %s", header)
			}
		}
	} else {
		if isInternal {
			dh.logger.DebugContext(ctx, "Skipping strict header requirements for internal connection")
		} else {
			dh.logger.DebugContext(ctx, "Skipping strict header requirements - authentication not required")
		}
	}

	// Use enhanced validator to validate all headers comprehensively (only for external connections)
	if !isInternal {
		headersStr := dh.buildHeadersString(metadata.Headers)
		headerValidationResult := dh.enhancedValidator.ValidateEmailHeaders(headersStr)

		if !headerValidationResult.Valid {
			// Log security event for failed header validation
			LogSecurityEvent(dh.logger, "header_validation_failed", headerValidationResult.SecurityThreat,
				headerValidationResult.ErrorMessage, headersStr, dh.conn.RemoteAddr().String())

			dh.logger.WarnContext(ctx, "Header validation failed",
				"error_type", headerValidationResult.ErrorType,
				"error_message", headerValidationResult.ErrorMessage,
				"security_threat", headerValidationResult.SecurityThreat,
				"security_score", headerValidationResult.SecurityScore,
			)

			return fmt.Errorf("header validation failed: %s", headerValidationResult.ErrorMessage)
		}

		dh.logger.DebugContext(ctx, "Header validation completed successfully",
			"security_score", headerValidationResult.SecurityScore,
			"header_count", headerValidationResult.ValidationDetails["header_count"],
		)
	} else {
		dh.logger.DebugContext(ctx, "Skipping enhanced header validation for internal connection")
	}

	// Validate From header matches MAIL FROM
	if fromHeader, exists := metadata.Headers["from"]; exists {
		if err := dh.validateFromHeader(ctx, fromHeader, metadata.From); err != nil {
			return err
		}
	}

	// Validate email addresses in headers (only for external connections)
	if !isInternal {
		if err := dh.validateEmailAddressesInHeaders(ctx, metadata.Headers); err != nil {
			return err
		}

		// Validate content-type restrictions
		if err := dh.validateContentTypeRestrictions(ctx, metadata.Headers); err != nil {
			return err
		}
	} else {
		dh.logger.DebugContext(ctx, "Skipping email address and content-type validation for internal connection")
	}

	return nil
}

// buildHeadersString builds a string representation of headers for validation
func (dh *DataHandler) buildHeadersString(headers map[string]string) string {
	var headerLines []string
	for name, value := range headers {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", name, value))
	}
	return strings.Join(headerLines, "\n")
}

// validateEmailAddressesInHeaders validates email addresses in headers
func (dh *DataHandler) validateEmailAddressesInHeaders(ctx context.Context, headers map[string]string) error {
	emailHeaders := []string{"from", "to", "cc", "bcc", "reply-to"}

	for _, headerName := range emailHeaders {
		if headerValue, exists := headers[headerName]; exists {
			// Use enhanced validator to validate email addresses
			validationResult := dh.enhancedValidator.ValidateSMTPParameter("MAIL_FROM", headerValue)

			if !validationResult.Valid {
				LogSecurityEvent(dh.logger, "email_header_validation_failed", validationResult.SecurityThreat,
					validationResult.ErrorMessage, headerValue, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Email header validation failed",
					"header", headerName,
					"error_type", validationResult.ErrorType,
					"error_message", validationResult.ErrorMessage,
					"security_threat", validationResult.SecurityThreat,
				)

				return fmt.Errorf("invalid email address in %s header: %s", headerName, validationResult.ErrorMessage)
			}
		}
	}

	return nil
}

// validateContentTypeRestrictions validates content-type restrictions
func (dh *DataHandler) validateContentTypeRestrictions(ctx context.Context, headers map[string]string) error {
	if contentType, exists := headers["content-type"]; exists {
		// Check for dangerous content types
		dangerousContentTypes := []string{
			"application/x-msdownload",    // Windows executables
			"application/x-executable",    // Executables
			"application/x-sh",            // Shell scripts
			"application/x-bat",           // Batch files
			"application/x-cmd",           // Command files
			"application/x-msdos-program", // DOS programs
			"application/x-winexe",        // Windows executables
		}

		contentTypeLower := strings.ToLower(contentType)
		for _, dangerous := range dangerousContentTypes {
			if strings.Contains(contentTypeLower, dangerous) {
				LogSecurityEvent(dh.logger, "dangerous_content_type", "attachment_threat",
					"Dangerous content type detected", contentType, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Dangerous content type detected",
					"content_type", contentType,
					"threat_type", "executable_attachment",
				)

				return fmt.Errorf("dangerous content type not allowed: %s", contentType)
			}
		}

		// Validate content-type format
		validationResult := dh.enhancedValidator.validateHeaderSecurityPatterns("content-type", contentType)
		if !validationResult.Valid {
			LogSecurityEvent(dh.logger, "content_type_validation_failed", validationResult.SecurityThreat,
				validationResult.ErrorMessage, contentType, dh.conn.RemoteAddr().String())

			return fmt.Errorf("invalid content-type header: %s", validationResult.ErrorMessage)
		}
	}

	return nil
}

// validateFromHeader validates the From header against MAIL FROM
func (dh *DataHandler) validateFromHeader(ctx context.Context, fromHeader, mailFrom string) error {
	// Extract email from From header (may contain display name)
	emailRegex := regexp.MustCompile(`<([^>]+)>|([^\s<>]+@[^\s<>]+)`)
	matches := emailRegex.FindStringSubmatch(fromHeader)

	var headerEmail string
	if len(matches) > 1 && matches[1] != "" {
		headerEmail = matches[1]
	} else if len(matches) > 2 && matches[2] != "" {
		headerEmail = matches[2]
	}

	// Compare with MAIL FROM (allow some flexibility)
	if headerEmail != "" && mailFrom != "" {
		if !strings.EqualFold(headerEmail, mailFrom) {
			dh.logger.WarnContext(ctx, "From header mismatch",
				"from_header", headerEmail,
				"mail_from", mailFrom,
			)
			// Log but don't reject - some legitimate cases exist
		}
	}

	return nil
}

// performSecurityScan performs comprehensive security scanning
func (dh *DataHandler) performSecurityScan(ctx context.Context, data []byte, metadata *MessageMetadata) (*SecurityScanResult, error) {
	result := &SecurityScanResult{
		Passed:  true,
		Threats: make([]string, 0),
	}

	// Perform antivirus scan if plugins are available
	if dh.builtinPlugins != nil {
		if err := dh.performAntivirusScan(ctx, data, result); err != nil {
			dh.logger.ErrorContext(ctx, "Antivirus scan failed", "error", err)
			return nil, err
		}
	}

	// Perform spam scan if plugins are available
	if dh.builtinPlugins != nil {
		if err := dh.performSpamScan(ctx, data, metadata, result); err != nil {
			dh.logger.ErrorContext(ctx, "Spam scan failed", "error", err)
			return nil, err
		}
	}

	// Perform content analysis
	if err := dh.performContentAnalysis(ctx, data, result); err != nil {
		dh.logger.ErrorContext(ctx, "Content analysis failed", "error", err)
		return nil, err
	}

	dh.logger.DebugContext(ctx, "Security scan completed",
		"passed", result.Passed,
		"threats", len(result.Threats),
		"spam_score", result.SpamScore,
		"virus_found", result.VirusFound,
	)

	return result, nil
}

// performAntivirusScan performs antivirus scanning
func (dh *DataHandler) performAntivirusScan(ctx context.Context, data []byte, result *SecurityScanResult) error {
	// This would integrate with actual antivirus plugins
	// For now, perform basic threat detection

	threatPatterns := []string{
		"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", // EICAR test
		"malware", "virus", "trojan", // Basic patterns
	}

	content := string(data)
	for _, pattern := range threatPatterns {
		if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
			result.Passed = false
			result.VirusFound = true
			result.Threats = append(result.Threats, "Virus detected: "+pattern)

			// Log rejection event for virus detection
			dh.msgLogger.LogRejection(logging.MessageContext{
				MessageID:      "", // Will be set later when metadata is available
				QueueID:        "",
				From:           "",
				To:             []string{},
				Subject:        "",
				Size:           int64(len(data)),
				ClientIP:       dh.session.remoteAddr,
				ClientHostname: dh.session.remoteAddr,
				Username:       dh.state.GetUsername(),
				Authenticated:  dh.state.IsAuthenticated(),
				TLSActive:      dh.state.IsTLSActive(),
				ReceptionTime:  dh.receptionTime,
				ProcessingTime: time.Now(),
				VirusFound:     true,
				VirusScanned:   true,
				Error:          fmt.Sprintf("Message rejected due to virus: %s", pattern),
			})

			dh.logger.WarnContext(ctx, "Virus detected in message",
				"pattern", pattern,
				"message_id", "unknown",
			)
		}
	}

	return nil
}

// performSpamScan performs spam detection
func (dh *DataHandler) performSpamScan(ctx context.Context, data []byte, metadata *MessageMetadata, result *SecurityScanResult) error {
	// Basic spam scoring
	spamScore := 0.0
	content := strings.ToLower(string(data))

	// Debug: Log the content being scanned
	previewLength := 200
	if len(content) < previewLength {
		previewLength = len(content)
	}
	dh.logger.DebugContext(ctx, "Spam scan content",
		"content_length", len(content),
		"content_preview", content[:previewLength],
		"gtube_in_content", strings.Contains(content, "xjs*c4jdbqadn1.nsbn3*2idnen*gtube-standard-anti-ube-test-email*c.34x"),
	)

	// Check for spam indicators
	spamPatterns := map[string]float64{
		// GTUBE test string (should always trigger spam detection)
		"XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X": 100.0,
		// EICAR test string (should trigger virus detection)
		"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*": 100.0,
		// Common spam patterns
		"viagra":          5.0,
		"cialis":          5.0,
		"lottery":         3.0,
		"winner":          2.0,
		"congratulations": 1.0,
		"urgent":          1.5,
		"act now":         2.0,
		"limited time":    1.5,
	}

	for pattern, score := range spamPatterns {
		// Convert pattern to lowercase for case-insensitive matching
		lowerPattern := strings.ToLower(pattern)
		if strings.Contains(content, lowerPattern) {
			spamScore += score

			// Log specific pattern detection
			if pattern == "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X" {
				dh.logger.InfoContext(ctx, "spam_detected",
					"event_type", "spam_detected",
					"pattern", "GTUBE",
					"spam_score", spamScore,
					"message_id", metadata.MessageID,
					"from_envelope", metadata.From,
					"to_envelope", metadata.To,
					"message_subject", metadata.Subject,
				)
			}
		}
	}

	result.SpamScore = spamScore

	// Threshold for spam detection
	if spamScore >= 5.0 {
		result.Passed = false
		result.Threats = append(result.Threats, fmt.Sprintf("High spam score: %.1f", spamScore))

		// Log rejection event for spam detection
		dh.msgLogger.LogRejection(logging.MessageContext{
			MessageID:      metadata.MessageID,
			QueueID:        metadata.MessageID,
			From:           metadata.From,
			To:             metadata.To,
			Subject:        metadata.Subject,
			Size:           metadata.Size,
			ClientIP:       dh.session.remoteAddr,
			ClientHostname: dh.session.remoteAddr,
			Username:       dh.state.GetUsername(),
			Authenticated:  dh.state.IsAuthenticated(),
			TLSActive:      dh.state.IsTLSActive(),
			ReceptionTime:  dh.receptionTime,
			ProcessingTime: time.Now(),
			SpamScore:      spamScore,
			SpamScanned:    true,
			Error:          fmt.Sprintf("Message rejected due to spam score: %.1f", spamScore),
		})

		dh.logger.WarnContext(ctx, "Message flagged as spam",
			"spam_score", spamScore,
			"message_id", metadata.MessageID,
			"from_envelope", metadata.From,
			"to_envelope", metadata.To,
			"message_subject", metadata.Subject,
		)
	}

	return nil
}

// performContentAnalysis performs comprehensive content analysis
func (dh *DataHandler) performContentAnalysis(ctx context.Context, data []byte, result *SecurityScanResult) error {
	content := string(data)

	// Check if this is an internal connection - be more permissive for internal connections
	isInternal := dh.isInternalConnection()

	// For internal connections, only do basic content analysis
	if isInternal {
		dh.logger.DebugContext(ctx, "Using permissive content analysis for internal connection",
			"remote_addr", dh.conn.RemoteAddr().String(),
		)

		// Only check for obvious security threats in internal connections
		if strings.Contains(content, "'; DROP TABLE") ||
			strings.Contains(content, "\"; DROP TABLE") ||
			strings.Contains(content, "UNION SELECT") ||
			strings.Contains(content, "<script") {
			result.Passed = false
			result.Threats = append(result.Threats, "Basic security violation detected")
			dh.logger.WarnContext(ctx, "Basic security violation detected in internal connection",
				"remote_addr", dh.conn.RemoteAddr().String(),
			)
		}
		return nil
	}

	// For external connections, use enhanced validator for comprehensive content analysis
	// Separate headers and body to avoid false positives on legitimate headers
	headers, body := dh.separateHeadersAndBody(content)

	// Validate headers separately (more permissive for legitimate headers)
	if headers != "" {
		headerValidationResult := dh.enhancedValidator.ValidateSMTPParameter("HEADER", headers)
		if !headerValidationResult.Valid {
			result.Passed = false
			result.Threats = append(result.Threats, fmt.Sprintf("Header validation failed: %s", headerValidationResult.ErrorMessage))

			LogSecurityEvent(dh.logger, "content_analysis_failed", headerValidationResult.SecurityThreat,
				headerValidationResult.ErrorMessage, headers[:min(200, len(headers))], dh.conn.RemoteAddr().String())

			dh.logger.WarnContext(ctx, "Header analysis failed",
				"error_type", headerValidationResult.ErrorType,
				"security_threat", headerValidationResult.SecurityThreat,
				"security_score", headerValidationResult.SecurityScore,
			)
		}
	}

	// Validate body content (strict validation for message body)
	if body != "" {
		bodyValidationResult := dh.enhancedValidator.ValidateSMTPParameter("DATA_LINE", body)
		if !bodyValidationResult.Valid {
			result.Passed = false
			result.Threats = append(result.Threats, fmt.Sprintf("Body validation failed: %s", bodyValidationResult.ErrorMessage))

			LogSecurityEvent(dh.logger, "content_analysis_failed", bodyValidationResult.SecurityThreat,
				bodyValidationResult.ErrorMessage, body[:min(200, len(body))], dh.conn.RemoteAddr().String())

			dh.logger.WarnContext(ctx, "Body analysis failed",
				"error_type", bodyValidationResult.ErrorType,
				"security_threat", bodyValidationResult.SecurityThreat,
				"security_score", bodyValidationResult.SecurityScore,
			)
		}
	}

	// Check for executable attachments (enhanced check)
	if strings.Contains(content, "Content-Type: application/") {
		dangerousTypes := []string{
			"application/x-msdownload",
			"application/x-executable",
			"application/x-sh",
			"application/x-bat",
			"application/x-cmd",
			"application/x-msdos-program",
			"application/x-winexe",
			"application/octet-stream",
		}

		for _, dangerousType := range dangerousTypes {
			if strings.Contains(strings.ToLower(content), dangerousType) {
				result.Passed = false
				result.Threats = append(result.Threats, fmt.Sprintf("Dangerous attachment type: %s", dangerousType))

				LogSecurityEvent(dh.logger, "dangerous_attachment", "attachment_threat",
					"Dangerous attachment type detected", dangerousType, dh.conn.RemoteAddr().String())

				dh.logger.WarnContext(ctx, "Dangerous attachment detected",
					"attachment_type", dangerousType,
					"threat_type", "executable_attachment",
				)
			}
		}
	}

	// Check for embedded scripts and malicious content
	maliciousPatterns := []string{
		"<script",
		"javascript:",
		"vbscript:",
		"data:text/html",
		"eval(",
		"expression(",
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(strings.ToLower(content), pattern) {
			result.Threats = append(result.Threats, fmt.Sprintf("Malicious content pattern: %s", pattern))
			dh.logger.WarnContext(ctx, "Malicious content pattern detected",
				"pattern", pattern,
				"threat_type", "malicious_content",
			)
		}
	}

	// Check for suspicious file extensions in attachments (but not in email addresses)
	suspiciousExtensions := []string{
		".exe", ".bat", ".cmd", ".pif", ".scr", ".vbs", ".js",
		".jar", ".app", ".deb", ".rpm", ".dmg", ".pkg", ".msi",
	}

	// Only check for .com if it's not part of an email address
	contentLower := strings.ToLower(content)
	for _, ext := range suspiciousExtensions {
		if strings.Contains(contentLower, ext) {
			// Special handling for .com - only flag if it's not in an email address
			if ext == ".com" {
				// Check if .com is part of an email address pattern
				if strings.Contains(contentLower, "@") && strings.Contains(contentLower, ".com") {
					// This is likely an email address, skip
					continue
				}
			}

			result.Threats = append(result.Threats, fmt.Sprintf("Suspicious file extension: %s", ext))
			dh.logger.WarnContext(ctx, "Suspicious file extension detected",
				"extension", ext,
				"threat_type", "suspicious_attachment",
			)
		}
	}

	return nil
}

// separateHeadersAndBody separates email headers from the message body
func (dh *DataHandler) separateHeadersAndBody(content string) (headers, body string) {
	// Find the double CRLF that separates headers from body
	doubleCRLF := "\r\n\r\n"
	separatorIndex := strings.Index(content, doubleCRLF)

	if separatorIndex == -1 {
		// Try single CRLF as fallback
		singleCRLF := "\n\n"
		separatorIndex = strings.Index(content, singleCRLF)
		if separatorIndex == -1 {
			// No clear separation found, treat entire content as headers
			return content, ""
		}
		headers = content[:separatorIndex]
		body = content[separatorIndex+len(singleCRLF):]
	} else {
		headers = content[:separatorIndex]
		body = content[separatorIndex+len(doubleCRLF):]
	}

	return headers, body
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleSecurityThreat handles detected security threats
func (dh *DataHandler) handleSecurityThreat(ctx context.Context, scanResult *SecurityScanResult, metadata *MessageMetadata) error {
	if scanResult.VirusFound {
		dh.logger.WarnContext(ctx, "Message rejected due to virus",
			"event_type", "rejection",
			"threats", scanResult.Threats,
			"message_id", metadata.MessageID,
		)

		// Log rejection event
		dh.msgLogger.LogRejection(logging.MessageContext{
			MessageID:      metadata.MessageID,
			QueueID:        metadata.MessageID,
			From:           metadata.From,
			To:             metadata.To,
			Subject:        metadata.Subject,
			Size:           metadata.Size,
			ClientIP:       dh.session.remoteAddr,
			ClientHostname: dh.session.remoteAddr,
			Username:       dh.state.GetUsername(),
			Authenticated:  dh.state.IsAuthenticated(),
			TLSActive:      dh.state.IsTLSActive(),
			ReceptionTime:  dh.receptionTime,
			ProcessingTime: time.Now(),
			Error:          "virus detected",
			VirusFound:     true,
		})

		return fmt.Errorf("554 5.7.1 Message rejected: virus detected")
	}

	if scanResult.SpamScore >= 10.0 {
		dh.logger.WarnContext(ctx, "Message rejected due to high spam score",
			"event_type", "rejection",
			"spam_score", scanResult.SpamScore,
			"message_id", metadata.MessageID,
		)

		// Log rejection event
		dh.msgLogger.LogRejection(logging.MessageContext{
			MessageID:      metadata.MessageID,
			QueueID:        metadata.MessageID,
			From:           metadata.From,
			To:             metadata.To,
			Subject:        metadata.Subject,
			Size:           metadata.Size,
			ClientIP:       dh.session.remoteAddr,
			ClientHostname: dh.session.remoteAddr,
			Username:       dh.state.GetUsername(),
			Authenticated:  dh.state.IsAuthenticated(),
			TLSActive:      dh.state.IsTLSActive(),
			ReceptionTime:  dh.receptionTime,
			ProcessingTime: time.Now(),
			Error:          "identified as spam",
			SpamScore:      scanResult.SpamScore,
		})

		return fmt.Errorf("554 5.7.1 Message rejected: identified as spam")
	}

	// For lower threat levels, quarantine instead of reject
	if len(scanResult.Threats) > 0 {
		scanResult.Quarantined = true
		dh.logger.InfoContext(ctx, "Message quarantined due to security concerns",
			"threats", scanResult.Threats,
			"message_id", metadata.MessageID,
		)
	}

	return nil
}

// saveMessage saves the message to the queue
func (dh *DataHandler) saveMessage(ctx context.Context, data []byte, metadata *MessageMetadata) error {
	// Process the message

	// Enqueue message for delivery
	_, err := dh.queueManager.EnqueueMessage(
		metadata.From,
		metadata.To,
		metadata.Subject,
		data,
		queue.PriorityNormal,
		dh.receptionTime,
	)
	if err != nil {
		dh.logger.ErrorContext(ctx, "Failed to enqueue message", "error", err)
		return fmt.Errorf("failed to save message: %w", err)
	}

	// Log message reception

	// Log message reception with timing
	dh.msgLogger.LogReception(logging.MessageContext{
		MessageID:      metadata.MessageID,
		QueueID:        metadata.MessageID,
		From:           metadata.From,
		To:             metadata.To,
		Subject:        metadata.Subject,
		Size:           metadata.Size,
		ClientIP:       dh.session.remoteAddr,
		ClientHostname: dh.session.remoteAddr,
		Username:       dh.state.GetUsername(),
		Authenticated:  dh.state.IsAuthenticated(),
		TLSActive:      dh.state.IsTLSActive(),
		ReceptionTime:  dh.receptionTime,
		ProcessingTime: time.Now(),
	})

	// Note: Queue integration processing would be handled by the queue manager

	return nil
}
