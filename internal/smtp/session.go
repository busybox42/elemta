// internal/smtp/session.go
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/base64"
	"encoding/hex"

	"crypto/tls"

	"github.com/busybox42/elemta/internal/plugin"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/google/uuid"
)

type State int

const (
	INIT State = iota
	MAIL
	RCPT
	DATA
)

// TLSHandler interface defines methods for handling TLS connections
type TLSHandler interface {
	WrapConnection(conn net.Conn) (net.Conn, error)
	GetTLSConfig() *tls.Config
	StartTLSListener(ctx context.Context) (net.Listener, error)
	RenewCertificates(ctx context.Context) error
	GetCertificateInfo() (map[string]interface{}, error)
	Stop() error
}

type Session struct {
	conn             net.Conn
	reader           *bufio.Reader
	writer           *bufio.Writer
	state            State
	message          *Message
	config           *Config
	logger           *slog.Logger
	Context          *Context
	authenticated    bool
	username         string
	authenticator    Authenticator
	queueManager     *QueueManager
	queueIntegration *QueueProcessorIntegration
	tlsManager       TLSHandler
	tls              bool // Flag to indicate if this session is using TLS
	builtinPlugins   *plugin.BuiltinPlugins
	// Authentication security tracking
	authAttempts     int       // Number of auth attempts for this session
	lastAuthAttempt  time.Time // Time of last auth attempt for rate limiting
	remoteAddr       string    // Client IP address for security tracking
	// Resource management
	sessionID        string           // Session ID for resource tracking
	resourceManager  *ResourceManager // Resource manager for rate limiting and monitoring
	// Enhanced input validation
	enhancedValidator *EnhancedValidator // Enhanced validator for comprehensive input validation
}

// For testing purposes only
var mockHandleSTARTTLS func(s *Session) error

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func NewSession(conn net.Conn, config *Config, authenticator Authenticator) *Session {
	remoteAddr := conn.RemoteAddr().String()
	sessionID := uuid.New().String()
	
	// Create structured logger for email transaction logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With(
		"component", "smtp-session",
		"remote_addr", remoteAddr,
		"session_id", sessionID,
		"service", "elemta-mta",
	)

	// Initialize plugin system
	builtinPlugins := plugin.NewBuiltinPlugins()

	// Get enabled plugins from config
	var enabledPlugins []string
	pluginConfig := make(map[string]map[string]interface{})

	// Use plugins from config instead of hardcoded test plugins
	if config.Plugins != nil && config.Plugins.Enabled {
		enabledPlugins = config.Plugins.Plugins
		logger.Info("Enabling configured plugins", "plugins", enabledPlugins)
	} else {
		logger.Info("No plugins enabled")
	}

	// Use plugin configuration from config file if available
	// Plugin configs should be loaded from the main configuration

	// Initialize plugins
	err := builtinPlugins.InitBuiltinPlugins(enabledPlugins, pluginConfig)
	if err != nil {
		logger.Warn("failed to initialize plugins", "error", err)
	}

	// Initialize enhanced validator for comprehensive input validation
	enhancedValidator := NewEnhancedValidator(logger)

	return &Session{
		conn:            conn,
		reader:          bufio.NewReader(conn),
		writer:          bufio.NewWriter(conn),
		state:           INIT,
		message:         NewMessage(),
		config:          config,
		logger:          logger,
		Context:         NewContext(),
		authenticated:   false,
		username:        "",
		authenticator:   authenticator,
		tls:             false, // Start without TLS
		builtinPlugins:  builtinPlugins,
		// Initialize security tracking
		authAttempts:    0,
		lastAuthAttempt: time.Time{},
		remoteAddr:      remoteAddr,
		// Initialize enhanced validation
		enhancedValidator: enhancedValidator,
	}
}

func (s *Session) write(msg string) error {
	_, err := s.writer.WriteString(msg)
	if err != nil {
		return err
	}
	return s.writer.Flush()
}

// writeWithLog writes a message and logs any errors, but doesn't return error
// Used for SMTP response where we can't meaningfully handle write errors
func (s *Session) writeWithLog(msg string) {
	if err := s.write(msg); err != nil {
		s.logger.Error("Failed to write SMTP response",
			slog.String("message", msg),
			slog.String("error", err.Error()),
		)
	}
}

func (s *Session) Handle() error {
	// Add defer for panic recovery and connection cleanup
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("session panic recovered",
				"panic", r,
				"stack", string(debug.Stack()))
		}
		s.logger.Info("session ended")
	}()

	// HOTFIX: Ensure MaxSize is never 0
	s.logger.Info("DEBUG: MaxSize before hotfix", "max_size", s.config.MaxSize)
	if s.config.MaxSize == 0 {
		s.config.MaxSize = 25 * 1024 * 1024 // 25MB
		s.logger.Info("DEBUG: Applied MaxSize hotfix", "new_max_size", s.config.MaxSize)
	}

	s.logger.Info("starting new session",
		"hostname", s.config.Hostname,
		"max_size", s.config.MaxSize)

	// 220 <domain> <greeting> <ESMTP> <server-info>
	if err := s.write(fmt.Sprintf("220 %s ESMTP Elemta MTA ready\r\n", s.config.Hostname)); err != nil {
		s.logger.Error("failed to send greeting",
			"error", err,
			"hostname", s.config.Hostname)
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Set reasonable session timeout default if not configured
	timeout := s.config.SessionTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	// Keep track of command count to detect flooding
	commandCount := 0
	commandTimer := time.Now()
	maxCommands := 100 // Max commands within the flood period
	floodPeriod := 60 * time.Second

	// Set a session overall timeout to prevent hung connections
	overallDeadline := time.Now().Add(30 * time.Minute)
	if err := s.conn.SetDeadline(overallDeadline); err != nil {
		s.logger.Warn("failed to set session deadline", "error", err)
	}

	for {
		// Check for command flooding
		commandCount++
		if commandCount > maxCommands {
			elapsed := time.Since(commandTimer)
			if elapsed < floodPeriod {
				s.logger.Warn("command flooding detected",
					"commands", commandCount,
					"period_seconds", elapsed.Seconds())
				s.writeWithLog("421 4.7.0 Too many commands, slow down\r\n")
				return errors.New("command flooding detected")
			}
			// Reset counter if we're outside the flood period
			commandCount = 0
			commandTimer = time.Now()
		}

		// Set read deadline for this command
		if err := s.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			s.logger.Warn("failed to set read deadline", "error", err)
		}
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.Warn("session timeout, closing connection",
					"timeout_seconds", timeout.Seconds(),
					"command_count", commandCount)
				s.writeWithLog("421 4.4.2 Connection timed out\r\n")
				return fmt.Errorf("session timeout after %v: %w", timeout, err)
			}
			// Handle different types of network errors
			if errors.Is(err, io.EOF) {
				s.logger.Info("client disconnected")
				return nil // Normal disconnection
			}
			s.logger.Error("read error",
				"error", err,
				"command_count", commandCount)
			return fmt.Errorf("failed to read command: %w", err)
		}

		// Comprehensive input validation and sanitization
		validationResult := validateSMTPCommand(line)
		if !validationResult.Valid {
			s.logger.Warn("smtp_security_violation",
				"event_type", "invalid_command_input",
				"error_type", validationResult.ErrorType,
				"error_message", validationResult.ErrorMessage,
				"security_threat", validationResult.SecurityThreat,
				"raw_command", line[:min(100, len(line))], // Limit log size
				"remote_addr", s.conn.RemoteAddr().String(),
			)
			
			// Send appropriate error response based on threat type
			switch validationResult.SecurityThreat {
			case "command_injection_attempt":
				s.writeWithLog("554 5.7.1 Command injection attempt detected\r\n")
			case "sql_injection_attempt":
				s.writeWithLog("554 5.7.1 SQL injection attempt detected\r\n")
			case "buffer_overflow_attempt":
				s.writeWithLog("500 5.5.2 Command too long\r\n")
			default:
				s.writeWithLog("500 5.5.2 Invalid command syntax\r\n")
			}
			continue
		}

		// Use sanitized command for processing
		line = validationResult.SanitizedValue
		line = strings.TrimSpace(line)
		
		s.logger.Debug("received command",
			"command", line,
			"state", stateToString(s.state),
			"authenticated", s.authenticated)

		// Update activity tracking if resource manager is available
		if s.resourceManager != nil && s.sessionID != "" {
			s.resourceManager.UpdateConnectionActivity(s.sessionID)
		}

		// Parse the command verb (first word) and arguments separately
		parts := strings.Fields(line)
		if len(parts) == 0 {
			s.writeWithLog("500 5.5.2 Invalid command\r\n")
			continue
		}

		// Upper case only the command verb for case-insensitive matching
		verb := strings.ToUpper(parts[0])

		switch {
		case verb == "QUIT":
			s.logger.Info("client quit")
			s.writeWithLog("221 2.0.0 Goodbye\r\n")
			return nil

		case verb == "HELO" || verb == "EHLO":
			// Extract the client identity
			clientIdentity := ""
			if len(parts) > 1 {
				clientIdentity = parts[1]
				
				// Enhanced hostname validation
				hostnameValidation := s.enhancedValidator.ValidateSMTPParameter("HELO", clientIdentity)
				if !hostnameValidation.Valid {
					LogSecurityEvent(s.logger, "invalid_helo_hostname", hostnameValidation.SecurityThreat,
						hostnameValidation.ErrorMessage, clientIdentity, s.conn.RemoteAddr().String())
					
					switch hostnameValidation.SecurityThreat {
					case "command_injection_attack":
						s.writeWithLog("554 5.7.1 Hostname rejected: contains dangerous characters\r\n")
					case "sql_injection_attack":
						s.writeWithLog("554 5.7.1 Hostname rejected: contains prohibited patterns\r\n")
					case "buffer_overflow_attempt":
						s.writeWithLog("501 5.5.4 Hostname rejected: exceeds maximum length\r\n")
					case "unicode_attack", "homograph_attack", "encoding_attack":
						s.writeWithLog("554 5.7.1 Hostname rejected: contains unsafe characters\r\n")
					default:
						s.writeWithLog("501 5.5.4 Invalid hostname format\r\n")
					}
					continue
				}
				
				// Store client identity in context for logging (using sanitized version)
				s.Context.Set("client_identity", hostnameValidation.SanitizedValue)
			} else {
				LogSecurityEvent(s.logger, "missing_helo_hostname", "validation_error", 
					"HELO/EHLO command missing hostname", line, s.conn.RemoteAddr().String())
				s.writeWithLog("501 5.5.4 Hostname required\r\n")
				continue
			}
			
			s.logger.Info("client hello", "command", verb, "hostname", SafeLogString(clientIdentity))

			// Respond with different formats for HELO vs EHLO (per RFC)
			if verb == "HELO" {
				// Simple response for HELO as per RFC 5321
				s.writeWithLog("250 " + s.config.Hostname + "\r\n")
			} else {
				// Multi-line response for EHLO as per RFC 5321
				s.writeWithLog("250-" + s.config.Hostname + " greets " + clientIdentity + "\r\n")

				// RFC 1870 SIZE extension
				maxSize := s.config.MaxSize
				if maxSize == 0 {
					maxSize = 25 * 1024 * 1024 // 25MB hardcoded fallback
				}
				s.writeWithLog("250-SIZE " + strconv.FormatInt(maxSize, 10) + "\r\n")

				// RFC 6152 8BITMIME extension
				s.writeWithLog("250-8BITMIME\r\n")

				// RFC 2920 PIPELINING extension
				s.writeWithLog("250-PIPELINING\r\n")

				// RFC 3463 Enhanced status codes
				s.writeWithLog("250-ENHANCEDSTATUSCODES\r\n")

				// RFC 2034 HELP
				s.writeWithLog("250-HELP\r\n")

				// RFC 4954 CHUNKING (if enabled)
				if s.config.DevMode {
					s.writeWithLog("250-CHUNKING\r\n")
				}

				// RFC 2821 STARTTLS (if enabled)
				if s.config.TLS != nil && s.config.TLS.Enabled && s.config.TLS.EnableStartTLS && !s.tls {
					s.writeWithLog("250-STARTTLS\r\n")
				}

	// RFC 4954 AUTH (if enabled)
	if s.authenticator != nil && s.authenticator.IsEnabled() {
		methods := s.authenticator.GetSupportedMethods()
		if len(methods) > 0 {
			authMethods := make([]string, len(methods))
			for i, method := range methods {
				authMethods[i] = string(method)
			}
			s.writeWithLog("250-AUTH " + strings.Join(authMethods, " ") + "\r\n")
		}
	}

				// RFC 3030 BINARYMIME (if CHUNKING is supported)
				if s.config.DevMode {
					s.writeWithLog("250-BINARYMIME\r\n")
				}

				// The last line must have a space instead of a dash after the code
				s.writeWithLog("250 SMTPUTF8\r\n")
			}

		case verb == "STARTTLS":
			if s.tls {
				s.writeWithLog("503 5.5.1 TLS already active\r\n")
				continue
			}

			if s.config.TLS == nil || !s.config.TLS.Enabled {
				s.writeWithLog("454 4.7.0 TLS not available\r\n")
				continue
			}

			if s.tlsManager == nil {
				s.writeWithLog("454 4.7.0 TLS manager not available\r\n")
				continue
			}

			s.writeWithLog("220 2.0.0 Ready to start TLS\r\n")

			// Wrap the connection with TLS
			if err := s.handleSTARTTLS(); err != nil {
				s.logger.Error("STARTTLS failed", "error", err)
				return err
			}

			// Reset state after TLS upgrade
			s.state = INIT
			s.tls = true

		case verb == "AUTH":
			// Pass the entire command line to handleAuth
			if err := s.handleAuth(line); err != nil {
				s.logger.Error("authentication error", "error", err)
				s.writeWithLog("535 5.7.8 Authentication failed\r\n")
			}

		case verb == "MAIL" || strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "mail from:"):
			// Check if authentication is required but not authenticated
			if s.authenticator != nil && s.authenticator.IsRequired() && !s.authenticated {
				s.writeWithLog("530 5.7.0 Authentication required\r\n")
				continue
			}

			if s.state != INIT {
				s.writeWithLog("503 5.5.1 Bad sequence of commands\r\n")
				continue
			}

			s.handleMailFrom(line)

		case verb == "RCPT" || strings.HasPrefix(line, "RCPT TO:") || strings.HasPrefix(line, "rcpt to:"):
			if s.state != MAIL && s.state != RCPT {
				s.writeWithLog("503 5.5.1 Bad sequence of commands\r\n")
				continue
			}

			s.handleRcptTo(line)

		case verb == "DATA":
			if s.state != RCPT {
				s.writeWithLog("503 5.5.1 Bad sequence of commands\r\n")
				continue
			}

			// Inform client to start sending data
			s.writeWithLog("354 Start mail input; end with <CRLF>.<CRLF>\r\n")

			// Read the message data
			data, err := s.readData()
			if err != nil {
				// Handle different error types with appropriate responses
				if strings.Contains(err.Error(), "message too large") {
					s.logger.Error("message size exceeded",
						"error", err,
						"max_size", s.config.MaxSize,
						"from", s.message.from)
					s.writeWithLog("552 5.3.4 Message size exceeds fixed maximum message size\r\n")
				} else if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection") {
					s.logger.Error("connection error during data read",
						"error", err,
						"from", s.message.from,
						"to_count", len(s.message.to))
					return fmt.Errorf("connection lost during data transfer: %w", err)
				} else {
					s.logger.Error("data read error",
						"error", err,
						"from", s.message.from,
						"to_count", len(s.message.to))
					s.writeWithLog("451 4.3.0 Error processing message data\r\n")
				}
				continue
			}

			// Enhanced header validation for DATA content
			messageStr := string(data)
			headerEndIndex := strings.Index(messageStr, "\r\n\r\n")
			if headerEndIndex == -1 {
				headerEndIndex = strings.Index(messageStr, "\n\n")
			}
			
			if headerEndIndex != -1 {
				headersSection := messageStr[:headerEndIndex]
				headerValidation := s.enhancedValidator.ValidateEmailHeaders(headersSection)
				if !headerValidation.Valid {
					LogSecurityEvent(s.logger, "invalid_email_headers", headerValidation.SecurityThreat,
						headerValidation.ErrorMessage, SafeLogString(headersSection[:min(200, len(headersSection))]), 
						s.conn.RemoteAddr().String())
					
					switch headerValidation.SecurityThreat {
					case "header_injection_attack":
						s.writeWithLog("554 5.7.1 Message rejected: header injection detected\r\n")
					case "buffer_overflow_attempt":
						s.writeWithLog("552 5.3.4 Message rejected: headers too large\r\n")
					case "resource_exhaustion":
						s.writeWithLog("552 5.3.4 Message rejected: too many headers\r\n")
					default:
						s.writeWithLog("554 5.6.0 Message rejected: invalid headers\r\n")
					}
					continue
				}
			}

			// Generate a unique message ID and set data
			s.message.data = data
			s.message.id = generateMessageID()
			s.message.receivedTime = time.Now()

			// Extract email details for comprehensive logging
			subject := s.extractSubjectFromData(data)
			messageID := s.extractMessageIDFromData(data)
			fromHeader := s.extractFromHeaderFromData(data)
			
			// Log comprehensive message reception
			s.logger.Info("message_received",
				"event_type", "message_received",
				"message_id", s.message.id,
				"from_envelope", s.message.from,
				"from_header", fromHeader,
				"to_envelope", s.message.to,
				"subject", subject,
				"header_message_id", messageID,
				"size_bytes", len(data),
				"received_time", s.message.receivedTime.Format(time.RFC3339),
			)

			// Before saving, validate message has required headers
			if !s.validateMessageHeaders() {
				s.writeWithLog("554 5.6.0 Message has invalid headers\r\n")
				continue
			}

			// Attempt to save the message to the queue
			if err := s.saveMessage(); err != nil {
				// Check for specific errors and return appropriate status codes
				if strings.Contains(err.Error(), "virus") {
					// Error already sent by saveMessage()
				} else if strings.Contains(err.Error(), "spam") {
					// Error already sent by saveMessage()
				} else if strings.Contains(err.Error(), "relay not allowed") {
					s.writeWithLog("550 5.7.1 Relaying denied\r\n")
				} else {
					s.logger.Error("save message error", "error", err)
					s.writeWithLog("451 4.3.0 Error saving message\r\n")
				}
				continue
			}

			// Set state back to INIT and report success with message ID
			s.state = INIT
			
			// Log comprehensive message acceptance (reuse variables from message_received)
			s.logger.Info("message_accepted",
				"event_type", "message_accepted",
				"message_id", s.message.id,
				"from_envelope", s.message.from,
				"to_envelope", s.message.to,
				"queue_status", "queued",
				"accepted_time", time.Now().Format(time.RFC3339),
			)
			
			s.writeWithLog(fmt.Sprintf("250 2.0.0 Ok: message %s queued\r\n", s.message.id))

		case verb == "RSET":
			// Reset message and state
			s.message = NewMessage()
			s.state = INIT
			s.writeWithLog("250 2.0.0 Ok: reset state\r\n")

		case verb == "NOOP":
			s.writeWithLog("250 2.0.0 Ok\r\n")

		case verb == "VRFY":
			// We don't support VRFY for security reasons
			s.writeWithLog("252 2.1.5 Cannot verify user\r\n")

		case verb == "EXPN":
			// We don't support EXPN for security reasons
			s.writeWithLog("252 2.1.5 Cannot expand list\r\n")

		case verb == "HELP":
			s.writeWithLog("214 2.0.0 SMTP server ready\r\n")

		case strings.HasPrefix(verb, "XDEBUG"):
			s.logger.Info("xdebug command", "command", line)
			s.handleXDEBUG(line)

		default:
			s.logger.Warn("unknown command", "command", line)
			s.writeWithLog("500 5.5.2 Command not recognized\r\n")
		}
	}
}

// handleSTARTTLS upgrades the connection to TLS
func (s *Session) handleSTARTTLS() error {
	// For testing, use mock if provided
	if mockHandleSTARTTLS != nil {
		return mockHandleSTARTTLS(s)
	}

	// Make sure we flush any pending writes before upgrading
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer before TLS upgrade: %w", err)
	}

	// Get the TLS manager from the server
	if s.tlsManager == nil {
		return fmt.Errorf("TLS manager not available")
	}

	// Wrap the connection with TLS
	tlsConn, err := s.tlsManager.WrapConnection(s.conn)
	if err != nil {
		return fmt.Errorf("failed to upgrade connection to TLS: %w", err)
	}

	// Replace the connection and create new reader/writer
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)

	s.logger.Info("connection upgraded to TLS",
		"cipher", tlsConn.(*tls.Conn).ConnectionState().CipherSuite,
		"protocol", tlsConn.(*tls.Conn).ConnectionState().Version)

	return nil
}

func (s *Session) handleXDEBUG(cmd string) {
	parts := strings.SplitN(cmd, " ", 2)
	var args string
	if len(parts) > 1 {
		args = parts[1]
	}

	if args == "" {
		s.writeWithLog("250-Debug information:\r\n")

		// Generate a stable session ID for debugging
		sessionID, ok := s.Context.Get("session_id")
		if !ok || sessionID == nil {
			// If we don't have a session ID in the context, generate one and store it
			sessionID = uuid.New().String()
			s.Context.Set("session_id", sessionID)
		}

		s.writeWithLog("250-Session ID: " + sessionID.(string) + "\r\n")
		s.writeWithLog("250-Client IP: " + s.conn.RemoteAddr().String() + "\r\n")
		s.writeWithLog("250-Hostname: " + s.config.Hostname + "\r\n")
		s.writeWithLog("250-State: " + stateToString(s.state) + "\r\n")

		// Handle nil message case properly
		if s.message != nil {
			s.writeWithLog("250-Mail From: " + s.message.from + "\r\n")
			s.writeWithLog("250-Rcpt To: " + strings.Join(s.message.to, ", ") + "\r\n")
			s.writeWithLog("250-Message ID: " + s.message.id + "\r\n")
			s.writeWithLog("250-Message Size: " + strconv.Itoa(len(s.message.data)) + " bytes\r\n")

			// Add plugin scan information if available
			if s.builtinPlugins != nil && s.message.data != nil && len(s.message.data) > 0 {
				s.writeWithLog("250-Plugin Scans:\r\n")

				// ClamAV virus scan results
				clean, infection, err := s.builtinPlugins.ScanForVirus(s.message.data, s.message.id)
				if err != nil {
					s.writeWithLog("250-  ClamAV: Error - " + err.Error() + "\r\n")
				} else if !clean {
					s.writeWithLog("250-  ClamAV: Virus detected - " + infection + "\r\n")
				} else {
					s.writeWithLog("250-  ClamAV: Clean\r\n")
				}

				// Rspamd spam scan results
				clean, score, rules, err := s.builtinPlugins.ScanForSpam(s.message.data, s.message.id)
				if err != nil {
					s.writeWithLog("250-  Rspamd: Error - " + err.Error() + "\r\n")
				} else if !clean {
					rulesList := ""
					if len(rules) > 0 {
						rulesList = " (" + strings.Join(rules, ", ") + ")"
					}
					s.writeWithLog(fmt.Sprintf("250-  Rspamd: Spam detected - Score: %.2f%s\r\n", score, rulesList))
				} else {
					s.writeWithLog(fmt.Sprintf("250-  Rspamd: Clean - Score: %.2f\r\n", score))
				}
			}
		} else {
			s.writeWithLog("250-Mail From: <none>\r\n")
			s.writeWithLog("250-Rcpt To: <none>\r\n")
			s.writeWithLog("250-Message ID: <none>\r\n")
			s.writeWithLog("250-Message Size: 0 bytes\r\n")
		}

		s.writeWithLog("250 Context: " + s.Context.Dump() + "\r\n")
		return
	}

	parts = strings.SplitN(args, " ", 2)
	subCmd := strings.ToUpper(parts[0])

	switch subCmd {
	case "HELP":
		s.writeWithLog("250-XDEBUG Commands:\r\n")
		s.writeWithLog("250-XDEBUG - Show all debug information\r\n")
		s.writeWithLog("250-XDEBUG CONTEXT - Show context information\r\n")
		s.writeWithLog("250-XDEBUG CONTEXT GET <key> - Get a context value\r\n")
		s.writeWithLog("250-XDEBUG CONTEXT SET <key> <value> - Set a context value\r\n")
		s.writeWithLog("250-XDEBUG CONTEXT DELETE <key> - Delete a context value\r\n")
		s.writeWithLog("250-XDEBUG CONTEXT CLEAR - Clear all context values\r\n")
		s.writeWithLog("250 XDEBUG HELP - Show this help message\r\n")

	case "CONTEXT":
		if len(parts) == 1 {
			s.writeWithLog("250-Context dump:\r\n")
			s.writeWithLog("250 " + s.Context.Dump() + "\r\n")
			return
		}

		contextArgs := strings.TrimSpace(parts[1])
		contextParts := strings.SplitN(contextArgs, " ", 2)
		contextOp := strings.ToUpper(contextParts[0])

		switch contextOp {
		case "GET":
			if len(contextParts) < 2 {
				s.writeWithLog("501 Missing key\r\n")
				return
			}
			key := strings.TrimSpace(contextParts[1])
			if value, ok := s.Context.Get(key); ok {
				s.writeWithLog("250 " + key + " = " + value.(string) + "\r\n")
			} else {
				s.writeWithLog("250 Key not found: " + key + "\r\n")
			}

		case "SET":
			if len(contextParts) < 2 {
				s.writeWithLog("501 Missing key and value\r\n")
				return
			}
			keyValue := strings.SplitN(contextParts[1], " ", 2)
			if len(keyValue) < 2 {
				s.writeWithLog("501 Missing value\r\n")
				return
			}
			key := strings.TrimSpace(keyValue[0])
			value := strings.TrimSpace(keyValue[1])
			s.Context.Set(key, value)
			s.writeWithLog("250 Set " + key + " = " + value + "\r\n")

		case "DELETE":
			if len(contextParts) < 2 {
				s.writeWithLog("501 Missing key\r\n")
				return
			}
			key := strings.TrimSpace(contextParts[1])
			s.Context.Delete(key)
			s.writeWithLog("250 Deleted key: " + key + "\r\n")

		case "CLEAR":
			s.Context.Clear()
			s.writeWithLog("250 Context cleared\r\n")

		default:
			s.writeWithLog("501 Unknown context operation: " + contextOp + "\r\n")
		}

	default:
		s.writeWithLog("501 Unknown XDEBUG command: " + subCmd + "\r\n")
	}
}

func stateToString(state State) string {
	switch state {
	case INIT:
		return "INIT"
	case MAIL:
		return "MAIL"
	case RCPT:
		return "RCPT"
	case DATA:
		return "DATA"
	default:
		return "UNKNOWN"
	}
}

// DataReaderState represents the state machine for RFC 5321 compliant data reading
type DataReaderState int

const (
	DataStateNormal DataReaderState = iota
	DataStateCR     // Just read CR (\r)
	DataStateCRLF   // Just read CRLF (\r\n)
	DataStateDot    // Just read CRLF.
)

func (s *Session) readData() ([]byte, error) {
	var buffer bytes.Buffer
	// Calculate size limit with a 10% margin to allow for headers
	maxSize := int(float64(s.config.MaxSize) * 1.1)
	totalBytes := 0
	isFirstLine := true
	state := DataStateNormal
	suspiciousPatterns := 0

	s.logger.Debug("reading message data with RFC 5321 compliance")

	// Set a longer timeout for data reading
	dataTimeout := 5 * time.Minute
	s.conn.SetReadDeadline(time.Now().Add(dataTimeout))

	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Error("error reading data", "error", err)
			return nil, fmt.Errorf("error reading message data: %w", err)
		}

		// RFC 5321 § 2.3.8 STRICT compliance: End-of-data MUST be exactly <CRLF>.<CRLF>
		// Check for the EXACT end-of-data sequence
		if s.isValidEndOfData(line, &state, &suspiciousPatterns) {
			s.logger.Debug("valid end-of-data sequence found", 
				"raw_line", line,
				"state", state,
				"suspicious_patterns", suspiciousPatterns)
			break
		}

		// Per RFC 5321, lines starting with a period have it duplicated in the data stream
		// We need to remove this extra period when processing (dot-stuffing removal)
		if len(line) > 0 && line[0] == '.' && len(line) > 1 {
			// Log potential dot-stuffing for security analysis
			s.logger.Debug("removing dot-stuffing", "original_line", line[:min(50, len(line))])
			line = line[1:]
		}

		// Add this line's length to our running total
		lineLength := len(line)
		totalBytes += lineLength

		// Check if we'd exceed the message size limit
		if totalBytes > maxSize {
			s.logger.Warn("message size exceeded",
				"size", totalBytes,
				"limit", s.config.MaxSize)
			return nil, fmt.Errorf("message too large: %d > %d", totalBytes, s.config.MaxSize)
		}

		// Handle headers to detect common issues
		if isFirstLine {
			isFirstLine = false
			// RFC 5322 recommends Date and From headers be present
			// We could check for these, but we won't reject if missing
		}

		buffer.WriteString(line)
	}

	// Log security metrics if suspicious patterns were detected
	if suspiciousPatterns > 0 {
		s.logger.Warn("smtp_security_alert",
			"event_type", "suspicious_end_of_data_patterns",
			"message_id", s.message.id,
			"from_envelope", s.message.from,
			"suspicious_count", suspiciousPatterns,
			"remote_addr", s.conn.RemoteAddr().String(),
		)
	}

	// Reset the connection timeout to normal
	s.conn.SetReadDeadline(time.Now().Add(s.config.SessionTimeout))

	// Log the message size and extract headers for indexing
	messageContent := buffer.String()
	s.logger.Info("message data read complete",
		"size_bytes", buffer.Len(),
		"line_count", strings.Count(messageContent, "\n"))

	// Extract and log email headers for better indexing
	if headerEnd := strings.Index(messageContent, "\r\n\r\n"); headerEnd != -1 {
		headers := messageContent[:headerEnd]
		s.logger.Info("email headers received",
			"headers", headers)

		// Extract key headers for indexing
		if subject := extractHeader(headers, "Subject"); subject != "" {
			s.logger.Info("email subject extracted",
				"subject", subject)
		}
		if messageID := extractHeader(headers, "Message-ID"); messageID != "" {
			s.logger.Info("email message-id extracted",
				"message_id", messageID)
		}
	}

	return buffer.Bytes(), nil
}

func (s *Session) saveMessage() error {
	s.logger.Info("saving message",
		"id", s.message.id,
		"from", s.message.from,
		"to", s.message.to)

	if s.config.DevMode {
		s.logger.Info("dev mode: simulating message save")
		return nil
	}

	// Relay permissions are now checked in handleRcptTo()
	// This is just a final safety check for explicit allowed relays configuration
	if len(s.config.AllowedRelays) > 0 {
		clientIP := GetClientIP(s.conn)
		if clientIP != nil && !IsAllowedRelay(clientIP, s.config.AllowedRelays) {
			s.logger.Warn("relay denied by allowed_relays configuration", "ip", clientIP.String())
			return errors.New("relay not allowed")
		}
	}

	// Scan for viruses using our built-in plugin system
	if s.builtinPlugins != nil {
		s.logger.Debug("scanning message for viruses", "id", s.message.id)
		clean, infection, err := s.builtinPlugins.ScanForVirus(s.message.data, s.message.id)
		if err != nil {
			// Log virus scan failure
			s.logger.Error("message_scan_failed",
				"event_type", "virus_scan_failed",
				"message_id", s.message.id,
				"from_envelope", s.message.from,
				"to_envelope", s.message.to,
				"scanner", "clamav",
				"error", err.Error(),
			)
			
			// Add header indicating scan failed
			s.message.data = addHeaderToMessage(s.message.data, "X-Virus-Scanned", "Error (ClamAV)")
			if s.config.Antivirus != nil && s.config.Antivirus.RejectOnFailure {
				s.writeWithLog("554 5.7.1 Unable to scan for viruses\r\n")
				return errors.New("virus scan failed")
			}
		} else if !clean {
			// Log virus detection and rejection
			s.logger.Warn("message_rejected",
				"event_type", "virus_detected",
				"message_id", s.message.id,
				"from_envelope", s.message.from,
				"to_envelope", s.message.to,
				"scanner", "clamav",
				"threat", infection,
				"action", "rejected",
			)
			
			// Message contains virus
			s.message.data = addHeaderToMessage(s.message.data, "X-Virus-Scanned", fmt.Sprintf("Infected (ClamAV): %s", infection))
			s.writeWithLog(fmt.Sprintf("554 5.7.1 Message contains a virus: %s\r\n", infection))
			return errors.New("message contains virus")
		} else {
			// Log clean scan
			s.logger.Info("message_scanned",
				"event_type", "virus_scan_clean",
				"message_id", s.message.id,
				"scanner", "clamav",
				"status", "clean",
			)
			
			// Message is clean
			s.message.data = addHeaderToMessage(s.message.data, "X-Virus-Scanned", "Clean (ClamAV)")
		}
	}

	// Scan for spam using our built-in plugin system
	if s.builtinPlugins != nil {
		s.logger.Debug("scanning message for spam", "id", s.message.id)
		clean, score, rules, err := s.builtinPlugins.ScanForSpam(s.message.data, s.message.id)
		if err != nil {
			// Log spam scan failure
			s.logger.Error("message_scan_failed",
				"event_type", "spam_scan_failed",
				"message_id", s.message.id,
				"from_envelope", s.message.from,
				"to_envelope", s.message.to,
				"scanner", "rspamd",
				"error", err.Error(),
			)
			
			// Add header indicating scan failed
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Scanned", "Error (Rspamd)")
			if s.config.Antispam != nil && s.config.Antispam.RejectOnSpam {
				s.writeWithLog("554 5.7.1 Unable to scan for spam\r\n")
				return errors.New("spam scan failed")
			}
		} else if !clean {
			// Log spam detection and rejection
			s.logger.Warn("message_rejected",
				"event_type", "spam_detected",
				"message_id", s.message.id,
				"from_envelope", s.message.from,
				"to_envelope", s.message.to,
				"scanner", "rspamd",
				"spam_score", score,
				"spam_rules", rules,
				"action", "rejected",
			)
			
			// Message is spam
			rulesList := ""
			if len(rules) > 0 {
				rulesList = " (" + strings.Join(rules, ", ") + ")"
			}
			// Add spam headers
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Scanned", "Yes")
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Score", fmt.Sprintf("%.2f", score))
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Status", "Yes")
			if len(rules) > 0 {
				s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Rules", strings.Join(rules, " "))
			}
			s.writeWithLog(fmt.Sprintf("554 5.7.1 Message identified as spam (score %.2f)%s\r\n", score, rulesList))
			return errors.New("message is spam")
		} else {
			// Log clean spam scan
			s.logger.Info("message_scanned",
				"event_type", "spam_scan_clean",
				"message_id", s.message.id,
				"scanner", "rspamd",
				"spam_score", score,
				"spam_rules", rules,
				"status", "clean",
			)
			
			// Add headers for clean message
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Scanned", "Yes")
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Score", fmt.Sprintf("%.2f", score))
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Status", "No")
			if len(rules) > 0 {
				s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Rules", strings.Join(rules, " "))
			}
		}
	}

	// Use the new queue integration if available, otherwise fallback to old queue manager
	if s.queueIntegration != nil {
		// Use new queue system with delivery handlers
		if err := s.queueIntegration.EnqueueMessage(s.message, queue.PriorityNormal); err != nil {
			s.logger.Error("failed to enqueue message in new queue system", "error", err)
			return err
		}
		s.logger.Info("message queued successfully in new queue system",
			"id", s.message.id,
			"priority", "normal")
	} else {
		// Fallback to old queue manager
		if s.queueManager == nil {
			// Fallback to create a new one if we don't have a shared instance
			s.logger.Warn("no shared queue manager, creating new instance")
			s.queueManager = NewQueueManager(s.config)
		}

		if err := s.queueManager.EnqueueMessage(s.message, PriorityNormal); err != nil {
			s.logger.Error("failed to enqueue message", "error", err)
			return err
		}

		s.logger.Info("message queued successfully in old queue system",
			"id", s.message.id,
			"priority", PriorityNormal)
	}

	return nil
}

func extractAddress(cmd string) string {
	start := strings.Index(cmd, "<")
	end := strings.Index(cmd, ">")
	if start == -1 || end == -1 || start > end {
		return ""
	}
	return cmd[start+1 : end]
}

// InputValidationResult contains detailed validation results
type InputValidationResult struct {
	Valid        bool
	ErrorType    string
	ErrorMessage string
	SanitizedValue string
	SecurityThreat string
}

// validateEmailAddress performs comprehensive RFC 5322 email validation with security checks
func validateEmailAddress(email string) bool {
	result := validateEmailAddressDetailed(email)
	return result.Valid
}

// validateEmailAddressDetailed performs comprehensive RFC 5322 email validation with detailed security analysis
func validateEmailAddressDetailed(email string) *InputValidationResult {
	result := &InputValidationResult{
		Valid: false,
		SanitizedValue: email,
	}

	// Basic format check
	if email == "" {
		result.ErrorType = "empty_email"
		result.ErrorMessage = "Email address cannot be empty"
		return result
	}

	// Special case: RFC 5321 allows "<>" for null sender (bounce messages)
	if email == "" {
		result.Valid = true
		return result
	}

	// Length validation - RFC 5321 limits
	if len(email) > 320 { // RFC 5321: 64 (local) + 1 (@) + 255 (domain) = 320
		result.ErrorType = "length_exceeded"
		result.ErrorMessage = "Email address exceeds RFC 5321 length limit (320 characters)"
		result.SecurityThreat = "potential_buffer_overflow"
		return result
	}

	// Command injection detection - check for dangerous characters
	dangerousPatterns := []string{
		"\n", "\r", "\x00", // Control characters
		"|", "&", ";", "`", "$", // Shell metacharacters
		"$(", "${", "``",        // Command substitution
		"../", "..\\",           // Path traversal
		"<script", "</script",   // Script injection
		"javascript:", "data:",  // Protocol injection
		"'", "\"",              // SQL injection characters (basic)
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(email), strings.ToLower(pattern)) {
			result.ErrorType = "injection_attempt"
			result.ErrorMessage = fmt.Sprintf("Dangerous pattern detected: %s", pattern)
			result.SecurityThreat = "command_injection_attempt"
			return result
		}
	}

	// SQL injection pattern detection
	sqlPatterns := []string{
		"union select", "drop table", "delete from", "insert into",
		"update set", "alter table", "create table", "exec ",
		"execute ", "sp_", "xp_", "@@", "char(", "cast(",
		"convert(", "substring(", "ascii(", "len(",
	}

	emailLower := strings.ToLower(email)
	for _, pattern := range sqlPatterns {
		if strings.Contains(emailLower, pattern) {
			result.ErrorType = "sql_injection"
			result.ErrorMessage = fmt.Sprintf("SQL injection pattern detected: %s", pattern)
			result.SecurityThreat = "sql_injection_attempt"
			return result
		}
	}

	// RFC 5322 format validation
	atIndex := strings.LastIndex(email, "@") // Use LastIndex for proper handling of @ in local part
	if atIndex <= 0 || atIndex == len(email)-1 {
		result.ErrorType = "invalid_format"
		result.ErrorMessage = "Invalid email format - missing or misplaced @ symbol"
		return result
	}

	localPart := email[:atIndex]
	domain := email[atIndex+1:]

	// Validate local part (before @)
	if len(localPart) == 0 || len(localPart) > 64 {
		result.ErrorType = "invalid_local_part"
		result.ErrorMessage = "Local part length must be 1-64 characters"
		return result
	}

	// RFC 5322 local part validation
	if !isValidLocalPart(localPart) {
		result.ErrorType = "invalid_local_part"
		result.ErrorMessage = "Local part contains invalid characters"
		return result
	}

	// Validate domain part (after @)
	if len(domain) == 0 || len(domain) > 255 {
		result.ErrorType = "invalid_domain"
		result.ErrorMessage = "Domain length must be 1-255 characters"
		return result
	}

	// Domain format validation
	if !isValidDomain(domain) {
		result.ErrorType = "invalid_domain"
		result.ErrorMessage = "Domain contains invalid characters or format"
		return result
	}

	// Additional security checks for domain
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		result.ErrorType = "malformed_domain"
		result.ErrorMessage = "Domain has malformed dot notation"
		result.SecurityThreat = "domain_spoofing_attempt"
		return result
	}

	result.Valid = true
	return result
}

// isValidLocalPart validates the local part of an email address according to RFC 5322
func isValidLocalPart(localPart string) bool {
	if len(localPart) == 0 {
		return false
	}

	// Check for consecutive dots
	if strings.Contains(localPart, "..") {
		return false
	}

	// Check for leading or trailing dots
	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return false
	}

	// Validate characters in local part
	for _, r := range localPart {
		if !isValidLocalPartChar(r) {
			return false
		}
	}

	return true
}

// isValidLocalPartChar checks if a character is valid in the local part of an email
func isValidLocalPartChar(r rune) bool {
	// RFC 5322 allows: A-Z, a-z, 0-9, and these special characters: !#$%&'*+-/=?^_`{|}~
	if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
		return true
	}

	specialChars := "!#$%&'*+-/=?^_`{|}~."
	return strings.ContainsRune(specialChars, r)
}

// isValidDomain validates the domain part of an email address
func isValidDomain(domain string) bool {
	if len(domain) == 0 {
		return false
	}

	// Split domain into labels
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false // Domain must have at least one dot
	}

	for _, label := range labels {
		if !isValidDomainLabel(label) {
			return false
		}
	}

	return true
}

// isValidDomainLabel validates a single label in a domain name
func isValidDomainLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}

	// Label cannot start or end with hyphen
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}

	// Validate characters in label
	for _, r := range label {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}

	return true
}

// validateSMTPCommand performs comprehensive validation and sanitization of SMTP commands
func validateSMTPCommand(command string) *InputValidationResult {
	result := &InputValidationResult{
		Valid: false,
		SanitizedValue: command,
	}

	// Length validation - RFC 5321 limits command lines to 512 octets including CRLF
	if len(command) > 510 { // 512 - 2 for CRLF
		result.ErrorType = "command_too_long"
		result.ErrorMessage = "Command exceeds RFC 5321 length limit (512 octets)"
		result.SecurityThreat = "buffer_overflow_attempt"
		return result
	}

	// Check for null bytes and other control characters
	for i, r := range command {
		if r == 0 || (r < 32 && r != 9 && r != 10 && r != 13) { // Allow TAB, LF, CR
			result.ErrorType = "invalid_control_character"
			result.ErrorMessage = fmt.Sprintf("Invalid control character at position %d", i)
			result.SecurityThreat = "command_injection_attempt"
			return result
		}
	}

	// Command injection detection - check for dangerous patterns
	dangerousPatterns := []string{
		"|", "&", ";", "`", "$", // Shell metacharacters
		"$(", "${", "``",        // Command substitution
		"../", "..\\",           // Path traversal
		"\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", // Control chars
		"\x08", "\x0b", "\x0c", "\x0e", "\x0f", "\x10", "\x11", "\x12",
		"<script", "</script",   // Script injection
		"javascript:", "data:",  // Protocol injection
		"file://", "ftp://",     // Protocol injection
	}

	commandLower := strings.ToLower(command)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(commandLower, pattern) {
			result.ErrorType = "injection_attempt"
			result.ErrorMessage = fmt.Sprintf("Dangerous pattern detected: %s", pattern)
			result.SecurityThreat = "command_injection_attempt"
			return result
		}
	}

	// SQL injection pattern detection
	sqlPatterns := []string{
		"union select", "drop table", "delete from", "insert into",
		"update set", "alter table", "create table", "exec ",
		"execute ", "sp_", "xp_", "@@", "char(", "cast(",
		"convert(", "substring(", "ascii(", "len(",
		"waitfor delay", "benchmark(", "sleep(",
		"information_schema", "sys.tables", "sysobjects",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(commandLower, pattern) {
			result.ErrorType = "sql_injection"
			result.ErrorMessage = fmt.Sprintf("SQL injection pattern detected: %s", pattern)
			result.SecurityThreat = "sql_injection_attempt"
			return result
		}
	}

	// SMTP command format validation
	if !isValidSMTPCommandFormat(command) {
		result.ErrorType = "invalid_smtp_format"
		result.ErrorMessage = "Command does not conform to SMTP format"
		return result
	}

	// Sanitize the command - remove any potentially dangerous characters while preserving functionality
	sanitized := sanitizeSMTPCommand(command)
	result.SanitizedValue = sanitized
	result.Valid = true
	return result
}

// isValidSMTPCommandFormat validates that the command follows basic SMTP syntax
func isValidSMTPCommandFormat(command string) bool {
	// Trim whitespace for validation
	trimmed := strings.TrimSpace(command)
	if len(trimmed) == 0 {
		return false
	}

	// Split into verb and arguments
	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return false
	}

	verb := strings.ToUpper(parts[0])

	// Validate known SMTP commands
	validCommands := map[string]bool{
		"EHLO": true, "HELO": true, "MAIL": true, "RCPT": true,
		"DATA": true, "QUIT": true, "RSET": true, "NOOP": true,
		"VRFY": true, "EXPN": true, "HELP": true, "AUTH": true,
		"STARTTLS": true, "XDEBUG": true,
	}

	// Check if it's a valid command or starts with a valid command
	isValid := validCommands[verb]
	if !isValid {
		// Check for compound commands like "MAIL FROM:" or "RCPT TO:"
		if strings.HasPrefix(trimmed, "MAIL FROM:") || strings.HasPrefix(trimmed, "mail from:") {
			isValid = true
		} else if strings.HasPrefix(trimmed, "RCPT TO:") || strings.HasPrefix(trimmed, "rcpt to:") {
			isValid = true
		}
	}

	return isValid
}

// sanitizeSMTPCommand removes potentially dangerous characters while preserving SMTP functionality
func sanitizeSMTPCommand(command string) string {
	// Create a byte slice for efficient manipulation
	result := make([]byte, 0, len(command))

	for _, r := range command {
		// Allow printable ASCII characters and specific control characters (TAB, CR, LF)
		if (r >= 32 && r <= 126) || r == 9 || r == 10 || r == 13 {
			// Convert to bytes and append
			if r <= 127 {
				result = append(result, byte(r))
			}
		}
		// Skip any other characters (effectively removing them)
	}

	return string(result)
}

// AuthenticationSecurityManager manages authentication security policies
type AuthenticationSecurityManager struct {
	failedAttempts map[string]*AuthFailureInfo // IP -> failure info
	accountLockout map[string]*AccountLockInfo // username -> lockout info
	mutex          sync.RWMutex
	config         *AuthSecurityConfig
}

// AuthFailureInfo tracks failed authentication attempts per IP
type AuthFailureInfo struct {
	Count       int
	FirstFail   time.Time
	LastFail    time.Time
	Blocked     bool
	BlockedUntil time.Time
}

// AccountLockInfo tracks account lockout status
type AccountLockInfo struct {
	FailedAttempts int
	FirstFail      time.Time
	LastFail       time.Time
	LockedUntil    time.Time
}

// AuthSecurityConfig defines authentication security policies
type AuthSecurityConfig struct {
	// Rate limiting
	MaxAttemptsPerIP       int           // Max attempts per IP per window
	RateLimitWindow        time.Duration // Rate limit time window
	IPBlockDuration        time.Duration // How long to block IPs
	
	// Account lockout
	MaxFailedAttempts      int           // Max failed attempts per account
	AccountLockoutDuration time.Duration // How long to lock accounts
	LockoutWindow          time.Duration // Time window for counting failures
	
	// TLS requirements
	RequireTLSForPLAIN     bool          // Require TLS for PLAIN auth
	RequireTLSForLOGIN     bool          // Require TLS for LOGIN auth
	DisableCRAMMD5         bool          // Disable CRAM-MD5 entirely
	
	// Logging
	LogAllAttempts         bool          // Log all auth attempts
	LogFailuresOnly        bool          // Log only failures
}

// Global authentication security manager
var authSecurityManager *AuthenticationSecurityManager
var authSecurityOnce sync.Once

// GetAuthSecurityManager returns the singleton authentication security manager
func GetAuthSecurityManager() *AuthenticationSecurityManager {
	authSecurityOnce.Do(func() {
		config := &AuthSecurityConfig{
			MaxAttemptsPerIP:       10,
			RateLimitWindow:        time.Minute * 15,
			IPBlockDuration:        time.Hour,
			MaxFailedAttempts:      5,
			AccountLockoutDuration: time.Minute * 30,
			LockoutWindow:          time.Hour,
			RequireTLSForPLAIN:     true,
			RequireTLSForLOGIN:     false, // LOGIN is already obscured by base64
			DisableCRAMMD5:         true,
			LogAllAttempts:         true,
			LogFailuresOnly:        false,
		}
		
		authSecurityManager = &AuthenticationSecurityManager{
			failedAttempts: make(map[string]*AuthFailureInfo),
			accountLockout: make(map[string]*AccountLockInfo),
			config:         config,
		}
		
		// Start cleanup goroutine
		go authSecurityManager.cleanupExpiredEntries()
	})
	return authSecurityManager
}

// IsIPBlocked checks if an IP address is currently blocked
func (asm *AuthenticationSecurityManager) IsIPBlocked(ip string) bool {
	asm.mutex.RLock()
	defer asm.mutex.RUnlock()
	
	info, exists := asm.failedAttempts[ip]
	if !exists {
		return false
	}
	
	if info.Blocked && time.Now().Before(info.BlockedUntil) {
		return true
	}
	
	// Clean up expired block
	if info.Blocked && time.Now().After(info.BlockedUntil) {
		info.Blocked = false
		info.Count = 0
	}
	
	return false
}

// IsAccountLocked checks if an account is currently locked
func (asm *AuthenticationSecurityManager) IsAccountLocked(username string) bool {
	asm.mutex.RLock()
	defer asm.mutex.RUnlock()
	
	info, exists := asm.accountLockout[username]
	if !exists {
		return false
	}
	
	if time.Now().Before(info.LockedUntil) {
		return true
	}
	
	// Clean up expired lockout
	if time.Now().After(info.LockedUntil) {
		info.FailedAttempts = 0
	}
	
	return false
}

// RecordAuthFailure records a failed authentication attempt
func (asm *AuthenticationSecurityManager) RecordAuthFailure(ip, username string) {
	asm.mutex.Lock()
	defer asm.mutex.Unlock()
	
	now := time.Now()
	
	// Record IP failure
	if info, exists := asm.failedAttempts[ip]; exists {
		// Reset count if outside rate limit window
		if now.Sub(info.FirstFail) > asm.config.RateLimitWindow {
			info.Count = 1
			info.FirstFail = now
		} else {
			info.Count++
		}
		info.LastFail = now
		
		// Block IP if threshold exceeded
		if info.Count >= asm.config.MaxAttemptsPerIP {
			info.Blocked = true
			info.BlockedUntil = now.Add(asm.config.IPBlockDuration)
		}
	} else {
		asm.failedAttempts[ip] = &AuthFailureInfo{
			Count:     1,
			FirstFail: now,
			LastFail:  now,
		}
	}
	
	// Record account failure
	if username != "" {
		if info, exists := asm.accountLockout[username]; exists {
			// Reset count if outside lockout window
			if now.Sub(info.FirstFail) > asm.config.LockoutWindow {
				info.FailedAttempts = 1
				info.FirstFail = now
			} else {
				info.FailedAttempts++
			}
			info.LastFail = now
			
			// Lock account if threshold exceeded
			if info.FailedAttempts >= asm.config.MaxFailedAttempts {
				info.LockedUntil = now.Add(asm.config.AccountLockoutDuration)
			}
		} else {
			asm.accountLockout[username] = &AccountLockInfo{
				FailedAttempts: 1,
				FirstFail:      now,
				LastFail:       now,
			}
		}
	}
}

// RecordAuthSuccess records a successful authentication (clears failure counters)
func (asm *AuthenticationSecurityManager) RecordAuthSuccess(ip, username string) {
	asm.mutex.Lock()
	defer asm.mutex.Unlock()
	
	// Clear IP failure count on success
	if info, exists := asm.failedAttempts[ip]; exists {
		info.Count = 0
		info.Blocked = false
	}
	
	// Clear account failure count on success
	if username != "" {
		if info, exists := asm.accountLockout[username]; exists {
			info.FailedAttempts = 0
		}
	}
}

// cleanupExpiredEntries periodically cleans up expired entries
func (asm *AuthenticationSecurityManager) cleanupExpiredEntries() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		asm.mutex.Lock()
		now := time.Now()
		
		// Clean up IP blocks
		for ip, info := range asm.failedAttempts {
			if info.Blocked && now.After(info.BlockedUntil) {
				delete(asm.failedAttempts, ip)
			} else if now.Sub(info.LastFail) > asm.config.RateLimitWindow*2 {
				delete(asm.failedAttempts, ip)
			}
		}
		
		// Clean up account lockouts
		for username, info := range asm.accountLockout {
			if now.After(info.LockedUntil) && now.Sub(info.LastFail) > asm.config.LockoutWindow*2 {
				delete(asm.accountLockout, username)
			}
		}
		
		asm.mutex.Unlock()
	}
}

// GetSecurityStatus returns current security status for monitoring
func (asm *AuthenticationSecurityManager) GetSecurityStatus() map[string]interface{} {
	asm.mutex.RLock()
	defer asm.mutex.RUnlock()
	
	status := make(map[string]interface{})
	status["blocked_ips"] = len(asm.failedAttempts)
	status["locked_accounts"] = len(asm.accountLockout)
	
	blockedCount := 0
	for _, info := range asm.failedAttempts {
		if info.Blocked && time.Now().Before(info.BlockedUntil) {
			blockedCount++
		}
	}
	status["currently_blocked_ips"] = blockedCount
	
	lockedCount := 0
	for _, info := range asm.accountLockout {
		if time.Now().Before(info.LockedUntil) {
			lockedCount++
		}
	}
	status["currently_locked_accounts"] = lockedCount
	
	return status
}

// validateBase64Input performs comprehensive validation of base64 encoded authentication data
func validateBase64Input(input string, maxDecodedLength int) *InputValidationResult {
	result := &InputValidationResult{
		Valid: false,
		SanitizedValue: input,
	}

	// Length validation for base64 input
	if len(input) > 4096 { // Reasonable limit for auth data
		result.ErrorType = "base64_too_long"
		result.ErrorMessage = "Base64 input exceeds maximum length"
		result.SecurityThreat = "buffer_overflow_attempt"
		return result
	}

	// Check for dangerous characters in base64 input (before decoding)
	for i, r := range input {
		// Base64 alphabet: A-Z, a-z, 0-9, +, /, = (padding)
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			result.ErrorType = "invalid_base64_character"
			result.ErrorMessage = fmt.Sprintf("Invalid base64 character at position %d", i)
			result.SecurityThreat = "command_injection_attempt"
			return result
		}
	}

	// Attempt to decode base64
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		result.ErrorType = "base64_decode_error"
		result.ErrorMessage = "Invalid base64 encoding"
		return result
	}

	// Validate decoded length
	if len(decoded) > maxDecodedLength {
		result.ErrorType = "decoded_data_too_long"
		result.ErrorMessage = "Decoded data exceeds maximum length"
		result.SecurityThreat = "buffer_overflow_attempt"
		return result
	}

	// Check decoded data for injection patterns
	decodedStr := string(decoded)
	injectionResult := validateAuthenticationData(decodedStr)
	if !injectionResult.Valid {
		result.ErrorType = injectionResult.ErrorType
		result.ErrorMessage = injectionResult.ErrorMessage
		result.SecurityThreat = injectionResult.SecurityThreat
		return result
	}

	result.Valid = true
	result.SanitizedValue = input
	return result
}

// validateAuthenticationData validates decoded authentication credentials
func validateAuthenticationData(data string) *InputValidationResult {
	result := &InputValidationResult{
		Valid: false,
		SanitizedValue: data,
	}

	// Check for null bytes and dangerous control characters
	for i, r := range data {
		if r == 0 || (r < 32 && r != 9 && r != 10 && r != 13) {
			result.ErrorType = "invalid_auth_character"
			result.ErrorMessage = fmt.Sprintf("Invalid control character in auth data at position %d", i)
			result.SecurityThreat = "command_injection_attempt"
			return result
		}
	}

	// Command injection detection in auth data
	dangerousPatterns := []string{
		"|", "&", ";", "`", "$", // Shell metacharacters
		"$(", "${", "``",        // Command substitution
		"../", "..\\",           // Path traversal
		"<script", "</script",   // Script injection
		"javascript:", "data:",  // Protocol injection
	}

	dataLower := strings.ToLower(data)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(dataLower, pattern) {
			result.ErrorType = "auth_injection_attempt"
			result.ErrorMessage = fmt.Sprintf("Dangerous pattern in auth data: %s", pattern)
			result.SecurityThreat = "command_injection_attempt"
			return result
		}
	}

	// SQL injection patterns in auth data
	sqlPatterns := []string{
		"union select", "drop table", "delete from", "insert into",
		"update set", "alter table", "create table", "exec ",
		"execute ", "sp_", "xp_", "@@", "char(", "cast(",
		"convert(", "substring(", "ascii(", "len(",
		"waitfor delay", "benchmark(", "sleep(",
		"information_schema", "sys.tables", "sysobjects",
		"' or '1'='1", "' or 1=1", "admin'--", "' union",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(dataLower, pattern) {
			result.ErrorType = "auth_sql_injection"
			result.ErrorMessage = fmt.Sprintf("SQL injection pattern in auth data: %s", pattern)
			result.SecurityThreat = "sql_injection_attempt"
			return result
		}
	}

	result.Valid = true
	return result
}

// handleMailFrom handles the MAIL FROM command with enhanced validation
func (s *Session) handleMailFrom(line string) {
	// Extract the address
	addr := extractAddress(line)

	// Enhanced email address validation with comprehensive security analysis
	if addr == "" {
		LogSecurityEvent(s.logger, "empty_mail_from", "validation_error", 
			"Empty address in MAIL FROM command", line, s.conn.RemoteAddr().String())
		s.writeWithLog("501 5.1.7 Invalid address format\r\n")
		return
	}

	// Use enhanced validator for comprehensive validation
	validationResult := s.enhancedValidator.ValidateSMTPParameter("MAIL_FROM", addr)
	if !validationResult.Valid {
		LogSecurityEvent(s.logger, "invalid_mail_from_address", validationResult.SecurityThreat,
			validationResult.ErrorMessage, addr, s.conn.RemoteAddr().String())

		// Send appropriate RFC-compliant error response based on threat type
		switch validationResult.SecurityThreat {
		case "command_injection_attack":
			s.writeWithLog("554 5.7.1 Address rejected: contains dangerous characters\r\n")
		case "sql_injection_attack":
			s.writeWithLog("554 5.7.1 Address rejected: contains prohibited patterns\r\n")
		case "buffer_overflow_attempt":
			s.writeWithLog("501 5.1.7 Address rejected: exceeds maximum length\r\n")
		case "unicode_attack", "homograph_attack", "encoding_attack":
			s.writeWithLog("554 5.7.1 Address rejected: contains unsafe characters\r\n")
		default:
			s.writeWithLog("501 5.1.7 Invalid address format\r\n")
		}
		return
	}

	// Check for SIZE parameter
	sizeParam := ""
	sizeIndex := strings.Index(strings.ToUpper(line), "SIZE=")
	if sizeIndex > 0 {
		sizeParam = line[sizeIndex+5:]
		spaceIndex := strings.Index(sizeParam, " ")
		if spaceIndex > 0 {
			sizeParam = sizeParam[:spaceIndex]
		}

		// Enhanced SIZE parameter validation
		if sizeParam != "" {
			sizeValidation := s.enhancedValidator.ValidateSMTPParameter("SIZE", sizeParam)
			if !sizeValidation.Valid {
				LogSecurityEvent(s.logger, "invalid_size_parameter", sizeValidation.SecurityThreat,
					sizeValidation.ErrorMessage, sizeParam, s.conn.RemoteAddr().String())
				
				switch sizeValidation.SecurityThreat {
				case "buffer_overflow_attempt":
					s.writeWithLog("501 5.5.4 SIZE parameter format invalid\r\n")
				case "resource_exhaustion":
					s.writeWithLog("552 5.3.4 SIZE parameter exceeds maximum allowed\r\n")
				default:
					s.writeWithLog("501 5.5.4 Invalid SIZE parameter\r\n")
				}
				return
			}
			
			// Additional check against configured maximum
			if size, err := strconv.ParseInt(sizeParam, 10, 64); err == nil {
				if size > s.config.MaxSize {
					s.logger.Warn("SIZE parameter exceeds configured maximum", 
						"size", size, "max", s.config.MaxSize)
					s.writeWithLog(fmt.Sprintf("552 5.3.4 Message size exceeds limit of %d bytes\r\n", s.config.MaxSize))
					return
				}
			}
		}
	}

	// Create a new message for this mail transaction
	s.message = NewMessage()
	s.message.from = addr
	s.state = MAIL
	s.logger.Info("mail from accepted", "from", addr, "size_param", sizeParam)
	s.writeWithLog("250 2.1.0 Sender ok\r\n")
}

// handleRcptTo handles the RCPT TO command with enhanced validation and relay control
func (s *Session) handleRcptTo(line string) {
	// Extract the address
	addr := extractAddress(line)

	// Enhanced email address validation with comprehensive security analysis
	if addr == "" {
		LogSecurityEvent(s.logger, "empty_rcpt_to", "validation_error", 
			"Empty address in RCPT TO command", line, s.conn.RemoteAddr().String())
		s.writeWithLog("501 5.1.3 Invalid address format\r\n")
		return
	}

	// Use enhanced validator for comprehensive validation
	validationResult := s.enhancedValidator.ValidateSMTPParameter("RCPT_TO", addr)
	if !validationResult.Valid {
		LogSecurityEvent(s.logger, "invalid_rcpt_to_address", validationResult.SecurityThreat,
			validationResult.ErrorMessage, addr, s.conn.RemoteAddr().String())

		// Send appropriate RFC-compliant error response based on threat type
		switch validationResult.SecurityThreat {
		case "command_injection_attack":
			s.writeWithLog("554 5.7.1 Recipient rejected: contains dangerous characters\r\n")
		case "sql_injection_attack":
			s.writeWithLog("554 5.7.1 Recipient rejected: contains prohibited patterns\r\n")
		case "buffer_overflow_attempt":
			s.writeWithLog("501 5.1.3 Recipient rejected: exceeds maximum length\r\n")
		case "unicode_attack", "homograph_attack", "encoding_attack":
			s.writeWithLog("554 5.7.1 Recipient rejected: contains unsafe characters\r\n")
		default:
			s.writeWithLog("501 5.1.3 Invalid recipient address format\r\n")
		}
		return
	}

	// Check recipient limit
	if len(s.message.to) >= 100 {
		s.logger.Warn("too many recipients", "count", len(s.message.to))
		s.writeWithLog("452 4.5.3 Too many recipients\r\n")
		return
	}

	// Check relay permissions for this recipient
	if !s.isRelayAllowed(addr) {
		s.logger.Warn("relay denied",
			"recipient", addr,
			"client_ip", s.conn.RemoteAddr().String(),
			"authenticated", s.authenticated,
			"is_internal", IsInternalConnection(s.conn))
		s.writeWithLog("554 5.7.1 Relay access denied\r\n")
		return
	}

	// Add the recipient to the message
	s.message.to = append(s.message.to, addr)
	s.state = RCPT
	s.logger.Info("rcpt to accepted", "to", addr, "count", len(s.message.to))
	s.writeWithLog("250 2.1.5 Recipient ok\r\n")
}

// handleAuth handles the AUTH command with comprehensive security checks
func (s *Session) handleAuth(cmd string) error {
	if s.authenticated {
		s.writeWithLog("503 5.5.1 Already authenticated\r\n")
		return nil
	}

	if !s.authenticator.IsEnabled() {
		s.writeWithLog("503 5.5.1 Authentication not enabled\r\n")
		return nil
	}

	// Get security manager
	securityManager := GetAuthSecurityManager()
	
	// Check if IP is blocked
	if securityManager.IsIPBlocked(s.remoteAddr) {
		s.logger.Warn("smtp_security_violation",
			"event_type", "blocked_ip_auth_attempt",
			"remote_addr", s.remoteAddr,
			"message", "Authentication attempt from blocked IP",
		)
		s.writeWithLog("421 4.7.1 Too many failed authentication attempts. Try again later.\r\n")
		return nil
	}

	// Check rate limiting for this session
	now := time.Now()
	if s.authAttempts > 0 && now.Sub(s.lastAuthAttempt) < time.Second*3 {
		s.logger.Warn("smtp_security_violation",
			"event_type", "auth_rate_limit_exceeded",
			"remote_addr", s.remoteAddr,
			"attempts", s.authAttempts,
			"message", "Authentication attempts too frequent",
		)
		s.writeWithLog("421 4.7.1 Authentication attempts too frequent. Slow down.\r\n")
		return nil
	}

	// Increment attempt counter and update timestamp
	s.authAttempts++
	s.lastAuthAttempt = now

	// Session-level rate limiting (max 5 attempts per session)
	if s.authAttempts > 5 {
		s.logger.Warn("smtp_security_violation",
			"event_type", "session_auth_limit_exceeded",
			"remote_addr", s.remoteAddr,
			"attempts", s.authAttempts,
			"message", "Too many authentication attempts in session",
		)
		s.writeWithLog("421 4.7.1 Too many authentication attempts in this session.\r\n")
		return errors.New("too many authentication attempts")
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		s.writeWithLog("501 5.5.4 Syntax error in parameters\r\n")
		return nil
	}

	method := AuthMethod(parts[1])
	
	// Check TLS requirements based on authentication method
	if !s.tls {
		switch method {
		case AuthMethodPlain:
			if securityManager.config.RequireTLSForPLAIN {
				s.logger.Warn("smtp_security_violation",
					"event_type", "plain_auth_without_tls",
					"remote_addr", s.remoteAddr,
					"message", "PLAIN authentication attempted without TLS",
				)
				s.writeWithLog("538 5.7.11 Encryption required for requested authentication mechanism\r\n")
				return nil
			}
		case AuthMethodLogin:
			if securityManager.config.RequireTLSForLOGIN {
				s.logger.Warn("smtp_security_violation",
					"event_type", "login_auth_without_tls",
					"remote_addr", s.remoteAddr,
					"message", "LOGIN authentication attempted without TLS",
				)
				s.writeWithLog("538 5.7.11 Encryption required for requested authentication mechanism\r\n")
				return nil
			}
		}
	}

	// Log authentication attempt
	s.logger.Info("smtp_auth_attempt",
		"event_type", "authentication_attempt",
		"method", string(method),
		"remote_addr", s.remoteAddr,
		"tls_enabled", s.tls,
		"session_attempts", s.authAttempts,
	)

	switch method {
	case AuthMethodPlain:
		return s.handleAuthPlain(cmd)
	case AuthMethodLogin:
		return s.handleAuthLogin()
	case AuthMethodCramMD5:
		return s.handleAuthCramMD5()
	default:
		s.writeWithLog("504 5.5.4 Authentication mechanism not supported\r\n")
		return nil
	}
}

// handleAuthPlain handles PLAIN authentication
func (s *Session) handleAuthPlain(cmd string) error {
	parts := strings.Fields(cmd)
	var authData string

	if len(parts) >= 3 {
		// AUTH PLAIN <base64-data>
		// The base64 data may contain spaces or be split across multiple parts
		// Take everything after "AUTH PLAIN " - this is the base64 encoded data
		prefix := "AUTH PLAIN "
		if len(cmd) > len(prefix) {
			authData = strings.TrimSpace(cmd[len(prefix):])
			s.logger.Debug("AUTH PLAIN one-step mode", "authData", authData)
		} else {
			s.writeWithLog("501 5.5.4 Invalid AUTH PLAIN format\r\n")
			return nil
		}
	} else {
		// AUTH PLAIN
		s.writeWithLog("334 \r\n")
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return err
		}
		authData = strings.TrimSpace(line)
		s.logger.Debug("AUTH PLAIN two-step mode", "authData", authData)
	}

	// Comprehensive validation of base64 authentication data
	authValidation := validateBase64Input(authData, 1024) // Max 1024 chars for combined auth data
	if !authValidation.Valid {
		s.logger.Warn("smtp_security_violation",
			"event_type", "invalid_auth_plain_input",
			"error_type", authValidation.ErrorType,
			"error_message", authValidation.ErrorMessage,
			"security_threat", authValidation.SecurityThreat,
			"remote_addr", s.conn.RemoteAddr().String(),
		)
		
		switch authValidation.SecurityThreat {
		case "command_injection_attempt":
			s.writeWithLog("554 5.7.1 Authentication data contains dangerous characters\r\n")
		case "sql_injection_attempt":
			s.writeWithLog("554 5.7.1 Authentication data contains SQL injection patterns\r\n")
		case "buffer_overflow_attempt":
			s.writeWithLog("501 5.5.2 Authentication data too long\r\n")
		default:
			s.writeWithLog("501 5.5.2 Invalid base64 encoding\r\n")
		}
		return nil
	}

	data, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		s.writeWithLog("501 5.5.2 Invalid base64 encoding\r\n")
		return nil
	}

	s.logger.Debug("AUTH PLAIN decoded data",
		"hexBytes", hex.EncodeToString(data),
		"stringData", string(data))

	parts = strings.Split(string(data), "\x00")
	if len(parts) != 3 {
		s.writeWithLog("501 5.5.2 Invalid PLAIN authentication data\r\n")
		return nil
	}

	username := parts[1]
	password := parts[2]

	// Additional validation for extracted username and password
	usernameValidation := validateAuthenticationData(username)
	if !usernameValidation.Valid {
		s.logger.Warn("smtp_security_violation",
			"event_type", "invalid_auth_plain_username",
			"error_type", usernameValidation.ErrorType,
			"security_threat", usernameValidation.SecurityThreat,
			"remote_addr", s.conn.RemoteAddr().String(),
		)
		s.writeWithLog("554 5.7.1 Invalid username format\r\n")
		return nil
	}

	passwordValidation := validateAuthenticationData(password)
	if !passwordValidation.Valid {
		s.logger.Warn("smtp_security_violation",
			"event_type", "invalid_auth_plain_password",
			"error_type", passwordValidation.ErrorType,
			"security_threat", passwordValidation.SecurityThreat,
			"remote_addr", s.conn.RemoteAddr().String(),
		)
		s.writeWithLog("554 5.7.1 Invalid password format\r\n")
		return nil
	}

	s.logger.Debug("AUTH PLAIN credentials",
		"username", username,
		"passwordLength", len(password))

	err = s.authenticate(username, password)
	if err != nil {
		return nil
	}

	return nil
}

// handleAuthLogin handles LOGIN authentication
func (s *Session) handleAuthLogin() error {
	// Send username challenge
	s.writeWithLog("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n")
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	
	usernameB64 := strings.TrimSpace(line)
	
	// Comprehensive validation of base64 username input
	usernameValidation := validateBase64Input(usernameB64, 256) // Max 256 chars for username
	if !usernameValidation.Valid {
		s.logger.Warn("smtp_security_violation",
			"event_type", "invalid_auth_username_input",
			"error_type", usernameValidation.ErrorType,
			"error_message", usernameValidation.ErrorMessage,
			"security_threat", usernameValidation.SecurityThreat,
			"remote_addr", s.conn.RemoteAddr().String(),
		)
		
		switch usernameValidation.SecurityThreat {
		case "command_injection_attempt":
			s.writeWithLog("554 5.7.1 Username contains dangerous characters\r\n")
		case "sql_injection_attempt":
			s.writeWithLog("554 5.7.1 Username contains SQL injection patterns\r\n")
		case "buffer_overflow_attempt":
			s.writeWithLog("501 5.5.2 Username too long\r\n")
		default:
			s.writeWithLog("501 5.5.2 Invalid base64 encoding\r\n")
		}
		return nil
	}
	
	usernameBytes, err := base64.StdEncoding.DecodeString(usernameB64)
	if err != nil {
		s.writeWithLog("501 5.5.2 Invalid base64 encoding\r\n")
		return nil
	}
	username := string(usernameBytes)

	// Send password challenge
	s.writeWithLog("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n")
	line, err = s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	
	passwordB64 := strings.TrimSpace(line)
	
	// Comprehensive validation of base64 password input
	passwordValidation := validateBase64Input(passwordB64, 512) // Max 512 chars for password
	if !passwordValidation.Valid {
		s.logger.Warn("smtp_security_violation",
			"event_type", "invalid_auth_password_input",
			"error_type", passwordValidation.ErrorType,
			"error_message", passwordValidation.ErrorMessage,
			"security_threat", passwordValidation.SecurityThreat,
			"remote_addr", s.conn.RemoteAddr().String(),
		)
		
		switch passwordValidation.SecurityThreat {
		case "command_injection_attempt":
			s.writeWithLog("554 5.7.1 Password contains dangerous characters\r\n")
		case "sql_injection_attempt":
			s.writeWithLog("554 5.7.1 Password contains SQL injection patterns\r\n")
		case "buffer_overflow_attempt":
			s.writeWithLog("501 5.5.2 Password too long\r\n")
		default:
			s.writeWithLog("501 5.5.2 Invalid base64 encoding\r\n")
		}
		return nil
	}
	
	passwordBytes, err := base64.StdEncoding.DecodeString(passwordB64)
	if err != nil {
		s.writeWithLog("501 5.5.2 Invalid base64 encoding\r\n")
		return nil
	}
	password := string(passwordBytes)

	// Authenticate and handle any errors
	err = s.authenticate(username, password)
	if err != nil {
		// Error already handled in authenticate method
		return nil
	}

	return nil
}

// handleAuthCramMD5 handles CRAM-MD5 authentication (DISABLED for security)
func (s *Session) handleAuthCramMD5() error {
	// CRAM-MD5 is inherently insecure and is disabled entirely
	// Reasons for disabling:
	// 1. Requires plaintext password storage (major security risk)
	// 2. Uses MD5 which is cryptographically broken
	// 3. Vulnerable to offline dictionary attacks
	// 4. Modern security standards recommend PLAIN/LOGIN over TLS instead
	
	s.logger.Warn("smtp_security_violation",
		"event_type", "cram_md5_attempt",
		"remote_addr", s.remoteAddr,
		"message", "CRAM-MD5 authentication attempted but disabled for security",
		"security_threat", "deprecated_auth_method",
	)
	
	// Record this as a security event but not a failed auth attempt
	// since CRAM-MD5 is completely disabled
	s.writeWithLog("504 5.5.4 CRAM-MD5 authentication mechanism disabled for security reasons\r\n")
	return nil
}

// authenticate performs the actual authentication with comprehensive security controls
func (s *Session) authenticate(username, password string) error {
	// Get metrics and security manager
	metrics := GetMetrics()
	securityManager := GetAuthSecurityManager()

	// Track authentication attempt
	metrics.AuthAttempts.Inc()

	// Check if account is locked
	if securityManager.IsAccountLocked(username) {
		s.logger.Warn("smtp_security_violation",
			"event_type", "locked_account_auth_attempt",
			"username", username,
			"remote_addr", s.remoteAddr,
			"message", "Authentication attempt on locked account",
		)
		
		// Don't reveal that account is locked to prevent enumeration
		s.writeWithLog("535 5.7.8 Authentication failed\r\n")
		return errors.New("account locked")
	}

	// Comprehensive authentication logging
	authStartTime := time.Now()
	defer func() {
		duration := time.Since(authStartTime)
		s.logger.Info("smtp_auth_complete",
			"event_type", "authentication_complete",
			"username", username,
			"remote_addr", s.remoteAddr,
			"duration_ms", duration.Milliseconds(),
			"authenticated", s.authenticated,
			"tls_enabled", s.tls,
		)
	}()

	// For internal networks, use simplified authentication (but still log properly)
	clientIP := GetClientIP(s.conn)
	if clientIP != nil && IsPrivateNetwork(clientIP) {
		s.authenticated = true
		s.username = username
		
		s.logger.Info("smtp_auth_success",
			"event_type", "authentication_success",
			"username", username,
			"remote_addr", s.remoteAddr,
			"client_ip", clientIP.String(),
			"auth_type", "internal_network",
			"tls_enabled", s.tls,
		)
		
		metrics.AuthSuccesses.Inc()
		securityManager.RecordAuthSuccess(s.remoteAddr, username)
		s.writeWithLog("235 2.7.0 Authentication successful\r\n")
		return nil
	}

	// Perform authentication for external networks
	if s.authenticator == nil {
		s.logger.Error("smtp_auth_failure",
			"event_type", "authentication_failure",
			"username", username,
			"remote_addr", s.remoteAddr,
			"error", "authenticator not configured",
			"failure_reason", "system_error",
		)
		
		metrics.AuthFailures.Inc()
		securityManager.RecordAuthFailure(s.remoteAddr, username)
		s.writeWithLog("535 5.7.8 Authentication failed\r\n")
		return errors.New("authenticator not configured")
	}

	// Attempt authentication with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	
	authenticated, err := s.authenticator.Authenticate(ctx, username, password)
	if err != nil {
		s.logger.Error("smtp_auth_failure",
			"event_type", "authentication_failure",
			"username", username,
			"remote_addr", s.remoteAddr,
			"error", err.Error(),
			"failure_reason", "auth_system_error",
		)
		
		metrics.AuthFailures.Inc()
		securityManager.RecordAuthFailure(s.remoteAddr, username)
		s.writeWithLog("535 5.7.8 Authentication failed\r\n")
		return err
	}

	if !authenticated {
		s.logger.Warn("smtp_auth_failure",
			"event_type", "authentication_failure",
			"username", username,
			"remote_addr", s.remoteAddr,
			"failure_reason", "invalid_credentials",
			"tls_enabled", s.tls,
		)
		
		metrics.AuthFailures.Inc()
		securityManager.RecordAuthFailure(s.remoteAddr, username)
		s.writeWithLog("535 5.7.8 Authentication credentials invalid\r\n")
		return fmt.Errorf("authentication failed for user %s", username)
	}

	// Authentication successful
	s.authenticated = true
	s.username = username
	
	s.logger.Info("smtp_auth_success",
		"event_type", "authentication_success",
		"username", username,
		"remote_addr", s.remoteAddr,
		"auth_type", "external_auth",
		"tls_enabled", s.tls,
	)

	// Track successful authentication and clear failure counters
	metrics.AuthSuccesses.Inc()
	securityManager.RecordAuthSuccess(s.remoteAddr, username)

	// Send success message
	s.writeWithLog("235 2.7.0 Authentication successful\r\n")
	return nil
}

// generateMessageID creates a unique message ID for the queued message
// Format: elemta-{node-id}-{queue-type}-{timestamp}-{uuid-segment}@{hostname}
func generateMessageID() string {
	// Get hostname for the domain part
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "mail.example.com"
	}

	// Get node ID from environment or default to 0
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		nodeID = "0"
	}

	// Generate UUID for uniqueness
	uuidStr := uuid.New().String()
	uuidSegment := strings.Replace(uuidStr[0:13], "-", "", -1)

	// Use nanosecond precision timestamp for additional uniqueness
	timestamp := time.Now().UnixNano()

	// Format: elemta-{node-id}-{timestamp}-{uuid-segment}@{hostname}
	return fmt.Sprintf("elemta-%s-%d-%s@%s", nodeID, timestamp, uuidSegment, hostname)
}

func (s *Session) validateMessageHeaders() bool {
	// Skip validation in dev mode
	if s.config.DevMode {
		return true
	}

	// Convert message data to string for header analysis
	messageStr := string(s.message.data)

	// Find the end of headers (blank line)
	headerEndIndex := strings.Index(messageStr, "\r\n\r\n")
	if headerEndIndex == -1 {
		// Try again with just LF
		headerEndIndex = strings.Index(messageStr, "\n\n")
	}

	if headerEndIndex == -1 {
		s.logger.Warn("no header/body separator found in message")
		return false
	}

	// Extract just the headers section
	headersSection := messageStr[:headerEndIndex]

	// Split headers into lines
	headerLines := strings.Split(headersSection, "\n")

	// Check for minimal required headers according to RFC 5322
	hasFrom := false
	hasDate := false
	hasMessageID := false

	for _, line := range headerLines {
		line = strings.TrimSpace(line)

		// Skip continuation lines
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}

		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "from:") {
			hasFrom = true
		} else if strings.HasPrefix(lowerLine, "date:") {
			hasDate = true
		} else if strings.HasPrefix(lowerLine, "message-id:") {
			hasMessageID = true
		}
	}

	// Log missing headers but don't reject the message
	// This is lenient behavior - many clients depend on the MTA to add these headers
	if !hasFrom {
		s.logger.Warn("message missing From header")
		// We won't add it, but we should notify the admin
	}

	if !hasDate {
		s.logger.Warn("message missing Date header")
		// We could add it here, but we're just validating
	}

	if !hasMessageID {
		s.logger.Warn("message missing Message-ID header")
		// We could add it here, but we're just validating
	}

	// For now, we'll accept messages even with missing headers
	// A production system might be stricter or add the headers
	return true
}

// isLocalDomain checks if a domain is configured as local
func (s *Session) isLocalDomain(domain string) bool {
	if s.config.LocalDomains == nil {
		return false
	}

	domain = strings.ToLower(domain)
	for _, localDomain := range s.config.LocalDomains {
		if strings.ToLower(localDomain) == domain {
			return true
		}
	}
	return false
}

// isRelayAllowed determines if this session is allowed to relay to the given recipient
func (s *Session) isRelayAllowed(recipient string) bool {
	// Extract domain from recipient
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]

	// Always allow delivery to local domains
	if s.isLocalDomain(domain) {
		s.logger.Debug("allowing local domain delivery", "domain", domain)
		return true
	}

	// For external domains (relay), check permissions
	clientIP := GetClientIP(s.conn)
	if clientIP == nil {
		s.logger.Warn("could not determine client IP")
		return false
	}

	// Internal networks can relay without authentication
	if IsPrivateNetwork(clientIP) {
		s.logger.Debug("allowing internal network relay",
			"client_ip", clientIP.String(),
			"domain", domain)
		return true
	}

	// External connections require authentication for relay
	if !s.authenticated {
		s.logger.Debug("external connection requires authentication for relay",
			"client_ip", clientIP.String(),
			"domain", domain,
			"authenticated", s.authenticated)
		return false
	}

	// Authenticated external connections can relay
	s.logger.Debug("allowing authenticated relay",
		"client_ip", clientIP.String(),
		"domain", domain,
		"username", s.username)
	return true
}

// addHeaderToMessage adds a header to the message data by finding the last existing header
// extractHeader extracts a header value from email headers
func extractHeader(headers, name string) string {
	lines := strings.Split(headers, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			value := strings.TrimSpace(line[len(name)+1:])
			return value
		}
	}
	return ""
}

func addHeaderToMessage(data []byte, name, value string) []byte {
	dataStr := string(data)

	// Parse the message to find where to insert the header
	lines := strings.Split(dataStr, "\n")
	insertIndex := -1

	// Find the last header line (non-empty line before body or end)
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			// Empty line - this is the header/body separator
			insertIndex = i
			break
		}
		// Check if this looks like a header (contains ':')
		if strings.Contains(line, ":") {
			insertIndex = i + 1
		}
	}

	if insertIndex == -1 {
		// No good place found, append at end
		header := fmt.Sprintf("\n%s: %s", name, value)
		return append(data, []byte(header)...)
	}

	// Insert the header at the found position
	header := fmt.Sprintf("%s: %s", name, value)
	newLines := make([]string, 0, len(lines)+1)

	// Add lines before insertion point
	newLines = append(newLines, lines[:insertIndex]...)

	// Add our new header
	newLines = append(newLines, header)

	// Add remaining lines
	newLines = append(newLines, lines[insertIndex:]...)

	return []byte(strings.Join(newLines, "\n"))
}

// extractSubjectFromData extracts the Subject header from email data
func (s *Session) extractSubjectFromData(data []byte) string {
	return s.extractHeaderFromData(data, "Subject")
}

// extractMessageIDFromData extracts the Message-ID header from email data
func (s *Session) extractMessageIDFromData(data []byte) string {
	return s.extractHeaderFromData(data, "Message-ID")
}

// extractFromHeaderFromData extracts the From header from email data
func (s *Session) extractFromHeaderFromData(data []byte) string {
	return s.extractHeaderFromData(data, "From")
}

// extractHeaderFromData extracts a specific header from email data
func (s *Session) extractHeaderFromData(data []byte, headerName string) string {
	content := string(data)
	
	// Find the end of headers (double CRLF)
	headerEnd := strings.Index(content, "\r\n\r\n")
	if headerEnd == -1 {
		// Try with just LF
		headerEnd = strings.Index(content, "\n\n")
		if headerEnd == -1 {
			return ""
		}
	}
	
	headers := content[:headerEnd]
	lines := strings.Split(headers, "\n")
	
	var headerValue strings.Builder
	inTargetHeader := false
	
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(headerName)+":") {
			// Found the header
			headerValue.WriteString(strings.TrimSpace(line[len(headerName)+1:]))
			inTargetHeader = true
		} else if inTargetHeader && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			// Continuation line
			headerValue.WriteString(" ")
			headerValue.WriteString(strings.TrimSpace(line))
		} else if inTargetHeader {
			// End of header
			break
		}
	}
	
	return strings.TrimSpace(headerValue.String())
}

// isValidEndOfData implements RFC 5321 § 2.3.8 strict compliance for end-of-data sequence
// The end-of-data sequence MUST be exactly <CRLF>.<CRLF> - no exceptions
func (s *Session) isValidEndOfData(line string, state *DataReaderState, suspiciousPatterns *int) bool {
	// RFC 5321 § 2.3.8: The end-of-data sequence is <CRLF>.<CRLF>
	// We must validate the EXACT sequence: \r\n.\r\n
	
	// The line should be exactly ".\r\n" (dot followed by CRLF)
	if line == ".\r\n" {
		s.logger.Debug("rfc5321_compliance", 
			"event", "valid_end_of_data_sequence",
			"line_bytes", []byte(line))
		return true
	}
	
	// Log and count any suspicious end-of-data patterns that could indicate smuggling attempts
	if strings.HasPrefix(line, ".") {
		*suspiciousPatterns++
		
		// Log different types of suspicious patterns
		if line == ".\n" {
			s.logger.Warn("smtp_security_violation",
				"event_type", "invalid_end_of_data_lf_only",
				"description", "End-of-data with LF only (missing CR) - RFC 5321 violation",
				"raw_line", line,
				"line_bytes", []byte(line),
				"remote_addr", s.conn.RemoteAddr().String(),
			)
		} else if line == "." {
			s.logger.Warn("smtp_security_violation",
				"event_type", "invalid_end_of_data_no_terminator", 
				"description", "End-of-data without proper line terminator - RFC 5321 violation",
				"raw_line", line,
				"line_bytes", []byte(line),
				"remote_addr", s.conn.RemoteAddr().String(),
			)
		} else if strings.TrimSpace(line) == "." {
			s.logger.Warn("smtp_security_violation",
				"event_type", "invalid_end_of_data_malformed",
				"description", "End-of-data with malformed line endings - potential smuggling attempt", 
				"raw_line", line,
				"line_bytes", []byte(line),
				"remote_addr", s.conn.RemoteAddr().String(),
			)
		} else {
			s.logger.Warn("smtp_security_violation",
				"event_type", "suspicious_dot_line",
				"description", "Line starting with dot but not valid end-of-data",
				"raw_line", line[:min(100, len(line))], // Limit log size
				"line_bytes", []byte(line[:min(20, len(line))]),
				"remote_addr", s.conn.RemoteAddr().String(),
			)
		}
		
		// For security, we reject all invalid end-of-data patterns
		// This prevents SMTP smuggling attacks that rely on lenient parsing
		return false
	}
	
	return false
}

