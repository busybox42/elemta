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
}

// For testing purposes only
var mockHandleSTARTTLS func(s *Session) error

func NewSession(conn net.Conn, config *Config, authenticator Authenticator) *Session {
	remoteAddr := conn.RemoteAddr().String()
	sessionID := uuid.New().String()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With(
		"component", "smtp-session",
		"remote_addr", remoteAddr,
		"session_id", sessionID,
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

	return &Session{
		conn:           conn,
		reader:         bufio.NewReader(conn),
		writer:         bufio.NewWriter(conn),
		state:          INIT,
		message:        NewMessage(),
		config:         config,
		logger:         logger,
		Context:        NewContext(),
		authenticated:  false,
		username:       "",
		authenticator:  authenticator,
		tls:            false, // Start without TLS
		builtinPlugins: builtinPlugins,
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

		line = strings.TrimSpace(line)
		s.logger.Debug("received command",
			"command", line,
			"state", stateToString(s.state),
			"authenticated", s.authenticated)

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
			s.logger.Info("client hello", "command", line)

			// Extract the client identity
			clientIdentity := ""
			if len(parts) > 1 {
				clientIdentity = parts[1]
				// Store client identity in context for logging
				s.Context.Set("client_identity", clientIdentity)
			}

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

			// Generate a unique message ID and set data
			s.message.data = data
			s.message.id = generateMessageID()
			s.message.receivedTime = time.Now()

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
			s.logger.Info("message accepted", "id", s.message.id)
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

func (s *Session) readData() ([]byte, error) {
	var buffer bytes.Buffer
	// Calculate size limit with a 10% margin to allow for headers
	maxSize := int(float64(s.config.MaxSize) * 1.1)
	totalBytes := 0
	isFirstLine := true

	s.logger.Debug("reading message data")

	// Set a longer timeout for data reading
	dataTimeout := 5 * time.Minute
	s.conn.SetReadDeadline(time.Now().Add(dataTimeout))

	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Error("error reading data", "error", err)
			return nil, fmt.Errorf("error reading message data: %w", err)
		}

		// Check for end of data marker (CRLF.CRLF)
		if line == ".\r\n" {
			s.logger.Debug("end of data marker found")
			break
		}

		// Per RFC 5321, lines starting with a period have it duplicated in the data stream
		// We need to remove this extra period when processing
		if len(line) > 0 && line[0] == '.' && len(line) > 1 {
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
			s.logger.Warn("virus scan failed", "error", err)
			// Add header indicating scan failed
			s.message.data = addHeaderToMessage(s.message.data, "X-Virus-Scanned", "Error (ClamAV)")
			if s.config.Antivirus != nil && s.config.Antivirus.RejectOnFailure {
				s.writeWithLog("554 5.7.1 Unable to scan for viruses\r\n")
				return errors.New("virus scan failed")
			}
		} else if !clean {
			// Message contains virus
			s.logger.Warn("virus detected", "virus", infection)
			s.message.data = addHeaderToMessage(s.message.data, "X-Virus-Scanned", fmt.Sprintf("Infected (ClamAV): %s", infection))
			s.writeWithLog(fmt.Sprintf("554 5.7.1 Message contains a virus: %s\r\n", infection))
			return errors.New("message contains virus")
		} else {
			// Message is clean
			s.message.data = addHeaderToMessage(s.message.data, "X-Virus-Scanned", "Clean (ClamAV)")
		}
	}

	// Scan for spam using our built-in plugin system
	if s.builtinPlugins != nil {
		s.logger.Debug("scanning message for spam", "id", s.message.id)
		clean, score, rules, err := s.builtinPlugins.ScanForSpam(s.message.data, s.message.id)
		if err != nil {
			s.logger.Warn("spam scan failed", "error", err)
			// Add header indicating scan failed
			s.message.data = addHeaderToMessage(s.message.data, "X-Spam-Scanned", "Error (Rspamd)")
			if s.config.Antispam != nil && s.config.Antispam.RejectOnSpam {
				s.writeWithLog("554 5.7.1 Unable to scan for spam\r\n")
				return errors.New("spam scan failed")
			}
		} else if !clean {
			// Message is spam
			s.logger.Warn("spam detected", "score", score, "rules", rules)
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
			s.logger.Info("message is not spam", "score", score, "rules", rules)
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

// validateEmailAddress performs basic RFC 5322 email validation
func validateEmailAddress(email string) bool {
	// Basic format check
	if email == "" {
		return false
	}

	// Special case: RFC 5321 allows "<>" for null sender (bounce messages)
	if email == "" {
		return true
	}

	// Simple email format validation
	atIndex := strings.Index(email, "@")
	if atIndex <= 0 || atIndex == len(email)-1 {
		return false
	}

	// Check for illegal characters
	illegalChars := []string{" ", ",", ";", "(", ")", "[", "]", "\\", "\"", "'"}
	for _, char := range illegalChars {
		if strings.Contains(email, char) {
			return false
		}
	}

	// Validate domain has at least one dot
	domain := email[atIndex+1:]
	if !strings.Contains(domain, ".") {
		return false
	}

	// More sophisticated validation could be added here

	return true
}

// handleMailFrom handles the MAIL FROM command with proper parsing
func (s *Session) handleMailFrom(line string) {
	// Extract the address
	addr := extractAddress(line)

	// Validate the email address
	if addr == "" || !validateEmailAddress(addr) {
		s.logger.Warn("invalid address in MAIL FROM", "command", line)
		s.writeWithLog("501 5.1.7 Invalid address format\r\n")
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

		// Check the size parameter
		if sizeParam != "" {
			size, err := strconv.ParseInt(sizeParam, 10, 64)
			if err != nil {
				s.logger.Warn("invalid size parameter", "size", sizeParam)
				s.writeWithLog("501 5.5.4 Invalid SIZE parameter\r\n")
				return
			}

			if size > s.config.MaxSize {
				s.logger.Warn("message too large", "size", size, "max", s.config.MaxSize)
				s.writeWithLog(fmt.Sprintf("552 5.3.4 Message size exceeds limit of %d bytes\r\n", s.config.MaxSize))
				return
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

// handleRcptTo handles the RCPT TO command with proper parsing and relay control
func (s *Session) handleRcptTo(line string) {
	// Extract the address
	addr := extractAddress(line)

	// Validate the email address
	if addr == "" || !validateEmailAddress(addr) {
		s.logger.Warn("invalid address in RCPT TO", "command", line)
		s.writeWithLog("501 5.1.3 Invalid address format\r\n")
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

// handleAuth handles the AUTH command
func (s *Session) handleAuth(cmd string) error {
	if s.authenticated {
		s.writeWithLog("503 5.5.1 Already authenticated\r\n")
		return nil
	}

	if !s.authenticator.IsEnabled() {
		s.writeWithLog("503 5.5.1 Authentication not enabled\r\n")
		return nil
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		s.writeWithLog("501 5.5.4 Syntax error in parameters\r\n")
		return nil
	}

	method := AuthMethod(parts[1])
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

// handleAuthCramMD5 handles CRAM-MD5 authentication
func (s *Session) handleAuthCramMD5() error {
	// CRAM-MD5 requires plaintext password storage which is a security risk
	// Most modern systems disable CRAM-MD5 in favor of PLAIN/LOGIN over TLS
	s.logger.Warn("CRAM-MD5 authentication attempted but disabled for security")
	s.writeWithLog("504 5.5.4 CRAM-MD5 authentication mechanism disabled for security reasons\r\n")
	return nil
}

// authenticate performs the actual authentication
func (s *Session) authenticate(username, password string) error {
	// Get metrics instance
	metrics := GetMetrics()

	// Track authentication attempt
	metrics.AuthAttempts.Inc()

	// Perform authentication
	if s.authenticator == nil {
		metrics.AuthFailures.Inc()
		s.writeWithLog("535 5.7.8 Authentication failed: authenticator not configured\r\n")
		return errors.New("authenticator not configured")
	}

	authenticated, err := s.authenticator.Authenticate(context.Background(), username, password)
	if err != nil {
		s.logger.Error("Authentication failed", "username", username, "error", err)
		metrics.AuthFailures.Inc()
		s.writeWithLog("535 5.7.8 Authentication failed\r\n")
		return err
	}

	if !authenticated {
		s.logger.Warn("Authentication failed", "username", username)
		metrics.AuthFailures.Inc()
		s.writeWithLog("535 5.7.8 Authentication credentials invalid\r\n")
		return fmt.Errorf("authentication failed for user %s", username)
	}

	s.authenticated = true
	s.username = username
	s.logger.Info("Authentication successful", "username", username)

	// Track successful authentication
	metrics.AuthSuccesses.Inc()

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
