// internal/smtp/session.go
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"encoding/base64"
	"encoding/hex"

	"crypto/tls"

	"github.com/busybox42/elemta/internal/plugin"
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
	conn           net.Conn
	reader         *bufio.Reader
	writer         *bufio.Writer
	state          State
	message        *Message
	config         *Config
	logger         *slog.Logger
	Context        *Context
	authenticated  bool
	username       string
	authenticator  Authenticator
	queueManager   *QueueManager
	tlsManager     TLSHandler
	tls            bool // Flag to indicate if this session is using TLS
	builtinPlugins *plugin.BuiltinPlugins
}

// For testing purposes only
var mockHandleSTARTTLS func(s *Session) error

func NewSession(conn net.Conn, config *Config, authenticator Authenticator) *Session {
	remoteAddr := conn.RemoteAddr().String()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With(
		"remote_addr", remoteAddr,
		"session_id", uuid.New().String(),
	)

	// Initialize plugin system
	builtinPlugins := plugin.NewBuiltinPlugins()

	// Get enabled plugins from config
	var enabledPlugins []string
	pluginConfig := make(map[string]map[string]interface{})

	// Always enable ClamAV and Rspamd for our tests
	enabledPlugins = []string{"clamav", "rspamd"}
	logger.Info("Enabling plugins for testing", "plugins", enabledPlugins)

	// Add ClamAV config
	if pluginConfig["clamav"] == nil {
		pluginConfig["clamav"] = make(map[string]interface{})
	}
	pluginConfig["clamav"]["host"] = "elemta-clamav"
	pluginConfig["clamav"]["port"] = 3310

	// Add Rspamd config
	if pluginConfig["rspamd"] == nil {
		pluginConfig["rspamd"] = make(map[string]interface{})
	}
	pluginConfig["rspamd"]["host"] = "elemta-rspamd"
	pluginConfig["rspamd"]["port"] = 11334
	pluginConfig["rspamd"]["threshold"] = 5.0

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

func (s *Session) Handle() error {
	s.logger.Info("starting new session")
	s.write("220 elemta ESMTP ready\r\n")

	timeout := s.config.SessionTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	for {
		s.conn.SetReadDeadline(time.Now().Add(timeout))
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.Warn("session timeout, closing connection")
				s.write("421 4.4.2 Connection timed out\r\n")
				return err
			}
			s.logger.Error("read error", "error", err)
			return err
		}

		line = strings.TrimSpace(line)
		s.logger.Debug("received command", "command", line)

		// Parse the command verb (first word) and arguments separately
		parts := strings.Fields(line)
		if len(parts) == 0 {
			s.write("500 5.5.2 Invalid command\r\n")
			continue
		}

		// Upper case only the command verb for case-insensitive matching
		verb := strings.ToUpper(parts[0])

		switch {
		case verb == "QUIT":
			s.logger.Info("client quit")
			s.write("221 Bye\r\n")
			return nil

		case verb == "HELO" || verb == "EHLO":
			s.logger.Info("client hello", "command", line)
			s.write("250-" + s.config.Hostname + "\r\n")
			s.write("250-SIZE " + strconv.FormatInt(s.config.MaxSize, 10) + "\r\n")
			s.write("250-8BITMIME\r\n")
			s.write("250-PIPELINING\r\n")
			s.write("250-ENHANCEDSTATUSCODES\r\n")

			// Advertise STARTTLS if TLS is enabled, STARTTLS is enabled, and this connection isn't already using TLS
			if s.config.TLS != nil && s.config.TLS.Enabled && s.config.TLS.EnableStartTLS && !s.tls {
				s.write("250-STARTTLS\r\n")
			}

			// Advertise AUTH if authentication is enabled
			if s.authenticator != nil && s.authenticator.IsEnabled() {
				methods := s.authenticator.GetSupportedMethods()
				if len(methods) > 0 {
					authMethods := make([]string, len(methods))
					for i, method := range methods {
						authMethods[i] = string(method)
					}
					s.write("250-AUTH " + strings.Join(authMethods, " ") + "\r\n")
				}
			}

			s.write("250 HELP\r\n")

		case verb == "STARTTLS":
			if s.tls {
				s.write("503 5.5.1 TLS already active\r\n")
				continue
			}

			if s.config.TLS == nil || !s.config.TLS.Enabled {
				s.write("454 4.7.0 TLS not available\r\n")
				continue
			}

			if s.tlsManager == nil {
				s.write("454 4.7.0 TLS manager not available\r\n")
				continue
			}

			s.write("220 2.0.0 Ready to start TLS\r\n")

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
				s.write("535 5.7.8 Authentication failed\r\n")
			}

		case verb == "MAIL" || strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "mail from:"):
			// Check if authentication is required but not authenticated
			if s.authenticator != nil && s.authenticator.IsRequired() && !s.authenticated {
				s.write("530 5.7.0 Authentication required\r\n")
				continue
			}

			if s.state != INIT {
				s.write("503 5.5.1 Bad sequence of commands\r\n")
				continue
			}

			addr := extractAddress(line)
			if addr == "" {
				s.logger.Warn("invalid address in MAIL FROM", "command", line)
				s.write("501 5.5.4 Invalid address\r\n")
				continue
			}

			// Create a new message for this mail transaction
			s.message = NewMessage()
			s.message.from = addr
			s.state = MAIL
			s.logger.Info("mail from accepted", "from", addr)
			s.write("250 Ok\r\n")

		case verb == "RCPT" || strings.HasPrefix(line, "RCPT TO:") || strings.HasPrefix(line, "rcpt to:"):
			if s.state != MAIL && s.state != RCPT {
				s.write("503 5.5.1 Bad sequence of commands\r\n")
				continue
			}

			addr := extractAddress(line)
			if addr == "" {
				s.logger.Warn("invalid address in RCPT TO", "command", line)
				s.write("501 5.5.4 Invalid address\r\n")
				continue
			}

			s.message.to = append(s.message.to, addr)
			s.state = RCPT
			s.logger.Info("rcpt to accepted", "to", addr)
			s.write("250 Ok\r\n")

		case verb == "DATA":
			if s.state != RCPT {
				s.write("503 5.5.1 Bad sequence of commands\r\n")
				continue
			}

			s.write("354 Start mail input\r\n")
			data, err := s.readData()
			if err != nil {
				s.logger.Error("data read error", "error", err)
				s.write("451 4.3.0 Data read error\r\n")
				continue
			}

			s.message.data = data
			s.message.id = generateMessageID()

			// Save the message to the queue
			if err := s.saveMessage(); err != nil {
				s.logger.Error("save message error", "error", err)
				s.write("451 4.3.0 Error saving message\r\n")
				continue
			}

			// Set state to INIT but keep message data for XDEBUG
			s.state = INIT
			s.logger.Info("message accepted", "id", s.message.id)
			s.write("250 Ok: message queued\r\n")

		case verb == "RSET":
			// Reset message and state
			s.message = nil
			s.state = INIT
			s.write("250 2.0.0 Ok\r\n")

		case verb == "NOOP":
			s.write("250 2.0.0 Ok\r\n")

		case verb == "VRFY":
			// We don't support VRFY for security reasons
			s.write("252 2.1.5 Cannot verify user\r\n")

		case verb == "EXPN":
			// We don't support EXPN for security reasons
			s.write("252 2.1.5 Cannot expand list\r\n")

		case verb == "HELP":
			s.write("214 2.0.0 SMTP server ready\r\n")

		case strings.HasPrefix(verb, "XDEBUG"):
			s.logger.Info("xdebug command", "command", line)
			s.handleXDEBUG(line)

		default:
			s.logger.Warn("unknown command", "command", line)
			s.write("500 5.5.2 Command not recognized\r\n")
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
		s.write("250-Debug information:\r\n")

		// Generate a stable session ID for debugging
		sessionID, ok := s.Context.Get("session_id")
		if !ok || sessionID == nil {
			// If we don't have a session ID in the context, generate one and store it
			sessionID = uuid.New().String()
			s.Context.Set("session_id", sessionID)
		}

		s.write("250-Session ID: " + sessionID.(string) + "\r\n")
		s.write("250-Client IP: " + s.conn.RemoteAddr().String() + "\r\n")
		s.write("250-Hostname: " + s.config.Hostname + "\r\n")
		s.write("250-State: " + stateToString(s.state) + "\r\n")

		// Handle nil message case properly
		if s.message != nil {
			s.write("250-Mail From: " + s.message.from + "\r\n")
			s.write("250-Rcpt To: " + strings.Join(s.message.to, ", ") + "\r\n")
			s.write("250-Message ID: " + s.message.id + "\r\n")
			s.write("250-Message Size: " + strconv.Itoa(len(s.message.data)) + " bytes\r\n")

			// Add plugin scan information if available
			if s.builtinPlugins != nil && s.message.data != nil && len(s.message.data) > 0 {
				s.write("250-Plugin Scans:\r\n")

				// ClamAV virus scan results
				clean, infection, err := s.builtinPlugins.ScanForVirus(s.message.data, s.message.id)
				if err != nil {
					s.write("250-  ClamAV: Error - " + err.Error() + "\r\n")
				} else if !clean {
					s.write("250-  ClamAV: Virus detected - " + infection + "\r\n")
				} else {
					s.write("250-  ClamAV: Clean\r\n")
				}

				// Rspamd spam scan results
				clean, score, rules, err := s.builtinPlugins.ScanForSpam(s.message.data, s.message.id)
				if err != nil {
					s.write("250-  Rspamd: Error - " + err.Error() + "\r\n")
				} else if !clean {
					rulesList := ""
					if len(rules) > 0 {
						rulesList = " (" + strings.Join(rules, ", ") + ")"
					}
					s.write(fmt.Sprintf("250-  Rspamd: Spam detected - Score: %.2f%s\r\n", score, rulesList))
				} else {
					s.write(fmt.Sprintf("250-  Rspamd: Clean - Score: %.2f\r\n", score))
				}
			}
		} else {
			s.write("250-Mail From: <none>\r\n")
			s.write("250-Rcpt To: <none>\r\n")
			s.write("250-Message ID: <none>\r\n")
			s.write("250-Message Size: 0 bytes\r\n")
		}

		s.write("250 Context: " + s.Context.Dump() + "\r\n")
		return
	}

	parts = strings.SplitN(args, " ", 2)
	subCmd := strings.ToUpper(parts[0])

	switch subCmd {
	case "HELP":
		s.write("250-XDEBUG Commands:\r\n")
		s.write("250-XDEBUG - Show all debug information\r\n")
		s.write("250-XDEBUG CONTEXT - Show context information\r\n")
		s.write("250-XDEBUG CONTEXT GET <key> - Get a context value\r\n")
		s.write("250-XDEBUG CONTEXT SET <key> <value> - Set a context value\r\n")
		s.write("250-XDEBUG CONTEXT DELETE <key> - Delete a context value\r\n")
		s.write("250-XDEBUG CONTEXT CLEAR - Clear all context values\r\n")
		s.write("250 XDEBUG HELP - Show this help message\r\n")

	case "CONTEXT":
		if len(parts) == 1 {
			s.write("250-Context dump:\r\n")
			s.write("250 " + s.Context.Dump() + "\r\n")
			return
		}

		contextArgs := strings.TrimSpace(parts[1])
		contextParts := strings.SplitN(contextArgs, " ", 2)
		contextOp := strings.ToUpper(contextParts[0])

		switch contextOp {
		case "GET":
			if len(contextParts) < 2 {
				s.write("501 Missing key\r\n")
				return
			}
			key := strings.TrimSpace(contextParts[1])
			if value, ok := s.Context.Get(key); ok {
				s.write("250 " + key + " = " + value.(string) + "\r\n")
			} else {
				s.write("250 Key not found: " + key + "\r\n")
			}

		case "SET":
			if len(contextParts) < 2 {
				s.write("501 Missing key and value\r\n")
				return
			}
			keyValue := strings.SplitN(contextParts[1], " ", 2)
			if len(keyValue) < 2 {
				s.write("501 Missing value\r\n")
				return
			}
			key := strings.TrimSpace(keyValue[0])
			value := strings.TrimSpace(keyValue[1])
			s.Context.Set(key, value)
			s.write("250 Set " + key + " = " + value + "\r\n")

		case "DELETE":
			if len(contextParts) < 2 {
				s.write("501 Missing key\r\n")
				return
			}
			key := strings.TrimSpace(contextParts[1])
			s.Context.Delete(key)
			s.write("250 Deleted key: " + key + "\r\n")

		case "CLEAR":
			s.Context.Clear()
			s.write("250 Context cleared\r\n")

		default:
			s.write("501 Unknown context operation: " + contextOp + "\r\n")
		}

	default:
		s.write("501 Unknown XDEBUG command: " + subCmd + "\r\n")
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
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" {
			break
		}
		if len(buffer.Bytes()) > int(s.config.MaxSize) {
			return nil, errors.New("message too large")
		}
		buffer.WriteString(line)
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

	if len(s.config.AllowedRelays) > 0 {
		clientIP := s.conn.RemoteAddr().(*net.TCPAddr).IP.String()
		allowed := false
		for _, relay := range s.config.AllowedRelays {
			if relay == clientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			s.logger.Warn("relay denied", "ip", clientIP)
			return errors.New("relay not allowed")
		}
	}

	// Scan for viruses using our built-in plugin system
	if s.builtinPlugins != nil {
		s.logger.Debug("scanning message for viruses", "id", s.message.id)
		clean, infection, err := s.builtinPlugins.ScanForVirus(s.message.data, s.message.id)
		if err != nil {
			s.logger.Warn("virus scan failed", "error", err)
			if s.config.Antivirus != nil && s.config.Antivirus.RejectOnFailure {
				s.write("554 5.7.1 Unable to scan for viruses\r\n")
				return errors.New("virus scan failed")
			}
		} else if !clean {
			// Message contains virus
			s.logger.Warn("virus detected", "virus", infection)
			s.write(fmt.Sprintf("554 5.7.1 Message contains a virus: %s\r\n", infection))
			return errors.New("message contains virus")
		}
	}

	// Scan for spam using our built-in plugin system
	if s.builtinPlugins != nil {
		s.logger.Debug("scanning message for spam", "id", s.message.id)
		clean, score, rules, err := s.builtinPlugins.ScanForSpam(s.message.data, s.message.id)
		if err != nil {
			s.logger.Warn("spam scan failed", "error", err)
			if s.config.Antispam != nil && s.config.Antispam.RejectOnSpam {
				s.write("554 5.7.1 Unable to scan for spam\r\n")
				return errors.New("spam scan failed")
			}
		} else if !clean {
			// Message is spam
			s.logger.Warn("spam detected", "score", score, "rules", rules)
			rulesList := ""
			if len(rules) > 0 {
				rulesList = " (" + strings.Join(rules, ", ") + ")"
			}
			s.write(fmt.Sprintf("554 5.7.1 Message identified as spam (score %.2f)%s\r\n", score, rulesList))
			return errors.New("message is spam")
		} else {
			s.logger.Info("message is not spam", "score", score, "rules", rules)
		}
	}

	// Use the shared QueueManager to enqueue the message with normal priority
	if s.queueManager == nil {
		// Fallback to create a new one if we don't have a shared instance
		s.logger.Warn("no shared queue manager, creating new instance")
		s.queueManager = NewQueueManager(s.config)
	}

	if err := s.queueManager.EnqueueMessage(s.message, PriorityNormal); err != nil {
		s.logger.Error("failed to enqueue message", "error", err)
		return err
	}

	s.logger.Info("message queued successfully",
		"id", s.message.id,
		"priority", PriorityNormal)
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

// handleAuth handles the AUTH command
func (s *Session) handleAuth(cmd string) error {
	if s.authenticated {
		s.write("503 5.5.1 Already authenticated\r\n")
		return nil
	}

	if !s.authenticator.IsEnabled() {
		s.write("503 5.5.1 Authentication not enabled\r\n")
		return nil
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		s.write("501 5.5.4 Syntax error in parameters\r\n")
		return nil
	}

	method := AuthMethod(parts[1])
	switch method {
	case AuthMethodPlain:
		return s.handleAuthPlain(cmd)
	case AuthMethodLogin:
		return s.handleAuthLogin()
	default:
		s.write("504 5.5.4 Authentication mechanism not supported\r\n")
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
			s.write("501 5.5.4 Invalid AUTH PLAIN format\r\n")
			return nil
		}
	} else {
		// AUTH PLAIN
		s.write("334 \r\n")
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return err
		}
		authData = strings.TrimSpace(line)
		s.logger.Debug("AUTH PLAIN two-step mode", "authData", authData)
	}

	data, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		s.write("501 5.5.2 Invalid base64 encoding\r\n")
		return nil
	}

	s.logger.Debug("AUTH PLAIN decoded data",
		"hexBytes", hex.EncodeToString(data),
		"stringData", string(data))

	parts = strings.Split(string(data), "\x00")
	if len(parts) != 3 {
		s.write("501 5.5.2 Invalid PLAIN authentication data\r\n")
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
	s.write("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n")
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	usernameB64 := strings.TrimSpace(line)
	usernameBytes, err := base64.StdEncoding.DecodeString(usernameB64)
	if err != nil {
		s.write("501 5.5.2 Invalid base64 encoding\r\n")
		return nil
	}
	username := string(usernameBytes)

	// Send password challenge
	s.write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n")
	line, err = s.reader.ReadString('\n')
	if err != nil {
		return err
	}
	passwordB64 := strings.TrimSpace(line)
	passwordBytes, err := base64.StdEncoding.DecodeString(passwordB64)
	if err != nil {
		s.write("501 5.5.2 Invalid base64 encoding\r\n")
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

// authenticate performs the actual authentication
func (s *Session) authenticate(username, password string) error {
	// Get metrics instance
	metrics := GetMetrics()

	// Track authentication attempt
	metrics.AuthAttempts.Inc()

	// Perform authentication
	if s.authenticator == nil {
		metrics.AuthFailures.Inc()
		s.write("535 5.7.8 Authentication failed: authenticator not configured\r\n")
		return errors.New("authenticator not configured")
	}

	authenticated, err := s.authenticator.Authenticate(context.Background(), username, password)
	if err != nil {
		s.logger.Error("Authentication failed", "username", username, "error", err)
		metrics.AuthFailures.Inc()
		s.write("535 5.7.8 Authentication failed\r\n")
		return err
	}

	if !authenticated {
		s.logger.Warn("Authentication failed", "username", username)
		metrics.AuthFailures.Inc()
		s.write("535 5.7.8 Authentication credentials invalid\r\n")
		return fmt.Errorf("authentication failed for user %s", username)
	}

	s.authenticated = true
	s.username = username
	s.logger.Info("Authentication successful", "username", username)

	// Track successful authentication
	metrics.AuthSuccesses.Inc()

	// Send success message
	s.write("235 2.7.0 Authentication successful\r\n")
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
