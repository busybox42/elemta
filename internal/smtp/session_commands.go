// internal/smtp/session_commands.go
package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// CommandResult represents the result of a command execution
type CommandResult struct {
	Success  bool
	Response string
	Error    error
	Duration time.Duration
	Command  string
}

// CommandHandler manages SMTP command processing for a session
type CommandHandler struct {
	session         *Session
	state           *SessionState
	authHandler     *AuthHandler
	logger          *slog.Logger
	conn            net.Conn
	config          *Config
	tlsManager      TLSHandler
	securityManager *CommandSecurityManager
}

// NewCommandHandler creates a new command handler
func NewCommandHandler(session *Session, state *SessionState, authHandler *AuthHandler,
	conn net.Conn, config *Config, tlsManager TLSHandler, logger *slog.Logger) *CommandHandler {
	return &CommandHandler{
		session:         session,
		state:           state,
		authHandler:     authHandler,
		logger:          logger.With("component", "session-commands"),
		conn:            conn,
		config:          config,
		tlsManager:      tlsManager,
		securityManager: NewCommandSecurityManager(logger),
	}
}

// ProcessCommand processes an SMTP command with comprehensive validation and logging
func (ch *CommandHandler) ProcessCommand(ctx context.Context, line string) error {
	startTime := time.Now()

	// Update activity
	ch.state.UpdateActivity(ctx)

	// Validate input with comprehensive security checks
	if err := ch.securityManager.ValidateCommand(ctx, line); err != nil {
		ch.logCommandResult(ctx, line, false, err.Error(), time.Since(startTime))
		return err
	}

	// Parse command
	cmd, args := ch.parseCommand(line)

	// Check if command is allowed in current phase
	if !ch.state.CanAcceptCommand(ctx, cmd) {
		err := fmt.Errorf("503 5.5.1 Bad sequence of commands")
		ch.logCommandResult(ctx, line, false, err.Error(), time.Since(startTime))
		return err
	}

	// Route command to appropriate handler
	var err error
	switch strings.ToUpper(cmd) {
	case "HELO":
		err = ch.HandleHELO(ctx, args)
	case "EHLO":
		err = ch.HandleEHLO(ctx, args)
	case "MAIL":
		err = ch.HandleMAIL(ctx, args)
	case "RCPT":
		err = ch.HandleRCPT(ctx, args)
	case "DATA":
		err = ch.HandleDATA(ctx)
	case "RSET":
		err = ch.HandleRSET(ctx)
	case "NOOP":
		err = ch.HandleNOOP(ctx)
	case "QUIT":
		err = ch.HandleQUIT(ctx)
	case "AUTH":
		err = ch.HandleAUTH(ctx, line)
	case "STARTTLS":
		err = ch.HandleSTARTTLS(ctx)
	case "HELP":
		err = ch.HandleHELP(ctx, args)
	case "VRFY":
		err = ch.HandleVRFY(ctx, args)
	case "EXPN":
		err = ch.HandleEXPN(ctx, args)
	case "XDEBUG":
		err = ch.HandleXDEBUG(ctx, line)
	default:
		err = ch.HandleUnknown(ctx, cmd)
	}

	// Log command result
	success := err == nil
	response := ""
	if err != nil {
		response = err.Error()
	}
	ch.logCommandResult(ctx, line, success, response, time.Since(startTime))

	return err
}

// HandleHELO processes the HELO command
func (ch *CommandHandler) HandleHELO(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing HELO command", "args", args)

	if args == "" {
		return fmt.Errorf("501 5.0.0 HELO requires domain address")
	}

	// Validate hostname
	if err := ch.validateHostname(ctx, args); err != nil {
		return fmt.Errorf("501 5.0.0 Invalid hostname: %s", args)
	}

	// Set phase to mail (allows MAIL command)
	if err := ch.state.SetPhase(ctx, PhaseMail); err != nil {
		return fmt.Errorf("451 4.3.0 Internal server error")
	}

	return ch.session.write(fmt.Sprintf("250 %s Hello %s", ch.config.Hostname, args))
}

// HandleEHLO processes the EHLO command
func (ch *CommandHandler) HandleEHLO(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing EHLO command", "args", args)

	if args == "" {
		return fmt.Errorf("501 5.0.0 EHLO requires domain address")
	}

	// Validate hostname
	if err := ch.validateHostname(ctx, args); err != nil {
		return fmt.Errorf("501 5.0.0 Invalid hostname: %s", args)
	}

	// Set phase to mail (allows MAIL command)
	if err := ch.state.SetPhase(ctx, PhaseMail); err != nil {
		return fmt.Errorf("451 4.3.0 Internal server error")
	}

	// Send EHLO response with extensions
	// Note: PIPELINING is NOT advertised because the server processes commands
	// sequentially (one at a time) rather than batching pipelined commands.
	// Per RFC 2920, servers MUST NOT advertise PIPELINING unless they can
	// accept multiple commands before sending any responses.
	responses := []string{
		fmt.Sprintf("250-%s Hello %s", ch.config.Hostname, args),
		"250-SIZE " + strconv.FormatInt(ch.config.MaxSize, 10),
		"250-8BITMIME",
		"250-SMTPUTF8",
	}

	// Add STARTTLS if available and not already using TLS
	if ch.tlsManager != nil && !ch.state.IsTLSActive() {
		responses = append(responses, "250-STARTTLS")
	}

	// Add AUTH methods if authentication is enabled
	// Always advertise AUTH if auth is enabled but not required (for webmail clients)
	// Or if TLS is active or not required for PLAIN auth
	if ch.config.Auth != nil && ch.config.Auth.Enabled {
		if !ch.config.Auth.Required || ch.state.IsTLSActive() || !ch.authHandler.securityManager.config.RequireTLSForPlain {
			authMethods := ch.authHandler.GetAuthMethodsString()
			if authMethods != "" {
				responses = append(responses, "250-AUTH "+authMethods)
			}
		}
	}

	// Add XDEBUG in development mode
	if ch.config.DevMode {
		responses = append(responses, "250-XDEBUG")
	}

	// Add final response
	responses = append(responses, "250 HELP")

	// Send all responses
	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return fmt.Errorf("failed to write EHLO response: %w", err)
		}
	}

	return nil
}

// HandleMAIL processes the MAIL FROM command with RFC 1870 SIZE extension support
func (ch *CommandHandler) HandleMAIL(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing MAIL command", "args", args)

	// Check if authentication is required and user is not authenticated
	if ch.config.Auth != nil && ch.config.Auth.Enabled && ch.config.Auth.Required && !ch.state.IsAuthenticated() {
		return fmt.Errorf("530 5.7.0 Authentication required")
	}

	// Parse MAIL FROM command with SIZE parameter (RFC 1870)
	mailFrom, declaredSize, err := ch.parseMailFrom(ctx, args)
	if err != nil {
		return err
	}

	// Validate email address
	if err := ch.validateEmailAddress(ctx, mailFrom); err != nil {
		return fmt.Errorf("553 5.1.3 Invalid sender address: %s", mailFrom)
	}

	// RFC 1870: Check declared SIZE against server's maximum
	// If client declares a size, reject if it exceeds our limit
	if declaredSize > 0 && declaredSize > ch.config.MaxSize {
		ch.logger.WarnContext(ctx, "Message SIZE exceeds maximum",
			"declared_size", declaredSize,
			"max_size", ch.config.MaxSize,
			"mail_from", mailFrom,
			"remote_addr", ch.session.remoteAddr,
		)
		return fmt.Errorf("552 5.3.4 Message size exceeds fixed maximum message size (%d bytes declared, %d bytes maximum)",
			declaredSize, ch.config.MaxSize)
	}

	// Set mail from in state
	if err := ch.state.SetMailFrom(ctx, mailFrom); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to set MAIL FROM in session state",
			"mail_from", mailFrom,
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// Transition to RCPT phase to allow RCPT TO commands
	if err := ch.state.SetPhase(ctx, PhaseRcpt); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to transition to RCPT phase",
			"mail_from", mailFrom,
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	ch.logger.InfoContext(ctx, "mail_from_accepted",
		"event_type", "mail_from_accepted",
		"mail_from", mailFrom,
		"declared_size", declaredSize,
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
		"client_ip", ch.session.remoteAddr,
		"connection_id", ch.session.sessionID,
		"tls_active", ch.state.IsTLSActive(),
	)

	return ch.session.write("250 2.1.0 Sender OK")
}

// HandleRCPT processes the RCPT TO command
func (ch *CommandHandler) HandleRCPT(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing RCPT command", "args", args)

	// Parse RCPT TO command
	rcptTo, err := ch.parseRcptTo(ctx, args)
	if err != nil {
		return err
	}

	// Validate email address
	if err := ch.validateEmailAddress(ctx, rcptTo); err != nil {
		return fmt.Errorf("553 5.1.3 Invalid recipient address: %s", rcptTo)
	}

	// Check relay permissions
	if err := ch.checkRelayPermissions(ctx, rcptTo); err != nil {
		return err
	}

	// Add recipient to state
	if err := ch.state.AddRecipient(ctx, rcptTo); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to add recipient to session state",
			"recipient", rcptTo,
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	ch.logger.InfoContext(ctx, "rcpt_to_accepted",
		"event_type", "rcpt_to_accepted",
		"rcpt_to", rcptTo,
		"mail_from", ch.state.GetMailFrom(),
		"total_recipients", ch.state.GetRecipientCount(),
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
		"client_ip", ch.session.remoteAddr,
		"connection_id", ch.session.sessionID,
	)

	return ch.session.write("250 2.1.5 Recipient OK")
}

// HandleDATA processes the DATA command
func (ch *CommandHandler) HandleDATA(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing DATA command")

	// Check if we have recipients
	if ch.state.GetRecipientCount() == 0 {
		return fmt.Errorf("503 5.5.1 RCPT first")
	}

	// Set phase to data
	if err := ch.state.SetPhase(ctx, PhaseData); err != nil {
		ch.logger.ErrorContext(ctx, "Failed to transition to DATA phase",
			"mail_from", ch.state.GetMailFrom(),
			"recipient_count", ch.state.GetRecipientCount(),
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// Send data prompt
	if err := ch.session.write("354 Start mail input; end with <CRLF>.<CRLF>"); err != nil {
		return fmt.Errorf("failed to write data prompt: %w", err)
	}

	ch.logger.InfoContext(ctx, "DATA command accepted, ready for message data",
		"mail_from", ch.state.GetMailFrom(),
		"recipients", ch.state.GetRecipientCount(),
	)

	return nil
}

// HandleRSET processes the RSET command
func (ch *CommandHandler) HandleRSET(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing RSET command")

	// Reset session state
	ch.state.Reset(ctx)

	ch.logger.InfoContext(ctx, "Session state reset")

	return ch.session.write("250 2.0.0 Reset OK")
}

// HandleNOOP processes the NOOP command
func (ch *CommandHandler) HandleNOOP(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing NOOP command")
	return ch.session.write("250 2.0.0 OK")
}

// HandleQUIT processes the QUIT command
func (ch *CommandHandler) HandleQUIT(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing QUIT command")

	// Set phase to quit
	if err := ch.state.SetPhase(ctx, PhaseQuit); err != nil {
		ch.logger.WarnContext(ctx, "Failed to set QUIT phase", "error", err)
	}

	ch.logger.InfoContext(ctx, "Client initiated session termination")

	// Send the goodbye message
	if err := ch.session.write(fmt.Sprintf("221 2.0.0 %s closing connection", ch.config.Hostname)); err != nil {
		return err
	}

	// Give the client a moment to read the response before closing
	time.Sleep(100 * time.Millisecond)

	return nil
}

// HandleAUTH processes the AUTH command
func (ch *CommandHandler) HandleAUTH(ctx context.Context, cmd string) error {
	return ch.authHandler.HandleAuth(ctx, cmd)
}

// HandleSTARTTLS processes the STARTTLS command
func (ch *CommandHandler) HandleSTARTTLS(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing STARTTLS command")

	// Check if TLS is already active
	if ch.state.IsTLSActive() {
		return fmt.Errorf("454 4.7.0 TLS already active")
	}

	// Check if TLS is available
	if ch.tlsManager == nil {
		return fmt.Errorf("454 4.7.0 TLS not available")
	}

	// Send TLS ready response
	if err := ch.session.write("220 2.0.0 Ready to start TLS"); err != nil {
		return fmt.Errorf("failed to write TLS ready response: %w", err)
	}

	// Upgrade connection to TLS
	tlsConn, err := ch.tlsManager.WrapConnection(ch.conn)
	if err != nil {
		ch.logger.ErrorContext(ctx, "Failed to upgrade connection to TLS", "error", err)
		return fmt.Errorf("454 4.7.0 TLS handshake failed")
	}

	// Update connection and state
	ch.conn = tlsConn
	ch.session.conn = tlsConn
	ch.state.SetTLSActive(ctx, true)

	// Reset session state after TLS upgrade
	ch.state.Reset(ctx)

	ch.logger.InfoContext(ctx, "TLS connection established successfully")

	return nil
}

// HandleHELP processes the HELP command
func (ch *CommandHandler) HandleHELP(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing HELP command", "args", args)

	helpText := []string{
		"214-Commands supported:",
		"214-HELO EHLO MAIL RCPT DATA RSET NOOP QUIT",
		"214-AUTH STARTTLS HELP VRFY EXPN",
		"214 For more info use \"HELP <topic>\"",
	}

	for _, line := range helpText {
		if err := ch.session.write(line); err != nil {
			return fmt.Errorf("failed to write help text: %w", err)
		}
	}

	return nil
}

// HandleVRFY processes the VRFY command
func (ch *CommandHandler) HandleVRFY(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing VRFY command", "args", args)

	// VRFY is typically disabled for security reasons
	return ch.session.write("252 2.5.2 Cannot VRFY user, but will accept message")
}

// HandleEXPN processes the EXPN command
func (ch *CommandHandler) HandleEXPN(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing EXPN command", "args", args)

	// EXPN is typically disabled for security reasons
	return ch.session.write("502 5.5.1 EXPN not supported")
}

// HandleXDEBUG processes the XDEBUG command (development only)
func (ch *CommandHandler) HandleXDEBUG(ctx context.Context, cmd string) error {
	ch.logger.DebugContext(ctx, "Processing XDEBUG command", "command", cmd)

	// Only allow in development mode
	if !ch.config.DevMode {
		return fmt.Errorf("502 5.5.1 Command not recognized")
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		// Show available XDEBUG commands
		commands := []string{
			"214-XDEBUG commands:",
			"214-  CONTEXT    - Show complete connection context",
			"214-  STATE      - Show session state information",
			"214-  CONNECTION - Show connection details",
			"214-  CONFIG     - Show server configuration",
			"214-  MEMORY     - Show memory usage statistics",
			"214-  RESOURCES  - Show resource usage",
			"214-  AUTH       - Show authentication details",
			"214-  TLS        - Show TLS connection status",
			"214-  QUEUE      - Show queue information",
			"214 For more info use \"XDEBUG <command>\"",
		}
		for _, cmd := range commands {
			if err := ch.session.write(cmd); err != nil {
				return err
			}
		}
		return nil
	}

	switch strings.ToUpper(parts[1]) {
	case "CONTEXT":
		return ch.handleXDEBUGContext(ctx)
	case "STATE":
		return ch.handleXDEBUGState(ctx)
	case "CONNECTION":
		return ch.handleXDEBUGConnection(ctx)
	case "CONFIG":
		return ch.handleXDEBUGConfig(ctx)
	case "MEMORY":
		return ch.handleXDEBUGMemory(ctx)
	case "RESOURCES":
		return ch.handleXDEBUGResources(ctx)
	case "AUTH":
		return ch.handleXDEBUGAuth(ctx)
	case "TLS":
		return ch.handleXDEBUGTLS(ctx)
	case "QUEUE":
		return ch.handleXDEBUGQueue(ctx)
	default:
		return ch.session.write("214 Unknown XDEBUG command")
	}
}

// HandleUnknown processes unknown commands
func (ch *CommandHandler) HandleUnknown(ctx context.Context, cmd string) error {
	ch.logger.WarnContext(ctx, "Unknown command received", "command", cmd)
	return fmt.Errorf("502 5.5.1 Command not recognized")
}

// Helper methods

// parseCommand parses a command line into command and arguments
func (ch *CommandHandler) parseCommand(line string) (string, string) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	cmd := strings.ToUpper(parts[0])
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	return cmd, args
}

// validateHostname validates a hostname per RFC 5321 §4.1.3
func (ch *CommandHandler) validateHostname(ctx context.Context, hostname string) error {
	if hostname == "" {
		return fmt.Errorf("empty hostname")
	}

	// Basic hostname validation
	if len(hostname) > 255 {
		return fmt.Errorf("hostname too long")
	}

	// Check if it's an address literal [x.x.x.x] or [IPv6:...] (RFC 5321 section 4.1.3)
	if len(hostname) >= 2 && hostname[0] == '[' && hostname[len(hostname)-1] == ']' {
		return ch.validateAddressLiteral(ctx, hostname)
	}

	// Validate as domain name
	return ch.validateDomainName(ctx, hostname)
}

// validateAddressLiteral validates IPv4 and IPv6 address literals per RFC 5321 §4.1.3
func (ch *CommandHandler) validateAddressLiteral(ctx context.Context, literal string) error {
	// Extract content between brackets
	content := literal[1 : len(literal)-1]

	if content == "" {
		return fmt.Errorf("malformed address literal: empty brackets")
	}

	// Check for IPv6 literal format: [IPv6:address] (RFC 5321 §4.1.3)
	if len(content) >= 5 && strings.ToUpper(content[:5]) == "IPV6:" {
		ipv6Addr := content[5:] // Remove "IPv6:" or "IPV6:" prefix

		if ipv6Addr == "" {
			return fmt.Errorf("malformed IPv6 address literal: missing address after IPv6: prefix")
		}

		// Validate IPv6 address
		ip := net.ParseIP(ipv6Addr)
		if ip == nil {
			return fmt.Errorf("malformed IPv6 address literal: invalid IPv6 address")
		}

		// Ensure it's actually an IPv6 address (ParseIP accepts both IPv4 and IPv6)
		if ip.To4() != nil {
			return fmt.Errorf("malformed IPv6 address literal: address is IPv4, not IPv6")
		}

		ch.logger.DebugContext(ctx, "accepted IPv6 address literal", "hostname", literal)
		return nil
	}

	// Check for general tagged address literal format: [tag:address]
	// This includes other address types defined in RFC 5321
	if strings.Contains(content, ":") {
		parts := strings.SplitN(content, ":", 2)
		tag := strings.ToUpper(parts[0])

		// Only IPv6 is widely supported; other tags could be added here
		// For now, we accept any tagged format but log it
		ch.logger.DebugContext(ctx, "accepted tagged address literal",
			"hostname", literal,
			"tag", tag)
		return nil
	}

	// Assume IPv4 literal format: [192.0.2.1]
	ip := net.ParseIP(content)
	if ip == nil {
		return fmt.Errorf("malformed IPv4 address literal: invalid IP address")
	}

	// Ensure it's actually IPv4 (not IPv6)
	if ip.To4() == nil {
		return fmt.Errorf("malformed IPv4 address literal: address is not IPv4 format")
	}

	ch.logger.DebugContext(ctx, "accepted IPv4 address literal", "hostname", literal)
	return nil
}

// validateDomainName validates a domain name per RFC 1035 and RFC 5321
func (ch *CommandHandler) validateDomainName(ctx context.Context, domain string) error {
	// Domain name validation per RFC 1035
	// - Labels separated by dots
	// - Each label: 1-63 characters
	// - Labels must start with alphanumeric, end with alphanumeric
	// - Labels can contain hyphens in the middle
	// - Total length <= 255 characters
	if len(domain) > 255 {
		return fmt.Errorf("invalid domain name: exceeds maximum length")
	}

	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return fmt.Errorf("invalid domain name: empty domain")
	}

	// Validate each label
	// RFC 1035: Label must start with letter or digit, end with letter or digit,
	// and can contain hyphens in the middle
	labelRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("invalid domain name: empty label")
		}

		if len(label) > 63 {
			return fmt.Errorf("invalid domain name: label exceeds 63 characters")
		}

		if !labelRegex.MatchString(label) {
			return fmt.Errorf("invalid domain name: malformed label")
		}
	}

	return nil
}

// parseMailFrom parses the MAIL FROM command
// parseMailFrom parses the MAIL FROM command and extracts address and SIZE parameter
// Returns: (address, declaredSize, error)
// declaredSize is 0 if SIZE parameter is not specified
func (ch *CommandHandler) parseMailFrom(ctx context.Context, args string) (string, int64, error) {
	if args == "" {
		return "", 0, fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Handle MAIL FROM:<address>
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return "", 0, fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Extract address part
	addr := strings.TrimPrefix(args, "FROM:")
	addr = strings.TrimPrefix(addr, "from:")
	addr = strings.TrimSpace(addr)

	// Store the full parameter string for parsing ESMTP parameters
	params := addr

	// Handle angle brackets and ESMTP parameters
	// Format: <address> SIZE=xxx BODY=8BITMIME SMTPUTF8 etc.
	if strings.HasPrefix(addr, "<") {
		// Find the closing bracket
		endBracket := strings.Index(addr, ">")
		if endBracket > 0 {
			// Extract just the address inside the brackets
			addr = addr[1:endBracket]
			// Parameters are after the closing bracket
			if endBracket+1 < len(params) {
				params = strings.TrimSpace(params[endBracket+1:])
			} else {
				params = ""
			}
		} else {
			// Malformed, try to extract what we can
			addr = strings.TrimPrefix(addr, "<")
			params = ""
		}
	} else {
		// No angle brackets - address might have space-separated parameters
		// Take only the first space-separated token
		if spaceIdx := strings.Index(addr, " "); spaceIdx > 0 {
			params = strings.TrimSpace(addr[spaceIdx+1:])
			addr = addr[:spaceIdx]
		} else {
			params = ""
		}
	}

	// Parse ESMTP parameters (RFC 1870 SIZE, RFC 6531 SMTPUTF8, etc.)
	var declaredSize int64 = 0

	if params != "" {
		upperParams := strings.ToUpper(params)

		// Check for SMTPUTF8 parameter
		if strings.Contains(upperParams, "SMTPUTF8") {
			ch.state.SetSMTPUTF8(ctx, true)
			ch.logger.DebugContext(ctx, "SMTPUTF8 requested for this message")
		}

		// Parse SIZE parameter (RFC 1870)
		// Format: SIZE=<size-value>
		if strings.Contains(upperParams, "SIZE=") {
			// Extract SIZE parameter
			sizeIdx := strings.Index(upperParams, "SIZE=")
			if sizeIdx >= 0 {
				sizeParam := params[sizeIdx+5:] // Skip "SIZE="

				// SIZE value is terminated by space or end of string
				var sizeStr string
				if spaceIdx := strings.Index(sizeParam, " "); spaceIdx > 0 {
					sizeStr = sizeParam[:spaceIdx]
				} else {
					sizeStr = sizeParam
				}

				// Validate and parse SIZE value
				sizeValue, err := strconv.ParseInt(sizeStr, 10, 64)
				if err != nil {
					ch.logger.WarnContext(ctx, "Invalid SIZE parameter",
						"size_param", sizeStr,
						"error", err,
					)
					return "", 0, fmt.Errorf("501 5.5.4 Invalid SIZE parameter syntax")
				}

				// Validate SIZE is non-negative and reasonable
				if sizeValue < 0 {
					ch.logger.WarnContext(ctx, "Negative SIZE parameter",
						"size_value", sizeValue,
					)
					return "", 0, fmt.Errorf("501 5.5.4 SIZE parameter must be non-negative")
				}

				// RFC 1870: SIZE=0 is valid (means size is unknown)
				// Very large sizes (> 10GB) are suspicious
				if sizeValue > 10*1024*1024*1024 { // 10GB sanity check
					ch.logger.WarnContext(ctx, "Unreasonably large SIZE parameter",
						"size_value", sizeValue,
					)
					return "", 0, fmt.Errorf("552 5.3.4 SIZE parameter exceeds reasonable limit")
				}

				declaredSize = sizeValue
				ch.logger.DebugContext(ctx, "SIZE parameter parsed",
					"declared_size", declaredSize,
				)
			}
		}
	}

	return addr, declaredSize, nil
}

// parseRcptTo parses the RCPT TO command
func (ch *CommandHandler) parseRcptTo(ctx context.Context, args string) (string, error) {
	if args == "" {
		return "", fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Handle RCPT TO:<address>
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return "", fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Extract address
	addr := strings.TrimPrefix(args, "TO:")
	addr = strings.TrimPrefix(addr, "to:")
	addr = strings.TrimSpace(addr)

	// Remove angle brackets if present
	if strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}

	return addr, nil
}

// validateEmailAddress validates an email address
func (ch *CommandHandler) validateEmailAddress(ctx context.Context, addr string) error {
	// Allow empty address for null sender
	if addr == "" {
		return nil
	}

	// Basic length check
	if len(addr) > 320 { // RFC 5321 limit
		return fmt.Errorf("address too long")
	}

	// Basic email validation
	if !strings.Contains(addr, "@") || len(addr) < 3 {
		ch.logger.WarnContext(ctx, "Email validation failed",
			"address", addr,
			"reason", "invalid_format",
		)
		return fmt.Errorf("invalid email address format")
	}

	return nil
}

// checkRelayPermissions checks if relay is allowed for a recipient
func (ch *CommandHandler) checkRelayPermissions(ctx context.Context, recipient string) error {
	// If authenticated, allow relay
	if ch.state.IsAuthenticated() {
		ch.logger.DebugContext(ctx, "Relay allowed for authenticated user",
			"recipient", recipient,
			"username", ch.state.GetUsername(),
		)
		return nil
	}

	// Check if recipient is in local domains first
	if ch.isLocalDomain(recipient) {
		ch.logger.DebugContext(ctx, "Local domain recipient accepted", "recipient", recipient)
		return nil
	}

	// For external domains, require authentication (unless explicitly allowed)
	// If authentication is not required, only allow local domains, not external relay
	if ch.config.Auth != nil && ch.config.Auth.Enabled && !ch.config.Auth.Required {
		ch.logger.WarnContext(ctx, "External relay denied - authentication not required but recipient is external domain",
			"recipient", recipient,
		)
		return fmt.Errorf("554 5.7.1 Relay access denied")
	}

	// Check if relay is explicitly allowed
	if ch.isRelayAllowed(recipient) {
		ch.logger.DebugContext(ctx, "Relay explicitly allowed", "recipient", recipient)
		return nil
	}

	ch.logger.WarnContext(ctx, "Relay denied for recipient",
		"recipient", recipient,
		"authenticated", ch.state.IsAuthenticated(),
	)

	return fmt.Errorf("554 5.7.1 Relay access denied")
}

// isLocalDomain checks if a recipient is in a local domain
func (ch *CommandHandler) isLocalDomain(recipient string) bool {
	if ch.config.LocalDomains == nil {
		return false
	}

	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return false
	}

	domain := strings.ToLower(parts[1])
	for _, localDomain := range ch.config.LocalDomains {
		if strings.ToLower(localDomain) == domain {
			return true
		}
	}

	return false
}

// isRelayAllowed checks if relay is allowed for a recipient
func (ch *CommandHandler) isRelayAllowed(recipient string) bool {
	// This would typically check against relay rules
	// For now, return false (no relay allowed without authentication)
	return false
}

// logCommandResult logs the result of a command execution
func (ch *CommandHandler) logCommandResult(ctx context.Context, command string, success bool, response string, duration time.Duration) {
	level := slog.LevelInfo
	var eventType string
	if !success {
		level = slog.LevelWarn
		eventType = "rejection"
		// Check for tempfail (4xx)
		if len(response) >= 3 && response[0] == '4' {
			eventType = "tempfail"
		}
	} else {
		// For successful commands, we can use specific event types if needed,
		// or leave empty to be categorized as system/info
		if strings.HasPrefix(strings.ToUpper(command), "MAIL FROM") {
			eventType = "mail_from_accepted"
		} else if strings.HasPrefix(strings.ToUpper(command), "RCPT TO") {
			eventType = "rcpt_to_accepted"
		} else if strings.HasPrefix(strings.ToUpper(command), "DATA") {
			eventType = "data_accepted"
		}
	}

	// Sanitize command for safe logging
	sanitizedCommand := ch.securityManager.SanitizeCommand(command)

	ch.logger.Log(ctx, level, "SMTP command processed",
		"event_type", eventType,
		"command", sanitizedCommand,
		"success", success,
		"response", response,
		"duration", duration,
		"phase", ch.state.GetPhase().String(),
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
	)
}

// XDEBUG subcommand handlers

// handleXDEBUGContext shows complete connection context (like Momentum's XDUMPCONTEXT)
func (ch *CommandHandler) handleXDEBUGContext(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG CONTEXT DUMP ===",
		"214-Connection Information:",
		fmt.Sprintf("214-  Remote Address: %s", ch.session.remoteAddr),
		fmt.Sprintf("214-  Session ID: %s", ch.session.sessionID),
		fmt.Sprintf("214-  Connected At: %s", time.Now().Format("2006-01-02 15:04:05")),
		fmt.Sprintf("214-  Session Duration: %v", ch.state.GetSessionDuration()),
		fmt.Sprintf("214-  Idle Time: %v", ch.state.GetIdleTime()),
		"214-Session State:",
		fmt.Sprintf("214-  Current Phase: %s", ch.state.GetPhase().String()),
		fmt.Sprintf("214-  Mail From: %s", ch.state.GetMailFrom()),
		fmt.Sprintf("214-  Recipients: %d", ch.state.GetRecipientCount()),
		fmt.Sprintf("214-  Data Size: %d bytes", ch.state.GetDataSize()),
		fmt.Sprintf("214-  Message Count: %d", ch.state.GetMessageCount()),
		"214-Authentication:",
		fmt.Sprintf("214-  Authenticated: %t", ch.state.IsAuthenticated()),
		fmt.Sprintf("214-  Username: %s", ch.state.GetUsername()),
		fmt.Sprintf("214-  Auth Attempts: %d", ch.state.GetAuthAttempts()),
		fmt.Sprintf("214-  Last Auth Attempt: %s", ch.state.GetLastAuthAttempt().Format("2006-01-02 15:04:05")),
		"214-TLS Status:",
		fmt.Sprintf("214-  TLS Active: %t", ch.state.IsTLSActive()),
		"214-Traffic Statistics:",
	}

	sent, received := ch.state.GetTrafficStats()
	responses = append(responses, fmt.Sprintf("214-  Bytes Sent: %d", sent))
	responses = append(responses, fmt.Sprintf("214-  Bytes Received: %d", received))

	// Add error information
	errors := ch.state.GetErrors()
	responses = append(responses, fmt.Sprintf("214-  Error Count: %d", len(errors)))

	responses = append(responses, "214-=== END CONTEXT DUMP ===")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGState shows detailed session state information
func (ch *CommandHandler) handleXDEBUGState(ctx context.Context) error {
	snapshot := ch.state.GetStateSnapshot()

	responses := []string{
		"214-=== XDEBUG STATE ===",
	}

	for key, value := range snapshot {
		responses = append(responses, fmt.Sprintf("214-  %s: %v", key, value))
	}

	responses = append(responses, "214-=== END STATE ===")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGConnection shows connection details
func (ch *CommandHandler) handleXDEBUGConnection(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG CONNECTION ===",
		fmt.Sprintf("214-  Remote Address: %s", ch.session.remoteAddr),
		fmt.Sprintf("214-  Session ID: %s", ch.session.sessionID),
		fmt.Sprintf("214-  Session Duration: %v", ch.state.GetSessionDuration()),
		fmt.Sprintf("214-  Idle Time: %v", ch.state.GetIdleTime()),
		fmt.Sprintf("214-  Connected At: %s", time.Now().Format("2006-01-02 15:04:05")),
		"214-=== END CONNECTION ===",
	}

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGConfig shows server configuration
func (ch *CommandHandler) handleXDEBUGConfig(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG CONFIG ===",
		fmt.Sprintf("214-  Hostname: %s", ch.config.Hostname),
		fmt.Sprintf("214-  Listen Address: %s", ch.config.ListenAddr),
		fmt.Sprintf("214-  Queue Directory: %s", ch.config.QueueDir),
		fmt.Sprintf("214-  Max Message Size: %d bytes", ch.config.MaxSize),
		fmt.Sprintf("214-  Development Mode: %t", ch.config.DevMode),
		fmt.Sprintf("214-  Local Domains: %v", ch.config.LocalDomains),
		fmt.Sprintf("214-  Max Workers: %d", ch.config.MaxWorkers),
		fmt.Sprintf("214-  Max Retries: %d", ch.config.MaxRetries),
		"214-=== END CONFIG ===",
	}

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGMemory shows memory usage statistics
func (ch *CommandHandler) handleXDEBUGMemory(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG MEMORY ===",
		fmt.Sprintf("214-  Goroutines: %d", runtime.NumGoroutine()),
	}

	// Get current memory stats directly from runtime (non-blocking)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	responses = append(responses, fmt.Sprintf("214-  Memory Usage: %d bytes", m.Alloc))
	responses = append(responses, fmt.Sprintf("214-  Memory System: %d bytes", m.Sys))
	responses = append(responses, fmt.Sprintf("214-  Memory Heap: %d bytes", m.HeapAlloc))
	responses = append(responses, fmt.Sprintf("214-  Memory Stack: %d bytes", m.StackInuse))
	responses = append(responses, fmt.Sprintf("214-  GC Collections: %d", m.NumGC))
	responses = append(responses, fmt.Sprintf("214-  Last GC: %s", time.Unix(0, int64(m.LastGC)).Format("2006-01-02 15:04:05")))

	// Try to get memory manager config safely (non-blocking)
	if ch.session.resourceManager != nil && ch.session.resourceManager.memoryManager != nil {
		// Access config directly without calling methods that might lock
		mm := ch.session.resourceManager.memoryManager
		responses = append(responses, fmt.Sprintf("214-  Memory Limit: %d bytes", mm.config.MaxMemoryUsage))
		responses = append(responses, fmt.Sprintf("214-  Warning Threshold: %.2f%%", mm.config.MemoryWarningThreshold*100))
		responses = append(responses, fmt.Sprintf("214-  Critical Threshold: %.2f%%", mm.config.MemoryCriticalThreshold*100))
		responses = append(responses, fmt.Sprintf("214-  Max Goroutines: %d", mm.config.MaxGoroutines))
	}

	responses = append(responses, "214-=== END MEMORY ===")
	responses = append(responses, "214 OK")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGResources shows resource usage
func (ch *CommandHandler) handleXDEBUGResources(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG RESOURCES ===",
	}

	// Get basic resource information safely
	responses = append(responses, fmt.Sprintf("214-  Goroutines: %d", runtime.NumGoroutine()))

	// Try to get resource manager info safely (non-blocking)
	if ch.session.resourceManager != nil {
		rm := ch.session.resourceManager

		// Access atomic values directly (non-blocking)
		responses = append(responses, fmt.Sprintf("214-  Active Connections: %d", atomic.LoadInt32(&rm.activeConnections)))
		responses = append(responses, fmt.Sprintf("214-  Total Requests: %d", atomic.LoadInt64(&rm.totalRequests)))
		responses = append(responses, fmt.Sprintf("214-  Rejected Requests: %d", atomic.LoadInt64(&rm.rejectedRequests)))

		// Calculate rejection rate safely
		total := atomic.LoadInt64(&rm.totalRequests)
		rejected := atomic.LoadInt64(&rm.rejectedRequests)
		if total > 0 {
			rejectionRate := float64(rejected) / float64(total) * 100
			responses = append(responses, fmt.Sprintf("214-  Rejection Rate: %.2f%%", rejectionRate))
		} else {
			responses = append(responses, "214-  Rejection Rate: 0.00%")
		}

		// Get pool stats safely
		if rm.goroutinePool != nil {
			pool := rm.goroutinePool
			availableWorkers := len(pool.workers)
			pendingTasks := len(pool.tasks)
			utilization := float64(pool.maxWorkers-availableWorkers) / float64(pool.maxWorkers) * 100

			responses = append(responses, fmt.Sprintf("214-  Max Workers: %d", pool.maxWorkers))
			responses = append(responses, fmt.Sprintf("214-  Available Workers: %d", availableWorkers))
			responses = append(responses, fmt.Sprintf("214-  Pending Tasks: %d", pendingTasks))
			responses = append(responses, fmt.Sprintf("214-  Pool Utilization: %.2f%%", utilization))
		}

		// Get connection limits safely
		if rm.limits != nil {
			responses = append(responses, fmt.Sprintf("214-  Max Connections: %d", rm.limits.MaxConnections))
			responses = append(responses, fmt.Sprintf("214-  Max Connections Per IP: %d", rm.limits.MaxConnectionsPerIP))
			responses = append(responses, fmt.Sprintf("214-  Connection Timeout: %v", rm.limits.ConnectionTimeout))
			responses = append(responses, fmt.Sprintf("214-  Session Timeout: %v", rm.limits.SessionTimeout))
		}
	}

	responses = append(responses, "214-=== END RESOURCES ===")
	responses = append(responses, "214 OK")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGAuth shows authentication details
func (ch *CommandHandler) handleXDEBUGAuth(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG AUTH ===",
		fmt.Sprintf("214-  Authenticated: %t", ch.state.IsAuthenticated()),
		fmt.Sprintf("214-  Username: %s", ch.state.GetUsername()),
		fmt.Sprintf("214-  Auth Attempts: %d", ch.state.GetAuthAttempts()),
		fmt.Sprintf("214-  Last Auth Attempt: %s", ch.state.GetLastAuthAttempt().Format("2006-01-02 15:04:05")),
	}

	if ch.config.Auth != nil {
		responses = append(responses, fmt.Sprintf("214-  Auth Enabled: %t", ch.config.Auth.Enabled))
		responses = append(responses, fmt.Sprintf("214-  Auth Required: %t", ch.config.Auth.Required))
		responses = append(responses, fmt.Sprintf("214-  Auth DataSource Type: %s", ch.config.Auth.DataSourceType))
		responses = append(responses, fmt.Sprintf("214-  Auth DataSource Host: %s", ch.config.Auth.DataSourceHost))
		responses = append(responses, fmt.Sprintf("214-  Auth DataSource Port: %d", ch.config.Auth.DataSourcePort))
	}

	responses = append(responses, "214-=== END AUTH ===")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGTLS shows TLS connection status
func (ch *CommandHandler) handleXDEBUGTLS(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG TLS ===",
		fmt.Sprintf("214-  TLS Active: %t", ch.state.IsTLSActive()),
	}

	if ch.config.TLS != nil {
		responses = append(responses, fmt.Sprintf("214-  TLS Enabled: %t", ch.config.TLS.Enabled))
		responses = append(responses, fmt.Sprintf("214-  STARTTLS Enabled: %t", ch.config.TLS.EnableStartTLS))
		responses = append(responses, fmt.Sprintf("214-  Cert File: %s", ch.config.TLS.CertFile))
		responses = append(responses, fmt.Sprintf("214-  Key File: %s", ch.config.TLS.KeyFile))
	}

	responses = append(responses, "214-=== END TLS ===")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}

// handleXDEBUGQueue shows queue information
func (ch *CommandHandler) handleXDEBUGQueue(ctx context.Context) error {
	responses := []string{
		"214-=== XDEBUG QUEUE ===",
		fmt.Sprintf("214-  Queue Directory: %s", ch.config.QueueDir),
		fmt.Sprintf("214-  Queue Processor Enabled: %t", ch.config.QueueProcessorEnabled),
		fmt.Sprintf("214-  Queue Process Interval: %d seconds", ch.config.QueueProcessInterval),
		fmt.Sprintf("214-  Queue Workers: %d", ch.config.QueueWorkers),
	}

	if ch.config.Delivery != nil {
		responses = append(responses, fmt.Sprintf("214-  Delivery Mode: %s", ch.config.Delivery.Mode))
		responses = append(responses, fmt.Sprintf("214-  Delivery Host: %s", ch.config.Delivery.Host))
		responses = append(responses, fmt.Sprintf("214-  Delivery Port: %d", ch.config.Delivery.Port))
		responses = append(responses, fmt.Sprintf("214-  Delivery Timeout: %d seconds", ch.config.Delivery.Timeout))
		responses = append(responses, fmt.Sprintf("214-  Max Retries: %d", ch.config.Delivery.MaxRetries))
	}

	responses = append(responses, "214-=== END QUEUE ===")

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}
