// internal/smtp/session_commands.go
package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
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
	case "BDAT":
		err = ch.HandleBDAT(ctx, args)
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
// RFC 5321 §4.1.1.1 - HELO command: Client identifies itself with domain name
// RFC 5321 §4.1.3 - Hostname validation requirements
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
// RFC 5321 §4.1.1.1 - EHLO command: Extended HELO for ESMTP capabilities
// RFC 5321 §4.1.1.1 - Server responds with multi-line 250 response listing capabilities
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
		"250-ENHANCEDSTATUSCODES",
		"250-CHUNKING",
		"250-DSN",
	}

	// Add STARTTLS if available and not already using TLS
	if ch.tlsManager != nil && !ch.state.IsTLSActive() {
		responses = append(responses, "250-STARTTLS")
	}

	// Add REQUIRETLS only when TLS is active (RFC 8689)
	if ch.state.IsTLSActive() {
		responses = append(responses, "250-REQUIRETLS")
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

	// Store declared size for buffer pre-allocation optimization
	ch.state.SetDeclaredSize(ctx, declaredSize)

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

	// Validate data command acceptance to prevent desynchronization attacks
	if !ch.state.CanAcceptDataCommand(ctx, "DATA") {
		ch.logger.WarnContext(ctx, "DATA command rejected - mode conflict or invalid phase",
			"event_type", "desynchronization_attempt",
			"current_mode", ch.state.GetDataTransferMode().String(),
			"current_phase", ch.state.GetPhase().String(),
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// Set data transfer mode to DATA
	if err := ch.state.SetDataTransferMode(ctx, DataModeDATA); err != nil {
		ch.logger.WarnContext(ctx, "Failed to set data transfer mode",
			"error", err,
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
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
		"data_transfer_mode", ch.state.GetDataTransferMode().String(),
	)

	return nil
}

// HandleBDAT processes the BDAT command (RFC 3030 CHUNKING extension)
func (ch *CommandHandler) HandleBDAT(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing BDAT command", "args", args)

	// Check if we have recipients
	if ch.state.GetRecipientCount() == 0 {
		return fmt.Errorf("503 5.5.1 RCPT first")
	}

	// Parse args: "<size> [LAST]"
	parts := strings.Fields(args)
	if len(parts) == 0 || len(parts) > 2 {
		return fmt.Errorf("501 5.5.4 Syntax: BDAT <chunk-size> [LAST]")
	}

	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || size < 0 {
		return fmt.Errorf("501 5.5.4 Invalid chunk size")
	}

	isLast := len(parts) == 2 && strings.EqualFold(parts[1], "LAST")
	if len(parts) == 2 && !isLast {
		return fmt.Errorf("501 5.5.4 Syntax: BDAT <chunk-size> [LAST]")
	}

	// Validate data command acceptance to prevent desynchronization attacks
	if !ch.state.CanAcceptDataCommand(ctx, "BDAT") {
		ch.logger.WarnContext(ctx, "BDAT command rejected - mode conflict or invalid phase",
			"event_type", "desynchronization_attempt",
			"current_mode", ch.state.GetDataTransferMode().String(),
			"current_phase", ch.state.GetPhase().String(),
		)
		return fmt.Errorf("503 5.5.1 Bad sequence of commands")
	}

	// First chunk: set data transfer mode to BDAT
	if ch.state.GetDataTransferMode() == DataModeNone {
		if err := ch.state.SetDataTransferMode(ctx, DataModeBDAT); err != nil {
			return fmt.Errorf("503 5.5.1 Bad sequence of commands")
		}
	}

	// Read the chunk data
	if err := ch.session.dataHandler.ReadBDATChunk(ctx, size); err != nil {
		// On error, reset BDAT state
		ch.session.dataHandler.ResetBDAT()
		ch.state.ClearDataTransferMode(ctx)
		return err
	}

	if isLast {
		// Process the complete message
		if err := ch.session.dataHandler.ProcessBDATMessage(ctx); err != nil {
			ch.state.ClearDataTransferMode(ctx)
			return err
		}

		if err := ch.session.write("250 2.0.0 Message accepted for delivery"); err != nil {
			return fmt.Errorf("failed to write BDAT response: %w", err)
		}
		return nil
	}

	// Intermediate chunk: acknowledge receipt
	if err := ch.session.write(fmt.Sprintf("250 2.0.0 %d bytes received", size)); err != nil {
		return fmt.Errorf("failed to write BDAT response: %w", err)
	}
	return nil
}

// HandleRSET processes the RSET command
func (ch *CommandHandler) HandleRSET(ctx context.Context) error {
	ch.logger.DebugContext(ctx, "Processing RSET command")

	// Reset session state
	ch.state.Reset(ctx)

	// Clear any in-progress BDAT data
	ch.session.dataHandler.ResetBDAT()

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

	// Extract address part (case-insensitive removal of "FROM:")
	addr := args[5:] // Skip "FROM:" or "from:" or any case variation (already validated above)
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

	// Parse ESMTP parameters (RFC 1870 SIZE, RFC 6531 SMTPUTF8, RFC 3461 DSN, RFC 8689 REQUIRETLS)
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

		// Parse DSN parameters (RFC 3461)
		dsnParams := &DSNParams{}
		hasDSN := false

		// Parse RET parameter (RFC 3461 Section 4.3)
		if strings.Contains(upperParams, "RET=") {
			retIdx := strings.Index(upperParams, "RET=")
			retParam := upperParams[retIdx+4:]
			if spaceIdx := strings.Index(retParam, " "); spaceIdx > 0 {
				retParam = retParam[:spaceIdx]
			}
			switch retParam {
			case "FULL":
				dsnParams.Return = DSNReturnFull
				hasDSN = true
			case "HDRS":
				dsnParams.Return = DSNReturnHeaders
				hasDSN = true
			default:
				return "", 0, fmt.Errorf("501 5.5.4 Invalid RET parameter: must be FULL or HDRS")
			}
		}

		// Parse ENVID parameter (RFC 3461 Section 4.4)
		if strings.Contains(upperParams, "ENVID=") {
			envIdx := strings.Index(upperParams, "ENVID=")
			envParam := params[envIdx+6:] // Use original case for ENVID value
			if spaceIdx := strings.Index(envParam, " "); spaceIdx > 0 {
				envParam = envParam[:spaceIdx]
			}
			if len(envParam) > 100 {
				return "", 0, fmt.Errorf("501 5.5.4 ENVID parameter too long (max 100 characters)")
			}
			dsnParams.EnvID = envParam
			hasDSN = true
		}

		if hasDSN {
			ch.state.SetDSNParams(ctx, dsnParams)
		}

		// Parse REQUIRETLS parameter (RFC 8689)
		if strings.Contains(upperParams, "REQUIRETLS") {
			if !ch.state.IsTLSActive() {
				return "", 0, fmt.Errorf("530 5.7.4 REQUIRETLS requires an active TLS connection")
			}
			ch.state.SetRequireTLS(ctx, true)
			ch.logger.DebugContext(ctx, "REQUIRETLS requested for this message")
		}
	}

	return addr, declaredSize, nil
}

// parseRcptTo parses the RCPT TO command with DSN parameters (RFC 3461)
func (ch *CommandHandler) parseRcptTo(ctx context.Context, args string) (string, error) {
	if args == "" {
		return "", fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Handle RCPT TO:<address>
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return "", fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Extract address (case-insensitive removal of "TO:")
	addr := args[3:] // Skip "TO:" or "to:" or any case variation (already validated above)
	addr = strings.TrimSpace(addr)

	// Extract ESMTP parameters after closing bracket
	var params string
	if strings.HasPrefix(addr, "<") {
		endBracket := strings.Index(addr, ">")
		if endBracket > 0 {
			if endBracket+1 < len(addr) {
				params = strings.TrimSpace(addr[endBracket+1:])
			}
			addr = addr[1:endBracket]
		} else {
			addr = strings.TrimPrefix(addr, "<")
		}
	} else {
		if spaceIdx := strings.Index(addr, " "); spaceIdx > 0 {
			params = strings.TrimSpace(addr[spaceIdx+1:])
			addr = addr[:spaceIdx]
		}
	}

	// Parse DSN recipient parameters (RFC 3461)
	if params != "" {
		upperParams := strings.ToUpper(params)
		rcptDSN := &DSNRecipientParams{}
		hasDSN := false

		// Parse NOTIFY parameter (RFC 3461 Section 4.1)
		if strings.Contains(upperParams, "NOTIFY=") {
			notifyIdx := strings.Index(upperParams, "NOTIFY=")
			notifyParam := upperParams[notifyIdx+7:]
			if spaceIdx := strings.Index(notifyParam, " "); spaceIdx > 0 {
				notifyParam = notifyParam[:spaceIdx]
			}

			notifyValues := strings.Split(notifyParam, ",")
			var notifyTypes []DSNNotifyType
			hasNever := false
			for _, v := range notifyValues {
				v = strings.TrimSpace(v)
				switch v {
				case "NEVER":
					hasNever = true
					notifyTypes = append(notifyTypes, DSNNotifyNever)
				case "SUCCESS":
					notifyTypes = append(notifyTypes, DSNNotifySuccess)
				case "FAILURE":
					notifyTypes = append(notifyTypes, DSNNotifyFailure)
				case "DELAY":
					notifyTypes = append(notifyTypes, DSNNotifyDelay)
				default:
					return "", fmt.Errorf("501 5.5.4 Invalid NOTIFY value: %s", v)
				}
			}
			// NEVER must be used alone
			if hasNever && len(notifyTypes) > 1 {
				return "", fmt.Errorf("501 5.5.4 NOTIFY=NEVER must not be combined with other values")
			}
			rcptDSN.Notify = notifyTypes
			hasDSN = true
		}

		// Parse ORCPT parameter (RFC 3461 Section 4.2)
		if strings.Contains(upperParams, "ORCPT=") {
			orcptIdx := strings.Index(upperParams, "ORCPT=")
			orcptParam := params[orcptIdx+6:] // Use original case
			if spaceIdx := strings.Index(orcptParam, " "); spaceIdx > 0 {
				orcptParam = orcptParam[:spaceIdx]
			}
			rcptDSN.ORCPT = orcptParam
			hasDSN = true
		}

		if hasDSN {
			ch.state.SetDSNRecipientParams(ctx, addr, rcptDSN)
		}
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

	// Basic email validation - must have @ and both local-part and domain
	atIndex := strings.Index(addr, "@")
	if atIndex == -1 || atIndex == 0 || atIndex == len(addr)-1 {
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
		ch.logger.InfoContext(ctx, "Relay allowed for authenticated user",
			"recipient", recipient,
			"username", ch.state.GetUsername(),
		)
		return nil
	}

	// Check if recipient is in local domains first
	if ch.isLocalDomain(ctx, recipient) {
		ch.logger.InfoContext(ctx, "Local domain recipient accepted", "recipient", recipient)
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
func (ch *CommandHandler) isLocalDomain(ctx context.Context, recipient string) bool {
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
	responses = append(responses, "214 OK")

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
	responses = append(responses, "214 OK")

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
		"214 OK",
	}

	for _, response := range responses {
		if err := ch.session.write(response); err != nil {
			return err
		}
	}
	return nil
}
