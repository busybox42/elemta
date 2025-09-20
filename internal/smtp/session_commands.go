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
	Success   bool
	Response  string
	Error     error
	Duration  time.Duration
	Command   string
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
	// enhancedValidator would be added here if needed
}

// NewCommandHandler creates a new command handler
func NewCommandHandler(session *Session, state *SessionState, authHandler *AuthHandler, 
	conn net.Conn, config *Config, tlsManager TLSHandler, logger *slog.Logger) *CommandHandler {
	return &CommandHandler{
		session:     session,
		state:       state,
		authHandler: authHandler,
		logger:      logger.With("component", "session-commands"),
		conn:        conn,
		config:      config,
		tlsManager:  tlsManager,
		// enhancedValidator would be initialized here if needed
	}
}

// ProcessCommand processes an SMTP command with comprehensive validation and logging
func (ch *CommandHandler) ProcessCommand(ctx context.Context, line string) error {
	startTime := time.Now()
	
	// Update activity
	ch.state.UpdateActivity(ctx)
	
	// Validate input
	if err := ch.validateCommandInput(ctx, line); err != nil {
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

	// Set phase to init (allows MAIL command)
	if err := ch.state.SetPhase(ctx, PhaseInit); err != nil {
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

	// Set phase to init (allows MAIL command)
	if err := ch.state.SetPhase(ctx, PhaseInit); err != nil {
		return fmt.Errorf("451 4.3.0 Internal server error")
	}

	// Send EHLO response with extensions
	responses := []string{
		fmt.Sprintf("250-%s Hello %s", ch.config.Hostname, args),
		"250-SIZE " + strconv.FormatInt(ch.config.MaxSize, 10),
		"250-8BITMIME",
		"250-PIPELINING",
	}

	// Add STARTTLS if available and not already using TLS
	if ch.tlsManager != nil && !ch.state.IsTLSActive() {
		responses = append(responses, "250-STARTTLS")
	}

	// Add AUTH methods if TLS is active or not required
	if ch.state.IsTLSActive() || !ch.authHandler.securityManager.config.RequireTLSForPlain {
		authMethods := ch.authHandler.GetAuthMethodsString()
		if authMethods != "" {
			responses = append(responses, "250-AUTH "+authMethods)
		}
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

// HandleMAIL processes the MAIL FROM command
func (ch *CommandHandler) HandleMAIL(ctx context.Context, args string) error {
	ch.logger.DebugContext(ctx, "Processing MAIL command", "args", args)

	// Parse MAIL FROM command
	mailFrom, err := ch.parseMailFrom(ctx, args)
	if err != nil {
		return err
	}

	// Validate email address
	if err := ch.validateEmailAddress(ctx, mailFrom); err != nil {
		return fmt.Errorf("553 5.1.3 Invalid sender address: %s", mailFrom)
	}

	// Set mail from in state
	if err := ch.state.SetMailFrom(ctx, mailFrom); err != nil {
		return fmt.Errorf("503 5.5.1 %s", err.Error())
	}

	ch.logger.InfoContext(ctx, "MAIL FROM accepted",
		"mail_from", mailFrom,
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
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
		return fmt.Errorf("503 5.5.1 %s", err.Error())
	}

	ch.logger.InfoContext(ctx, "RCPT TO accepted",
		"rcpt_to", rcptTo,
		"total_recipients", ch.state.GetRecipientCount(),
		"authenticated", ch.state.IsAuthenticated(),
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
		return fmt.Errorf("503 5.5.1 %s", err.Error())
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

	return ch.session.write(fmt.Sprintf("221 2.0.0 %s closing connection", ch.config.Hostname))
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
		return ch.session.write("214 XDEBUG commands: STATE")
	}

	switch strings.ToUpper(parts[1]) {
	case "STATE":
		snapshot := ch.state.GetStateSnapshot()
		response := fmt.Sprintf("214-Session State: %+v", snapshot)
		return ch.session.write(response)
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

// validateCommandInput validates the command input for security
func (ch *CommandHandler) validateCommandInput(ctx context.Context, line string) error {
	// Basic length check
	if len(line) > 1000 {
		ch.logger.WarnContext(ctx, "Command line too long", "length", len(line))
		return fmt.Errorf("500 5.5.2 Line too long")
	}

	// Basic command validation
	// Enhanced validation would be implemented here
	if strings.Contains(strings.ToUpper(line), "DROP") || 
	   strings.Contains(strings.ToUpper(line), "DELETE") ||
	   strings.Contains(line, ";") {
		ch.logger.WarnContext(ctx, "Command validation failed",
			"line", line,
			"reason", "suspicious_content",
		)
		return fmt.Errorf("554 5.7.1 Command rejected: security violation")
	}

	return nil
}

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

// validateHostname validates a hostname
func (ch *CommandHandler) validateHostname(ctx context.Context, hostname string) error {
	if hostname == "" {
		return fmt.Errorf("empty hostname")
	}

	// Basic hostname validation
	if len(hostname) > 255 {
		return fmt.Errorf("hostname too long")
	}

	// Use regex for basic hostname validation
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		ch.logger.WarnContext(ctx, "Invalid hostname format", "hostname", hostname)
		return fmt.Errorf("invalid hostname format")
	}

	return nil
}

// parseMailFrom parses the MAIL FROM command
func (ch *CommandHandler) parseMailFrom(ctx context.Context, args string) (string, error) {
	if args == "" {
		return "", fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Handle MAIL FROM:<address>
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return "", fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Extract address
	addr := strings.TrimPrefix(args, "FROM:")
	addr = strings.TrimPrefix(addr, "from:")
	addr = strings.TrimSpace(addr)

	// Remove angle brackets if present
	if strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}

	return addr, nil
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

	// Check if recipient is in local domains
	if ch.isLocalDomain(recipient) {
		ch.logger.DebugContext(ctx, "Local domain recipient accepted", "recipient", recipient)
		return nil
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
	if !success {
		level = slog.LevelWarn
	}

	ch.logger.Log(ctx, level, "SMTP command processed",
		"command", command,
		"success", success,
		"response", response,
		"duration", duration,
		"phase", ch.state.GetPhase().String(),
		"authenticated", ch.state.IsAuthenticated(),
		"username", ch.state.GetUsername(),
	)
}
