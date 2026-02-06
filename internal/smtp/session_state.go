// internal/smtp/session_state.go
package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// SMTPPhase represents the current phase of the SMTP session
type SMTPPhase int

const (
	PhaseInit SMTPPhase = iota
	PhaseMail
	PhaseRcpt
	PhaseData
	PhaseAuth
	PhaseTLS
	PhaseQuit
)

// String returns the string representation of SMTPPhase
func (p SMTPPhase) String() string {
	switch p {
	case PhaseInit:
		return "INIT"
	case PhaseMail:
		return "MAIL"
	case PhaseRcpt:
		return "RCPT"
	case PhaseData:
		return "DATA"
	case PhaseAuth:
		return "AUTH"
	case PhaseTLS:
		return "TLS"
	case PhaseQuit:
		return "QUIT"
	default:
		return "UNKNOWN"
	}
}

// DataTransferMode represents the current data transfer mode for desynchronization attack prevention
type DataTransferMode int

const (
	DataModeNone DataTransferMode = iota
	DataModeDATA
	DataModeBDAT
	DataModeBURL
)

// String returns the string representation of DataTransferMode
func (m DataTransferMode) String() string {
	switch m {
	case DataModeNone:
		return "NONE"
	case DataModeDATA:
		return "DATA"
	case DataModeBDAT:
		return "BDAT"
	case DataModeBURL:
		return "BURL"
	default:
		return "UNKNOWN"
	}
}

// SessionState manages the state of an SMTP session with thread safety
type SessionState struct {
	mu                 sync.RWMutex
	phase              SMTPPhase
	authenticated      bool
	username           string
	mailFrom           string
	rcptTo             []string
	dataSize           int64
	declaredSize       int64 // SIZE parameter from MAIL FROM command (RFC 1870)
	tlsActive          bool
	smtputf8           bool
	authAttempts       int
	lastAuthAttempt    time.Time
	sessionStartTime   time.Time
	lastActivityTime   time.Time
	messageCount       int64
	bytesSent          int64
	bytesReceived      int64
	errors             []error
	logger             *slog.Logger
	dataTransferMode   DataTransferMode // Track data transfer mode to prevent desynchronization attacks
	dsnParams          *DSNParams
	dsnRecipientParams map[string]*DSNRecipientParams
	requireTLS         bool
}

// NewSessionState creates a new session state manager
func NewSessionState(logger *slog.Logger) *SessionState {
	now := time.Now()
	return &SessionState{
		phase:            PhaseInit,
		authenticated:    false,
		rcptTo:           make([]string, 0),
		sessionStartTime: now,
		lastActivityTime: now,
		logger:           logger.With("component", "session-state"),
		dataTransferMode: DataModeNone,
	}
}

// GetPhase returns the current SMTP phase (thread-safe)
func (ss *SessionState) GetPhase() SMTPPhase {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.phase
}

// SetPhase sets the current SMTP phase (thread-safe)
func (ss *SessionState) SetPhase(ctx context.Context, phase SMTPPhase) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	oldPhase := ss.phase
	if !ss.isValidPhaseTransition(oldPhase, phase) {
		err := fmt.Errorf("invalid phase transition from %s to %s", oldPhase, phase)
		ss.logger.ErrorContext(ctx, "Invalid SMTP phase transition",
			"old_phase", oldPhase.String(),
			"new_phase", phase.String(),
			"error", err,
		)
		return err
	}

	ss.phase = phase
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "SMTP phase transition",
		"old_phase", oldPhase.String(),
		"new_phase", phase.String(),
	)

	return nil
}

// IsAuthenticated returns whether the session is authenticated (thread-safe)
func (ss *SessionState) IsAuthenticated() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.authenticated
}

// SetAuthenticated sets the authentication status (thread-safe)
func (ss *SessionState) SetAuthenticated(ctx context.Context, authenticated bool, username string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.authenticated = authenticated
	ss.username = username
	ss.lastActivityTime = time.Now()

	ss.logger.InfoContext(ctx, "Authentication status changed",
		"authenticated", authenticated,
		"username", username,
	)
}

// GetUsername returns the authenticated username (thread-safe)
func (ss *SessionState) GetUsername() string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.username
}

// SetMailFrom sets the MAIL FROM address (thread-safe)
func (ss *SessionState) SetMailFrom(ctx context.Context, mailFrom string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.phase != PhaseInit && ss.phase != PhaseMail {
		err := fmt.Errorf("cannot set MAIL FROM in phase %s", ss.phase)
		ss.logger.ErrorContext(ctx, "Invalid MAIL FROM command",
			"phase", ss.phase.String(),
			"mail_from", mailFrom,
			"error", err,
		)
		return err
	}

	ss.mailFrom = mailFrom
	ss.phase = PhaseMail
	ss.rcptTo = ss.rcptTo[:0] // Clear recipients
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "MAIL FROM set",
		"mail_from", mailFrom,
		"phase", ss.phase.String(),
	)

	return nil
}

// GetMailFrom returns the MAIL FROM address (thread-safe)
func (ss *SessionState) GetMailFrom() string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.mailFrom
}

// AddRecipient adds a recipient to the RCPT TO list (thread-safe)
func (ss *SessionState) AddRecipient(ctx context.Context, recipient string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.phase != PhaseMail && ss.phase != PhaseRcpt {
		err := fmt.Errorf("cannot add recipient in phase %s", ss.phase)
		ss.logger.ErrorContext(ctx, "Invalid RCPT TO command",
			"phase", ss.phase.String(),
			"recipient", recipient,
			"error", err,
		)
		return err
	}

	ss.rcptTo = append(ss.rcptTo, recipient)
	ss.phase = PhaseRcpt
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Recipient added",
		"recipient", recipient,
		"total_recipients", len(ss.rcptTo),
		"phase", ss.phase.String(),
	)

	return nil
}

// GetRecipients returns the list of recipients (thread-safe)
func (ss *SessionState) GetRecipients() []string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	// Return a copy to prevent external modification
	recipients := make([]string, len(ss.rcptTo))
	copy(recipients, ss.rcptTo)
	return recipients
}

// GetRecipientCount returns the number of recipients (thread-safe)
func (ss *SessionState) GetRecipientCount() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.rcptTo)
}

// SetDataSize sets the size of the message data (thread-safe)
func (ss *SessionState) SetDataSize(ctx context.Context, size int64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.dataSize = size
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Data size set",
		"data_size", size,
	)
}

// GetDataSize returns the message data size (thread-safe)
func (ss *SessionState) GetDataSize() int64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.dataSize
}

// SetDeclaredSize sets the declared message size from MAIL FROM command (thread-safe)
func (ss *SessionState) SetDeclaredSize(ctx context.Context, size int64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.declaredSize = size
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Declared size set",
		"declared_size", size,
	)
}

// GetDeclaredSize returns the declared message size (thread-safe)
func (ss *SessionState) GetDeclaredSize() int64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.declaredSize
}

// SetTLSActive sets the TLS status (thread-safe)
func (ss *SessionState) SetTLSActive(ctx context.Context, active bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.tlsActive = active
	ss.lastActivityTime = time.Now()

	ss.logger.InfoContext(ctx, "TLS status changed",
		"tls_active", active,
	)
}

// IsTLSActive returns whether TLS is active (thread-safe)
func (ss *SessionState) IsTLSActive() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.tlsActive
}

// SetSMTPUTF8 sets the SMTPUTF8 status (thread-safe)
func (ss *SessionState) SetSMTPUTF8(ctx context.Context, enabled bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.smtputf8 = enabled
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "SMTPUTF8 status changed",
		"smtputf8", enabled,
	)
}

// IsSMTPUTF8() returns whether SMTPUTF8 is enabled (thread-safe)
func (ss *SessionState) IsSMTPUTF8() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.smtputf8
}

// IncrementAuthAttempts increments the authentication attempt counter (thread-safe)
func (ss *SessionState) IncrementAuthAttempts(ctx context.Context) int {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.authAttempts++
	ss.lastAuthAttempt = time.Now()
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Authentication attempt recorded",
		"auth_attempts", ss.authAttempts,
	)

	return ss.authAttempts
}

// GetAuthAttempts returns the number of authentication attempts (thread-safe)
func (ss *SessionState) GetAuthAttempts() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.authAttempts
}

// GetLastAuthAttempt returns the time of the last authentication attempt (thread-safe)
func (ss *SessionState) GetLastAuthAttempt() time.Time {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.lastAuthAttempt
}

// UpdateActivity updates the last activity time (thread-safe)
func (ss *SessionState) UpdateActivity(ctx context.Context) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.lastActivityTime = time.Now()
}

// GetSessionDuration returns the duration since session start (thread-safe)
func (ss *SessionState) GetSessionDuration() time.Duration {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return time.Since(ss.sessionStartTime)
}

// GetIdleTime returns the time since last activity (thread-safe)
func (ss *SessionState) GetIdleTime() time.Duration {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return time.Since(ss.lastActivityTime)
}

// IncrementMessageCount increments the message counter (thread-safe)
func (ss *SessionState) IncrementMessageCount(ctx context.Context) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.messageCount++
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Message count incremented",
		"message_count", ss.messageCount,
	)
}

// GetMessageCount returns the number of messages processed (thread-safe)
func (ss *SessionState) GetMessageCount() int64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.messageCount
}

// AddBytesSent adds to the bytes sent counter (thread-safe)
func (ss *SessionState) AddBytesSent(ctx context.Context, bytes int64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.bytesSent += bytes
	ss.lastActivityTime = time.Now()
}

// AddBytesReceived adds to the bytes received counter (thread-safe)
func (ss *SessionState) AddBytesReceived(ctx context.Context, bytes int64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.bytesReceived += bytes
	ss.lastActivityTime = time.Now()
}

// GetTrafficStats returns the traffic statistics (thread-safe)
func (ss *SessionState) GetTrafficStats() (sent int64, received int64) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.bytesSent, ss.bytesReceived
}

// AddError adds an error to the session error list (thread-safe)
func (ss *SessionState) AddError(ctx context.Context, err error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.errors = append(ss.errors, err)
	ss.lastActivityTime = time.Now()

	ss.logger.ErrorContext(ctx, "Session error recorded",
		"event_type", "rejection",
		"error", err,
		"total_errors", len(ss.errors),
	)
}

// GetErrors returns a copy of the error list (thread-safe)
func (ss *SessionState) GetErrors() []error {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	errors := make([]error, len(ss.errors))
	copy(errors, ss.errors)
	return errors
}

// Reset resets the session state for a new transaction (thread-safe)
func (ss *SessionState) Reset(ctx context.Context) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.phase = PhaseInit
	ss.mailFrom = ""
	ss.rcptTo = ss.rcptTo[:0] // Clear but keep capacity
	ss.dataSize = 0
	ss.declaredSize = 0 // Clear declared size for new transaction
	ss.smtputf8 = false
	ss.dataTransferMode = DataModeNone // Clear data transfer mode on reset
	ss.dsnParams = nil
	ss.dsnRecipientParams = nil
	ss.requireTLS = false
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Session state reset for new transaction")
}

// GetStateSnapshot returns a snapshot of the current state (thread-safe)
func (ss *SessionState) GetStateSnapshot() map[string]interface{} {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return map[string]interface{}{
		"phase":            ss.phase.String(),
		"authenticated":    ss.authenticated,
		"username":         ss.username,
		"mail_from":        ss.mailFrom,
		"rcpt_count":       len(ss.rcptTo),
		"data_size":        ss.dataSize,
		"tls_active":       ss.tlsActive,
		"smtputf8":         ss.smtputf8,
		"auth_attempts":    ss.authAttempts,
		"session_duration": time.Since(ss.sessionStartTime).String(),
		"idle_time":        time.Since(ss.lastActivityTime).String(),
		"message_count":    ss.messageCount,
		"bytes_sent":       ss.bytesSent,
		"bytes_received":   ss.bytesReceived,
		"error_count":      len(ss.errors),
	}
}

// isValidPhaseTransition checks if a phase transition is valid
func (ss *SessionState) isValidPhaseTransition(from, to SMTPPhase) bool {
	// Define valid transitions
	validTransitions := map[SMTPPhase][]SMTPPhase{
		PhaseInit: {PhaseMail, PhaseAuth, PhaseTLS, PhaseQuit, PhaseInit},
		PhaseMail: {PhaseRcpt, PhaseInit, PhaseQuit},
		PhaseRcpt: {PhaseRcpt, PhaseData, PhaseInit, PhaseQuit}, // Can add more recipients
		PhaseData: {PhaseInit, PhaseQuit},                       // Back to init after data
		PhaseAuth: {PhaseInit, PhaseMail, PhaseQuit},            // After successful auth
		PhaseTLS:  {PhaseInit, PhaseAuth, PhaseMail, PhaseQuit}, // After TLS upgrade
		PhaseQuit: {},                                           // Terminal state
	}

	allowedTransitions, exists := validTransitions[from]
	if !exists {
		return false
	}

	for _, allowed := range allowedTransitions {
		if allowed == to {
			return true
		}
	}

	return false
}

// CanAcceptCommand checks if a command can be accepted in the current phase
func (ss *SessionState) CanAcceptCommand(ctx context.Context, command string) bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	// Define which commands are allowed in each phase
	allowedCommands := map[SMTPPhase][]string{
		PhaseInit: {"HELO", "EHLO", "QUIT", "RSET", "NOOP", "HELP", "AUTH", "STARTTLS", "VRFY", "EXPN", "XDEBUG"},
		PhaseMail: {"MAIL", "AUTH", "STARTTLS", "QUIT", "RSET", "NOOP", "HELP", "VRFY", "EXPN", "XDEBUG"}, // Allow AUTH after EHLO
		PhaseRcpt: {"RCPT", "QUIT", "RSET", "NOOP", "HELP", "DATA", "BDAT", "VRFY", "EXPN", "XDEBUG"},
		PhaseData: {"QUIT", "RSET", "NOOP", "HELP", "XDEBUG"},
		PhaseAuth: {"AUTH", "QUIT", "RSET", "NOOP", "HELP", "XDEBUG"},
		PhaseTLS:  {"HELO", "EHLO", "QUIT", "RSET", "NOOP", "HELP", "AUTH", "MAIL", "VRFY", "EXPN", "XDEBUG"},
		PhaseQuit: {}, // No commands allowed after QUIT
	}

	// When in BDAT transfer mode, only allow BDAT, RSET, QUIT, NOOP
	// to prevent mixing commands mid-chunked-transfer
	command = strings.ToUpper(strings.TrimSpace(command))
	if ss.dataTransferMode == DataModeBDAT {
		switch command {
		case "BDAT", "RSET", "QUIT", "NOOP":
			return true
		default:
			return false
		}
	}

	allowed, exists := allowedCommands[ss.phase]
	if !exists {
		return false
	}

	for _, allowedCmd := range allowed {
		if allowedCmd == command {
			return true
		}
	}

	return false
}

// SetDataTransferMode sets the data transfer mode (thread-safe)
func (ss *SessionState) SetDataTransferMode(ctx context.Context, mode DataTransferMode) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Prevent mixing of different data transfer modes (desynchronization attack prevention)
	if ss.dataTransferMode != DataModeNone && ss.dataTransferMode != mode {
		err := fmt.Errorf("cannot switch from %s to %s - data transfer mode conflict", ss.dataTransferMode.String(), mode.String())
		ss.logger.WarnContext(ctx, "Data transfer mode conflict detected",
			"event_type", "desynchronization_attempt",
			"current_mode", ss.dataTransferMode.String(),
			"requested_mode", mode.String(),
			"error", err,
		)
		return err
	}

	ss.dataTransferMode = mode
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Data transfer mode set",
		"mode", mode.String(),
	)

	return nil
}

// GetDataTransferMode returns the current data transfer mode (thread-safe)
func (ss *SessionState) GetDataTransferMode() DataTransferMode {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.dataTransferMode
}

// CanAcceptDataCommand checks if a data command (DATA/BDAT/BURL) can be accepted
func (ss *SessionState) CanAcceptDataCommand(ctx context.Context, command string) bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	command = strings.ToUpper(strings.TrimSpace(command))

	// Check if we're already in a different data transfer mode
	switch ss.dataTransferMode {
	case DataModeDATA:
		if command != "DATA" {
			ss.logger.WarnContext(ctx, "Data command rejected - mode conflict",
				"event_type", "desynchronization_attempt",
				"current_mode", ss.dataTransferMode.String(),
				"command", command,
			)
			return false
		}
	case DataModeBDAT:
		if command != "BDAT" {
			ss.logger.WarnContext(ctx, "Data command rejected - mode conflict",
				"event_type", "desynchronization_attempt",
				"current_mode", ss.dataTransferMode.String(),
				"command", command,
			)
			return false
		}
	case DataModeBURL:
		if command != "BURL" {
			ss.logger.WarnContext(ctx, "Data command rejected - mode conflict",
				"event_type", "desynchronization_attempt",
				"current_mode", ss.dataTransferMode.String(),
				"command", command,
			)
			return false
		}
	}

	// Check phase compatibility - data commands only allowed in RCPT phase
	if ss.phase != PhaseRcpt {
		ss.logger.WarnContext(ctx, "Data command rejected - invalid phase",
			"current_phase", ss.phase.String(),
			"command", command,
		)
		return false
	}

	return true
}

// ClearDataTransferMode clears the data transfer mode (thread-safe)
func (ss *SessionState) ClearDataTransferMode(ctx context.Context) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.dataTransferMode = DataModeNone
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "Data transfer mode cleared")
}

// SetDSNParams sets the DSN envelope parameters (thread-safe)
func (ss *SessionState) SetDSNParams(ctx context.Context, params *DSNParams) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.dsnParams = params
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "DSN params set",
		"return", string(params.Return),
		"envid", params.EnvID,
	)
}

// GetDSNParams returns the DSN envelope parameters (thread-safe)
func (ss *SessionState) GetDSNParams() *DSNParams {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.dsnParams
}

// SetDSNRecipientParams sets DSN parameters for a specific recipient (thread-safe)
func (ss *SessionState) SetDSNRecipientParams(ctx context.Context, addr string, params *DSNRecipientParams) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.dsnRecipientParams == nil {
		ss.dsnRecipientParams = make(map[string]*DSNRecipientParams)
	}
	ss.dsnRecipientParams[addr] = params
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "DSN recipient params set",
		"recipient", addr,
		"notify", params.Notify,
		"orcpt", params.ORCPT,
	)
}

// GetAllDSNRecipientParams returns all per-recipient DSN parameters (thread-safe)
func (ss *SessionState) GetAllDSNRecipientParams() map[string]*DSNRecipientParams {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.dsnRecipientParams == nil {
		return nil
	}
	// Return a copy
	result := make(map[string]*DSNRecipientParams, len(ss.dsnRecipientParams))
	for k, v := range ss.dsnRecipientParams {
		result[k] = v
	}
	return result
}

// SetRequireTLS sets the REQUIRETLS flag (thread-safe)
func (ss *SessionState) SetRequireTLS(ctx context.Context, required bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.requireTLS = required
	ss.lastActivityTime = time.Now()

	ss.logger.DebugContext(ctx, "REQUIRETLS set",
		"require_tls", required,
	)
}

// IsRequireTLS returns whether REQUIRETLS is set for this transaction (thread-safe)
func (ss *SessionState) IsRequireTLS() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.requireTLS
}
