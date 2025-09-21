// internal/smtp/session_refactored.go
package smtp

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/google/uuid"
)

// Session represents a refactored SMTP session with modular components
type Session struct {
	// Core connection components
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	// Modular handlers
	state           *SessionState
	commandHandler  *CommandHandler
	authHandler     *AuthHandler
	dataHandler     *DataHandler

	// Configuration and dependencies
	config            *Config
	logger            *slog.Logger
	context           *Context
	authenticator     Authenticator
	queueManager      queue.QueueManager
	tlsManager        TLSHandler
	builtinPlugins    *plugin.BuiltinPlugins
	resourceManager   *ResourceManager
	// enhancedValidator would be added here if needed

	// Session metadata
	sessionID    string
	remoteAddr   string
	startTime    time.Time

	// Thread safety
	mu sync.RWMutex

	// Graceful shutdown
	shutdownCh chan struct{}
	done       chan struct{}
}

// NewSession creates a new SMTP session with modular architecture
func NewSession(conn net.Conn, config *Config, authenticator Authenticator) *Session {
	remoteAddr := conn.RemoteAddr().String()
	sessionID := uuid.New().String()
	startTime := time.Now()

	// Create structured logger for the session
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With(
		"component", "smtp-session",
		"remote_addr", remoteAddr,
		"session_id", sessionID,
		"service", "elemta-mta",
	)

	// Create core session
	session := &Session{
		conn:              conn,
		reader:            bufio.NewReader(conn),
		writer:            bufio.NewWriter(conn),
		config:            config,
		logger:            logger,
		authenticator:     authenticator,
		sessionID:         sessionID,
		remoteAddr:        remoteAddr,
		startTime:         startTime,
		shutdownCh:        make(chan struct{}),
		done:              make(chan struct{}),
		// enhancedValidator would be initialized here if needed
	}

	// Initialize modular components
	session.initializeComponents()

	logger.InfoContext(context.Background(), "New SMTP session created",
		"session_id", sessionID,
		"remote_addr", remoteAddr,
		"hostname", config.Hostname,
		"max_size", config.MaxSize,
	)

	return session
}

// initializeComponents initializes all modular components
func (s *Session) initializeComponents() {
	// Create session state manager
	s.state = NewSessionState(s.logger)

	// Create authentication handler
	s.authHandler = NewAuthHandler(s, s.state, s.authenticator, s.conn, s.logger)

	// Create command handler
	s.commandHandler = NewCommandHandler(s, s.state, s.authHandler, s.conn, 
		s.config, s.tlsManager, s.logger)

	// Create data handler
	s.dataHandler = NewDataHandler(s, s.state, s.conn, s.reader, s.config,
		s.queueManager, s.builtinPlugins, s.logger)

	s.logger.DebugContext(context.Background(), "Session components initialized")
}

// SetTLSManager sets the TLS manager for the session
func (s *Session) SetTLSManager(tlsManager TLSHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.tlsManager = tlsManager
	if s.commandHandler != nil {
		s.commandHandler.tlsManager = tlsManager
	}
}

// SetQueueManager sets the queue manager for the session
func (s *Session) SetQueueManager(queueManager queue.QueueManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.queueManager = queueManager
	if s.dataHandler != nil {
		s.dataHandler.queueManager = queueManager
	}
}

// Note: Queue integration is handled by the QueueManager

// SetBuiltinPlugins sets the builtin plugins for the session
func (s *Session) SetBuiltinPlugins(builtinPlugins *plugin.BuiltinPlugins) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.builtinPlugins = builtinPlugins
	if s.dataHandler != nil {
		s.dataHandler.builtinPlugins = builtinPlugins
	}
}

// SetResourceManager sets the resource manager for the session
func (s *Session) SetResourceManager(resourceManager *ResourceManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resourceManager = resourceManager
}

// Handle processes the SMTP session with comprehensive error handling and logging
func (s *Session) Handle() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Set up panic recovery
	defer func() {
		if r := recover(); r != nil {
			s.logger.ErrorContext(ctx, "Session panic recovered",
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
		close(s.done)
	}()

	s.logger.InfoContext(ctx, "Starting SMTP session",
		"hostname", s.config.Hostname,
		"max_size", s.config.MaxSize,
	)

	// Send greeting
	if err := s.sendGreeting(ctx); err != nil {
		s.logger.ErrorContext(ctx, "Failed to send greeting", "error", err)
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Main command processing loop
	return s.processCommands(ctx)
}

// sendGreeting sends the initial SMTP greeting
func (s *Session) sendGreeting(ctx context.Context) error {
	greeting := fmt.Sprintf("220 %s ESMTP Elemta MTA ready", s.config.Hostname)
	
	if err := s.write(greeting); err != nil {
		return fmt.Errorf("failed to write greeting: %w", err)
	}

	s.logger.InfoContext(ctx, "SMTP greeting sent", "greeting", greeting)
	return nil
}

// processCommands processes SMTP commands in the main loop
func (s *Session) processCommands(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			s.logger.InfoContext(ctx, "Session context cancelled")
			return ctx.Err()
		case <-s.shutdownCh:
			s.logger.InfoContext(ctx, "Session shutdown requested")
			return nil
		default:
			// Continue processing
		}

		// Set read timeout
		if err := s.conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			s.logger.WarnContext(ctx, "Failed to set read deadline", "error", err)
		}

		// Read command line
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.logger.InfoContext(ctx, "Session timeout")
				s.write("421 4.4.2 Timeout")
				return fmt.Errorf("session timeout")
			}
			
			s.logger.InfoContext(ctx, "Client disconnected", "error", err)
			return nil // Normal disconnection
		}

		// Update activity tracking
		s.state.UpdateActivity(ctx)

		// Handle special case for DATA command
		if s.state.GetPhase() == PhaseData {
			if err := s.handleDataPhase(ctx); err != nil {
				s.logger.ErrorContext(ctx, "Data phase handling failed", "error", err)
				s.writeError(ctx, err)
				continue
			}
			// Send success response
			s.write("250 2.0.0 Message accepted for delivery")
			continue
		}

		// Process regular commands
		if err := s.commandHandler.ProcessCommand(ctx, line); err != nil {
			s.logger.WarnContext(ctx, "Command processing failed",
				"command", line,
				"error", err,
			)
			s.writeError(ctx, err)

			// Check for QUIT command
			if s.state.GetPhase() == PhaseQuit {
				s.logger.InfoContext(ctx, "Session terminated by client")
				return nil
			}
		} else {
			// Check for QUIT command after successful command processing
			if s.state.GetPhase() == PhaseQuit {
				s.logger.InfoContext(ctx, "Session terminated by client")
				return nil
			}
		}
	}
}

// handleDataPhase handles the DATA phase of message transmission
func (s *Session) handleDataPhase(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Entering DATA phase",
		"mail_from", s.state.GetMailFrom(),
		"recipients", s.state.GetRecipientCount(),
	)

	// Read message data
	data, err := s.dataHandler.ReadData(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to read message data", "error", err)
		return err
	}

	// Process the complete message
	if err := s.dataHandler.ProcessMessage(ctx, data); err != nil {
		s.logger.ErrorContext(ctx, "Message processing failed", "error", err)
		return err
	}

	s.logger.InfoContext(ctx, "Message processed successfully",
		"size", len(data),
		"mail_from", s.state.GetMailFrom(),
		"recipients", s.state.GetRecipientCount(),
	)

	return nil
}

// write writes a response to the client (thread-safe)
func (s *Session) write(msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.writer.WriteString(msg + "\r\n"); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	// Update traffic statistics
	s.state.AddBytesSent(context.Background(), int64(len(msg)+2))

	return nil
}

// writeWithLog writes a response with logging (thread-safe)
func (s *Session) writeWithLog(msg string) {
	if err := s.write(msg); err != nil {
		s.logger.ErrorContext(context.Background(), "Failed to write response",
			"message", msg,
			"error", err,
		)
	} else {
		s.logger.DebugContext(context.Background(), "Response sent", "message", msg)
	}
}

// writeError writes an error response to the client
func (s *Session) writeError(ctx context.Context, err error) {
	errorMsg := err.Error()
	
	// Extract SMTP error code if present, otherwise use generic error
	if len(errorMsg) >= 3 && errorMsg[0] >= '4' && errorMsg[0] <= '5' {
		s.writeWithLog(errorMsg)
	} else {
		s.writeWithLog("451 4.3.0 Internal server error")
	}

	// Log the error
	s.logger.WarnContext(ctx, "SMTP error response sent",
		"error", err,
		"response", errorMsg,
	)

	// Add error to session state
	s.state.AddError(ctx, err)
}

// Close gracefully closes the session
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Signal shutdown
	select {
	case <-s.shutdownCh:
		// Already shutting down
	default:
		close(s.shutdownCh)
	}

	// Wait for session to complete (with timeout)
	select {
	case <-s.done:
		// Session completed
	case <-time.After(5 * time.Second):
		s.logger.WarnContext(context.Background(), "Session close timeout")
	}

	// Close connection
	if err := s.conn.Close(); err != nil {
		s.logger.WarnContext(context.Background(), "Failed to close connection", "error", err)
		return err
	}

	// Log session summary
	s.logSessionSummary()

	return nil
}

// logSessionSummary logs a summary of the session
func (s *Session) logSessionSummary() {
	duration := time.Since(s.startTime)
	snapshot := s.state.GetStateSnapshot()
	sent, received := s.state.GetTrafficStats()

	s.logger.InfoContext(context.Background(), "Session completed",
		"duration", duration,
		"messages_processed", s.state.GetMessageCount(),
		"bytes_sent", sent,
		"bytes_received", received,
		"auth_attempts", s.state.GetAuthAttempts(),
		"authenticated", s.state.IsAuthenticated(),
		"username", s.state.GetUsername(),
		"final_phase", s.state.GetPhase().String(),
		"errors", len(s.state.GetErrors()),
		"state_snapshot", snapshot,
	)
}

// GetSessionID returns the session ID
func (s *Session) GetSessionID() string {
	return s.sessionID
}

// GetRemoteAddr returns the remote address
func (s *Session) GetRemoteAddr() string {
	return s.remoteAddr
}

// GetStartTime returns the session start time
func (s *Session) GetStartTime() time.Time {
	return s.startTime
}

// GetState returns the session state (read-only access)
func (s *Session) GetState() *SessionState {
	return s.state
}

// IsAuthenticated returns whether the session is authenticated
func (s *Session) IsAuthenticated() bool {
	return s.state.IsAuthenticated()
}

// GetUsername returns the authenticated username
func (s *Session) GetUsername() string {
	return s.state.GetUsername()
}

// GetPhase returns the current SMTP phase
func (s *Session) GetPhase() SMTPPhase {
	return s.state.GetPhase()
}

// GetDuration returns the session duration
func (s *Session) GetDuration() time.Duration {
	return s.state.GetSessionDuration()
}

// GetIdleTime returns the idle time since last activity
func (s *Session) GetIdleTime() time.Duration {
	return s.state.GetIdleTime()
}

// GetMessageCount returns the number of messages processed
func (s *Session) GetMessageCount() int64 {
	return s.state.GetMessageCount()
}

// GetTrafficStats returns traffic statistics
func (s *Session) GetTrafficStats() (sent int64, received int64) {
	return s.state.GetTrafficStats()
}

// GetErrors returns session errors
func (s *Session) GetErrors() []error {
	return s.state.GetErrors()
}

// GetStateSnapshot returns a snapshot of the session state
func (s *Session) GetStateSnapshot() map[string]interface{} {
	snapshot := s.state.GetStateSnapshot()
	snapshot["session_id"] = s.sessionID
	snapshot["remote_addr"] = s.remoteAddr
	snapshot["start_time"] = s.startTime
	return snapshot
}

// Cleanup performs session cleanup
func (s *Session) Cleanup(ctx context.Context) {
	s.logger.DebugContext(ctx, "Performing session cleanup")

	// Cleanup authentication handler
	if s.authHandler != nil {
		s.authHandler.Cleanup(ctx)
	}

	// Additional cleanup tasks can be added here
	s.logger.DebugContext(ctx, "Session cleanup completed")
}
