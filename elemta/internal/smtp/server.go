package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/elemta/elemta/internal/common"
	"github.com/elemta/elemta/internal/config"
	"github.com/elemta/elemta/internal/rule"
)

// Response codes as defined in RFC 5321
const (
	StatusReady                       = 220 // Service ready
	StatusClosing                     = 221 // Service closing transmission channel
	StatusOK                          = 250 // Requested mail action okay, completed
	StatusStartMailInput              = 354 // Start mail input
	StatusNotAvailable                = 421 // Service not available, closing transmission channel
	StatusMailboxUnavailable          = 450 // Requested mail action not taken: mailbox unavailable
	StatusLocalError                  = 451 // Requested action aborted: local error in processing
	StatusInsufficientStorage         = 452 // Requested action not taken: insufficient system storage
	StatusSyntaxError                 = 500 // Syntax error, command unrecognized
	StatusSyntaxErrorInParameters     = 501 // Syntax error in parameters or arguments
	StatusCommandNotImplemented       = 502 // Command not implemented
	StatusBadSequence                 = 503 // Bad sequence of commands
	StatusParameterNotImplemented     = 504 // Command parameter not implemented
	StatusNotAuthenticated            = 530 // Authentication required
	StatusAuthenticationFailed        = 535 // Authentication credentials invalid
	StatusMailboxUnavailablePermanent = 550 // Requested action not taken: mailbox unavailable
	StatusUserNotLocalPermanent       = 551 // User not local; please try <forward-path>
	StatusExceededStorageAllocation   = 552 // Requested mail action aborted: exceeded storage allocation
	StatusMailboxNameNotAllowed       = 553 // Requested action not taken: mailbox name not allowed
	StatusTransactionFailed           = 554 // Transaction failed
)

// Server represents an SMTP server
type Server struct {
	config         *config.Config
	listener       net.Listener
	tlsConfig      *tls.Config
	ruleEngine     *rule.Engine
	sessionCounter uint64
	wg             sync.WaitGroup
	shutdown       chan struct{}
	connections    int32 // Atomic counter for active connections
	maxConnections int32
}

// NewServer creates a new SMTP server
func NewServer(cfg *config.Config, ruleEngine *rule.Engine) (*Server, error) {
	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	return &Server{
		config:         cfg,
		tlsConfig:      tlsConfig,
		ruleEngine:     ruleEngine,
		shutdown:       make(chan struct{}),
		maxConnections: int32(cfg.SMTP.MaxConnections),
	}, nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.SMTP.ListenAddress, s.config.SMTP.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	log.Printf("SMTP server listening on %s", addr)

	s.wg.Add(1)
	go s.serve()

	return nil
}

// Stop stops the SMTP server
func (s *Server) Stop() error {
	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// serve accepts incoming connections
func (s *Server) serve() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				log.Printf("Error accepting connection: %v", err)
				continue
			}
		}

		// Check if we've reached the maximum number of connections
		if s.maxConnections > 0 && atomic.LoadInt32(&s.connections) >= s.maxConnections {
			log.Printf("Maximum connections reached, rejecting connection from %s", conn.RemoteAddr())
			conn.Write([]byte(fmt.Sprintf("%d %s\r\n", StatusNotAvailable, "Too many connections, try again later")))
			conn.Close()
			continue
		}

		atomic.AddInt32(&s.connections, 1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer atomic.AddInt32(&s.connections, -1)
			s.handleConnection(conn)
		}()
	}
}

// handleConnection handles a client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set connection timeouts
	if err := conn.SetDeadline(time.Now().Add(time.Duration(s.config.SMTP.Timeouts.Connection) * time.Second)); err != nil {
		log.Printf("Failed to set connection deadline: %v", err)
		return
	}

	// Get client IP
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Create a new session
	sessionID := fmt.Sprintf("%d", atomic.AddUint64(&s.sessionCounter, 1))
	session := GetSession(sessionID, clientIP)
	defer ReleaseSession(session)

	// Run connect phase rules
	if err := s.ruleEngine.RunConnectRules(session); err != nil {
		log.Printf("Connect phase rule error: %v", err)
		conn.Write([]byte(fmt.Sprintf("%d %s\r\n", StatusNotAvailable, "Connection rejected")))
		return
	}

	// Send greeting
	greeting := fmt.Sprintf("%d %s ESMTP ElemTA ready\r\n", StatusReady, s.config.SMTP.Hostname)
	if _, err := conn.Write([]byte(greeting)); err != nil {
		log.Printf("Failed to send greeting: %v", err)
		return
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Main command loop
	for {
		// Reset deadline for each command
		if err := conn.SetDeadline(time.Now().Add(time.Duration(s.config.SMTP.Timeouts.Command) * time.Second)); err != nil {
			log.Printf("Failed to set command deadline: %v", err)
			return
		}

		// Read command
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading command: %v", err)
			}
			return
		}

		// Trim CRLF
		line = strings.TrimRight(line, "\r\n")

		// Parse command
		cmd, args, err := ParseCommand(line)
		if err != nil {
			writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusSyntaxError, err.Error()))
			writer.Flush()
			continue
		}

		// Handle command
		if err := s.handleCommand(conn, reader, writer, session, cmd, args); err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("Error handling command: %v", err)
			return
		}

		// Check if we should quit
		if session.State == common.StateQuit {
			return
		}
	}
}

// handleCommand handles an SMTP command
func (s *Server) handleCommand(conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, session *common.Session, cmd Command, args string) error {
	switch cmd {
	case CmdHelo:
		return s.handleHelo(writer, session, args, false)
	case CmdEhlo:
		return s.handleHelo(writer, session, args, true)
	case CmdMailFrom:
		return s.handleMailFrom(writer, session, args)
	case CmdRcptTo:
		return s.handleRcptTo(writer, session, args)
	case CmdData:
		return s.handleData(conn, reader, writer, session)
	case CmdRset:
		return s.handleRset(writer, session)
	case CmdQuit:
		return s.handleQuit(writer, session)
	case CmdNoop:
		return s.handleNoop(writer)
	case CmdHelp:
		return s.handleHelp(writer)
	case CmdStartTLS:
		return s.handleStartTLS(conn, writer, session)
	case CmdAuth:
		return s.handleAuth(reader, writer, session, args)
	case CmdXDebug:
		return s.handleXDebug(writer, session, args)
	default:
		writer.WriteString(fmt.Sprintf("%d Command not implemented\r\n", StatusCommandNotImplemented))
		writer.Flush()
		return nil
	}
}

// handleHelo handles the HELO/EHLO command
func (s *Server) handleHelo(writer *bufio.Writer, session *common.Session, args string, isEhlo bool) error {
	if args == "" {
		writer.WriteString(fmt.Sprintf("%d Missing hostname\r\n", StatusSyntaxErrorInParameters))
		writer.Flush()
		return nil
	}

	// Transition state
	if _, err := Transition(session, CmdHelo, args); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusSyntaxErrorInParameters, err.Error()))
		writer.Flush()
		return nil
	}

	// Run HELO phase rules
	if err := s.ruleEngine.RunHeloRules(session); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusMailboxUnavailablePermanent, err.Error()))
		writer.Flush()
		return nil
	}

	if isEhlo {
		// Send EHLO response with capabilities
		writer.WriteString(fmt.Sprintf("%d-%s\r\n", StatusOK, s.config.SMTP.Hostname))

		// List extensions
		writer.WriteString("250-SIZE 52428800\r\n") // 50MB max message size
		writer.WriteString("250-8BITMIME\r\n")
		writer.WriteString("250-PIPELINING\r\n")
		writer.WriteString("250-ENHANCEDSTATUSCODES\r\n")

		// Only offer STARTTLS if not already in TLS mode and TLS is configured
		if !session.TLSEnabled && s.tlsConfig != nil {
			writer.WriteString("250-STARTTLS\r\n")
		}

		// Only offer AUTH if TLS is enabled or we allow plain auth
		if session.TLSEnabled || s.config.SMTP.AllowInsecureAuth {
			writer.WriteString("250-AUTH PLAIN LOGIN\r\n")
		}

		writer.WriteString("250 HELP\r\n")
	} else {
		// Simple HELO response
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusOK, s.config.SMTP.Hostname))
	}

	writer.Flush()
	return nil
}

// handleMailFrom handles the MAIL FROM command
func (s *Server) handleMailFrom(writer *bufio.Writer, session *common.Session, args string) error {
	// Transition state
	if _, err := Transition(session, CmdMailFrom, args); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusSyntaxErrorInParameters, err.Error()))
		writer.Flush()
		return nil
	}

	// Run MAIL FROM phase rules
	if err := s.ruleEngine.RunMailFromRules(session); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusMailboxUnavailablePermanent, err.Error()))
		writer.Flush()
		return nil
	}

	writer.WriteString(fmt.Sprintf("%d OK\r\n", StatusOK))
	writer.Flush()
	return nil
}

// handleRcptTo handles the RCPT TO command
func (s *Server) handleRcptTo(writer *bufio.Writer, session *common.Session, args string) error {
	// Transition state
	if _, err := Transition(session, CmdRcptTo, args); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusSyntaxErrorInParameters, err.Error()))
		writer.Flush()
		return nil
	}

	// Run RCPT TO phase rules
	if err := s.ruleEngine.RunRcptToRules(session); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusMailboxUnavailablePermanent, err.Error()))
		writer.Flush()
		return nil
	}

	writer.WriteString(fmt.Sprintf("%d OK\r\n", StatusOK))
	writer.Flush()
	return nil
}

// handleData handles the DATA command
func (s *Server) handleData(conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, session *common.Session) error {
	// Transition state
	if _, err := Transition(session, CmdData, ""); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusBadSequence, err.Error()))
		writer.Flush()
		return nil
	}

	// Send intermediate response
	writer.WriteString(fmt.Sprintf("%d Start mail input; end with <CRLF>.<CRLF>\r\n", StatusStartMailInput))
	writer.Flush()

	// Set data timeout
	if err := conn.SetDeadline(time.Now().Add(time.Duration(s.config.SMTP.Timeouts.Data) * time.Second)); err != nil {
		log.Printf("Failed to set data deadline: %v", err)
		return err
	}

	// Read message data
	var line string
	var err error
	inHeader := true
	headerName := ""

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return err
		}

		// Check for end of message
		if line == ".\r\n" {
			break
		}

		// Handle dot-stuffing (RFC 5321, section 4.5.2)
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}

		// Process headers for DKIM/etc later
		if inHeader {
			// Empty line marks end of headers
			if line == "\r\n" {
				inHeader = false
			} else if unicode.IsSpace(rune(line[0])) {
				// Continuation of previous header
				if headerName != "" {
					// Store header continuation
				}
			} else {
				// New header
				colonIdx := strings.Index(line, ":")
				if colonIdx > 0 {
					headerName = strings.TrimSpace(line[:colonIdx])
					// Store header
				}
			}
		}

		// Append to buffer
		session.AppendData([]byte(line))
	}

	// Finalize data and get complete message
	messageData := session.FinalizeData()

	// Run DATA phase rules
	if err := s.ruleEngine.RunDataRules(session, messageData); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusTransactionFailed, err.Error()))
		writer.Flush()
		return nil
	}

	// Queue the message
	queueID, err := s.queueMessage(session, messageData)
	if err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusLocalError, err.Error()))
		writer.Flush()
		return nil
	}

	writer.WriteString(fmt.Sprintf("%d OK: queued as %s\r\n", StatusOK, queueID))
	writer.Flush()
	return nil
}

// handleRset handles the RSET command
func (s *Server) handleRset(writer *bufio.Writer, session *common.Session) error {
	session.Reset()
	writer.WriteString(fmt.Sprintf("%d OK\r\n", StatusOK))
	writer.Flush()
	return nil
}

// handleQuit handles the QUIT command
func (s *Server) handleQuit(writer *bufio.Writer, session *common.Session) error {
	if _, err := Transition(session, CmdQuit, ""); err != nil {
		writer.WriteString(fmt.Sprintf("%d %s\r\n", StatusSyntaxErrorInParameters, err.Error()))
		writer.Flush()
		return nil
	}

	writer.WriteString(fmt.Sprintf("%d %s closing connection\r\n", StatusClosing, s.config.SMTP.Hostname))
	writer.Flush()
	return nil
}

// handleNoop handles the NOOP command
func (s *Server) handleNoop(writer *bufio.Writer) error {
	writer.WriteString(fmt.Sprintf("%d OK\r\n", StatusOK))
	writer.Flush()
	return nil
}

// handleHelp handles the HELP command
func (s *Server) handleHelp(writer *bufio.Writer) error {
	writer.WriteString(fmt.Sprintf("%d Supported commands: HELO EHLO MAIL RCPT DATA RSET NOOP QUIT HELP XDEBUG\r\n", StatusOK))
	writer.Flush()
	return nil
}

// handleStartTLS handles the STARTTLS command
func (s *Server) handleStartTLS(conn net.Conn, writer *bufio.Writer, session *common.Session) error {
	if session.TLSEnabled {
		writer.WriteString(fmt.Sprintf("%d TLS already active\r\n", StatusSyntaxErrorInParameters))
		writer.Flush()
		return nil
	}

	if s.tlsConfig == nil {
		writer.WriteString(fmt.Sprintf("%d TLS not available\r\n", StatusCommandNotImplemented))
		writer.Flush()
		return nil
	}

	writer.WriteString(fmt.Sprintf("%d Ready to start TLS\r\n", StatusReady))
	writer.Flush()

	// Upgrade connection to TLS
	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return err
	}

	// Update session
	session.TLSEnabled = true
	session.Secure = true

	// Replace connection with TLS connection
	conn = tlsConn

	return nil
}

// handleAuth handles the AUTH command
func (s *Server) handleAuth(reader *bufio.Reader, writer *bufio.Writer, session *common.Session, args string) error {
	// Only allow AUTH in TLS mode unless explicitly configured to allow insecure auth
	if !session.TLSEnabled && !s.config.SMTP.AllowInsecureAuth {
		writer.WriteString(fmt.Sprintf("%d Must issue a STARTTLS command first\r\n", StatusNotAuthenticated))
		writer.Flush()
		return nil
	}

	// Parse auth method
	parts := strings.Fields(args)
	if len(parts) == 0 {
		writer.WriteString(fmt.Sprintf("%d AUTH mechanism not specified\r\n", StatusSyntaxErrorInParameters))
		writer.Flush()
		return nil
	}

	method := strings.ToUpper(parts[0])
	switch method {
	case "PLAIN":
		// Handle PLAIN auth
		var authData string
		if len(parts) > 1 {
			authData = parts[1]
		} else {
			// Request auth data
			writer.WriteString("334 \r\n")
			writer.Flush()

			// Read response
			response, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			authData = strings.TrimSpace(response)
		}

		// Authenticate
		if s.authenticate(session, "PLAIN", authData) {
			session.Authenticated = true
			writer.WriteString(fmt.Sprintf("%d Authentication successful\r\n", StatusOK))
		} else {
			writer.WriteString(fmt.Sprintf("%d Authentication failed\r\n", StatusAuthenticationFailed))
		}
		writer.Flush()

	case "LOGIN":
		// Handle LOGIN auth
		writer.WriteString("334 VXNlcm5hbWU6\r\n") // Base64 for "Username:"
		writer.Flush()

		// Read username
		username, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		username = strings.TrimSpace(username)

		writer.WriteString("334 UGFzc3dvcmQ6\r\n") // Base64 for "Password:"
		writer.Flush()

		// Read password
		password, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		password = strings.TrimSpace(password)

		// Authenticate
		if s.authenticate(session, "LOGIN", username, password) {
			session.Authenticated = true
			writer.WriteString(fmt.Sprintf("%d Authentication successful\r\n", StatusOK))
		} else {
			writer.WriteString(fmt.Sprintf("%d Authentication failed\r\n", StatusAuthenticationFailed))
		}
		writer.Flush()

	default:
		writer.WriteString(fmt.Sprintf("%d Unsupported authentication mechanism\r\n", StatusParameterNotImplemented))
		writer.Flush()
	}

	return nil
}

// authenticate authenticates a user
func (s *Server) authenticate(session *common.Session, method string, args ...string) bool {
	// This is a placeholder. In a real implementation, you would check credentials
	// against a database or other authentication source.
	return false
}

// queueMessage queues a message for delivery
func (s *Server) queueMessage(session *common.Session, data []byte) (string, error) {
	// This is a placeholder. In a real implementation, you would queue the message
	// for delivery and return a queue ID.
	queueID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Run queue phase rules
	if err := s.ruleEngine.RunQueueRules(session, data, queueID); err != nil {
		return "", err
	}

	return queueID, nil
}

// createTLSConfig creates a TLS configuration
func createTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
	}, nil
}

// handleXDebug handles the XDEBUG command
func (s *Server) handleXDebug(writer *bufio.Writer, session *common.Session, args string) error {
	// If no arguments, dump everything
	if args == "" {
		writer.WriteString(fmt.Sprintf("%d-Debug information:\r\n", StatusOK))
		writer.WriteString(fmt.Sprintf("250-Session ID: %s\r\n", session.ID))
		writer.WriteString(fmt.Sprintf("250-State: %s\r\n", session.State))
		writer.WriteString(fmt.Sprintf("250-Client IP: %s\r\n", session.ClientIP))
		writer.WriteString(fmt.Sprintf("250-Client Name: %s\r\n", session.ClientName))
		writer.WriteString(fmt.Sprintf("250-Hostname: %s\r\n", session.Hostname))
		writer.WriteString(fmt.Sprintf("250-Mail From: %s\r\n", session.MailFrom))
		writer.WriteString(fmt.Sprintf("250-Rcpt To: %v\r\n", session.RcptTo))
		writer.WriteString(fmt.Sprintf("250-Secure: %v\r\n", session.Secure))
		writer.WriteString(fmt.Sprintf("250-Authenticated: %v\r\n", session.Authenticated))
		writer.WriteString(fmt.Sprintf("250-TLS Enabled: %v\r\n", session.TLSEnabled))
		writer.WriteString(fmt.Sprintf("250-Start Time: %s\r\n", session.StartTime.Format(time.RFC3339)))
		writer.WriteString(fmt.Sprintf("250-Last Activity: %s\r\n", session.LastActivity.Format(time.RFC3339)))
		writer.WriteString(fmt.Sprintf("250-Extensions: %v\r\n", session.Extensions))
		writer.WriteString(fmt.Sprintf("250-Context:\r\n"))

		// Dump context
		if session.Context != nil {
			contextDump := session.Context.Dump()
			lines := strings.Split(contextDump, "\n")
			for i, line := range lines {
				if i == len(lines)-1 && line == "" {
					continue
				}
				if i == len(lines)-1 {
					writer.WriteString(fmt.Sprintf("250 %s\r\n", line))
				} else {
					writer.WriteString(fmt.Sprintf("250-%s\r\n", line))
				}
			}
		} else {
			writer.WriteString("250 No context available\r\n")
		}
	} else {
		// Handle specific debug commands
		parts := strings.SplitN(args, " ", 2)
		subCmd := strings.ToUpper(parts[0])

		switch subCmd {
		case "CONTEXT":
			// If no subcommand arguments, dump the entire context
			if len(parts) == 1 {
				writer.WriteString(fmt.Sprintf("%d-Context dump:\r\n", StatusOK))
				if session.Context != nil {
					contextDump := session.Context.Dump()
					lines := strings.Split(contextDump, "\n")
					for i, line := range lines {
						if i == len(lines)-1 && line == "" {
							continue
						}
						if i == len(lines)-1 {
							writer.WriteString(fmt.Sprintf("250 %s\r\n", line))
						} else {
							writer.WriteString(fmt.Sprintf("250-%s\r\n", line))
						}
					}
				} else {
					writer.WriteString("250 No context available\r\n")
				}
			} else {
				// Handle context operations
				contextArgs := strings.TrimSpace(parts[1])
				contextParts := strings.SplitN(contextArgs, " ", 2)
				contextOp := strings.ToUpper(contextParts[0])

				switch contextOp {
				case "GET":
					if len(contextParts) < 2 {
						writer.WriteString(fmt.Sprintf("%d Missing key\r\n", StatusSyntaxErrorInParameters))
					} else {
						key := strings.TrimSpace(contextParts[1])
						if session.Context != nil {
							if value, ok := session.Context.Get(key); ok {
								writer.WriteString(fmt.Sprintf("%d %s = %v\r\n", StatusOK, key, value))
							} else {
								writer.WriteString(fmt.Sprintf("%d Key not found: %s\r\n", StatusOK, key))
							}
						} else {
							writer.WriteString(fmt.Sprintf("%d No context available\r\n", StatusOK))
						}
					}
				case "SET":
					if len(contextParts) < 2 {
						writer.WriteString(fmt.Sprintf("%d Missing key and value\r\n", StatusSyntaxErrorInParameters))
					} else {
						keyValue := strings.SplitN(contextParts[1], " ", 2)
						if len(keyValue) < 2 {
							writer.WriteString(fmt.Sprintf("%d Missing value\r\n", StatusSyntaxErrorInParameters))
						} else {
							key := strings.TrimSpace(keyValue[0])
							value := strings.TrimSpace(keyValue[1])
							if session.Context != nil {
								session.Context.Set(key, value)
								writer.WriteString(fmt.Sprintf("%d Set %s = %s\r\n", StatusOK, key, value))
							} else {
								writer.WriteString(fmt.Sprintf("%d No context available\r\n", StatusOK))
							}
						}
					}
				case "DELETE":
					if len(contextParts) < 2 {
						writer.WriteString(fmt.Sprintf("%d Missing key\r\n", StatusSyntaxErrorInParameters))
					} else {
						key := strings.TrimSpace(contextParts[1])
						if session.Context != nil {
							session.Context.Delete(key)
							writer.WriteString(fmt.Sprintf("%d Deleted key: %s\r\n", StatusOK, key))
						} else {
							writer.WriteString(fmt.Sprintf("%d No context available\r\n", StatusOK))
						}
					}
				case "CLEAR":
					if session.Context != nil {
						session.Context.Clear()
						writer.WriteString(fmt.Sprintf("%d Context cleared\r\n", StatusOK))
					} else {
						writer.WriteString(fmt.Sprintf("%d No context available\r\n", StatusOK))
					}
				default:
					writer.WriteString(fmt.Sprintf("%d Unknown context operation: %s\r\n", StatusSyntaxErrorInParameters, contextOp))
				}
			}
		case "SESSION":
			writer.WriteString(fmt.Sprintf("%d-Session information:\r\n", StatusOK))
			writer.WriteString(fmt.Sprintf("250-ID: %s\r\n", session.ID))
			writer.WriteString(fmt.Sprintf("250-State: %s\r\n", session.State))
			writer.WriteString(fmt.Sprintf("250-Client IP: %s\r\n", session.ClientIP))
			writer.WriteString(fmt.Sprintf("250-Client Name: %s\r\n", session.ClientName))
			writer.WriteString(fmt.Sprintf("250-Hostname: %s\r\n", session.Hostname))
			writer.WriteString(fmt.Sprintf("250-Mail From: %s\r\n", session.MailFrom))
			writer.WriteString(fmt.Sprintf("250-Rcpt To: %v\r\n", session.RcptTo))
			writer.WriteString(fmt.Sprintf("250-Secure: %v\r\n", session.Secure))
			writer.WriteString(fmt.Sprintf("250-Authenticated: %v\r\n", session.Authenticated))
			writer.WriteString(fmt.Sprintf("250-TLS Enabled: %v\r\n", session.TLSEnabled))
			writer.WriteString(fmt.Sprintf("250-Start Time: %s\r\n", session.StartTime.Format(time.RFC3339)))
			writer.WriteString(fmt.Sprintf("250 Last Activity: %s\r\n", session.LastActivity.Format(time.RFC3339)))
		case "HELP":
			writer.WriteString(fmt.Sprintf("%d-XDEBUG commands:\r\n", StatusOK))
			writer.WriteString("250-XDEBUG - Show all debug information\r\n")
			writer.WriteString("250-XDEBUG CONTEXT - Show context information\r\n")
			writer.WriteString("250-XDEBUG CONTEXT GET <key> - Get a context value\r\n")
			writer.WriteString("250-XDEBUG CONTEXT SET <key> <value> - Set a context value\r\n")
			writer.WriteString("250-XDEBUG CONTEXT DELETE <key> - Delete a context value\r\n")
			writer.WriteString("250-XDEBUG CONTEXT CLEAR - Clear all context values\r\n")
			writer.WriteString("250-XDEBUG SESSION - Show session information\r\n")
			writer.WriteString("250 XDEBUG HELP - Show this help message\r\n")
		default:
			writer.WriteString(fmt.Sprintf("%d Unknown debug command: %s\r\n", StatusSyntaxErrorInParameters, subCmd))
		}
	}

	writer.Flush()
	return nil
}
