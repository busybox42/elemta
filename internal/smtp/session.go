// internal/smtp/session.go
package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type State int

const (
	INIT State = iota
	MAIL
	RCPT
	DATA
)

type Session struct {
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	state   State
	message *Message
	config  *Config
	logger  *slog.Logger
	Context *Context
}

func NewSession(conn net.Conn, config *Config) *Session {
	remoteAddr := conn.RemoteAddr().String()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With(
		"remote_addr", remoteAddr,
		"session_id", uuid.New().String(),
	)

	return &Session{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		writer:  bufio.NewWriter(conn),
		state:   INIT,
		message: NewMessage(),
		config:  config,
		logger:  logger,
		Context: NewContext(),
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

	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Error("read error", "error", err)
			return err
		}

		cmd := strings.TrimSpace(strings.ToUpper(line))
		s.logger.Debug("received command", "command", cmd)

		switch {
		case strings.HasPrefix(cmd, "QUIT"):
			s.logger.Info("client quit")
			s.write("221 Bye\r\n")
			return nil

		case strings.HasPrefix(cmd, "HELO"), strings.HasPrefix(cmd, "EHLO"):
			s.logger.Info("client hello", "command", cmd)
			s.write("250-" + s.config.Hostname + "\r\n")
			s.write("250-SIZE " + strconv.FormatInt(s.config.MaxSize, 10) + "\r\n")
			s.write("250-8BITMIME\r\n")
			s.write("250-PIPELINING\r\n")
			s.write("250-ENHANCEDSTATUSCODES\r\n")
			s.write("250 HELP\r\n")

		case strings.HasPrefix(cmd, "MAIL FROM:"):
			if s.state != INIT {
				s.logger.Warn("bad sequence", "state", s.state)
				s.write("503 Bad sequence\r\n")
				continue
			}
			addr := extractAddress(cmd)
			if addr == "" {
				s.logger.Warn("invalid address in MAIL FROM", "command", cmd)
				s.write("501 Invalid address\r\n")
				continue
			}
			s.message.from = addr
			s.state = MAIL
			s.logger.Info("mail from accepted", "from", addr)
			s.write("250 Ok\r\n")

		case strings.HasPrefix(cmd, "RCPT TO:"):
			if s.state != MAIL && s.state != RCPT {
				s.logger.Warn("bad sequence", "state", s.state)
				s.write("503 Bad sequence\r\n")
				continue
			}
			addr := extractAddress(cmd)
			if addr == "" {
				s.logger.Warn("invalid address in RCPT TO", "command", cmd)
				s.write("501 Invalid address\r\n")
				continue
			}
			s.message.to = append(s.message.to, addr)
			s.state = RCPT
			s.logger.Info("recipient accepted", "to", addr)
			s.write("250 Ok\r\n")

		case strings.HasPrefix(cmd, "DATA"):
			if s.state != RCPT {
				s.logger.Warn("bad sequence", "state", s.state)
				s.write("503 Bad sequence\r\n")
				continue
			}
			s.write("354 Start mail input; end with <CRLF>.<CRLF>\r\n")
			data, err := s.readData()
			if err != nil {
				s.logger.Error("data read error", "error", err)
				s.write("554 Error reading data\r\n")
				continue
			}
			s.message.data = data
			if err := s.saveMessage(); err != nil {
				s.logger.Error("save error", "error", err)
				s.write("554 Error saving message\r\n")
				continue
			}
			s.logger.Info("message saved",
				"from", s.message.from,
				"to", strings.Join(s.message.to, ","),
				"size", len(s.message.data))
			s.state = INIT
			s.message = NewMessage()
			s.write("250 Ok: message queued\r\n")

		case strings.HasPrefix(cmd, "XDEBUG"):
			s.logger.Info("xdebug command", "command", cmd)
			s.handleXDEBUG(cmd)

		default:
			s.logger.Warn("unknown command", "command", cmd)
			s.write("500 Unknown command\r\n")
		}
	}
}

func (s *Session) handleXDEBUG(cmd string) {
	parts := strings.SplitN(cmd, " ", 2)
	var args string
	if len(parts) > 1 {
		args = parts[1]
	}

	if args == "" {
		s.write("250-Debug information:\r\n")
		s.write("250-Session ID: " + uuid.New().String() + "\r\n")
		s.write("250-Client IP: " + s.conn.RemoteAddr().String() + "\r\n")
		s.write("250-Hostname: " + s.config.Hostname + "\r\n")
		s.write("250-State: " + stateToString(s.state) + "\r\n")
		s.write("250-Mail From: " + s.message.from + "\r\n")
		s.write("250-Rcpt To: " + strings.Join(s.message.to, ", ") + "\r\n")
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

	if err := os.MkdirAll(s.config.QueueDir, 0755); err != nil {
		return err
	}

	s.message.status = StatusQueued
	if err := s.message.Save(s.config); err != nil {
		s.message.status = StatusFailed
		return err
	}

	s.logger.Info("message saved successfully",
		"id", s.message.id,
		"status", s.message.status)
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
