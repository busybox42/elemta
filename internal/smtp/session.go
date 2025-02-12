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
            s.write("250-elemta\r\n")
            s.write("250-SIZE " + strconv.FormatInt(s.config.MaxSize, 10) + "\r\n")
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
            
        default:
            s.logger.Warn("unknown command", "command", cmd)
            s.write("500 Unknown command\r\n")
        }
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