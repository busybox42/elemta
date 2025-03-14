package smtp

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elemta/elemta/internal/common"
	ctx "github.com/elemta/elemta/internal/context"
)

// Command represents an SMTP command
type Command string

const (
	// SMTP commands as defined in RFC 5321
	CmdHelo     Command = "HELO"
	CmdEhlo     Command = "EHLO"
	CmdMailFrom Command = "MAIL FROM"
	CmdRcptTo   Command = "RCPT TO"
	CmdData     Command = "DATA"
	CmdRset     Command = "RSET"
	CmdVrfy     Command = "VRFY"
	CmdExpn     Command = "EXPN"
	CmdHelp     Command = "HELP"
	CmdNoop     Command = "NOOP"
	CmdQuit     Command = "QUIT"
	CmdStartTLS Command = "STARTTLS"
	CmdAuth     Command = "AUTH"

	// Custom commands
	CmdXDebug Command = "XDEBUG"
)

// ParseCommand parses a command from a string
func ParseCommand(line string) (Command, string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", errors.New("empty command")
	}

	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])

	var args string
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	switch cmd {
	case string(CmdHelo), string(CmdEhlo), string(CmdRset), string(CmdVrfy),
		string(CmdExpn), string(CmdHelp), string(CmdNoop), string(CmdQuit),
		string(CmdStartTLS), string(CmdAuth), string(CmdXDebug):
		return Command(cmd), args, nil
	case "MAIL":
		if strings.HasPrefix(strings.ToUpper(args), "FROM:") {
			return CmdMailFrom, args, nil
		}
	case "RCPT":
		if strings.HasPrefix(strings.ToUpper(args), "TO:") {
			return CmdRcptTo, args, nil
		}
	}

	if cmd == string(CmdData) {
		return CmdData, args, nil
	}

	return "", "", fmt.Errorf("unknown command: %s", cmd)
}

// Transition attempts to transition the session to a new state based on the command
func Transition(session *common.Session, cmd Command, args string) (common.State, error) {
	session.Mu.Lock()
	defer session.Mu.Unlock()

	session.LastActivity = time.Now()

	switch cmd {
	case CmdHelo, CmdEhlo:
		// HELO/EHLO can be issued at any time to reset the session
		session.State = common.StateHelo
		session.MailFrom = ""
		session.RcptTo = nil
		session.Data = nil
		session.Hostname = args
		return session.State, nil

	case CmdRset:
		// RSET can be issued at any time to reset the session
		session.State = common.StateHelo
		session.MailFrom = ""
		session.RcptTo = nil
		session.Data = nil
		return session.State, nil

	case CmdMailFrom:
		// MAIL FROM can only be issued after HELO/EHLO
		if session.State != common.StateHelo {
			return session.State, fmt.Errorf("out of sequence command: %s", cmd)
		}
		// Parse the email address from the args
		addr, err := parseAddress(args)
		if err != nil {
			return session.State, err
		}
		session.MailFrom = addr
		session.State = common.StateMailFrom
		return session.State, nil

	case CmdRcptTo:
		// RCPT TO can only be issued after MAIL FROM or another RCPT TO
		if session.State != common.StateMailFrom && session.State != common.StateRcptTo {
			return session.State, fmt.Errorf("out of sequence command: %s", cmd)
		}
		// Parse the email address from the args
		addr, err := parseAddress(args)
		if err != nil {
			return session.State, err
		}
		session.RcptTo = append(session.RcptTo, addr)
		session.State = common.StateRcptTo
		return session.State, nil

	case CmdData:
		// DATA can only be issued after at least one RCPT TO
		if session.State != common.StateRcptTo {
			return session.State, fmt.Errorf("out of sequence command: %s", cmd)
		}
		session.State = common.StateData
		return session.State, nil

	case CmdQuit:
		// QUIT can be issued at any time
		session.State = common.StateQuit
		return session.State, nil

	case CmdNoop, CmdHelp, CmdXDebug:
		// These commands don't change the state
		return session.State, nil

	case CmdStartTLS:
		// STARTTLS can only be issued after HELO/EHLO and before MAIL FROM
		if session.State != common.StateHelo {
			return session.State, fmt.Errorf("out of sequence command: %s", cmd)
		}
		if session.TLSEnabled {
			return session.State, errors.New("TLS already enabled")
		}
		// State doesn't change, but we'll set TLSEnabled after handshake
		return session.State, nil

	case CmdAuth:
		// AUTH can only be issued after HELO/EHLO and before MAIL FROM
		if session.State != common.StateHelo {
			return session.State, fmt.Errorf("out of sequence command: %s", cmd)
		}
		// Authentication will be handled by the caller
		return session.State, nil

	default:
		return session.State, fmt.Errorf("unknown command: %s", cmd)
	}
}

// Helper function to parse email addresses from MAIL FROM and RCPT TO commands
func parseAddress(args string) (string, error) {
	// Simple parsing for now, will be enhanced later
	start := strings.Index(args, "<")
	end := strings.Index(args, ">")

	if start == -1 || end == -1 || start >= end {
		return "", fmt.Errorf("invalid email address format: %s", args)
	}

	addr := strings.TrimSpace(args[start+1 : end])
	if addr == "" {
		return "", errors.New("empty email address")
	}

	return addr, nil
}

// SessionPool implements a lock-free session pool using sync.Pool
var SessionPool = sync.Pool{
	New: func() interface{} {
		return &common.Session{
			Extensions: make(map[string]bool),
			Buffer:     make([]byte, 0, 4096),
		}
	},
}

// GetSession gets a session from the pool
func GetSession(id string, clientIP string) *common.Session {
	session := SessionPool.Get().(*common.Session)
	session.ID = id
	session.State = common.StateInit
	session.StartTime = time.Now()
	session.LastActivity = time.Now()
	session.ClientIP = clientIP
	session.Secure = false
	session.Authenticated = false
	session.Hostname = ""
	session.MailFrom = ""
	session.RcptTo = nil
	session.Data = nil
	session.TLSEnabled = false

	// Clear extensions map but reuse it
	for k := range session.Extensions {
		delete(session.Extensions, k)
	}

	// Clear context but reuse it
	if session.Context != nil {
		session.Context.Clear()
	} else {
		session.Context = ctx.NewContext()
	}

	return session
}

// ReleaseSession returns a session to the pool
func ReleaseSession(s *common.Session) {
	// Clear sensitive data
	s.MailFrom = ""
	s.RcptTo = nil
	s.Data = nil
	s.Buffer = s.Buffer[:0]

	// Clear context
	if s.Context != nil {
		s.Context.Clear()
	}

	SessionPool.Put(s)
}
