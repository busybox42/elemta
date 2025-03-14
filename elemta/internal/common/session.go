package common

import (
	"sync"
	"time"

	"github.com/elemta/elemta/internal/context"
)

// State represents the current state of the SMTP session
type State int

const (
	// SMTP states as defined in RFC 5321
	StateInit State = iota
	StateHelo
	StateMailFrom
	StateRcptTo
	StateData
	StateQuit
)

// StateNames maps state values to their string representations
var StateNames = map[State]string{
	StateInit:     "INIT",
	StateHelo:     "HELO/EHLO",
	StateMailFrom: "MAIL FROM",
	StateRcptTo:   "RCPT TO",
	StateData:     "DATA",
	StateQuit:     "QUIT",
}

// String returns the string representation of the state
func (s State) String() string {
	return StateNames[s]
}

// Session represents an SMTP session
type Session struct {
	ID            string
	State         State
	Hostname      string
	MailFrom      string
	RcptTo        []string
	Data          []byte
	Secure        bool
	Authenticated bool
	ClientIP      string
	ClientName    string
	StartTime     time.Time
	LastActivity  time.Time
	Extensions    map[string]bool
	TLSEnabled    bool
	Context       *context.Context

	// Performance optimizations
	Buffer []byte
	Mu     sync.Mutex // Protects session state
}

// NewSession creates a new SMTP session
func NewSession(id string, clientIP string) *Session {
	return &Session{
		ID:           id,
		State:        StateInit,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		ClientIP:     clientIP,
		Extensions:   make(map[string]bool),
		Buffer:       make([]byte, 0, 4096), // Pre-allocate buffer to reduce allocations
		Context:      context.NewContext(),  // Initialize context
	}
}

// Reset resets the session to the initial state after HELO/EHLO
func (s *Session) Reset() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.State = StateHelo
	s.MailFrom = ""
	s.RcptTo = nil
	s.Data = nil
	s.LastActivity = time.Now()

	// Reuse buffer to avoid allocations
	s.Buffer = s.Buffer[:0]
}

// AppendData appends data to the session's data buffer
func (s *Session) AppendData(data []byte) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.Buffer = append(s.Buffer, data...)
}

// GetBuffer returns a copy of the session's data buffer
func (s *Session) GetBuffer() []byte {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	buf := make([]byte, len(s.Buffer))
	copy(buf, s.Buffer)
	return buf
}

// ClearBuffer clears the session's data buffer
func (s *Session) ClearBuffer() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.Buffer = s.Buffer[:0]
}

// FinalizeData finalizes the data phase and returns the complete message
func (s *Session) FinalizeData() []byte {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	// Copy buffer to avoid race conditions
	s.Data = make([]byte, len(s.Buffer))
	copy(s.Data, s.Buffer)

	// Reset buffer for reuse
	s.Buffer = s.Buffer[:0]

	// Return to HELO state
	s.State = StateHelo

	return s.Data
}
