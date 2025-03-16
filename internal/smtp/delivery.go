package smtp

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RetryInfo stores information about delivery attempts
type RetryInfo struct {
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	NextAttempt time.Time `json:"next_attempt"`
	LastError   string    `json:"last_error"`
}

type MessageInfo struct {
	ID         string        `json:"id"`
	From       string        `json:"from"`
	To         []string      `json:"to"`
	Status     MessageStatus `json:"status"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
	Size       int           `json:"size"`        // Size of the message in bytes
	ReceivedAt time.Time     `json:"received_at"` // Time when the message was received
	Retry      RetryInfo     `json:"retry"`       // Retry information
}

// ConnectionPool manages a pool of SMTP connections
type ConnectionPool struct {
	connections map[string][]*textproto.Conn
	mu          sync.Mutex
	maxIdle     int
	idleTimeout time.Duration
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxIdle int, idleTimeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		connections: make(map[string][]*textproto.Conn),
		maxIdle:     maxIdle,
		idleTimeout: idleTimeout,
	}
}

// Get gets a connection from the pool or creates a new one
func (p *ConnectionPool) Get(addr string) (*textproto.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conns, ok := p.connections[addr]; ok && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.connections[addr] = conns[:len(conns)-1]
		return conn, nil
	}

	// No connection in pool, create a new one
	netConn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, err
	}

	return textproto.NewConn(netConn), nil
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(addr string, conn *textproto.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conns, ok := p.connections[addr]; ok {
		if len(conns) >= p.maxIdle {
			conn.Close()
			return
		}
		p.connections[addr] = append(conns, conn)
	} else {
		p.connections[addr] = []*textproto.Conn{conn}
	}
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conns := range p.connections {
		for _, conn := range conns {
			conn.Close()
		}
	}
	p.connections = make(map[string][]*textproto.Conn)
}

// CleanupIdleConnections removes idle connections
func (p *ConnectionPool) CleanupIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Implementation would track connection age and close old ones
	// For simplicity, we'll just clear the pool in this example
	for _, conns := range p.connections {
		for _, conn := range conns {
			conn.Close()
		}
	}
	p.connections = make(map[string][]*textproto.Conn)
}

type DeliveryManager struct {
	config         *Config
	logger         *slog.Logger
	running        bool
	activeMu       sync.Mutex
	activeJobs     map[string]bool
	connectionPool *ConnectionPool
	tlsConfig      *tls.Config
}

func NewDeliveryManager(config *Config) *DeliveryManager {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // Set to true only for testing
		MinVersion:         tls.VersionTLS12,
	}

	return &DeliveryManager{
		config:         config,
		logger:         logger,
		activeJobs:     make(map[string]bool),
		connectionPool: NewConnectionPool(10, 5*time.Minute),
		tlsConfig:      tlsConfig,
	}
}

func (dm *DeliveryManager) Start() {
	dm.running = true
	go dm.processQueue()
	go dm.cleanupConnections()
}

func (dm *DeliveryManager) Stop() {
	dm.running = false
	dm.connectionPool.Close()
}

func (dm *DeliveryManager) cleanupConnections() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for dm.running {
		<-ticker.C
		dm.connectionPool.CleanupIdleConnections()
	}
}

func (dm *DeliveryManager) processQueue() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for dm.running {
		<-ticker.C

		// Process active queue
		dm.processQueueDir(filepath.Join(dm.config.QueueDir, "active"))

		// Process deferred queue (messages that need to be retried)
		dm.processQueueDir(filepath.Join(dm.config.QueueDir, "deferred"))
	}
}

func (dm *DeliveryManager) processQueueDir(queueDir string) {
	files, err := os.ReadDir(queueDir)
	if err != nil {
		dm.logger.Error("failed to read queue directory", "dir", queueDir, "error", err)
		return
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			continue
		}

		msgPath := filepath.Join(queueDir, file.Name())

		// Check if it's time to process this message
		metaPath := msgPath + ".json"
		info, err := dm.loadMetadata(metaPath)
		if err != nil {
			dm.logger.Error("failed to load metadata", "path", metaPath, "error", err)
			continue
		}

		// Skip if it's not time for retry yet
		if info.Status == StatusFailed && time.Now().Before(info.Retry.NextAttempt) {
			continue
		}

		if err := dm.deliverMessage(msgPath); err != nil {
			dm.logger.Error("delivery failed",
				"message_id", file.Name(),
				"error", err)
		}
	}
}

func (dm *DeliveryManager) deliverMessage(path string) error {
	messageID := filepath.Base(path)

	// Atomic job tracking
	dm.activeMu.Lock()
	if dm.activeJobs[messageID] {
		dm.activeMu.Unlock()
		return nil // Already being processed
	}
	dm.activeJobs[messageID] = true
	dm.activeMu.Unlock()

	defer func() {
		dm.activeMu.Lock()
		delete(dm.activeJobs, messageID)
		dm.activeMu.Unlock()
	}()

	// Read message data
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	metaPath := path + ".json"
	info, err := dm.loadMetadata(metaPath)
	if err != nil {
		return err
	}

	// Skip if not in deliverable state
	if info.Status != StatusQueued && info.Status != StatusFailed {
		return nil
	}

	// Update status to delivering
	info.Status = StatusDelivering
	info.UpdatedAt = time.Now()
	if err := dm.saveMetadata(metaPath, info); err != nil {
		return err
	}

	// Get metrics instance
	metrics := GetMetrics()

	// Record message size
	metrics.MessageSize.Observe(float64(len(data)))

	// Attempt delivery with metrics tracking
	deliveryErr := metrics.TrackDeliveryDuration(func() error {
		return dm.attemptDelivery(info, data)
	})

	if deliveryErr != nil {
		// Update retry information with exponential backoff
		info.Status = StatusFailed
		info.Retry.Attempts++
		info.Retry.LastAttempt = time.Now()
		info.Retry.LastError = deliveryErr.Error()

		// Calculate next retry time with exponential backoff
		backoffMinutes := math.Min(float64(info.Retry.Attempts*info.Retry.Attempts*5), 60*24) // Max 24 hours
		info.Retry.NextAttempt = time.Now().Add(time.Duration(backoffMinutes) * time.Minute)

		// Move to deferred queue if not already there
		if !strings.Contains(path, "/deferred/") {
			newPath := filepath.Join(dm.config.QueueDir, "deferred", messageID)
			newMetaPath := newPath + ".json"

			// Save metadata before moving
			if err := dm.saveMetadata(metaPath, info); err != nil {
				dm.logger.Error("Failed to save metadata before move", "error", err)
			}

			// Move the files
			if err := os.Rename(path, newPath); err != nil {
				dm.logger.Error("Failed to move message to deferred queue", "error", err)
			}
			if err := os.Rename(metaPath, newMetaPath); err != nil {
				dm.logger.Error("Failed to move metadata to deferred queue", "error", err)
			}

			// Update metrics
			metrics.MessagesFailed.Inc()

			return deliveryErr
		}

		// Just update metadata if already in deferred queue
		if err := dm.saveMetadata(metaPath, info); err != nil {
			dm.logger.Error("Failed to update metadata after failed delivery", "error", err)
		}

		return deliveryErr
	}

	// Update final status to delivered
	info.Status = StatusDelivered
	info.UpdatedAt = time.Now()
	if err := dm.saveMetadata(metaPath, info); err != nil {
		return err
	}

	// Update metrics
	metrics.MessagesDelivered.Inc()

	// Cleanup message file after successful delivery
	if err := os.Remove(path); err != nil {
		dm.logger.Error("Failed to remove delivered message file", "message_id", messageID, "error", err)
	} else {
		dm.logger.Info("Message file removed after successful delivery", "message_id", messageID)
	}

	// Cleanup metadata file after successful delivery
	if err := os.Remove(metaPath); err != nil {
		dm.logger.Error("Failed to remove metadata file", "message_id", messageID, "error", err)
	} else {
		dm.logger.Info("Metadata file removed after successful delivery", "message_id", messageID)
	}

	return nil
}

func (dm *DeliveryManager) attemptDelivery(info *MessageInfo, data []byte) error {
	if dm.config.DevMode {
		dm.logger.Info("dev mode: simulating delivery",
			"message_id", info.ID,
			"from", info.From,
			"to", info.To)
		return nil
	}

	var lastError error
	for _, recipient := range info.To {
		if err := dm.deliverToRecipient(recipient, info.From, data); err != nil {
			lastError = err
			dm.logger.Error("recipient delivery failed",
				"message_id", info.ID,
				"recipient", recipient,
				"error", err)
			continue
		}
		dm.logger.Info("recipient delivery successful",
			"message_id", info.ID,
			"recipient", recipient)
	}
	return lastError
}

func (dm *DeliveryManager) deliverToRecipient(recipient, from string, data []byte) error {
	parts := strings.Split(recipient, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient address: %s", recipient)
	}
	domain := parts[1]

	// Try the localhost first if it's a local delivery
	if domain == "localhost" || domain == "127.0.0.1" {
		return dm.deliverToHost("localhost", 25, recipient, from, data, false)
	}

	// Try MX records first
	mxRecords, err := net.LookupMX(domain)
	if err == nil && len(mxRecords) > 0 {
		// Try with TLS first (port 587)
		for _, mx := range mxRecords {
			mxHost := strings.TrimSuffix(mx.Host, ".")
			if err := dm.deliverToHost(mxHost, 587, recipient, from, data, true); err == nil {
				return nil
			}
		}

		// Fallback to standard SMTP (port 25)
		for _, mx := range mxRecords {
			mxHost := strings.TrimSuffix(mx.Host, ".")
			if err := dm.deliverToHost(mxHost, 25, recipient, from, data, false); err == nil {
				return nil
			}
		}
	}

	// Fallback to A/AAAA records if no MX records or all MX attempts failed
	dm.logger.Info("no MX records found or all MX attempts failed, trying A/AAAA records", "domain", domain)

	// Try A records
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}

	// Try with TLS first (port 587)
	for _, ip := range ips {
		if err := dm.deliverToHost(ip.String(), 587, recipient, from, data, true); err == nil {
			return nil
		}
	}

	// Fallback to standard SMTP (port 25)
	for _, ip := range ips {
		if err := dm.deliverToHost(ip.String(), 25, recipient, from, data, false); err == nil {
			return nil
		}
	}

	return fmt.Errorf("delivery failed to all possible servers for %s", domain)
}

func (dm *DeliveryManager) deliverToHost(host string, port int, recipient, from string, data []byte, useTLS bool) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	dm.logger.Info("attempting delivery",
		"server", addr,
		"recipient", recipient,
		"tls", useTLS)

	// Get metrics instance
	metrics := GetMetrics()

	// Try to get connection from pool
	var textConn *textproto.Conn
	var conn net.Conn
	var err error

	// For new connections
	if useTLS {
		// For TLS connections, we don't use the pool
		dialer := &net.Dialer{
			Timeout: 30 * time.Second,
		}
		conn, err = dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("connection failed to %s: %v", addr, err)
		}

		// Create text proto client
		textConn = textproto.NewConn(conn)
	} else {
		// Try to get from pool for non-TLS
		textConn, err = dm.connectionPool.Get(addr)
		if err != nil {
			return fmt.Errorf("connection failed to %s: %v", addr, err)
		}
	}

	// Ensure connection is closed or returned to pool
	defer func() {
		if useTLS {
			textConn.Close()
		} else {
			// Return to pool only if it's a non-TLS connection
			dm.connectionPool.Put(addr, textConn)
		}
	}()

	// Read initial greeting
	code, msg, err := textConn.ReadResponse(220)
	if err != nil {
		dm.logger.Error("server greeting error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("server greeting failed: %v", err)
	}
	dm.logger.Info("server greeting",
		"server", addr,
		"code", code,
		"message", msg)

	// If using TLS, upgrade the connection
	if useTLS {
		// Send EHLO
		id, err := textConn.Cmd("EHLO %s", dm.config.Hostname)
		if err != nil {
			return fmt.Errorf("EHLO command failed: %v", err)
		}
		textConn.StartResponse(id)
		code, msg, err = textConn.ReadResponse(250)
		textConn.EndResponse(id)
		if err != nil {
			dm.logger.Error("EHLO error",
				"server", addr,
				"code", code,
				"message", msg,
				"error", err)
			return fmt.Errorf("EHLO failed: %v", err)
		}

		// Start TLS
		id, err = textConn.Cmd("STARTTLS")
		if err != nil {
			return fmt.Errorf("STARTTLS command failed: %v", err)
		}
		textConn.StartResponse(id)
		code, msg, err = textConn.ReadResponse(220)
		textConn.EndResponse(id)
		if err != nil {
			dm.logger.Error("STARTTLS error",
				"server", addr,
				"code", code,
				"message", msg,
				"error", err)
			return fmt.Errorf("STARTTLS failed: %v", err)
		}

		// Upgrade to TLS
		tlsConn := tls.Client(conn, dm.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			dm.logger.Error("TLS handshake error",
				"server", addr,
				"error", err)
			metrics.TLSHandshakeFailures.Inc()
			return fmt.Errorf("TLS handshake failed: %v", err)
		}

		// Update TLS metrics
		metrics.TLSConnections.Inc()

		// Replace the connection with the TLS connection
		textConn.Close()
		textConn = textproto.NewConn(tlsConn)

		// Send EHLO again after TLS upgrade
		id, err = textConn.Cmd("EHLO %s", dm.config.Hostname)
		if err != nil {
			return fmt.Errorf("EHLO after TLS command failed: %v", err)
		}
		textConn.StartResponse(id)
		code, msg, err = textConn.ReadResponse(250)
		textConn.EndResponse(id)
		if err != nil {
			dm.logger.Error("EHLO after TLS error",
				"server", addr,
				"code", code,
				"message", msg,
				"error", err)
			return fmt.Errorf("EHLO after TLS failed: %v", err)
		}
	} else {
		// Send HELO for non-TLS connections
		id, err := textConn.Cmd("HELO %s", dm.config.Hostname)
		if err != nil {
			return fmt.Errorf("HELO command failed: %v", err)
		}
		textConn.StartResponse(id)
		code, msg, err = textConn.ReadResponse(250)
		textConn.EndResponse(id)
		if err != nil {
			dm.logger.Error("HELO error",
				"server", addr,
				"code", code,
				"message", msg,
				"error", err)
			return fmt.Errorf("HELO failed: %v", err)
		}
		dm.logger.Info("HELO response",
			"server", addr,
			"code", code,
			"message", msg)
	}

	// Send MAIL FROM
	id, err := textConn.Cmd("MAIL FROM:<%s>", from)
	if err != nil {
		return fmt.Errorf("MAIL FROM command failed: %v", err)
	}
	textConn.StartResponse(id)
	code, msg, err = textConn.ReadResponse(250)
	textConn.EndResponse(id)
	if err != nil {
		dm.logger.Error("MAIL FROM error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	dm.logger.Info("MAIL FROM response",
		"server", addr,
		"code", code,
		"message", msg)

	// Send RCPT TO
	id, err = textConn.Cmd("RCPT TO:<%s>", recipient)
	if err != nil {
		return fmt.Errorf("RCPT TO command failed: %v", err)
	}
	textConn.StartResponse(id)
	code, msg, err = textConn.ReadResponse(250)
	textConn.EndResponse(id)
	if err != nil {
		dm.logger.Error("RCPT TO error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("RCPT TO failed: %v", err)
	}
	dm.logger.Info("RCPT TO response",
		"server", addr,
		"code", code,
		"message", msg)

	// Send DATA
	id, err = textConn.Cmd("DATA")
	if err != nil {
		return fmt.Errorf("DATA command failed: %v", err)
	}
	textConn.StartResponse(id)
	code, msg, err = textConn.ReadResponse(354)
	textConn.EndResponse(id)
	if err != nil {
		dm.logger.Error("DATA initiation error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("DATA initiation failed: %v", err)
	}
	dm.logger.Info("DATA initiation response",
		"server", addr,
		"code", code,
		"message", msg)

	// Send message content
	id, err = textConn.Cmd(string(data) + "\r\n.")
	if err != nil {
		return fmt.Errorf("sending message content failed: %v", err)
	}
	textConn.StartResponse(id)
	code, msg, err = textConn.ReadResponse(250)
	textConn.EndResponse(id)
	if err != nil {
		dm.logger.Error("message content error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("message content failed: %v", err)
	}
	dm.logger.Info("message content response",
		"server", addr,
		"code", code,
		"message", msg)

	// Send QUIT
	id, err = textConn.Cmd("QUIT")
	if err != nil {
		return fmt.Errorf("QUIT command failed: %v", err)
	}
	textConn.StartResponse(id)
	code, msg, err = textConn.ReadResponse(221)
	textConn.EndResponse(id)
	if err != nil {
		dm.logger.Error("QUIT error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
	} else {
		dm.logger.Info("QUIT response",
			"server", addr,
			"code", code,
			"message", msg)
	}

	dm.logger.Info("delivery successful", "server", addr, "recipient", recipient)
	return nil
}

func (dm *DeliveryManager) loadMetadata(path string) (*MessageInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var info MessageInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (dm *DeliveryManager) saveMetadata(path string, info *MessageInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
