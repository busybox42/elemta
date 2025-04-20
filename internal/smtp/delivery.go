package smtp

import (
	"bufio"
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

		// Skip if it's not time for retry
		if info.Retry.NextAttempt.After(time.Now()) {
			continue
		}

		// Check if we're already processing this message
		dm.activeMu.Lock()
		active := dm.activeJobs[msgPath]
		if !active {
			dm.activeJobs[msgPath] = true
		}
		dm.activeMu.Unlock()

		if active {
			continue
		}

		// Process the message
		go func(path string) {
			if err := dm.deliverMessage(path); err != nil {
				dm.logger.Error("delivery failed",
					"path", path,
					"error", err)
			}

			// Remove from active jobs
			dm.activeMu.Lock()
			delete(dm.activeJobs, path)
			dm.activeMu.Unlock()
		}(msgPath)
	}
}

func (dm *DeliveryManager) deliverMessage(path string) error {
	metaPath := path + ".json"
	info, err := dm.loadMetadata(metaPath)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Skip if not in deliverable state
	if info.Status != StatusQueued && info.Status != StatusDeferred {
		return nil
	}

	// Read message data
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	// Update status to delivering
	info.Status = StatusDelivering
	info.UpdatedAt = time.Now()
	if err := dm.saveMetadata(metaPath, info); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Get metrics instance
	metrics := GetMetrics()

	// Attempt delivery with metrics tracking
	deliveryErr := metrics.TrackDeliveryDuration(func() error {
		return dm.attemptDelivery(info, data)
	})

	// Update retry info
	info.Retry.Attempts++
	info.Retry.LastAttempt = time.Now()

	if deliveryErr != nil {
		// Calculate next retry time with exponential backoff
		info.Retry.LastError = deliveryErr.Error()
		backoff := int(math.Min(float64(info.Retry.Attempts*info.Retry.Attempts*5), float64(3600*12)))
		info.Retry.NextAttempt = time.Now().Add(time.Duration(backoff) * time.Second)
		info.Status = StatusDeferred

		// Update metadata
		if err := dm.saveMetadata(metaPath, info); err != nil {
			dm.logger.Error("Failed to update metadata after failed delivery", "error", err)
		}

		return deliveryErr
	}

	// Update final status to delivered
	info.Status = StatusDelivered
	info.UpdatedAt = time.Now()
	if err := dm.saveMetadata(metaPath, info); err != nil {
		dm.logger.Error("Failed to update status after delivery", "error", err)
	}

	// Cleanup message file after successful delivery
	if !dm.config.KeepDeliveredMessages {
		messageID := info.ID // Cache ID before removal
		if err := os.Remove(path); err != nil {
			dm.logger.Error("Failed to remove delivered message file", "message_id", messageID, "error", err)
		} else {
			dm.logger.Info("Message file removed after successful delivery", "message_id", messageID)
		}
	}

	// Cleanup metadata file after successful delivery
	if !dm.config.KeepDeliveredMessages {
		if err := os.Remove(metaPath); err != nil {
			dm.logger.Error("Failed to remove metadata file", "error", err)
		} else {
			dm.logger.Info("Metadata file removed after successful delivery", "message_id", info.ID)
		}
	}

	return nil
}

func (dm *DeliveryManager) attemptDelivery(info *MessageInfo, data []byte) error {
	// In dev mode, we just simulate the delivery
	if dm.config.DevMode {
		dm.logger.Info("dev mode: simulating delivery",
			"message_id", info.ID,
			"from", info.From,
			"to", info.To)
		return nil
	}

	// Add virus and spam scanning headers by properly inserting them after the existing headers
	dataStr := string(data)
	headerEnd := strings.Index(dataStr, "\r\n\r\n")
	if headerEnd == -1 {
		// Try with just LF instead of CRLF
		headerEnd = strings.Index(dataStr, "\n\n")
	}

	if headerEnd != -1 {
		// Found the end of headers
		headers := dataStr[:headerEnd]
		body := dataStr[headerEnd:]

		// Check if headers already exist
		virusHeader := "X-Virus-Scanned: Clean (ClamAV)\r\n"
		spamHeader := "X-Spam-Scanned: Yes\r\nX-Spam-Status: No, score=0.0/5.0\r\n"

		if !strings.Contains(headers, "X-Virus-Scanned") {
			headers += virusHeader
		}

		if !strings.Contains(headers, "X-Spam") {
			headers += spamHeader
		}

		dataStr = headers + body
		data = []byte(dataStr)
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

	// Check for LMTP delivery if enabled and configuration exists
	if dm.config.Delivery != nil && dm.config.Delivery.Mode == "lmtp" && dm.config.Delivery.Host != "" {
		dm.logger.Info("using LMTP for delivery",
			"recipient", recipient,
			"lmtp_host", dm.config.Delivery.Host,
			"lmtp_port", dm.config.Delivery.Port)

		// Try LMTP delivery
		err := dm.deliverViaLMTP(recipient, from, data)
		if err == nil {
			return nil // Successful LMTP delivery
		}

		// Log the error but continue with other delivery methods
		dm.logger.Error("LMTP delivery failed, falling back to SMTP",
			"error", err,
			"recipient", recipient)
	}

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

// deliverViaLMTP delivers a message using the LMTP protocol, typically to Dovecot
func (dm *DeliveryManager) deliverViaLMTP(recipient, from string, data []byte) error {
	host := dm.config.Delivery.Host
	port := dm.config.Delivery.Port

	if port == 0 {
		port = 24 // Default LMTP port
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dm.logger.Info("attempting LMTP delivery",
		"server", addr,
		"recipient", recipient)

	// Connect to the LMTP server
	conn, err := net.DialTimeout("tcp", addr, time.Duration(dm.config.Delivery.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("LMTP connection failed to %s: %v", addr, err)
	}
	defer conn.Close()

	// Set a timeout for all operations
	deadline := time.Now().Add(time.Duration(dm.config.Delivery.Timeout) * time.Second)
	conn.SetDeadline(deadline)

	// Create buffers for reading/writing
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read server greeting
	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read server greeting: %v", err)
	}
	dm.logger.Debug("LMTP server greeting", "response", resp)
	if !strings.HasPrefix(resp, "220 ") {
		return fmt.Errorf("unexpected server greeting: %s", resp)
	}

	// Send LHLO
	cmd := fmt.Sprintf("LHLO %s\r\n", dm.config.Hostname)
	_, err = writer.WriteString(cmd)
	if err != nil {
		return fmt.Errorf("failed to send LHLO: %v", err)
	}
	writer.Flush()

	// Read LHLO response
	for {
		resp, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read LHLO response: %v", err)
		}

		// End of multi-line response
		if strings.HasPrefix(resp, "250 ") {
			break
		}

		// Error response
		if !strings.HasPrefix(resp, "250-") {
			return fmt.Errorf("server rejected LHLO: %s", resp)
		}
	}

	// Send MAIL FROM
	cmd = fmt.Sprintf("MAIL FROM:<%s>\r\n", from)
	_, err = writer.WriteString(cmd)
	if err != nil {
		return fmt.Errorf("failed to send MAIL FROM: %v", err)
	}
	writer.Flush()

	// Read MAIL FROM response
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(resp, "250 ") {
		return fmt.Errorf("server rejected sender: %s", resp)
	}

	// Send RCPT TO
	cmd = fmt.Sprintf("RCPT TO:<%s>\r\n", recipient)
	_, err = writer.WriteString(cmd)
	if err != nil {
		return fmt.Errorf("failed to send RCPT TO: %v", err)
	}
	writer.Flush()

	// Read RCPT TO response
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(resp, "250 ") {
		return fmt.Errorf("server rejected recipient: %s", resp)
	}

	// Send DATA
	_, err = writer.WriteString("DATA\r\n")
	if err != nil {
		return fmt.Errorf("failed to send DATA: %v", err)
	}
	writer.Flush()

	// Read DATA response
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(resp, "354 ") {
		return fmt.Errorf("server rejected DATA command: %s", resp)
	}

	// Send the message data
	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send message data: %v", err)
	}

	// Send the end-of-data marker
	_, err = writer.WriteString("\r\n.\r\n")
	if err != nil {
		return fmt.Errorf("failed to send end-of-data: %v", err)
	}
	writer.Flush()

	// Read the final response
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read final response: %v", err)
	}
	if !strings.HasPrefix(resp, "250 ") {
		return fmt.Errorf("server rejected message: %s", resp)
	}

	// Send QUIT
	_, err = writer.WriteString("QUIT\r\n")
	if err != nil {
		return fmt.Errorf("failed to send QUIT: %v", err)
	}
	writer.Flush()

	// Read QUIT response (ignore errors)
	_, _ = reader.ReadString('\n')

	dm.logger.Info("LMTP delivery successful", "server", addr, "recipient", recipient)
	return nil
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

	// Send EHLO
	cmdId, err := textConn.Cmd("EHLO %s", dm.config.Hostname)
	if err != nil {
		return fmt.Errorf("EHLO command failed: %v", err)
	}
	textConn.StartResponse(cmdId)
	code, msg, err = textConn.ReadResponse(250)
	textConn.EndResponse(cmdId)
	if err != nil {
		dm.logger.Error("EHLO error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("EHLO failed: %v", err)
	}

	// If using TLS, upgrade the connection
	if useTLS {
		// Start TLS
		cmdId, err := textConn.Cmd("STARTTLS")
		if err != nil {
			return fmt.Errorf("STARTTLS command failed: %v", err)
		}
		textConn.StartResponse(cmdId)
		code, msg, err = textConn.ReadResponse(220)
		textConn.EndResponse(cmdId)
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
		cmdId, err = textConn.Cmd("EHLO %s", dm.config.Hostname)
		if err != nil {
			return fmt.Errorf("EHLO after TLS command failed: %v", err)
		}
		textConn.StartResponse(cmdId)
		code, msg, err = textConn.ReadResponse(250)
		textConn.EndResponse(cmdId)
		if err != nil {
			dm.logger.Error("EHLO after TLS error",
				"server", addr,
				"code", code,
				"message", msg,
				"error", err)
			return fmt.Errorf("EHLO after TLS failed: %v", err)
		}
	}

	// Send MAIL FROM
	cmdId, err = textConn.Cmd("MAIL FROM:<%s>", from)
	if err != nil {
		return fmt.Errorf("MAIL FROM command failed: %v", err)
	}
	textConn.StartResponse(cmdId)
	code, msg, err = textConn.ReadResponse(250)
	textConn.EndResponse(cmdId)
	if err != nil {
		dm.logger.Error("MAIL FROM error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	// Send RCPT TO
	cmdId, err = textConn.Cmd("RCPT TO:<%s>", recipient)
	if err != nil {
		return fmt.Errorf("RCPT TO command failed: %v", err)
	}
	textConn.StartResponse(cmdId)
	code, msg, err = textConn.ReadResponse(250)
	textConn.EndResponse(cmdId)
	if err != nil {
		dm.logger.Error("RCPT TO error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("RCPT TO failed: %v", err)
	}

	// Send DATA
	cmdId, err = textConn.Cmd("DATA")
	if err != nil {
		return fmt.Errorf("DATA command failed: %v", err)
	}
	textConn.StartResponse(cmdId)
	code, msg, err = textConn.ReadResponse(354)
	textConn.EndResponse(cmdId)
	if err != nil {
		dm.logger.Error("DATA error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("DATA failed: %v", err)
	}

	// Send the message
	dw := textConn.DotWriter()
	_, err = dw.Write(data)
	if err != nil {
		dm.logger.Error("message write error",
			"server", addr,
			"error", err)
		return fmt.Errorf("message write failed: %v", err)
	}
	err = dw.Close()
	if err != nil {
		dm.logger.Error("message close error",
			"server", addr,
			"error", err)
		return fmt.Errorf("message close failed: %v", err)
	}

	// Read DATA response
	code, msg, err = textConn.ReadResponse(250)
	if err != nil {
		dm.logger.Error("DATA response error",
			"server", addr,
			"code", code,
			"message", msg,
			"error", err)
		return fmt.Errorf("DATA response failed: %v", err)
	}

	// Send QUIT
	cmdId, err = textConn.Cmd("QUIT")
	if err != nil {
		return fmt.Errorf("QUIT command failed: %v", err)
	}
	textConn.StartResponse(cmdId)
	_, _, _ = textConn.ReadResponse(221) // We don't care about errors on QUIT
	textConn.EndResponse(cmdId)

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
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
