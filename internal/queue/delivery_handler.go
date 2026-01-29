package queue

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// SMTPDeliveryHandler implements DeliveryHandler for SMTP delivery
type SMTPDeliveryHandler struct {
	logger                    *slog.Logger
	timeout                   time.Duration
	retryDNS                  bool
	maxMXLookups              int
	failedQueueRetentionHours int
}

// NewSMTPDeliveryHandler creates a new SMTP delivery handler
func NewSMTPDeliveryHandler(failedQueueRetentionHours int) *SMTPDeliveryHandler {
	return &SMTPDeliveryHandler{
		logger:                    slog.Default().With("component", "smtp-delivery"),
		timeout:                   30 * time.Second,
		retryDNS:                  true,
		maxMXLookups:              3,
		failedQueueRetentionHours: failedQueueRetentionHours,
	}
}

// DeliverMessage attempts to deliver a message via SMTP
func (h *SMTPDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := h.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata attempts to deliver a message via SMTP and returns delivery metadata
func (h *SMTPDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	// Group recipients by domain for efficient delivery
	domainGroups := h.groupRecipientsByDomain(msg.To)

	var lastError error
	delivered := 0
	var firstSuccessfulIP string
	var firstSuccessfulHost string

	for domain, recipients := range domainGroups {
		ip, host, err := h.deliverToDomainWithMetadata(ctx, msg, domain, recipients, content)
		if err != nil {
			h.logger.Error("Failed to deliver to domain",
				"domain", domain,
				"recipients", recipients,
				"error", err)
			lastError = err
		} else {
			delivered += len(recipients)
			h.logger.Info("Successfully delivered to domain",
				"domain", domain,
				"recipients", len(recipients))

			// Capture first successful delivery IP
			if firstSuccessfulIP == "" && ip != "" {
				firstSuccessfulIP = ip
				firstSuccessfulHost = host
			}
		}
	}

	// Create delivery result
	result := &DeliveryResult{
		Success:         delivered > 0,
		DeliveryIP:      firstSuccessfulIP,
		DeliveryHost:    firstSuccessfulHost,
		DeliveryTime:    time.Now(),
		ResponseMessage: fmt.Sprintf("Delivered to %d/%d recipients", delivered, len(msg.To)),
	}

	// If at least one domain succeeded, consider it a partial success
	if delivered > 0 && delivered < len(msg.To) {
		result.Error = fmt.Errorf("partial delivery: %d/%d recipients delivered, last error: %v",
			delivered, len(msg.To), lastError)
		return result, result.Error
	}

	// If no recipients were delivered, return the last error
	if delivered == 0 {
		if lastError != nil {
			result.Error = lastError
			return result, lastError
		}
		result.Error = fmt.Errorf("delivery failed for all recipients")
		return result, result.Error
	}

	// All recipients delivered successfully
	return result, nil
}

// groupRecipientsByDomain groups email recipients by their domain
func (h *SMTPDeliveryHandler) groupRecipientsByDomain(recipients []string) map[string][]string {
	groups := make(map[string][]string)

	for _, recipient := range recipients {
		parts := strings.Split(recipient, "@")
		if len(parts) != 2 {
			h.logger.Warn("Invalid email address", "recipient", recipient)
			continue
		}

		domain := strings.ToLower(parts[1])
		groups[domain] = append(groups[domain], recipient)
	}

	return groups
}

// TODO: Implement direct SMTP delivery functionality
// deliverToDomain delivers messages to all recipients in a specific domain
/*
func (h *SMTPDeliveryHandler) deliverToDomain(ctx context.Context, msg Message, domain string, recipients []string, content []byte) error {
	_, _, err := h.deliverToDomainWithMetadata(ctx, msg, domain, recipients, content)
	return err
}
*/

// deliverToDomainWithMetadata delivers messages to all recipients in a specific domain and returns delivery metadata
func (h *SMTPDeliveryHandler) deliverToDomainWithMetadata(ctx context.Context, msg Message, domain string, recipients []string, content []byte) (string, string, error) {
	// Look up MX records for the domain
	mxRecords, err := h.lookupMX(ctx, domain)
	if err != nil {
		return "", "", fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		return "", "", fmt.Errorf("no MX records found for domain %s", domain)
	}

	// Try each MX record in order of preference
	var lastError error
	for _, mx := range mxRecords {
		ip, host, err := h.attemptDeliveryToHostWithMetadata(ctx, mx.Host, msg, recipients, content)
		if err != nil {
			h.logger.Warn("Delivery failed to MX host",
				"host", mx.Host,
				"priority", mx.Pref,
				"error", err)
			lastError = err
			continue
		}

		// Success - return the IP and host
		return ip, host, nil
	}

	return "", "", fmt.Errorf("delivery failed to all MX hosts for domain %s: %w", domain, lastError)
}

// lookupMX performs MX record lookup with retries
func (h *SMTPDeliveryHandler) lookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	var mxRecords []*net.MX
	var err error

	for attempt := 0; attempt < h.maxMXLookups; attempt++ {
		mxRecords, err = net.LookupMX(domain)
		if err == nil {
			break
		}

		h.logger.Debug("MX lookup attempt failed",
			"domain", domain,
			"attempt", attempt+1,
			"error", err)

		// Wait before retry (with context cancellation check)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
			// Continue to next attempt
		}
	}

	return mxRecords, err
}

// attemptDeliveryToHost attempts delivery to a specific SMTP host
/*
func (h *SMTPDeliveryHandler) attemptDeliveryToHost(ctx context.Context, host string, msg Message, recipients []string, content []byte) error {
	_, _, err := h.attemptDeliveryToHostWithMetadata(ctx, host, msg, recipients, content)
	return err
}
*/

// attemptDeliveryToHostWithMetadata attempts delivery to a specific SMTP host and returns delivery metadata
func (h *SMTPDeliveryHandler) attemptDeliveryToHostWithMetadata(ctx context.Context, host string, msg Message, recipients []string, content []byte) (string, string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Determine port (try 25, fallback ports)
	ports := []string{"25", "587", "2525"}

	var lastError error
	for _, port := range ports {
		address := net.JoinHostPort(host, port)

		ip, hostIP, err := h.deliverToAddressWithMetadata(ctx, address, msg, recipients, content)
		if err != nil {
			h.logger.Debug("Delivery attempt failed",
				"address", address,
				"error", err)
			lastError = err
			continue
		}

		// Success - return the IP and host
		return ip, hostIP, nil
	}

	return "", "", fmt.Errorf("delivery failed to all ports for host %s: %w", host, lastError)
}

// deliverToAddress performs the actual SMTP delivery to a specific address
/*
func (h *SMTPDeliveryHandler) deliverToAddress(ctx context.Context, address string, msg Message, recipients []string, content []byte) error {
	_, _, err := h.deliverToAddressWithMetadata(ctx, address, msg, recipients, content)
	return err
}
*/

// deliverToAddressWithMetadata performs the actual SMTP delivery to a specific address and returns delivery metadata
func (h *SMTPDeliveryHandler) deliverToAddressWithMetadata(ctx context.Context, address string, msg Message, recipients []string, content []byte) (string, string, error) {
	h.logger.Debug("Attempting SMTP delivery",
		"address", address,
		"from", msg.From,
		"recipients", recipients)

	// Connect to SMTP server and capture connection info
	client, conn, err := h.connectSMTPWithMetadata(ctx, address)
	if err != nil {
		return "", "", fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() { _ = client.Close() }()

	// Set sender (strip angle brackets if present to avoid parameter issues)
	sender := strings.Trim(msg.From, "<>")

	// Use the Text() method to get the underlying textproto connection
	// and send raw MAIL FROM without ESMTP extensions
	text := client.Text
	if text == nil {
		// Fallback to standard Mail() if we can't get the text connection
		if err := client.Mail(sender); err != nil {
			return "", "", fmt.Errorf("MAIL FROM failed: %w", err)
		}
	} else {
		// Send raw MAIL FROM command without SIZE or other extensions
		mailCmd := fmt.Sprintf("MAIL FROM:<%s>", sender)
		id, err := text.Cmd(mailCmd)
		if err != nil {
			return "", "", fmt.Errorf("MAIL FROM command failed: %w", err)
		}
		text.StartResponse(id)
		defer text.EndResponse(id)
		_, _, err = text.ReadResponse(250)
		if err != nil {
			return "", "", fmt.Errorf("MAIL FROM failed: %w", err)
		}
	}

	// Set recipients
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return "", "", fmt.Errorf("RCPT TO failed for %s: %w", recipient, err)
		}
	}

	// Send message data
	writer, err := client.Data()
	if err != nil {
		return "", "", fmt.Errorf("DATA command failed: %w", err)
	}

	if _, err := writer.Write(content); err != nil {
		return "", "", fmt.Errorf("failed to write message data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close data writer: %w", err)
	}

	// Quit gracefully
	if err := client.Quit(); err != nil {
		h.logger.Warn("QUIT command failed", "error", err)
	}

	h.logger.Info("SMTP delivery successful",
		"address", address,
		"from", msg.From,
		"recipients", len(recipients))

	// Capture delivery IP and host from connection
	deliveryIP := ""
	deliveryHost := ""
	if conn != nil {
		remoteAddr := conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			deliveryIP = host
			deliveryHost = host
		} else {
			deliveryIP = remoteAddr
			deliveryHost = remoteAddr
		}
	}

	return deliveryIP, deliveryHost, nil
}

// connectSMTP establishes a connection to the SMTP server
/*
func (h *SMTPDeliveryHandler) connectSMTP(ctx context.Context, address string) (*smtp.Client, error) {
	client, _, err := h.connectSMTPWithMetadata(ctx, address)
	return client, err
}
*/

// connectSMTPWithMetadata establishes a connection to the SMTP server and returns connection metadata
func (h *SMTPDeliveryHandler) connectSMTPWithMetadata(ctx context.Context, address string) (*smtp.Client, net.Conn, error) {
	// Create dialer with context support
	dialer := &net.Dialer{
		Timeout: h.timeout,
	}

	// Dial with context
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	// Create SMTP client
	client, err := smtp.NewClient(conn, strings.Split(address, ":")[0])
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Send EHLO/HELO
	hostname := "localhost"
	if err := client.Hello(hostname); err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("HELLO command failed: %w", err)
	}

	return client, conn, nil
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (h *SMTPDeliveryHandler) GetFailedQueueRetentionHours() int {
	return h.failedQueueRetentionHours
}

// MockDeliveryHandler implements DeliveryHandler for testing
type MockDeliveryHandler struct {
	logger                    *slog.Logger
	shouldFail                bool
	deliveries                []Message
	mutex                     sync.Mutex
	failedQueueRetentionHours int
}

// NewMockDeliveryHandler creates a new mock delivery handler for testing
func NewMockDeliveryHandler(failedQueueRetentionHours int) *MockDeliveryHandler {
	return &MockDeliveryHandler{
		logger:                    slog.Default().With("component", "mock-delivery"),
		deliveries:                make([]Message, 0),
		failedQueueRetentionHours: failedQueueRetentionHours,
	}
}

// TemporaryError represents a temporary failure that should be retried
type TemporaryError struct {
	msg string
}

func (e *TemporaryError) Error() string {
	return e.msg
}

func (e *TemporaryError) Temporary() bool {
	return true
}

// DeliverMessage simulates message delivery
func (m *MockDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	_, err := m.DeliverMessageWithMetadata(ctx, msg, content)
	return err
}

// DeliverMessageWithMetadata simulates message delivery and returns delivery metadata
func (m *MockDeliveryHandler) DeliverMessageWithMetadata(ctx context.Context, msg Message, content []byte) (*DeliveryResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.shouldFail {
		return &DeliveryResult{
			Success:         false,
			Error:           &TemporaryError{msg: "mock delivery failure"},
			DeliveryTime:    time.Now(),
			ResponseMessage: "mock delivery failed",
		}, &TemporaryError{msg: "mock delivery failure"}
	}

	// Simulate network delay
	select {
	case <-ctx.Done():
		return &DeliveryResult{
			Success:         false,
			Error:           ctx.Err(),
			DeliveryTime:    time.Now(),
			ResponseMessage: "context cancelled",
		}, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	m.deliveries = append(m.deliveries, msg)
	m.logger.Info("Mock delivery successful", "message_id", msg.ID)

	return &DeliveryResult{
		Success:         true,
		Error:           nil,
		DeliveryIP:      "127.0.0.1",
		DeliveryHost:    "localhost",
		DeliveryTime:    time.Now(),
		ResponseMessage: "mock delivery successful",
	}, nil
}

// SetShouldFail configures the mock to fail deliveries
func (m *MockDeliveryHandler) SetShouldFail(fail bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.shouldFail = fail
}

// GetFailedQueueRetentionHours returns the failed queue retention setting
func (m *MockDeliveryHandler) GetFailedQueueRetentionHours() int {
	return m.failedQueueRetentionHours
}

// GetDeliveries returns all delivered messages
func (m *MockDeliveryHandler) GetDeliveries() []Message {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	result := make([]Message, len(m.deliveries))
	copy(result, m.deliveries)
	return result
}

// Reset clears all delivery history
func (m *MockDeliveryHandler) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.deliveries = m.deliveries[:0]
}
