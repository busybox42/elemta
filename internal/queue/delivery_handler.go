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
	logger       *slog.Logger
	timeout      time.Duration
	retryDNS     bool
	maxMXLookups int
}

// NewSMTPDeliveryHandler creates a new SMTP delivery handler
func NewSMTPDeliveryHandler() *SMTPDeliveryHandler {
	return &SMTPDeliveryHandler{
		logger:       slog.Default().With("component", "smtp-delivery"),
		timeout:      30 * time.Second,
		retryDNS:     true,
		maxMXLookups: 3,
	}
}

// DeliverMessage attempts to deliver a message via SMTP
func (h *SMTPDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	// Group recipients by domain for efficient delivery
	domainGroups := h.groupRecipientsByDomain(msg.To)

	var lastError error
	delivered := 0

	for domain, recipients := range domainGroups {
		if err := h.deliverToDomain(ctx, msg, domain, recipients, content); err != nil {
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
		}
	}

	// If at least one domain succeeded, consider it a partial success
	if delivered > 0 && delivered < len(msg.To) {
		return fmt.Errorf("partial delivery: %d/%d recipients delivered, last error: %v",
			delivered, len(msg.To), lastError)
	}

	// If no recipients were delivered, return the last error
	if delivered == 0 {
		if lastError != nil {
			return lastError
		}
		return fmt.Errorf("delivery failed for all recipients")
	}

	// All recipients delivered successfully
	return nil
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

// deliverToDomain delivers messages to all recipients in a specific domain
func (h *SMTPDeliveryHandler) deliverToDomain(ctx context.Context, msg Message, domain string, recipients []string, content []byte) error {
	// Look up MX records for the domain
	mxRecords, err := h.lookupMX(ctx, domain)
	if err != nil {
		return fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for domain %s", domain)
	}

	// Try each MX record in order of preference
	var lastError error
	for _, mx := range mxRecords {
		if err := h.attemptDeliveryToHost(ctx, mx.Host, msg, recipients, content); err != nil {
			h.logger.Warn("Delivery failed to MX host",
				"host", mx.Host,
				"priority", mx.Pref,
				"error", err)
			lastError = err
			continue
		}

		// Success
		return nil
	}

	return fmt.Errorf("delivery failed to all MX hosts for domain %s: %w", domain, lastError)
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
func (h *SMTPDeliveryHandler) attemptDeliveryToHost(ctx context.Context, host string, msg Message, recipients []string, content []byte) error {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Determine port (try 25, fallback ports)
	ports := []string{"25", "587", "2525"}

	var lastError error
	for _, port := range ports {
		address := net.JoinHostPort(host, port)

		if err := h.deliverToAddress(ctx, address, msg, recipients, content); err != nil {
			h.logger.Debug("Delivery attempt failed",
				"address", address,
				"error", err)
			lastError = err
			continue
		}

		// Success
		return nil
	}

	return fmt.Errorf("delivery failed to all ports for host %s: %w", host, lastError)
}

// deliverToAddress performs the actual SMTP delivery to a specific address
func (h *SMTPDeliveryHandler) deliverToAddress(ctx context.Context, address string, msg Message, recipients []string, content []byte) error {
	h.logger.Debug("Attempting SMTP delivery",
		"address", address,
		"from", msg.From,
		"recipients", recipients)

	// Connect to SMTP server
	client, err := h.connectSMTP(ctx, address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() { _ = client.Close() }()

	// Set sender
	if err := client.Mail(msg.From); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set recipients
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", recipient, err)
		}
	}

	// Send message data
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	// Quit gracefully
	if err := client.Quit(); err != nil {
		h.logger.Warn("QUIT command failed", "error", err)
	}

	h.logger.Info("SMTP delivery successful",
		"address", address,
		"from", msg.From,
		"recipients", len(recipients))

	return nil
}

// connectSMTP establishes a connection to the SMTP server
func (h *SMTPDeliveryHandler) connectSMTP(ctx context.Context, address string) (*smtp.Client, error) {
	// Create dialer with context support
	dialer := &net.Dialer{
		Timeout: h.timeout,
	}

	// Dial with context
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	// Create SMTP client
	client, err := smtp.NewClient(conn, strings.Split(address, ":")[0])
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Send EHLO/HELO
	hostname := "localhost"
	if err := client.Hello(hostname); err != nil {
		client.Close()
		return nil, fmt.Errorf("HELLO command failed: %w", err)
	}

	return client, nil
}

// MockDeliveryHandler implements DeliveryHandler for testing
type MockDeliveryHandler struct {
	logger     *slog.Logger
	shouldFail bool
	deliveries []Message
	mutex      sync.Mutex
}

// NewMockDeliveryHandler creates a new mock delivery handler for testing
func NewMockDeliveryHandler() *MockDeliveryHandler {
	return &MockDeliveryHandler{
		logger:     slog.Default().With("component", "mock-delivery"),
		deliveries: make([]Message, 0),
	}
}

// DeliverMessage simulates message delivery
func (m *MockDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.shouldFail {
		return fmt.Errorf("mock delivery failure")
	}

	// Simulate network delay
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	m.deliveries = append(m.deliveries, msg)
	m.logger.Info("Mock delivery successful", "message_id", msg.ID)

	return nil
}

// SetShouldFail configures the mock to fail deliveries
func (m *MockDeliveryHandler) SetShouldFail(fail bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.shouldFail = fail
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
