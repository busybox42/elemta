package queue

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// LMTPDeliveryHandler implements DeliveryHandler for LMTP delivery (e.g., to Dovecot)
type LMTPDeliveryHandler struct {
	logger  *slog.Logger
	timeout time.Duration
	host    string
	port    int
}

// NewLMTPDeliveryHandler creates a new LMTP delivery handler
func NewLMTPDeliveryHandler(host string, port int) *LMTPDeliveryHandler {
	if port == 0 {
		port = 2424 // Default LMTP port (common for Dovecot)
	}

	return &LMTPDeliveryHandler{
		logger:  slog.Default().With("component", "lmtp-delivery"),
		timeout: 30 * time.Second,
		host:    host,
		port:    port,
	}
}

// DeliverMessage attempts to deliver a message via LMTP
func (h *LMTPDeliveryHandler) DeliverMessage(ctx context.Context, msg Message, content []byte) error {
	h.logger.Info("Attempting LMTP delivery",
		"message_id", msg.ID,
		"from", msg.From,
		"to", msg.To,
		"server", fmt.Sprintf("%s:%d", h.host, h.port))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Connect to LMTP server
	addr := fmt.Sprintf("%s:%d", h.host, h.port)
	conn, err := net.DialTimeout("tcp", addr, h.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to LMTP server %s: %w", addr, err)
	}
	defer conn.Close()

	// Set connection deadline
	deadline := time.Now().Add(h.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		h.logger.Warn("Failed to set connection deadline", "error", err)
	}

	// Create buffers for reading/writing
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Helper function to send command and read response
	sendCommand := func(cmd string) (string, error) {
		h.logger.Debug("LMTP command", "command", strings.TrimSpace(cmd))

		if _, err := writer.WriteString(cmd); err != nil {
			return "", fmt.Errorf("failed to send command: %w", err)
		}
		if err := writer.Flush(); err != nil {
			return "", fmt.Errorf("failed to flush command: %w", err)
		}

		resp, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read response: %w", err)
		}

		resp = strings.TrimSpace(resp)
		h.logger.Debug("LMTP response", "response", resp)
		return resp, nil
	}

	// Read server greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read server greeting: %w", err)
	}
	greeting = strings.TrimSpace(greeting)
	h.logger.Debug("LMTP server greeting", "response", greeting)

	if !strings.HasPrefix(greeting, "220 ") {
		return fmt.Errorf("unexpected server greeting: %s", greeting)
	}

	// Send LHLO
	hostname := "elemta.local"
	lhloResp, err := sendCommand(fmt.Sprintf("LHLO %s\r\n", hostname))
	if err != nil {
		return fmt.Errorf("LHLO failed: %w", err)
	}

	// Handle multi-line LHLO response
	if strings.HasPrefix(lhloResp, "250-") {
		// Read remaining lines until we get "250 " (final line)
		for {
			resp, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read LHLO continuation: %w", err)
			}
			resp = strings.TrimSpace(resp)
			h.logger.Debug("LMTP response", "response", resp)

			if strings.HasPrefix(resp, "250 ") {
				break
			}
			if !strings.HasPrefix(resp, "250-") {
				return fmt.Errorf("server rejected LHLO: %s", resp)
			}
		}
	} else if !strings.HasPrefix(lhloResp, "250 ") {
		return fmt.Errorf("server rejected LHLO: %s", lhloResp)
	}

	// Send MAIL FROM
	mailFromResp, err := sendCommand(fmt.Sprintf("MAIL FROM:<%s>\r\n", msg.From))
	if err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}
	if !strings.HasPrefix(mailFromResp, "250 ") {
		return fmt.Errorf("server rejected sender: %s", mailFromResp)
	}

	// Send RCPT TO for each recipient
	var acceptedRecipients []string
	var failedRecipients []string

	for _, recipient := range msg.To {
		rcptResp, err := sendCommand(fmt.Sprintf("RCPT TO:<%s>\r\n", recipient))
		if err != nil {
			h.logger.Error("RCPT TO command failed", "recipient", recipient, "error", err)
			failedRecipients = append(failedRecipients, recipient)
			continue
		}

		if strings.HasPrefix(rcptResp, "250 ") {
			acceptedRecipients = append(acceptedRecipients, recipient)
			h.logger.Debug("Recipient accepted", "recipient", recipient)
		} else {
			h.logger.Error("Recipient rejected", "recipient", recipient, "response", rcptResp)
			failedRecipients = append(failedRecipients, recipient)
		}
	}

	// Check if any recipients were accepted
	if len(acceptedRecipients) == 0 {
		return fmt.Errorf("all recipients rejected: %v", failedRecipients)
	}

	// Send DATA
	dataResp, err := sendCommand("DATA\r\n")
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	if !strings.HasPrefix(dataResp, "354 ") {
		return fmt.Errorf("server rejected DATA command: %s", dataResp)
	}

	// Send message content
	h.logger.Debug("Sending message content", "size", len(content))
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	// Send end-of-data marker
	if _, err := writer.WriteString("\r\n.\r\n"); err != nil {
		return fmt.Errorf("failed to send end-of-data marker: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush message data: %w", err)
	}

	// Read response for each accepted recipient (LMTP returns per-recipient responses)
	deliveredCount := 0
	for range acceptedRecipients {
		resp, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read delivery response: %w", err)
		}
		resp = strings.TrimSpace(resp)
		h.logger.Debug("Delivery response", "response", resp)

		if strings.HasPrefix(resp, "250 ") {
			deliveredCount++
		} else {
			h.logger.Error("Delivery failed for recipient", "response", resp)
		}
	}

	// Send QUIT
	quitResp, err := sendCommand("QUIT\r\n")
	if err != nil {
		h.logger.Warn("QUIT command failed", "error", err)
	} else if !strings.HasPrefix(quitResp, "221 ") {
		h.logger.Warn("Unexpected QUIT response", "response", quitResp)
	}

	// Check delivery success
	if deliveredCount == 0 {
		return fmt.Errorf("delivery failed for all accepted recipients")
	} else if deliveredCount < len(acceptedRecipients) {
		h.logger.Warn("Partial delivery success",
			"delivered", deliveredCount,
			"total", len(acceptedRecipients))
	}

	h.logger.Info("LMTP delivery successful",
		"message_id", msg.ID,
		"delivered", deliveredCount,
		"total_recipients", len(msg.To),
		"failed_recipients", len(failedRecipients))

	// Return error if some recipients failed but we had partial success
	if len(failedRecipients) > 0 {
		return fmt.Errorf("partial delivery: %d/%d recipients delivered, failed: %v",
			deliveredCount, len(msg.To), failedRecipients)
	}

	return nil
}
