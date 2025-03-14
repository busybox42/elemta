package antispam

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// SpamAssassin represents a SpamAssassin spam scanner
type SpamAssassin struct {
	address   string
	timeout   time.Duration
	connected bool
	scanLimit int64
	threshold float64
	config    Config
}

// NewSpamAssassin creates a new SpamAssassin scanner
func NewSpamAssassin(config Config) *SpamAssassin {
	address := config.Address
	if address == "" {
		address = "localhost:783" // Default SpamAssassin spamd port
	}

	timeout := time.Duration(0)
	if t, ok := config.Options["timeout"].(int); ok {
		timeout = time.Duration(t) * time.Second
	}

	scanLimit := int64(0)
	if sl, ok := config.Options["scan_limit"].(int64); ok {
		scanLimit = sl
	}

	threshold := config.Threshold
	if threshold == 0 {
		threshold = 5.0 // Default spam threshold
	}

	return &SpamAssassin{
		address:   address,
		timeout:   timeout,
		scanLimit: scanLimit,
		threshold: threshold,
		config:    config,
	}
}

// Connect establishes a connection to the SpamAssassin server
func (s *SpamAssassin) Connect() error {
	if s.connected {
		return nil
	}

	// Test connection by pinging the server
	conn, err := net.DialTimeout("tcp", s.address, s.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to SpamAssassin: %w", err)
	}
	conn.Close()

	s.connected = true
	return nil
}

// Close closes the connection to the SpamAssassin server
func (s *SpamAssassin) Close() error {
	s.connected = false
	return nil
}

// IsConnected returns true if the scanner is connected
func (s *SpamAssassin) IsConnected() bool {
	return s.connected
}

// Name returns the name of the scanner
func (s *SpamAssassin) Name() string {
	if s.config.Name != "" {
		return s.config.Name
	}
	return "spamassassin"
}

// Type returns the type of the scanner
func (s *SpamAssassin) Type() string {
	return "spamassassin"
}

// ScanBytes scans a byte slice for spam
func (s *SpamAssassin) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	if !s.connected {
		return nil, ErrNotConnected
	}

	// Limit scan size if configured
	if s.scanLimit > 0 && int64(len(data)) > s.scanLimit {
		data = data[:s.scanLimit]
	}

	// Apply context timeout if needed
	var cancel context.CancelFunc
	if s.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	// Connect to SpamAssassin
	var conn net.Conn
	var err error

	// Use dialer with context for timeout
	dialer := &net.Dialer{}
	conn, err = dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SpamAssassin: %w", err)
	}
	defer conn.Close()

	// Send CHECK command
	cmd := fmt.Sprintf("CHECK SPAMC/1.5\r\nContent-length: %d\r\n\r\n", len(data))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("failed to send command to SpamAssassin: %w", err)
	}

	// Send data
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to send data to SpamAssassin: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response from SpamAssassin: %w", err)
	}

	// Parse response
	parts := strings.Split(response, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid response from SpamAssassin: %s", response)
	}

	if parts[0] != "SPAMD/1.5" {
		return nil, fmt.Errorf("unexpected protocol version: %s", parts[0])
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %s", parts[1])
	}

	if statusCode != 0 {
		return nil, fmt.Errorf("SpamAssassin returned error code: %d", statusCode)
	}

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to read headers from SpamAssassin: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse spam score
	score := 0.0
	var rules []string
	if scoreStr, ok := headers["Spam"]; ok {
		parts := strings.Split(scoreStr, ";")
		if len(parts) >= 1 {
			if strings.TrimSpace(parts[0]) == "True" {
				// It's spam, get the score
				if len(parts) >= 2 {
					scoreStr := strings.TrimSpace(parts[1])
					if strings.HasPrefix(scoreStr, "score=") {
						scoreStr = strings.TrimPrefix(scoreStr, "score=")
						score, _ = strconv.ParseFloat(scoreStr, 64)
					}
				}
			}
		}
	}

	// Extract rules if available
	if rulesStr, ok := headers["Rules"]; ok {
		rules = strings.Split(rulesStr, ",")
		for i, rule := range rules {
			rules[i] = strings.TrimSpace(rule)
		}
	}

	// Create result
	result := &ScanResult{
		Engine:    s.Name(),
		Timestamp: time.Now(),
		Clean:     score < s.threshold,
		Score:     score,
		Threshold: s.threshold,
		Rules:     rules,
		Details:   make(map[string]interface{}),
	}

	// Add headers to details
	for k, v := range headers {
		result.Details[k] = v
	}

	return result, nil
}

// ScanReader scans a reader for spam
func (s *SpamAssassin) ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	if !s.connected {
		return nil, ErrNotConnected
	}

	// Read all data from the reader
	var data []byte
	var err error

	if s.scanLimit > 0 {
		// Limit the amount of data read
		limitReader := io.LimitReader(reader, s.scanLimit)
		data, err = io.ReadAll(limitReader)
	} else {
		data, err = io.ReadAll(reader)
	}

	if err != nil {
		return nil, err
	}

	return s.ScanBytes(ctx, data)
}

// ScanFile scans a file for spam
func (s *SpamAssassin) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	return nil, errors.New("direct file scanning not supported by SpamAssassin, use ScanBytes or ScanReader instead")
}
