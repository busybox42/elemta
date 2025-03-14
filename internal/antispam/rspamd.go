package antispam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Rspamd represents a Rspamd spam scanner
type Rspamd struct {
	address    string
	timeout    time.Duration
	connected  bool
	scanLimit  int64
	threshold  float64
	config     Config
	httpClient *http.Client
	apiKey     string
}

// RspamdResponse represents the response from Rspamd
type RspamdResponse struct {
	IsSpam    bool                `json:"is_spam"`
	Score     float64             `json:"score"`
	Threshold float64             `json:"threshold"`
	Required  float64             `json:"required_score"`
	Action    string              `json:"action"`
	Symbols   map[string]Symbol   `json:"symbols"`
	MessageID string              `json:"message-id"`
	Milter    map[string]string   `json:"milter"`
	Urls      []string            `json:"urls"`
	Emails    []string            `json:"emails"`
	DKIMSig   []map[string]string `json:"dkim-signature"`
	SPF       map[string]string   `json:"spf"`
	DMARC     map[string]string   `json:"dmarc"`
	Fuzzy     []string            `json:"fuzzy"`
	Time      float64             `json:"time_real"`
	Scan_Time float64             `json:"scan_time"`
}

// Symbol represents a Rspamd rule symbol
type Symbol struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	Description string   `json:"description"`
	Options     []string `json:"options"`
}

// NewRspamd creates a new Rspamd scanner
func NewRspamd(config Config) *Rspamd {
	address := config.Address
	if address == "" {
		address = "http://localhost:11333" // Default Rspamd address
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
		threshold = 6.0 // Default spam threshold
	}

	apiKey := ""
	if key, ok := config.Options["api_key"].(string); ok {
		apiKey = key
	}

	return &Rspamd{
		address:   address,
		timeout:   timeout,
		scanLimit: scanLimit,
		threshold: threshold,
		config:    config,
		apiKey:    apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Connect establishes a connection to the Rspamd server
func (r *Rspamd) Connect() error {
	if r.connected {
		return nil
	}

	// Test connection by pinging the server
	ctx := context.Background()
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", r.address+"/ping", nil)
	if err != nil {
		return fmt.Errorf("failed to create request to Rspamd: %w", err)
	}

	if r.apiKey != "" {
		req.Header.Set("Password", r.apiKey)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Rspamd: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Rspamd returned non-OK status: %d", resp.StatusCode)
	}

	r.connected = true
	return nil
}

// Close closes the connection to the Rspamd server
func (r *Rspamd) Close() error {
	r.connected = false
	return nil
}

// IsConnected returns true if the scanner is connected
func (r *Rspamd) IsConnected() bool {
	return r.connected
}

// Name returns the name of the scanner
func (r *Rspamd) Name() string {
	if r.config.Name != "" {
		return r.config.Name
	}
	return "rspamd"
}

// Type returns the type of the scanner
func (r *Rspamd) Type() string {
	return "rspamd"
}

// ScanBytes scans a byte slice for spam
func (r *Rspamd) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	if !r.connected {
		return nil, ErrNotConnected
	}

	// Limit scan size if configured
	if r.scanLimit > 0 && int64(len(data)) > r.scanLimit {
		data = data[:r.scanLimit]
	}

	// Apply context timeout if needed
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	// Create request to Rspamd
	req, err := http.NewRequestWithContext(ctx, "POST", r.address+"/checkv2", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request to Rspamd: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r.apiKey != "" {
		req.Header.Set("Password", r.apiKey)
	}

	// Send request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send data to Rspamd: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Rspamd returned non-OK status: %d", resp.StatusCode)
	}

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from Rspamd: %w", err)
	}

	// Parse JSON response
	var rspamdResp RspamdResponse
	if err := json.Unmarshal(respBody, &rspamdResp); err != nil {
		return nil, fmt.Errorf("failed to parse Rspamd response: %w", err)
	}

	// Extract rules that were triggered
	var rules []string
	for name, symbol := range rspamdResp.Symbols {
		if symbol.Score > 0 {
			rules = append(rules, name)
		}
	}

	// Create result
	result := &ScanResult{
		Engine:    r.Name(),
		Timestamp: time.Now(),
		Clean:     !rspamdResp.IsSpam && rspamdResp.Score < r.threshold,
		Score:     rspamdResp.Score,
		Threshold: r.threshold,
		Rules:     rules,
		Details:   make(map[string]interface{}),
	}

	// Add response details
	result.Details["action"] = rspamdResp.Action
	result.Details["required_score"] = rspamdResp.Required
	result.Details["scan_time"] = rspamdResp.Scan_Time
	result.Details["symbols"] = rspamdResp.Symbols

	return result, nil
}

// ScanReader scans a reader for spam
func (r *Rspamd) ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	if !r.connected {
		return nil, ErrNotConnected
	}

	// Read all data from the reader
	var data []byte
	var err error

	if r.scanLimit > 0 {
		// Limit the amount of data read
		limitReader := io.LimitReader(reader, r.scanLimit)
		data, err = io.ReadAll(limitReader)
	} else {
		data, err = io.ReadAll(reader)
	}

	if err != nil {
		return nil, err
	}

	return r.ScanBytes(ctx, data)
}

// ScanFile scans a file for spam
func (r *Rspamd) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	return nil, errors.New("direct file scanning not supported by Rspamd, use ScanBytes or ScanReader instead")
}
