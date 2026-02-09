package soap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/zimbra"
)

// Client handles SOAP API calls to Zimbra
type Client struct {
	config     *zimbra.SOAPConfig
	logger     *slog.Logger
	httpClient *http.Client

	// Authentication
	authToken  string
	authExpiry time.Time
	authMutex  sync.RWMutex

	// Circuit breaker
	failureCount int
	lastFailure  time.Time
	circuitOpen  bool
	circuitMutex sync.RWMutex

	// Metrics
	requestCount    int64
	errorCount      int64
	lastRequestTime time.Time
	mutex           sync.RWMutex
}

// SOAPEnvelope represents a SOAP envelope
type SOAPEnvelope struct {
	XMLName xml.Name    `xml:"soap:Envelope"`
	Xmlns   string      `xml:"xmlns:soap,attr"`
	Header  *SOAPHeader `xml:"soap:Header,omitempty"`
	Body    SOAPBody    `xml:"soap:Body"`
}

// SOAPHeader represents SOAP header with authentication
type SOAPHeader struct {
	Context *AuthContext `xml:"context,omitempty"`
}

// AuthContext holds authentication information
type AuthContext struct {
	XMLName   xml.Name `xml:"context"`
	Xmlns     string   `xml:"xmlns,attr"`
	AuthToken string   `xml:"authToken,omitempty"`
	SessionID string   `xml:"sessionId,omitempty"`
}

// SOAPBody represents SOAP body
type SOAPBody struct {
	Content interface{} `xml:",innerxml"`
}

// AuthRequest represents authentication request
type AuthRequest struct {
	XMLName  xml.Name `xml:"AuthRequest"`
	Xmlns    string   `xml:"xmlns,attr"`
	Name     string   `xml:"name"`
	Password string   `xml:"password"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	XMLName   xml.Name `xml:"AuthResponse"`
	AuthToken string   `xml:"authToken"`
	Lifetime  int64    `xml:"lifetime"`
	SessionID string   `xml:"sessionId,omitempty"`
}

// SOAPFault represents a SOAP fault
type SOAPFault struct {
	XMLName xml.Name `xml:"soap:Fault"`
	Code    string   `xml:"faultcode"`
	String  string   `xml:"faultstring"`
	Detail  string   `xml:"detail"`
}

func (f SOAPFault) Error() string {
	return fmt.Sprintf("SOAP fault: %s - %s", f.Code, f.String)
}

// NewClient creates a new SOAP client for Zimbra
func NewClient(config *zimbra.SOAPConfig, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	// Create HTTP client with appropriate TLS configuration
	transport := &http.Transport{
		TLSClientConfig: config.TLSConfig,
	}

	if config.SkipTLSVerify {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &Client{
		config:     config,
		logger:     logger,
		httpClient: httpClient,
	}
}

// Connect initializes the SOAP client and authenticates
func (c *Client) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to Zimbra SOAP API",
		slog.String("url", c.config.AdminURL),
	)

	// Authenticate to get initial token
	err := c.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	c.logger.Info("Successfully connected to Zimbra SOAP API")
	return nil
}

// Close shuts down the SOAP client
func (c *Client) Close() error {
	c.logger.Info("Shutting down SOAP client")

	// Invalidate auth token
	c.authMutex.Lock()
	c.authToken = ""
	c.authExpiry = time.Time{}
	c.authMutex.Unlock()

	return nil
}

// authenticate performs authentication with Zimbra admin
func (c *Client) authenticate(ctx context.Context) error {
	c.logger.Debug("Authenticating with Zimbra admin API")

	authReq := AuthRequest{
		Xmlns:    "urn:zimbraAdmin",
		Name:     c.config.AdminUser,
		Password: c.config.AdminPassword,
	}

	envelope := SOAPEnvelope{
		Xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
		Body: SOAPBody{
			Content: authReq,
		},
	}

	var authResp AuthResponse
	err := c.makeRequest(ctx, c.config.AdminURL, envelope, &authResp)
	if err != nil {
		c.logger.Error("Authentication failed",
			slog.String("error", err.Error()),
		)
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Store authentication token
	c.authMutex.Lock()
	c.authToken = authResp.AuthToken
	c.authExpiry = time.Now().Add(time.Duration(authResp.Lifetime) * time.Millisecond)
	c.authMutex.Unlock()

	c.logger.Info("Authentication successful",
		slog.Time("expires", c.authExpiry),
	)

	return nil
}

// makeRequest performs a SOAP request
func (c *Client) makeRequest(ctx context.Context, url string, request interface{}, response interface{}) error {
	// Check circuit breaker
	if c.isCircuitOpen() {
		return fmt.Errorf("circuit breaker is open")
	}

	// Marshal request to XML
	var requestData []byte
	var err error

	if envelope, ok := request.(SOAPEnvelope); ok {
		requestData, err = xml.MarshalIndent(envelope, "", "  ")
	} else {
		// Wrap in envelope if not already wrapped
		envelope := SOAPEnvelope{
			Xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
			Body: SOAPBody{
				Content: request,
			},
		}
		requestData, err = xml.MarshalIndent(envelope, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Add XML declaration
	requestData = append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"), requestData...)

	c.logger.Debug("Making SOAP request",
		slog.String("url", url),
		slog.Int("body_size", len(requestData)),
	)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(requestData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
	httpReq.Header.Set("SOAPAction", "")

	// Make HTTP request
	c.mutex.Lock()
	c.requestCount++
	c.lastRequestTime = time.Now()
	c.mutex.Unlock()

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		c.recordFailure()
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		c.recordFailure()
		return fmt.Errorf("failed to read response: %w", err)
	}

	c.logger.Debug("Received SOAP response",
		slog.Int("status_code", resp.StatusCode),
		slog.Int("body_size", len(respData)),
	)

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(respData))
	}

	// Parse response
	var envelope SOAPEnvelope
	err = xml.Unmarshal(respData, &envelope)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for SOAP fault
	var fault SOAPFault
	if xml.Unmarshal([]byte(envelope.Body.Content.(string)), &fault) == nil && fault.Code != "" {
		c.recordFailure()
		return fault
	}

	// Unmarshal response body into target struct
	if response != nil {
		err = xml.Unmarshal([]byte(envelope.Body.Content.(string)), response)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response body: %w", err)
		}
	}

	c.recordSuccess()
	return nil
}

// makeAuthenticatedRequest makes an authenticated SOAP request
// Currently unused but reserved for future Zimbra integration
//
//nolint:unused
func (c *Client) makeAuthenticatedRequest(ctx context.Context, request interface{}, response interface{}) error {
	// Ensure we have a valid auth token
	err := c.ensureAuthenticated(ctx)
	if err != nil {
		return fmt.Errorf("failed to ensure authentication: %w", err)
	}

	// Get current auth token
	c.authMutex.RLock()
	token := c.authToken
	c.authMutex.RUnlock()

	// Create envelope with auth header
	envelope := SOAPEnvelope{
		Xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
		Header: &SOAPHeader{
			Context: &AuthContext{
				Xmlns:     "urn:zimbra",
				AuthToken: token,
			},
		},
		Body: SOAPBody{
			Content: request,
		},
	}

	return c.makeRequest(ctx, c.config.URL, envelope, response)
}

// ensureAuthenticated ensures the client is authenticated
// Currently unused but reserved for future Zimbra integration
//
//nolint:unused
func (c *Client) ensureAuthenticated(ctx context.Context) error {
	c.authMutex.RLock()
	hasToken := c.authToken != ""
	isExpired := time.Now().After(c.authExpiry.Add(-5 * time.Minute)) // 5 min buffer
	c.authMutex.RUnlock()

	if !hasToken || isExpired {
		c.logger.Debug("Authentication token missing or expired, re-authenticating")
		return c.authenticate(ctx)
	}

	return nil
}

// Circuit breaker methods
func (c *Client) isCircuitOpen() bool {
	c.circuitMutex.RLock()
	defer c.circuitMutex.RUnlock()

	if !c.circuitOpen {
		return false
	}

	// Check if circuit should be reset
	if time.Since(c.lastFailure) > c.config.CircuitBreakerTimeout {
		c.circuitOpen = false
		c.failureCount = 0
		c.logger.Info("Circuit breaker reset")
		return false
	}

	return true
}

func (c *Client) recordFailure() {
	c.circuitMutex.Lock()
	defer c.circuitMutex.Unlock()

	c.failureCount++
	c.lastFailure = time.Now()

	c.mutex.Lock()
	c.errorCount++
	c.mutex.Unlock()

	if c.failureCount >= c.config.CircuitBreakerThreshold {
		c.circuitOpen = true
		c.logger.Warn("Circuit breaker opened",
			slog.Int("failure_count", c.failureCount),
		)
	}
}

func (c *Client) recordSuccess() {
	c.circuitMutex.Lock()
	defer c.circuitMutex.Unlock()

	c.failureCount = 0
}

// GetStats returns client statistics
func (c *Client) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	c.authMutex.RLock()
	hasToken := c.authToken != ""
	tokenExpiry := c.authExpiry
	c.authMutex.RUnlock()

	c.circuitMutex.RLock()
	circuitOpen := c.circuitOpen
	failureCount := c.failureCount
	c.circuitMutex.RUnlock()

	return map[string]interface{}{
		"total_requests":    c.requestCount,
		"total_errors":      c.errorCount,
		"last_request_time": c.lastRequestTime,
		"has_auth_token":    hasToken,
		"auth_token_expiry": tokenExpiry,
		"circuit_open":      circuitOpen,
		"failure_count":     failureCount,
	}
}
