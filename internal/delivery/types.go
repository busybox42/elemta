package delivery

import (
	"fmt"
	"time"
)

// Message represents an email message for delivery
type Message struct {
	ID       string              `json:"id"`
	From     string              `json:"from"`
	To       []string            `json:"to"`
	Data     []byte              `json:"data"`
	Priority int                 `json:"priority"` // 0 = highest, higher numbers = lower priority
	Headers  map[string][]string `json:"headers"`

	// Metadata
	CreatedAt   time.Time `json:"created_at"`
	QueuedAt    time.Time `json:"queued_at"`
	Size        int64     `json:"size"`
	MessageID   string    `json:"message_id"` // RFC message ID
	Subject     string    `json:"subject"`
	ContentType string    `json:"content_type"`
}

// RouteType defines the type of delivery route
type RouteType string

const (
	RouteTypeDirect RouteType = "direct" // Direct SMTP delivery via MX records
	RouteTypeRelay  RouteType = "relay"  // Delivery via relay host
	RouteTypeLocal  RouteType = "local"  // Local delivery
)

// Route represents a delivery route for a set of recipients
type Route struct {
	Type        RouteType `json:"type"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Recipients  []string  `json:"recipients"`
	Priority    int       `json:"priority"`
	TLSRequired bool      `json:"tls_required"`
	Auth        *AuthInfo `json:"auth,omitempty"`
}

// AuthInfo holds authentication information for SMTP delivery
type AuthInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Method   string `json:"method"` // PLAIN, LOGIN, CRAM-MD5, etc.
}

// DeliveryResult represents the result of a delivery attempt
type DeliveryResult struct {
	MessageID            string         `json:"message_id"`
	DeliveryID           string         `json:"delivery_id"`
	Success              bool           `json:"success"`
	StartTime            time.Time      `json:"start_time"`
	EndTime              time.Time      `json:"end_time"`
	Duration             time.Duration  `json:"duration"`
	TotalRecipients      int            `json:"total_recipients"`
	SuccessfulRecipients int            `json:"successful_recipients"`
	FailedRecipients     int            `json:"failed_recipients"`
	Routes               []*RouteResult `json:"routes"`
	Error                error          `json:"error,omitempty"`
}

// RouteResult represents the result of delivery via a specific route
type RouteResult struct {
	Route     *Route        `json:"route"`
	Success   bool          `json:"success"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Error     error         `json:"error,omitempty"`

	// SMTP response details
	ResponseCode int    `json:"response_code,omitempty"`
	ResponseText string `json:"response_text,omitempty"`

	// Connection details
	RemoteAddr string `json:"remote_addr,omitempty"`
	TLSUsed    bool   `json:"tls_used"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSCipher  string `json:"tls_cipher,omitempty"`
}

// DeliveryStatus represents the current status of a delivery
type DeliveryStatus string

const (
	StatusPending    DeliveryStatus = "pending"
	StatusInProgress DeliveryStatus = "in_progress"
	StatusCompleted  DeliveryStatus = "completed"
	StatusFailed     DeliveryStatus = "failed"
	StatusRetrying   DeliveryStatus = "retrying"
	StatusAborted    DeliveryStatus = "aborted"
)

// DeliveryAttempt represents a single delivery attempt
type DeliveryAttempt struct {
	ID        string         `json:"id"`
	MessageID string         `json:"message_id"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Duration  time.Duration  `json:"duration"`
	Status    DeliveryStatus `json:"status"`
	Route     *Route         `json:"route"`
	Error     error          `json:"error,omitempty"`

	// Retry information
	AttemptNumber int           `json:"attempt_number"`
	NextRetry     time.Time     `json:"next_retry,omitempty"`
	RetryBackoff  time.Duration `json:"retry_backoff,omitempty"`

	// SMTP details
	SMTPResponse string `json:"smtp_response,omitempty"`
	SMTPCode     int    `json:"smtp_code,omitempty"`
}

// Priority constants for message prioritization
const (
	PriorityCritical = 0
	PriorityHigh     = 100
	PriorityNormal   = 200
	PriorityLow      = 300
	PriorityBulk     = 400
)

// ConnectionInfo represents information about an SMTP connection
type ConnectionInfo struct {
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	RemoteAddr     string    `json:"remote_addr"`
	LocalAddr      string    `json:"local_addr"`
	Connected      bool      `json:"connected"`
	ConnectedAt    time.Time `json:"connected_at"`
	LastUsed       time.Time `json:"last_used"`
	TLSEnabled     bool      `json:"tls_enabled"`
	TLSVersion     string    `json:"tls_version,omitempty"`
	TLSCipher      string    `json:"tls_cipher,omitempty"`
	Capabilities   []string  `json:"capabilities,omitempty"`
	MaxMessageSize int64     `json:"max_message_size,omitempty"`
}

// DNSResult represents the result of a DNS lookup
type DNSResult struct {
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Records   []string  `json:"records"`
	TTL       int       `json:"ttl"`
	CachedAt  time.Time `json:"cached_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MXRecord represents an MX record
type MXRecord struct {
	Host     string `json:"host"`
	Priority int    `json:"priority"`
	TTL      int    `json:"ttl"`
}

// DeliveryMetrics represents delivery statistics
type DeliveryMetrics struct {
	TotalMessages        int64         `json:"total_messages"`
	SuccessfulDeliveries int64         `json:"successful_deliveries"`
	FailedDeliveries     int64         `json:"failed_deliveries"`
	PendingDeliveries    int64         `json:"pending_deliveries"`
	RetryingDeliveries   int64         `json:"retrying_deliveries"`
	AverageDeliveryTime  time.Duration `json:"average_delivery_time"`
	MaxDeliveryTime      time.Duration `json:"max_delivery_time"`
	MinDeliveryTime      time.Duration `json:"min_delivery_time"`

	// Connection statistics
	TotalConnections   int64         `json:"total_connections"`
	ActiveConnections  int64         `json:"active_connections"`
	PooledConnections  int64         `json:"pooled_connections"`
	ConnectionErrors   int64         `json:"connection_errors"`
	AverageConnectTime time.Duration `json:"average_connect_time"`

	// DNS statistics
	DNSQueries     int64 `json:"dns_queries"`
	DNSCacheHits   int64 `json:"dns_cache_hits"`
	DNSCacheMisses int64 `json:"dns_cache_misses"`
	DNSErrors      int64 `json:"dns_errors"`

	// TLS statistics
	TLSConnections       int64 `json:"tls_connections"`
	TLSHandshakeFailures int64 `json:"tls_handshake_failures"`
	TLSUpgradeSuccesses  int64 `json:"tls_upgrade_successes"`
	TLSUpgradeFailures   int64 `json:"tls_upgrade_failures"`
}

// RoutingRule represents a routing rule for message delivery
type RoutingRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`

	// Conditions
	FromDomain  []string            `json:"from_domain,omitempty"`
	ToDomain    []string            `json:"to_domain,omitempty"`
	FromAddress []string            `json:"from_address,omitempty"`
	ToAddress   []string            `json:"to_address,omitempty"`
	Subject     []string            `json:"subject,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	MessageSize *SizeRange          `json:"message_size,omitempty"`
	TimeRange   *TimeRange          `json:"time_range,omitempty"`

	// Actions
	RouteType        RouteType     `json:"route_type"`
	RelayHost        string        `json:"relay_host,omitempty"`
	RelayPort        int           `json:"relay_port,omitempty"`
	ForceAuth        bool          `json:"force_auth,omitempty"`
	ForceTLS         bool          `json:"force_tls,omitempty"`
	DeliveryPriority int           `json:"delivery_priority,omitempty"`
	MaxRetries       int           `json:"max_retries,omitempty"`
	RetryDelay       time.Duration `json:"retry_delay,omitempty"`
}

// SizeRange represents a size range for routing rules
type SizeRange struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// TimeRange represents a time range for routing rules
type TimeRange struct {
	Start string `json:"start"` // HH:MM format
	End   string `json:"end"`   // HH:MM format
	Days  []int  `json:"days"`  // 0=Sunday, 1=Monday, etc.
}

// QueueMetrics represents queue-related delivery metrics
type QueueMetrics struct {
	PendingMessages    int64 `json:"pending_messages"`
	ProcessingMessages int64 `json:"processing_messages"`
	CompletedMessages  int64 `json:"completed_messages"`
	FailedMessages     int64 `json:"failed_messages"`
	RetryingMessages   int64 `json:"retrying_messages"`

	// By priority
	CriticalMessages int64 `json:"critical_messages"`
	HighMessages     int64 `json:"high_messages"`
	NormalMessages   int64 `json:"normal_messages"`
	LowMessages      int64 `json:"low_messages"`
	BulkMessages     int64 `json:"bulk_messages"`

	// Timing
	OldestMessage    time.Time     `json:"oldest_message"`
	AverageQueueTime time.Duration `json:"average_queue_time"`
	MaxQueueTime     time.Duration `json:"max_queue_time"`
}

// ErrorType represents different types of delivery errors
type ErrorType string

const (
	ErrorTypeConnection ErrorType = "connection"
	ErrorTypeDNS        ErrorType = "dns"
	ErrorTypeSMTP       ErrorType = "smtp"
	ErrorTypeTLS        ErrorType = "tls"
	ErrorTypeAuth       ErrorType = "auth"
	ErrorTypeTimeout    ErrorType = "timeout"
	ErrorTypeRateLimit  ErrorType = "rate_limit"
	ErrorTypeQuota      ErrorType = "quota"
	ErrorTypePolicy     ErrorType = "policy"
	ErrorTypeUnknown    ErrorType = "unknown"
)

// DeliveryError represents a structured delivery error
type DeliveryError struct {
	Type       ErrorType     `json:"type"`
	Code       int           `json:"code,omitempty"`
	Message    string        `json:"message"`
	Details    string        `json:"details,omitempty"`
	Temporary  bool          `json:"temporary"`
	Retryable  bool          `json:"retryable"`
	RetryAfter time.Duration `json:"retry_after,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// Error implements the error interface
func (e *DeliveryError) Error() string {
	return fmt.Sprintf("%s error: %s", e.Type, e.Message)
}
