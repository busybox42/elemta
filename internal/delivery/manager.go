package delivery

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager handles all aspects of message delivery with advanced features
type Manager struct {
	config         *Config
	logger         *slog.Logger
	connectionPool *ConnectionPool
	dnsCache       *DNSCache
	router         *Router
	tracker        *DeliveryTracker
	tlsConfig      *tls.Config

	// Runtime state
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	workers chan struct{}
	mu      sync.RWMutex
}

// Config holds configuration for the delivery manager
type Config struct {
	// Connection settings
	MaxConnectionsPerHost int           `yaml:"max_connections_per_host" json:"max_connections_per_host"`
	ConnectionTimeout     time.Duration `yaml:"connection_timeout" json:"connection_timeout"`
	IdleTimeout           time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	KeepAliveInterval     time.Duration `yaml:"keep_alive_interval" json:"keep_alive_interval"`

	// DNS settings
	DNSCacheSize int           `yaml:"dns_cache_size" json:"dns_cache_size"`
	DNSCacheTTL  time.Duration `yaml:"dns_cache_ttl" json:"dns_cache_ttl"`
	DNSTimeout   time.Duration `yaml:"dns_timeout" json:"dns_timeout"`

	// Failed queue settings
	FailedQueueRetentionHours int `yaml:"failed_queue_retention_hours" json:"failed_queue_retention_hours"` // 0 = immediate deletion
	DNSRetries                int `yaml:"dns_retries" json:"dns_retries"`

	// Delivery settings
	MaxConcurrentDeliveries int           `yaml:"max_concurrent_deliveries" json:"max_concurrent_deliveries"`
	DeliveryTimeout         time.Duration `yaml:"delivery_timeout" json:"delivery_timeout"`
	RetryAttempts           int           `yaml:"retry_attempts" json:"retry_attempts"`
	RetryBackoff            time.Duration `yaml:"retry_backoff" json:"retry_backoff"`

	// TLS settings
	TLSEnabled            bool          `yaml:"tls_enabled" json:"tls_enabled"`
	TLSMinVersion         string        `yaml:"tls_min_version" json:"tls_min_version"`
	TLSInsecureSkipVerify bool          `yaml:"tls_insecure_skip_verify" json:"tls_insecure_skip_verify"`
	TLSHandshakeTimeout   time.Duration `yaml:"tls_handshake_timeout" json:"tls_handshake_timeout"`

	// Routing settings
	LocalDomains  []string `yaml:"local_domains" json:"local_domains"`
	RelayHost     string   `yaml:"relay_host" json:"relay_host"`
	RelayPort     int      `yaml:"relay_port" json:"relay_port"`
	RelayAuth     bool     `yaml:"relay_auth" json:"relay_auth"`
	RelayUsername string   `yaml:"relay_username" json:"relay_username"`
	RelayPassword string   `yaml:"relay_password" json:"relay_password"`

	// Monitoring
	MetricsEnabled      bool          `yaml:"metrics_enabled" json:"metrics_enabled"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`

	// Server identification
	Hostname string `yaml:"hostname" json:"hostname"`
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxConnectionsPerHost: 10,
		ConnectionTimeout:     30 * time.Second,
		IdleTimeout:           5 * time.Minute,
		KeepAliveInterval:     30 * time.Second,

		DNSCacheSize: 1000,
		DNSCacheTTL:  1 * time.Hour,
		DNSTimeout:   10 * time.Second,
		DNSRetries:   3,

		MaxConcurrentDeliveries: 50,
		DeliveryTimeout:         5 * time.Minute,
		RetryAttempts:           3,
		RetryBackoff:            1 * time.Minute,

		TLSEnabled:            true,
		TLSMinVersion:         "1.2",
		TLSInsecureSkipVerify: false,
		TLSHandshakeTimeout:   10 * time.Second,

		LocalDomains: []string{"localhost"},
		RelayPort:    587,
		RelayAuth:    false,

		MetricsEnabled:      true,
		HealthCheckInterval: 30 * time.Second,

		Hostname: "localhost",
	}
}

// NewManager creates a new delivery manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create TLS configuration
	tlsConfig, err := createTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:         config,
		logger:         slog.Default().With("component", "delivery-manager"),
		connectionPool: NewConnectionPool(config),
		dnsCache:       NewDNSCache(config),
		router:         NewRouter(config),
		tracker:        NewDeliveryTracker(config),
		tlsConfig:      tlsConfig,
		ctx:            ctx,
		cancel:         cancel,
		workers:        make(chan struct{}, config.MaxConcurrentDeliveries),
	}

	return manager, nil
}

// Start initializes and starts the delivery manager
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("delivery manager already running")
	}

	m.logger.Info("Starting delivery manager",
		"max_connections_per_host", m.config.MaxConnectionsPerHost,
		"max_concurrent_deliveries", m.config.MaxConcurrentDeliveries,
		"tls_enabled", m.config.TLSEnabled)

	// Start background services
	go m.connectionPool.cleanup(m.ctx)
	go m.dnsCache.cleanup(m.ctx)
	go m.tracker.cleanup(m.ctx)

	if m.config.MetricsEnabled {
		go m.reportMetrics(m.ctx)
	}

	m.running = true
	m.logger.Info("Delivery manager started successfully")

	return nil
}

// Stop gracefully shuts down the delivery manager
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.logger.Info("Stopping delivery manager")

	// Cancel background services
	m.cancel()

	// Close connection pool
	m.connectionPool.Close()

	// Clear DNS cache
	m.dnsCache.Clear()

	m.running = false
	m.logger.Info("Delivery manager stopped")

	return nil
}

// DeliverMessage delivers a message using the configured routing and delivery strategies
func (m *Manager) DeliverMessage(ctx context.Context, msg *Message) (*DeliveryResult, error) {
	if !m.running {
		return nil, fmt.Errorf("delivery manager not running")
	}

	// Acquire worker slot
	select {
	case m.workers <- struct{}{}:
		defer func() { <-m.workers }()
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("delivery manager at capacity")
	}

	// Start tracking this delivery
	deliveryID := m.tracker.StartDelivery(msg)
	defer m.tracker.FinishDelivery(deliveryID)

	// Create delivery context with timeout
	ctx, cancel := context.WithTimeout(ctx, m.config.DeliveryTimeout)
	defer cancel()

	m.logger.Info("Starting message delivery",
		"message_id", msg.ID,
		"from", msg.From,
		"recipients", len(msg.To),
		"delivery_id", deliveryID)

	// Route the message
	routes, err := m.router.RouteMessage(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("routing failed: %w", err)
	}

	// Deliver to each route
	result := &DeliveryResult{
		MessageID:       msg.ID,
		DeliveryID:      deliveryID,
		StartTime:       time.Now(),
		Routes:          make([]*RouteResult, 0, len(routes)),
		TotalRecipients: len(msg.To),
	}

	for _, route := range routes {
		routeResult := m.deliverToRoute(ctx, msg, route)
		result.Routes = append(result.Routes, routeResult)

		if routeResult.Success {
			result.SuccessfulRecipients += len(route.Recipients)
		} else {
			result.FailedRecipients += len(route.Recipients)
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = result.FailedRecipients == 0

	// Update tracking
	m.tracker.UpdateDelivery(deliveryID, result)

	m.logger.Info("Message delivery completed",
		"message_id", msg.ID,
		"delivery_id", deliveryID,
		"success", result.Success,
		"successful_recipients", result.SuccessfulRecipients,
		"failed_recipients", result.FailedRecipients,
		"duration", result.Duration)

	return result, nil
}

// deliverToRoute handles delivery to a specific route
func (m *Manager) deliverToRoute(ctx context.Context, msg *Message, route *Route) *RouteResult {
	result := &RouteResult{
		Route:     route,
		StartTime: time.Now(),
	}

	m.logger.Debug("Delivering to route",
		"route_type", route.Type,
		"host", route.Host,
		"port", route.Port,
		"recipients", len(route.Recipients))

	// Handle different route types
	switch route.Type {
	case RouteTypeDirect:
		result.Error = m.deliverDirect(ctx, msg, route)
	case RouteTypeRelay:
		result.Error = m.deliverRelay(ctx, msg, route)
	case RouteTypeLocal:
		result.Error = m.deliverLocal(ctx, msg, route)
	default:
		result.Error = fmt.Errorf("unsupported route type: %s", route.Type)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = result.Error == nil

	if result.Error != nil {
		m.logger.Error("Route delivery failed",
			"route_type", route.Type,
			"host", route.Host,
			"error", result.Error)
	} else {
		m.logger.Info("Route delivery successful",
			"route_type", route.Type,
			"host", route.Host,
			"recipients", len(route.Recipients),
			"duration", result.Duration)
	}

	return result
}

// deliverDirect handles direct SMTP delivery to MX servers
func (m *Manager) deliverDirect(ctx context.Context, msg *Message, route *Route) error {
	// Group recipients by domain
	domainGroups := make(map[string][]string)
	for _, recipient := range route.Recipients {
		parts := strings.Split(recipient, "@")
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(parts[1])
		domainGroups[domain] = append(domainGroups[domain], recipient)
	}

	// Deliver to each domain
	var lastError error
	for domain, recipients := range domainGroups {
		if err := m.deliverToDomain(ctx, msg, domain, recipients); err != nil {
			m.logger.Error("Domain delivery failed",
				"domain", domain,
				"recipients", len(recipients),
				"error", err)
			lastError = err
		}
	}

	return lastError
}

// deliverToDomain handles delivery to a specific domain using MX records
func (m *Manager) deliverToDomain(ctx context.Context, msg *Message, domain string, recipients []string) error {
	// Look up MX records
	mxRecords, err := m.dnsCache.LookupMX(ctx, domain)
	if err != nil {
		return fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for domain %s", domain)
	}

	// Sort by priority (lower number = higher priority)
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	// Try each MX record
	var lastError error
	for _, mx := range mxRecords {
		if err := m.deliverToHost(ctx, msg, mx.Host, 25, recipients); err != nil {
			m.logger.Debug("MX delivery failed",
				"host", mx.Host,
				"priority", mx.Pref,
				"error", err)
			lastError = err
			continue
		}

		// Success
		return nil
	}

	return fmt.Errorf("delivery failed to all MX servers for domain %s: %w", domain, lastError)
}

// deliverToHost handles delivery to a specific host
func (m *Manager) deliverToHost(ctx context.Context, msg *Message, host string, port int, recipients []string) error {
	// Get connection from pool
	conn, err := m.connectionPool.GetConnection(ctx, host, port)
	if err != nil {
		return fmt.Errorf("failed to get connection to %s:%d: %w", host, port, err)
	}
	defer m.connectionPool.ReturnConnection(host, port, conn)

	// Create SMTP client
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Say EHLO
	if err := client.Hello(m.config.Hostname); err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}

	// Start TLS if available and configured
	if m.config.TLSEnabled {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(m.tlsConfig); err != nil {
				m.logger.Warn("STARTTLS failed, continuing without TLS",
					"host", host,
					"error", err)
			} else {
				m.logger.Debug("STARTTLS successful", "host", host)
			}
		}
	}

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

	if _, err := writer.Write(msg.Data); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	// Quit gracefully
	if err := client.Quit(); err != nil {
		m.logger.Debug("QUIT failed", "error", err)
	}

	return nil
}

// deliverRelay handles delivery through a relay server
func (m *Manager) deliverRelay(ctx context.Context, msg *Message, route *Route) error {
	return m.deliverToHost(ctx, msg, route.Host, route.Port, route.Recipients)
}

// deliverLocal handles local delivery (placeholder for local delivery agent)
func (m *Manager) deliverLocal(ctx context.Context, msg *Message, route *Route) error {
	// This would integrate with a local delivery agent
	// For now, we'll just log the delivery
	m.logger.Info("Local delivery",
		"recipients", route.Recipients,
		"message_id", msg.ID)

	// Simulate local delivery processing time
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// GetConnectionStats returns connection pool statistics
func (m *Manager) GetConnectionStats() map[string]interface{} {
	return m.connectionPool.GetStats()
}

// GetDNSStats returns DNS cache statistics
func (m *Manager) GetDNSStats() map[string]interface{} {
	return m.dnsCache.GetStats()
}

// GetDeliveryStats returns delivery statistics
func (m *Manager) GetDeliveryStats() map[string]interface{} {
	return m.tracker.GetStats()
}

// reportMetrics periodically reports metrics
func (m *Manager) reportMetrics(ctx context.Context) {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.logger.Info("Delivery manager metrics",
				"connection_stats", m.GetConnectionStats(),
				"dns_stats", m.GetDNSStats(),
				"delivery_stats", m.GetDeliveryStats())
		}
	}
}

// createTLSConfig creates a TLS configuration from the config
func createTLSConfig(config *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.TLSInsecureSkipVerify,
	}

	// Set minimum TLS version
	switch config.TLSMinVersion {
	case "1.0":
		tlsConfig.MinVersion = tls.VersionTLS10
	case "1.1":
		tlsConfig.MinVersion = tls.VersionTLS11
	case "1.2":
		tlsConfig.MinVersion = tls.VersionTLS12
	case "1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
	default:
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	return tlsConfig, nil
}
