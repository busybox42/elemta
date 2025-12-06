package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"log/slog"
)

// RateLimiterPlugin implements comprehensive rate limiting for SMTP connections
type RateLimiterPlugin struct {
	config *RateLimiterConfig
	logger *slog.Logger

	// Rate limiters for different types of limits
	connectionLimiter *ConnectionRateLimiter
	messageLimiter    *MessageRateLimiter
	volumeLimiter     *VolumeRateLimiter
	authLimiter       *AuthRateLimiter

	// Whitelist/blacklist management
	whitelist *AccessList
	blacklist *AccessList

	// Redis client for distributed rate limiting
	redisClient *RedisClient

	// Metrics
	metrics *RateLimiterMetrics

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// RateLimiterConfig contains configuration for the rate limiter plugin
type RateLimiterConfig struct {
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// Connection limits
	MaxConnectionsPerIP     int           `toml:"max_connections_per_ip" json:"max_connections_per_ip" yaml:"max_connections_per_ip"`
	ConnectionRatePerMinute int           `toml:"connection_rate_per_minute" json:"connection_rate_per_minute" yaml:"connection_rate_per_minute"`
	ConnectionBurstSize     int           `toml:"connection_burst_size" json:"connection_burst_size" yaml:"connection_burst_size"`
	ConnectionTimeout       time.Duration `toml:"connection_timeout" json:"connection_timeout" yaml:"connection_timeout"`

	// Message limits
	MaxMessagesPerMinute    int `toml:"max_messages_per_minute" json:"max_messages_per_minute" yaml:"max_messages_per_minute"`
	MaxMessagesPerHour      int `toml:"max_messages_per_hour" json:"max_messages_per_hour" yaml:"max_messages_per_hour"`
	MaxRecipientsPerMessage int `toml:"max_recipients_per_message" json:"max_recipients_per_message" yaml:"max_recipients_per_message"`
	MaxRecipientsPerHour    int `toml:"max_recipients_per_hour" json:"max_recipients_per_hour" yaml:"max_recipients_per_hour"`

	// Volume limits
	MaxMessageSize   string        `toml:"max_message_size" json:"max_message_size" yaml:"max_message_size"`
	MaxDataPerHour   string        `toml:"max_data_per_hour" json:"max_data_per_hour" yaml:"max_data_per_hour"`
	VolumeBurstSize  string        `toml:"volume_burst_size" json:"volume_burst_size" yaml:"volume_burst_size"`
	VolumeRateWindow time.Duration `toml:"volume_rate_window" json:"volume_rate_window" yaml:"volume_rate_window"`

	// Authentication limits
	MaxAuthAttemptsPerMinute int           `toml:"max_auth_attempts_per_minute" json:"max_auth_attempts_per_minute" yaml:"max_auth_attempts_per_minute"`
	AuthLockoutDuration      time.Duration `toml:"auth_lockout_duration" json:"auth_lockout_duration" yaml:"auth_lockout_duration"`
	AuthBurstSize            int           `toml:"auth_burst_size" json:"auth_burst_size" yaml:"auth_burst_size"`

	// Access lists
	WhitelistIPs     []string `toml:"whitelist_ips" json:"whitelist_ips" yaml:"whitelist_ips"`
	WhitelistDomains []string `toml:"whitelist_domains" json:"whitelist_domains" yaml:"whitelist_domains"`
	BlacklistIPs     []string `toml:"blacklist_ips" json:"blacklist_ips" yaml:"blacklist_ips"`
	BlacklistDomains []string `toml:"blacklist_domains" json:"blacklist_domains" yaml:"blacklist_domains"`

	// Valkey backend for distributed rate limiting
	ValkeyURL       string `toml:"valkey_url" json:"valkey_url" yaml:"valkey_url"`
	ValkeyKeyPrefix string `toml:"valkey_key_prefix" json:"valkey_key_prefix" yaml:"valkey_key_prefix"`

	// Advanced settings
	CacheSize       int           `toml:"cache_size" json:"cache_size" yaml:"cache_size"`
	CacheTTL        time.Duration `toml:"cache_ttl" json:"cache_ttl" yaml:"cache_ttl"`
	CleanupInterval time.Duration `toml:"cleanup_interval" json:"cleanup_interval" yaml:"cleanup_interval"`
	MetricsEnabled  bool          `toml:"metrics_enabled" json:"metrics_enabled" yaml:"metrics_enabled"`
}

// DefaultRateLimiterConfig returns sensible defaults for rate limiting
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		Enabled: true,

		// Connection limits - conservative defaults
		MaxConnectionsPerIP:     10,
		ConnectionRatePerMinute: 100,
		ConnectionBurstSize:     20,
		ConnectionTimeout:       30 * time.Second,

		// Message limits - reasonable for most use cases
		MaxMessagesPerMinute:    60,
		MaxMessagesPerHour:      1000,
		MaxRecipientsPerMessage: 100,
		MaxRecipientsPerHour:    5000,

		// Volume limits - 50MB per message, 1GB per hour
		MaxMessageSize:   "50MB",
		MaxDataPerHour:   "1GB",
		VolumeBurstSize:  "100MB",
		VolumeRateWindow: 5 * time.Minute,

		// Authentication limits - prevent brute force
		MaxAuthAttemptsPerMinute: 5,
		AuthLockoutDuration:      15 * time.Minute,
		AuthBurstSize:            10,

		// Access lists - empty by default
		WhitelistIPs:     []string{},
		WhitelistDomains: []string{},
		BlacklistIPs:     []string{},
		BlacklistDomains: []string{},

		// Valkey backend - disabled by default
		ValkeyURL:       "",
		ValkeyKeyPrefix: "elemta:ratelimit:",

		// Advanced settings
		CacheSize:       10000,
		CacheTTL:        1 * time.Hour,
		CleanupInterval: 5 * time.Minute,
		MetricsEnabled:  true,
	}
}

// TokenBucket implements the token bucket algorithm for rate limiting
type TokenBucket struct {
	capacity   int64     // Maximum number of tokens
	tokens     int64     // Current number of tokens
	lastRefill time.Time // Last time tokens were refilled
	refillRate int64     // Tokens per second
	mu         sync.Mutex
}

// DistributedTokenBucket implements token bucket with Redis backend
type DistributedTokenBucket struct {
	capacity    int64
	refillRate  int64
	redisClient *RedisClient
	key         string
	ttl         time.Duration
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // Start with full bucket
		lastRefill: time.Now(),
		refillRate: refillRate,
	}
}

// TryConsume attempts to consume the specified number of tokens
// Returns true if tokens were consumed, false if insufficient tokens
func (tb *TokenBucket) TryConsume(tokens int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()

	// Refill tokens based on time elapsed
	timePassed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := int64(timePassed * float64(tb.refillRate))

	tb.tokens += tokensToAdd
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now

	// Check if we have enough tokens
	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}

	return false
}

// GetTokens returns the current number of tokens (for monitoring)
func (tb *TokenBucket) GetTokens() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	timePassed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := int64(timePassed * float64(tb.refillRate))

	currentTokens := tb.tokens + tokensToAdd
	if currentTokens > tb.capacity {
		return tb.capacity
	}
	return currentTokens
}

// NewDistributedTokenBucket creates a new distributed token bucket
func NewDistributedTokenBucket(capacity, refillRate int64, redisClient *RedisClient, key string, ttl time.Duration) *DistributedTokenBucket {
	return &DistributedTokenBucket{
		capacity:    capacity,
		refillRate:  refillRate,
		redisClient: redisClient,
		key:         key,
		ttl:         ttl,
	}
}

// TryConsume attempts to consume the specified number of tokens from Redis
func (dtb *DistributedTokenBucket) TryConsume(ctx context.Context, tokens int64) (bool, error) {
	if dtb.redisClient == nil || !dtb.redisClient.enabled {
		return false, fmt.Errorf("Redis client not available")
	}

	// Get current state from Redis
	state, err := dtb.redisClient.GetTokenBucket(ctx, dtb.key)
	if err != nil {
		// If key doesn't exist, create initial state
		state = &TokenBucketState{
			Tokens:     float64(dtb.capacity),
			LastRefill: time.Now(),
		}
	}

	now := time.Now()

	// Refill tokens based on time elapsed
	timePassed := now.Sub(state.LastRefill).Seconds()
	tokensToAdd := int64(timePassed * float64(dtb.refillRate))

	state.Tokens += float64(tokensToAdd)
	if state.Tokens > float64(dtb.capacity) {
		state.Tokens = float64(dtb.capacity)
	}
	state.LastRefill = now

	// Check if we have enough tokens
	if state.Tokens >= float64(tokens) {
		state.Tokens -= float64(tokens)

		// Save updated state to Redis
		err = dtb.redisClient.SetTokenBucket(ctx, dtb.key, state, dtb.ttl)
		if err != nil {
			return false, fmt.Errorf("failed to update token bucket state: %w", err)
		}

		return true, nil
	}

	// Save current state even if we couldn't consume tokens
	err = dtb.redisClient.SetTokenBucket(ctx, dtb.key, state, dtb.ttl)
	if err != nil {
		return false, fmt.Errorf("failed to update token bucket state: %w", err)
	}

	return false, nil
}

// ConnectionRateLimiter manages connection rate limits per IP
type ConnectionRateLimiter struct {
	config        *RateLimiterConfig
	buckets       map[string]*TokenBucket
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewConnectionRateLimiter creates a new connection rate limiter
func NewConnectionRateLimiter(config *RateLimiterConfig) *ConnectionRateLimiter {
	ctx, cancel := context.WithCancel(context.Background())

	limiter := &ConnectionRateLimiter{
		config:  config,
		buckets: make(map[string]*TokenBucket),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup goroutine
	limiter.cleanupTicker = time.NewTicker(config.CleanupInterval)
	go limiter.cleanup()

	return limiter
}

// CheckConnection checks if a connection should be allowed for the given IP
func (crl *ConnectionRateLimiter) CheckConnection(ip string) (bool, string) {
	crl.mu.Lock()
	defer crl.mu.Unlock()

	bucket, exists := crl.buckets[ip]
	if !exists {
		// Create new bucket for this IP
		bucket = NewTokenBucket(
			int64(crl.config.ConnectionBurstSize),
			int64(crl.config.ConnectionRatePerMinute)/60, // Convert per minute to per second
		)
		crl.buckets[ip] = bucket
	}

	// Try to consume one token for the connection
	if bucket.TryConsume(1) {
		return true, ""
	}

	return false, fmt.Sprintf("connection rate limit exceeded for %s", ip)
}

// CheckConnectionRate checks the connection rate (not actual connections)
func (crl *ConnectionRateLimiter) CheckConnectionRate(ip string) (bool, string) {
	crl.mu.Lock()
	defer crl.mu.Unlock()

	bucket, exists := crl.buckets[ip]
	if !exists {
		// Create new bucket for this IP
		bucket = NewTokenBucket(
			int64(crl.config.ConnectionBurstSize),
			int64(crl.config.ConnectionRatePerMinute)/60, // Convert per minute to per second
		)
		crl.buckets[ip] = bucket
	}

	// Try to consume one token for the connection rate check
	if bucket.TryConsume(1) {
		return true, ""
	}

	return false, fmt.Sprintf("connection rate limit exceeded for %s", ip)
}

// cleanup removes old buckets to prevent memory leaks
func (crl *ConnectionRateLimiter) cleanup() {
	for {
		select {
		case <-crl.ctx.Done():
			return
		case <-crl.cleanupTicker.C:
			crl.mu.Lock()
			// Remove buckets that haven't been used recently
			// For now, we'll keep all buckets but this could be enhanced
			// to remove inactive IPs after a certain period
			crl.mu.Unlock()
		}
	}
}

// Close stops the connection rate limiter
func (crl *ConnectionRateLimiter) Close() {
	crl.cancel()
	if crl.cleanupTicker != nil {
		crl.cleanupTicker.Stop()
	}
}

// MessageRateLimiter manages message rate limits per sender/domain
type MessageRateLimiter struct {
	config  *RateLimiterConfig
	buckets map[string]*TokenBucket
	mu      sync.RWMutex
}

// NewMessageRateLimiter creates a new message rate limiter
func NewMessageRateLimiter(config *RateLimiterConfig) *MessageRateLimiter {
	return &MessageRateLimiter{
		config:  config,
		buckets: make(map[string]*TokenBucket),
	}
}

// CheckMessageRate checks if a message should be allowed for the given sender
func (mrl *MessageRateLimiter) CheckMessageRate(sender string) (bool, string) {
	mrl.mu.Lock()
	defer mrl.mu.Unlock()

	bucket, exists := mrl.buckets[sender]
	if !exists {
		// Create new bucket for this sender
		bucket = NewTokenBucket(
			int64(mrl.config.MaxMessagesPerMinute),
			int64(mrl.config.MaxMessagesPerMinute)/60, // Convert per minute to per second
		)
		mrl.buckets[sender] = bucket
	}

	// Try to consume one token for the message
	if bucket.TryConsume(1) {
		return true, ""
	}

	return false, fmt.Sprintf("message rate limit exceeded for sender %s", sender)
}

// CheckRecipientRate checks if recipients should be allowed for the given sender
func (mrl *MessageRateLimiter) CheckRecipientRate(sender string, recipientCount int) (bool, string) {
	mrl.mu.Lock()
	defer mrl.mu.Unlock()

	key := fmt.Sprintf("%s:recipients", sender)
	bucket, exists := mrl.buckets[key]
	if !exists {
		// Create new bucket for recipients from this sender
		bucket = NewTokenBucket(
			int64(mrl.config.MaxRecipientsPerHour),
			int64(mrl.config.MaxRecipientsPerHour)/3600, // Convert per hour to per second
		)
		mrl.buckets[key] = bucket
	}

	// Try to consume tokens for the recipients
	if bucket.TryConsume(int64(recipientCount)) {
		return true, ""
	}

	return false, fmt.Sprintf("recipient rate limit exceeded for sender %s", sender)
}

// VolumeRateLimiter manages volume-based rate limits per IP
type VolumeRateLimiter struct {
	config  *RateLimiterConfig
	buckets map[string]*TokenBucket
	mu      sync.RWMutex
}

// NewVolumeRateLimiter creates a new volume rate limiter
func NewVolumeRateLimiter(config *RateLimiterConfig) *VolumeRateLimiter {
	return &VolumeRateLimiter{
		config:  config,
		buckets: make(map[string]*TokenBucket),
	}
}

// CheckVolumeRate checks if data transfer should be allowed for the given IP
func (vrl *VolumeRateLimiter) CheckVolumeRate(ip string, dataSize int64) (bool, string) {
	vrl.mu.Lock()
	defer vrl.mu.Unlock()

	bucket, exists := vrl.buckets[ip]
	if !exists {
		// Create new bucket for this IP
		// Parse volume limits from config strings
		maxDataPerHour, err := parseSize(vrl.config.MaxDataPerHour)
		if err != nil {
			return false, fmt.Sprintf("invalid volume configuration: %v", err)
		}

		bucket = NewTokenBucket(
			maxDataPerHour,
			maxDataPerHour/3600, // Convert per hour to per second
		)
		vrl.buckets[ip] = bucket
	}

	// Try to consume tokens for the data size
	if bucket.TryConsume(dataSize) {
		return true, ""
	}

	return false, fmt.Sprintf("volume rate limit exceeded for %s", ip)
}

// AuthRateLimiter manages authentication rate limits per IP
type AuthRateLimiter struct {
	config   *RateLimiterConfig
	buckets  map[string]*TokenBucket
	lockouts map[string]time.Time
	mu       sync.RWMutex
}

// NewAuthRateLimiter creates a new authentication rate limiter
func NewAuthRateLimiter(config *RateLimiterConfig) *AuthRateLimiter {
	return &AuthRateLimiter{
		config:   config,
		buckets:  make(map[string]*TokenBucket),
		lockouts: make(map[string]time.Time),
	}
}

// CheckAuthRate checks if authentication should be allowed for the given IP
func (arl *AuthRateLimiter) CheckAuthRate(ip string) (bool, string) {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	// Check if IP is currently locked out
	if lockoutTime, exists := arl.lockouts[ip]; exists {
		if time.Now().Before(lockoutTime) {
			return false, fmt.Sprintf("authentication locked out for %s until %v", ip, lockoutTime)
		}
		// Lockout expired, remove it
		delete(arl.lockouts, ip)
	}

	bucket, exists := arl.buckets[ip]
	if !exists {
		// Create new bucket for this IP
		bucket = NewTokenBucket(
			int64(arl.config.AuthBurstSize),
			int64(arl.config.MaxAuthAttemptsPerMinute)/60, // Convert per minute to per second
		)
		arl.buckets[ip] = bucket
	}

	// Try to consume one token for the auth attempt
	if bucket.TryConsume(1) {
		return true, ""
	}

	// Rate limit exceeded, set lockout
	arl.lockouts[ip] = time.Now().Add(arl.config.AuthLockoutDuration)
	return false, fmt.Sprintf("authentication rate limit exceeded for %s, locked out for %v", ip, arl.config.AuthLockoutDuration)
}

// AccessList manages whitelist and blacklist functionality
type AccessList struct {
	whitelistIPs     map[string]bool
	whitelistDomains map[string]bool
	blacklistIPs     map[string]bool
	blacklistDomains map[string]bool
	mu               sync.RWMutex
}

// NewAccessList creates a new access list
func NewAccessList(config *RateLimiterConfig) *AccessList {
	al := &AccessList{
		whitelistIPs:     make(map[string]bool),
		whitelistDomains: make(map[string]bool),
		blacklistIPs:     make(map[string]bool),
		blacklistDomains: make(map[string]bool),
	}

	// Initialize with configured lists
	for _, ip := range config.WhitelistIPs {
		al.whitelistIPs[ip] = true
	}
	for _, domain := range config.WhitelistDomains {
		al.whitelistDomains[domain] = true
	}
	for _, ip := range config.BlacklistIPs {
		al.blacklistIPs[ip] = true
	}
	for _, domain := range config.BlacklistDomains {
		al.blacklistDomains[domain] = true
	}

	return al
}

// IsWhitelisted checks if an IP or domain is whitelisted
func (al *AccessList) IsWhitelisted(ip, domain string) bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	// Check IP whitelist
	if _, exists := al.whitelistIPs[ip]; exists {
		return true
	}

	// Check domain whitelist
	if _, exists := al.whitelistDomains[domain]; exists {
		return true
	}

	return false
}

// IsBlacklisted checks if an IP or domain is blacklisted
func (al *AccessList) IsBlacklisted(ip, domain string) bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	// Check IP blacklist
	if _, exists := al.blacklistIPs[ip]; exists {
		return true
	}

	// Check domain blacklist
	if _, exists := al.blacklistDomains[domain]; exists {
		return true
	}

	return false
}

// RateLimiterMetrics tracks rate limiting metrics
type RateLimiterMetrics struct {
	ConnectionLimitsHit    int64
	MessageLimitsHit       int64
	VolumeLimitsHit        int64
	AuthLimitsHit          int64
	WhitelistHits          int64
	BlacklistHits          int64
	TotalRequestsProcessed int64
	mu                     sync.RWMutex
}

// NewRateLimiterMetrics creates new rate limiter metrics
func NewRateLimiterMetrics() *RateLimiterMetrics {
	return &RateLimiterMetrics{}
}

// IncrementConnectionLimitsHit increments the connection limits hit counter
func (rm *RateLimiterMetrics) IncrementConnectionLimitsHit() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.ConnectionLimitsHit++
}

// IncrementMessageLimitsHit increments the message limits hit counter
func (rm *RateLimiterMetrics) IncrementMessageLimitsHit() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.MessageLimitsHit++
}

// IncrementVolumeLimitsHit increments the volume limits hit counter
func (rm *RateLimiterMetrics) IncrementVolumeLimitsHit() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.VolumeLimitsHit++
}

// IncrementAuthLimitsHit increments the auth limits hit counter
func (rm *RateLimiterMetrics) IncrementAuthLimitsHit() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.AuthLimitsHit++
}

// IncrementWhitelistHits increments the whitelist hits counter
func (rm *RateLimiterMetrics) IncrementWhitelistHits() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.WhitelistHits++
}

// IncrementBlacklistHits increments the blacklist hits counter
func (rm *RateLimiterMetrics) IncrementBlacklistHits() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.BlacklistHits++
}

// IncrementTotalRequests increments the total requests counter
func (rm *RateLimiterMetrics) IncrementTotalRequests() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.TotalRequestsProcessed++
}

// GetMetrics returns current metrics
func (rm *RateLimiterMetrics) GetMetrics() map[string]int64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return map[string]int64{
		"connection_limits_hit":    rm.ConnectionLimitsHit,
		"message_limits_hit":       rm.MessageLimitsHit,
		"volume_limits_hit":        rm.VolumeLimitsHit,
		"auth_limits_hit":          rm.AuthLimitsHit,
		"whitelist_hits":           rm.WhitelistHits,
		"blacklist_hits":           rm.BlacklistHits,
		"total_requests_processed": rm.TotalRequestsProcessed,
	}
}

// parseSize parses size strings like "50MB", "1GB" into bytes
func parseSize(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Simple parser for common size units
	// This could be enhanced to support more formats
	sizeStr = sizeStr[:len(sizeStr)-2] // Remove last 2 characters (unit)
	var multiplier int64

	switch sizeStr[len(sizeStr)-1:] {
	case "B":
		multiplier = 1
		sizeStr = sizeStr[:len(sizeStr)-1]
	case "K":
		multiplier = 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case "M":
		multiplier = 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	case "G":
		multiplier = 1024 * 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	default:
		return 0, fmt.Errorf("unsupported size unit")
	}

	var size int64
	if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
		return 0, fmt.Errorf("invalid size format: %v", err)
	}

	return size * multiplier, nil
}
