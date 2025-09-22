package plugin

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"log/slog"
)

// NewRateLimiterPlugin creates a new rate limiter plugin instance
func NewRateLimiterPlugin() *RateLimiterPlugin {
	ctx, cancel := context.WithCancel(context.Background())

	return &RateLimiterPlugin{
		config:  DefaultRateLimiterConfig(),
		logger:  slog.Default().With("component", "rate-limiter-plugin"),
		metrics: NewRateLimiterMetrics(),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// GetInfo returns plugin information
func (rlp *RateLimiterPlugin) GetInfo() *PluginInfo {
	return &PluginInfo{
		Name:        "rate-limiter",
		Description: "Comprehensive rate limiting plugin for SMTP connections",
		Version:     "1.0.0",
		Type:        PluginTypeRateLimit,
		Author:      "Elemta Team",
	}
}

// Init initializes the rate limiter plugin with configuration
func (rlp *RateLimiterPlugin) Init(config map[string]interface{}) error {
	rlp.logger.Info("Initializing rate limiter plugin")

	// Parse configuration
	if config != nil {
		if err := rlp.parseConfig(config); err != nil {
			return fmt.Errorf("failed to parse configuration: %w", err)
		}
	}

	if !rlp.config.Enabled {
		rlp.logger.Info("Rate limiter plugin disabled")
		return nil
	}

	// Initialize Valkey client if configured
	if rlp.config.ValkeyURL != "" {
		var err error
		rlp.redisClient, err = NewRedisClient(rlp.config.ValkeyURL, rlp.config.ValkeyKeyPrefix, rlp.logger)
		if err != nil {
			rlp.logger.Warn("Failed to initialize Valkey client, falling back to local rate limiting", "error", err)
		} else {
			rlp.logger.Info("Valkey client initialized for distributed rate limiting")
		}
	}

	// Initialize rate limiters
	rlp.connectionLimiter = NewConnectionRateLimiter(rlp.config)
	rlp.messageLimiter = NewMessageRateLimiter(rlp.config)
	rlp.volumeLimiter = NewVolumeRateLimiter(rlp.config)
	rlp.authLimiter = NewAuthRateLimiter(rlp.config)

	// Initialize access lists
	rlp.whitelist = NewAccessList(rlp.config)
	rlp.blacklist = NewAccessList(rlp.config)

	rlp.logger.Info("Rate limiter plugin initialized successfully",
		"connection_limit_per_ip", rlp.config.MaxConnectionsPerIP,
		"message_limit_per_minute", rlp.config.MaxMessagesPerMinute,
		"max_message_size", rlp.config.MaxMessageSize,
		"auth_attempts_per_minute", rlp.config.MaxAuthAttemptsPerMinute)

	return nil
}

// Close shuts down the rate limiter plugin
func (rlp *RateLimiterPlugin) Close() error {
	rlp.logger.Info("Shutting down rate limiter plugin")

	rlp.cancel()

	if rlp.connectionLimiter != nil {
		rlp.connectionLimiter.Close()
	}

	// Close Valkey client
	if rlp.redisClient != nil {
		if err := rlp.redisClient.Close(); err != nil {
			rlp.logger.Warn("Error closing Valkey client", "error", err)
		}
	}

	rlp.logger.Info("Rate limiter plugin shut down successfully")
	return nil
}

// parseConfig parses configuration from a map
func (rlp *RateLimiterPlugin) parseConfig(config map[string]interface{}) error {
	// This is a simplified config parser
	// In a production system, you'd want to use a proper config library

	if enabled, ok := config["enabled"].(bool); ok {
		rlp.config.Enabled = enabled
	}

	if maxConnections, ok := config["max_connections_per_ip"].(int); ok {
		rlp.config.MaxConnectionsPerIP = maxConnections
	}

	if connectionRate, ok := config["connection_rate_per_minute"].(int); ok {
		rlp.config.ConnectionRatePerMinute = connectionRate
	}

	if maxMessages, ok := config["max_messages_per_minute"].(int); ok {
		rlp.config.MaxMessagesPerMinute = maxMessages
	}

	if maxMessageSize, ok := config["max_message_size"].(string); ok {
		rlp.config.MaxMessageSize = maxMessageSize
	}

	if maxAuthAttempts, ok := config["max_auth_attempts_per_minute"].(int); ok {
		rlp.config.MaxAuthAttemptsPerMinute = maxAuthAttempts
	}

	if authLockoutDuration, ok := config["auth_lockout_duration"].(string); ok {
		if duration, err := time.ParseDuration(authLockoutDuration); err == nil {
			rlp.config.AuthLockoutDuration = duration
		}
	}

	// Parse whitelist/blacklist arrays
	if whitelistIPs, ok := config["whitelist_ips"].([]interface{}); ok {
		for _, ip := range whitelistIPs {
			if ipStr, ok := ip.(string); ok {
				rlp.config.WhitelistIPs = append(rlp.config.WhitelistIPs, ipStr)
			}
		}
	}

	if blacklistIPs, ok := config["blacklist_ips"].([]interface{}); ok {
		for _, ip := range blacklistIPs {
			if ipStr, ok := ip.(string); ok {
				rlp.config.BlacklistIPs = append(rlp.config.BlacklistIPs, ipStr)
			}
		}
	}

	return nil
}

// extractIP extracts the IP address from a network address
func (rlp *RateLimiterPlugin) extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	// Handle both TCP and UDP addresses
	addrStr := addr.String()
	if idx := strings.LastIndex(addrStr, ":"); idx != -1 {
		return addrStr[:idx]
	}
	return addrStr
}

// extractDomain extracts the domain from an email address
func (rlp *RateLimiterPlugin) extractDomain(email string) string {
	if idx := strings.LastIndex(email, "@"); idx != -1 {
		return email[idx+1:]
	}
	return ""
}

// Plugin interface implementations

// ConnectionHook implementation
func (rlp *RateLimiterPlugin) OnConnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	if !rlp.config.Enabled {
		return &PluginResult{Action: ActionContinue}, nil
	}

	rlp.metrics.IncrementTotalRequests()

	ip := rlp.extractIP(remoteAddr)
	if ip == "" {
		rlp.logger.Warn("Could not extract IP from remote address", "remote_addr", remoteAddr)
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check whitelist first
	if rlp.whitelist.IsWhitelisted(ip, "") {
		rlp.metrics.IncrementWhitelistHits()
		rlp.logger.Debug("IP whitelisted, allowing connection", "ip", ip)
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check blacklist
	if rlp.blacklist.IsBlacklisted(ip, "") {
		rlp.metrics.IncrementBlacklistHits()
		rlp.logger.Info("IP blacklisted, rejecting connection", "ip", ip)
		return &PluginResult{
			Action:  ActionReject,
			Message: "Connection rejected: IP address blacklisted",
		}, nil
	}

	// Check connection rate limit
	allowed, reason := rlp.connectionLimiter.CheckConnectionRate(ip)
	if !allowed {
		rlp.metrics.IncrementConnectionLimitsHit()
		rlp.logger.Warn("Connection rate limit exceeded", "ip", ip, "reason", reason)
		return &PluginResult{
			Action:  ActionReject,
			Message: fmt.Sprintf("Connection rate limit exceeded: %s", reason),
		}, nil
	}

	rlp.logger.Debug("Connection allowed", "ip", ip)
	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnDisconnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	// No rate limiting needed for disconnection
	return &PluginResult{Action: ActionContinue}, nil
}

// MailTransactionHook implementation
func (rlp *RateLimiterPlugin) OnMailFrom(ctx *HookContext, sender string, params map[string]string) (*PluginResult, error) {
	if !rlp.config.Enabled {
		return &PluginResult{Action: ActionContinue}, nil
	}

	ip := rlp.extractIP(ctx.RemoteAddr)
	if ip == "" {
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check whitelist first
	if rlp.whitelist.IsWhitelisted(ip, rlp.extractDomain(sender)) {
		rlp.metrics.IncrementWhitelistHits()
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check blacklist
	if rlp.blacklist.IsBlacklisted(ip, rlp.extractDomain(sender)) {
		rlp.metrics.IncrementBlacklistHits()
		rlp.logger.Info("Sender blacklisted", "sender", sender, "ip", ip)
		return &PluginResult{
			Action:  ActionReject,
			Message: "Sender blacklisted",
		}, nil
	}

	// Check message rate limit
	allowed, reason := rlp.messageLimiter.CheckMessageRate(sender)
	if !allowed {
		rlp.metrics.IncrementMessageLimitsHit()
		rlp.logger.Warn("Message rate limit exceeded", "sender", sender, "reason", reason)
		return &PluginResult{
			Action:  ActionReject,
			Message: fmt.Sprintf("Message rate limit exceeded: %s", reason),
		}, nil
	}

	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnRcptTo(ctx *HookContext, recipient string, params map[string]string) (*PluginResult, error) {
	if !rlp.config.Enabled {
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Get sender from context if available
	var sender string
	if senderData, exists := ctx.Get("sender"); exists {
		if senderStr, ok := senderData.(string); ok {
			sender = senderStr
		}
	}

	if sender == "" {
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check recipient rate limit (1 recipient per call)
	allowed, reason := rlp.messageLimiter.CheckRecipientRate(sender, 1)
	if !allowed {
		rlp.metrics.IncrementMessageLimitsHit()
		rlp.logger.Warn("Recipient rate limit exceeded", "sender", sender, "reason", reason)
		return &PluginResult{
			Action:  ActionReject,
			Message: fmt.Sprintf("Recipient rate limit exceeded: %s", reason),
		}, nil
	}

	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnData(ctx *HookContext) (*PluginResult, error) {
	// Data rate limiting will be handled in OnMessageComplete
	return &PluginResult{Action: ActionContinue}, nil
}

// MessageProcessingHook implementation
func (rlp *RateLimiterPlugin) OnMessageComplete(ctx *HookContext, rawMessage []byte) (*PluginResult, error) {
	if !rlp.config.Enabled {
		return &PluginResult{Action: ActionContinue}, nil
	}

	ip := rlp.extractIP(ctx.RemoteAddr)
	if ip == "" {
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check volume rate limit
	allowed, reason := rlp.volumeLimiter.CheckVolumeRate(ip, int64(len(rawMessage)))
	if !allowed {
		rlp.metrics.IncrementVolumeLimitsHit()
		rlp.logger.Warn("Volume rate limit exceeded", "ip", ip, "message_size", len(rawMessage), "reason", reason)
		return &PluginResult{
			Action:  ActionReject,
			Message: fmt.Sprintf("Volume rate limit exceeded: %s", reason),
		}, nil
	}

	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnHeaders(ctx *HookContext, headers map[string][]string) (*PluginResult, error) {
	// No rate limiting needed for headers
	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnBody(ctx *HookContext, body []byte) (*PluginResult, error) {
	// Volume limiting will be handled in OnMessageComplete
	return &PluginResult{Action: ActionContinue}, nil
}

// SMTPCommandHook implementation
func (rlp *RateLimiterPlugin) OnAuth(ctx *HookContext, mechanism, username string) (*PluginResult, error) {
	if !rlp.config.Enabled {
		return &PluginResult{Action: ActionContinue}, nil
	}

	ip := rlp.extractIP(ctx.RemoteAddr)
	if ip == "" {
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check whitelist first
	if rlp.whitelist.IsWhitelisted(ip, rlp.extractDomain(username)) {
		rlp.metrics.IncrementWhitelistHits()
		return &PluginResult{Action: ActionContinue}, nil
	}

	// Check authentication rate limit
	allowed, reason := rlp.authLimiter.CheckAuthRate(ip)
	if !allowed {
		rlp.metrics.IncrementAuthLimitsHit()
		rlp.logger.Warn("Authentication rate limit exceeded", "ip", ip, "username", username, "reason", reason)
		return &PluginResult{
			Action:  ActionReject,
			Message: fmt.Sprintf("Authentication rate limit exceeded: %s", reason),
		}, nil
	}

	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnHelo(ctx *HookContext, hostname string) (*PluginResult, error) {
	// No rate limiting needed for HELO
	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnEhlo(ctx *HookContext, hostname string) (*PluginResult, error) {
	// No rate limiting needed for EHLO
	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnStartTLS(ctx *HookContext) (*PluginResult, error) {
	// No rate limiting needed for STARTTLS
	return &PluginResult{Action: ActionContinue}, nil
}

// SecurityHook implementation
func (rlp *RateLimiterPlugin) OnRateLimitCheck(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	// This is the main rate limiting hook
	return rlp.OnConnect(ctx, remoteAddr)
}

func (rlp *RateLimiterPlugin) OnGreylistCheck(ctx *HookContext, sender, recipient string, remoteAddr net.Addr) (*PluginResult, error) {
	// Greylisting is not implemented in this plugin
	return &PluginResult{Action: ActionContinue}, nil
}

func (rlp *RateLimiterPlugin) OnReputationCheck(ctx *HookContext, remoteAddr net.Addr, domain string) (*PluginResult, error) {
	// Reputation checking is not implemented in this plugin
	return &PluginResult{Action: ActionContinue}, nil
}

// GetMetrics returns current rate limiting metrics
func (rlp *RateLimiterPlugin) GetMetrics() map[string]interface{} {
	metrics := rlp.metrics.GetMetrics()

	// Convert metrics to interface{} map and add configuration information
	result := make(map[string]interface{})
	for k, v := range metrics {
		result[k] = v
	}

	result["config"] = map[string]interface{}{
		"enabled":                      rlp.config.Enabled,
		"max_connections_per_ip":       rlp.config.MaxConnectionsPerIP,
		"connection_rate_per_minute":   rlp.config.ConnectionRatePerMinute,
		"max_messages_per_minute":      rlp.config.MaxMessagesPerMinute,
		"max_message_size":             rlp.config.MaxMessageSize,
		"max_auth_attempts_per_minute": rlp.config.MaxAuthAttemptsPerMinute,
		"auth_lockout_duration":        rlp.config.AuthLockoutDuration.String(),
		"whitelist_ips_count":          len(rlp.config.WhitelistIPs),
		"blacklist_ips_count":          len(rlp.config.BlacklistIPs),
	}

	return result
}

// UpdateConfig updates the plugin configuration at runtime
func (rlp *RateLimiterPlugin) UpdateConfig(config map[string]interface{}) error {
	rlp.logger.Info("Updating rate limiter plugin configuration")

	// Parse new configuration
	if err := rlp.parseConfig(config); err != nil {
		return fmt.Errorf("failed to parse new configuration: %w", err)
	}

	// Reinitialize rate limiters with new config
	if rlp.config.Enabled {
		if rlp.connectionLimiter != nil {
			rlp.connectionLimiter.Close()
		}
		if rlp.connectionLimiter != nil {
			rlp.connectionLimiter.Close()
		}

		rlp.connectionLimiter = NewConnectionRateLimiter(rlp.config)
		rlp.messageLimiter = NewMessageRateLimiter(rlp.config)
		rlp.volumeLimiter = NewVolumeRateLimiter(rlp.config)
		rlp.authLimiter = NewAuthRateLimiter(rlp.config)

		// Update access lists
		rlp.whitelist = NewAccessList(rlp.config)
		rlp.blacklist = NewAccessList(rlp.config)
	}

	rlp.logger.Info("Rate limiter plugin configuration updated successfully")
	return nil
}

// AddToWhitelist adds an IP or domain to the whitelist
func (rlp *RateLimiterPlugin) AddToWhitelist(item string) error {
	if rlp.whitelist == nil {
		return fmt.Errorf("whitelist not initialized")
	}

	// Determine if it's an IP or domain
	if net.ParseIP(item) != nil {
		rlp.whitelist.whitelistIPs[item] = true
		rlp.logger.Info("Added IP to whitelist", "ip", item)
	} else {
		rlp.whitelist.whitelistDomains[item] = true
		rlp.logger.Info("Added domain to whitelist", "domain", item)
	}

	return nil
}

// AddToBlacklist adds an IP or domain to the blacklist
func (rlp *RateLimiterPlugin) AddToBlacklist(item string) error {
	if rlp.blacklist == nil {
		return fmt.Errorf("blacklist not initialized")
	}

	// Determine if it's an IP or domain
	if net.ParseIP(item) != nil {
		rlp.blacklist.blacklistIPs[item] = true
		rlp.logger.Info("Added IP to blacklist", "ip", item)
	} else {
		rlp.blacklist.blacklistDomains[item] = true
		rlp.logger.Info("Added domain to blacklist", "domain", item)
	}

	return nil
}

// RemoveFromWhitelist removes an IP or domain from the whitelist
func (rlp *RateLimiterPlugin) RemoveFromWhitelist(item string) error {
	if rlp.whitelist == nil {
		return fmt.Errorf("whitelist not initialized")
	}

	// Determine if it's an IP or domain
	if net.ParseIP(item) != nil {
		delete(rlp.whitelist.whitelistIPs, item)
		rlp.logger.Info("Removed IP from whitelist", "ip", item)
	} else {
		delete(rlp.whitelist.whitelistDomains, item)
		rlp.logger.Info("Removed domain from whitelist", "domain", item)
	}

	return nil
}

// RemoveFromBlacklist removes an IP or domain from the blacklist
func (rlp *RateLimiterPlugin) RemoveFromBlacklist(item string) error {
	if rlp.blacklist == nil {
		return fmt.Errorf("blacklist not initialized")
	}

	// Determine if it's an IP or domain
	if net.ParseIP(item) != nil {
		delete(rlp.blacklist.blacklistIPs, item)
		rlp.logger.Info("Removed IP from blacklist", "ip", item)
	} else {
		delete(rlp.blacklist.blacklistDomains, item)
		rlp.logger.Info("Removed domain from blacklist", "domain", item)
	}

	return nil
}
