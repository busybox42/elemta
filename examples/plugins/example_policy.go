package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
)

// ExamplePolicyPlugin is a simple policy plugin that demonstrates
// how to implement custom policies for Elemta SMTP server
type ExamplePolicyPlugin struct {
	plugin.BasePlugin
	// Configuration options
	config *PolicyConfig
	// Cache for IP reputation data
	ipReputationCache map[string]IPReputation
	// Allowed domains for relay
	allowedDomains map[string]bool
	// Rate limiting data
	rateLimits map[string]*RateLimitInfo
}

// PolicyConfig holds the configuration for the policy plugin
type PolicyConfig struct {
	// Maximum messages per minute from a single IP
	MaxMessagesPerMinute int `yaml:"max_messages_per_minute"`
	// Maximum recipients per message
	MaxRecipientsPerMessage int `yaml:"max_recipients_per_message"`
	// List of allowed sender domains
	AllowedSenderDomains []string `yaml:"allowed_sender_domains"`
	// List of blocked recipient domains
	BlockedRecipientDomains []string `yaml:"blocked_recipient_domains"`
	// List of allowed relay domains
	AllowedRelayDomains []string `yaml:"allowed_relay_domains"`
	// Whether to block IPs with bad reputation
	BlockBadReputation bool `yaml:"block_bad_reputation"`
	// Minimum reputation score (0-100)
	MinReputationScore int `yaml:"min_reputation_score"`
}

// IPReputation represents reputation data for an IP address
type IPReputation struct {
	Score      int       // 0-100, higher is better
	LastUpdate time.Time // When the score was last updated
}

// RateLimitInfo tracks rate limiting data for an IP
type RateLimitInfo struct {
	MessageCount int       // Number of messages in the current window
	WindowStart  time.Time // Start of the current window
}

// NewExamplePolicyPlugin creates a new instance of the policy plugin
func NewExamplePolicyPlugin() *ExamplePolicyPlugin {
	// Default configuration
	config := &PolicyConfig{
		MaxMessagesPerMinute:    60,
		MaxRecipientsPerMessage: 50,
		AllowedSenderDomains:    []string{"example.com", "trusted.org"},
		BlockedRecipientDomains: []string{"blocked.com", "spam.org"},
		AllowedRelayDomains:     []string{"example.com", "trusted.org"},
		BlockBadReputation:      true,
		MinReputationScore:      50,
	}

	// Initialize the plugin
	plugin := &ExamplePolicyPlugin{
		config:            config,
		ipReputationCache: make(map[string]IPReputation),
		allowedDomains:    make(map[string]bool),
		rateLimits:        make(map[string]*RateLimitInfo),
	}

	// Convert allowed domains to a map for faster lookup
	for _, domain := range config.AllowedRelayDomains {
		plugin.allowedDomains[domain] = true
	}

	return plugin
}

// Init initializes the plugin
func (p *ExamplePolicyPlugin) Init() error {
	// Log initialization
	fmt.Println("Initializing Example Policy Plugin")
	return nil
}

// Close cleans up resources
func (p *ExamplePolicyPlugin) Close() error {
	// Clean up resources
	p.ipReputationCache = nil
	p.allowedDomains = nil
	p.rateLimits = nil
	return nil
}

// OnConnect is called when a client connects
func (p *ExamplePolicyPlugin) OnConnect(ctx *plugin.Context) (*plugin.Result, error) {
	session := ctx.Session
	remoteIP := session.RemoteAddr.(*net.TCPAddr).IP.String()

	// Check IP reputation
	if p.config.BlockBadReputation {
		reputation, exists := p.ipReputationCache[remoteIP]
		if exists && reputation.Score < p.config.MinReputationScore {
			return &plugin.Result{
				Action:  plugin.ActionReject,
				Message: fmt.Sprintf("Connection rejected due to poor IP reputation: %d", reputation.Score),
			}, nil
		}
	}

	// Check rate limits
	if !p.checkRateLimit(remoteIP) {
		return &plugin.Result{
			Action:  plugin.ActionReject,
			Message: "Rate limit exceeded, please try again later",
		}, nil
	}

	// Allow the connection
	return &plugin.Result{
		Action:  plugin.ActionContinue,
		Message: "Connection accepted",
	}, nil
}

// OnMailFrom is called when a client issues a MAIL FROM command
func (p *ExamplePolicyPlugin) OnMailFrom(ctx *plugin.Context) (*plugin.Result, error) {
	session := ctx.Session
	envelope := session.Envelope

	// Extract domain from sender
	parts := strings.Split(envelope.MailFrom.Address, "@")
	if len(parts) != 2 {
		return &plugin.Result{
			Action:  plugin.ActionReject,
			Message: "Invalid sender address format",
		}, nil
	}

	senderDomain := strings.ToLower(parts[1])

	// Check if sender domain is allowed
	allowed := false
	for _, domain := range p.config.AllowedSenderDomains {
		if senderDomain == domain || strings.HasSuffix(senderDomain, "."+domain) {
			allowed = true
			break
		}
	}

	if !allowed {
		return &plugin.Result{
			Action:  plugin.ActionReject,
			Message: fmt.Sprintf("Sender domain %s is not allowed", senderDomain),
		}, nil
	}

	return &plugin.Result{
		Action:  plugin.ActionContinue,
		Message: "Sender accepted",
	}, nil
}

// OnRcptTo is called when a client issues a RCPT TO command
func (p *ExamplePolicyPlugin) OnRcptTo(ctx *plugin.Context) (*plugin.Result, error) {
	session := ctx.Session
	envelope := session.Envelope

	// Check if we've exceeded the maximum recipients per message
	if len(envelope.RcptTo) >= p.config.MaxRecipientsPerMessage {
		return &plugin.Result{
			Action:  plugin.ActionReject,
			Message: fmt.Sprintf("Maximum recipients per message (%d) exceeded", p.config.MaxRecipientsPerMessage),
		}, nil
	}

	// Extract domain from recipient
	rcptTo := ctx.RcptTo
	parts := strings.Split(rcptTo.Address, "@")
	if len(parts) != 2 {
		return &plugin.Result{
			Action:  plugin.ActionReject,
			Message: "Invalid recipient address format",
		}, nil
	}

	recipientDomain := strings.ToLower(parts[1])

	// Check if recipient domain is blocked
	for _, domain := range p.config.BlockedRecipientDomains {
		if recipientDomain == domain || strings.HasSuffix(recipientDomain, "."+domain) {
			return &plugin.Result{
				Action:  plugin.ActionReject,
				Message: fmt.Sprintf("Recipient domain %s is blocked", recipientDomain),
			}, nil
		}
	}

	// Check if we're allowed to relay to this domain
	if !session.IsAuthenticated {
		// For unauthenticated sessions, check if the domain is in our allowed relay domains
		if _, ok := p.allowedDomains[recipientDomain]; !ok {
			return &plugin.Result{
				Action:  plugin.ActionReject,
				Message: "Relay access denied",
			}, nil
		}
	}

	return &plugin.Result{
		Action:  plugin.ActionContinue,
		Message: "Recipient accepted",
	}, nil
}

// OnData is called when a client sends message data
func (p *ExamplePolicyPlugin) OnData(ctx *plugin.Context) (*plugin.Result, error) {
	// This is where you could implement content-based policies
	// For example, checking message size, scanning for keywords, etc.

	// For this example, we'll just accept all messages
	return &plugin.Result{
		Action:  plugin.ActionContinue,
		Message: "Message accepted",
	}, nil
}

// Helper method to check and update rate limits
func (p *ExamplePolicyPlugin) checkRateLimit(ip string) bool {
	now := time.Now()

	// Get or create rate limit info for this IP
	info, exists := p.rateLimits[ip]
	if !exists {
		info = &RateLimitInfo{
			MessageCount: 0,
			WindowStart:  now,
		}
		p.rateLimits[ip] = info
	}

	// Check if we need to reset the window
	if now.Sub(info.WindowStart) > time.Minute {
		info.MessageCount = 0
		info.WindowStart = now
	}

	// Check if rate limit is exceeded
	if info.MessageCount >= p.config.MaxMessagesPerMinute {
		return false
	}

	// Increment message count
	info.MessageCount++
	return true
}

// Create a new instance of the plugin
var PolicyPlugin = NewExamplePolicyPlugin()

// Export the plugin
func main() {}
