package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
)

// ExamplePolicyPlugin is a simple policy plugin that demonstrates
// how to implement custom policies for Elemta SMTP server
type ExamplePolicyPlugin struct {
	info plugin.PluginInfo
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

// IPReputation holds reputation data for an IP address
type IPReputation struct {
	Score      int       // 0-100, higher is better
	LastUpdate time.Time // When the score was last updated
}

// RateLimitInfo holds rate limiting data for an IP address
type RateLimitInfo struct {
	MessageCount int       // Number of messages in the current window
	WindowStart  time.Time // Start of the current window
}

// NewExamplePolicyPlugin creates a new instance of the policy plugin
func NewExamplePolicyPlugin() *ExamplePolicyPlugin {
	return &ExamplePolicyPlugin{
		info: plugin.PluginInfo{
			Name:        "example_policy",
			Description: "Example policy plugin for Elemta SMTP server",
			Version:     "1.0.0",
			Type:        plugin.PluginTypeRule,
			Author:      "Elemta Team",
		},
		config: &PolicyConfig{
			MaxMessagesPerMinute:    60,
			MaxRecipientsPerMessage: 100,
			AllowedSenderDomains:    []string{},
			BlockedRecipientDomains: []string{},
			AllowedRelayDomains:     []string{},
			BlockBadReputation:      true,
			MinReputationScore:      50,
		},
		ipReputationCache: make(map[string]IPReputation),
		allowedDomains:    make(map[string]bool),
		rateLimits:        make(map[string]*RateLimitInfo),
	}
}

// GetInfo returns information about the plugin
func (p *ExamplePolicyPlugin) GetInfo() plugin.PluginInfo {
	return p.info
}

// Init initializes the plugin
func (p *ExamplePolicyPlugin) Init(config map[string]interface{}) error {
	// In a real implementation, this would parse the configuration
	fmt.Println("Initializing example policy plugin")
	return nil
}

// Close cleans up resources
func (p *ExamplePolicyPlugin) Close() error {
	// Clean up resources
	fmt.Println("Closing example policy plugin")
	return nil
}

// GetStages returns the processing stages this plugin should be executed in
func (p *ExamplePolicyPlugin) GetStages() []plugin.ProcessingStage {
	return []plugin.ProcessingStage{
		plugin.StageConnect,
		plugin.StageMailFrom,
		plugin.StageRcptTo,
		plugin.StageDataComplete,
	}
}

// GetPriority returns the plugin priority (higher values run first)
func (p *ExamplePolicyPlugin) GetPriority() plugin.PluginPriority {
	return plugin.PriorityNormal
}

// Execute implements the plugin logic
func (p *ExamplePolicyPlugin) Execute(ctx map[string]interface{}) (*plugin.PluginResult, error) {
	// Get the current stage
	stageVal, ok := ctx["stage"]
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionReject,
			Message: "500 Internal server error: missing stage in context",
		}, nil
	}

	stage, ok := stageVal.(plugin.ProcessingStage)
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionReject,
			Message: "500 Internal server error: invalid stage type",
		}, nil
	}

	// Execute the appropriate handler based on the stage
	switch stage {
	case plugin.StageConnect:
		return p.onConnect(ctx)
	case plugin.StageMailFrom:
		return p.onMailFrom(ctx)
	case plugin.StageRcptTo:
		return p.onRcptTo(ctx)
	case plugin.StageDataComplete:
		return p.onData(ctx)
	default:
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}
}

// onConnect handles the CONNECT stage
func (p *ExamplePolicyPlugin) onConnect(ctx map[string]interface{}) (*plugin.PluginResult, error) {
	// Get the remote IP
	ipVal, ok := ctx["remote_ip"]
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}

	ip, ok := ipVal.(string)
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}

	// Check IP reputation if enabled
	if p.config.BlockBadReputation {
		if rep, ok := p.ipReputationCache[ip]; ok {
			if rep.Score < p.config.MinReputationScore {
				return &plugin.PluginResult{
					Action:  plugin.ActionReject,
					Message: fmt.Sprintf("550 5.7.1 Connection rejected due to poor reputation score: %d", rep.Score),
				}, nil
			}
		}
	}

	// Check rate limits
	if !p.checkRateLimit(ip) {
		return &plugin.PluginResult{
			Action:  plugin.ActionReject,
			Message: fmt.Sprintf("450 4.7.1 Rate limit exceeded for %s", ip),
		}, nil
	}

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "",
	}, nil
}

// onMailFrom handles the MAIL FROM stage
func (p *ExamplePolicyPlugin) onMailFrom(ctx map[string]interface{}) (*plugin.PluginResult, error) {
	// Get the sender address
	fromVal, ok := ctx["mail_from"]
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}

	from, ok := fromVal.(string)
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}

	// Check if sender domain is allowed
	if len(p.config.AllowedSenderDomains) > 0 {
		parts := strings.Split(from, "@")
		if len(parts) == 2 {
			domain := strings.ToLower(parts[1])
			allowed := false

			for _, allowedDomain := range p.config.AllowedSenderDomains {
				if domain == strings.ToLower(allowedDomain) {
					allowed = true
					break
				}
			}

			if !allowed {
				return &plugin.PluginResult{
					Action:  plugin.ActionReject,
					Message: fmt.Sprintf("550 5.7.1 Sender domain %s not allowed", domain),
				}, nil
			}
		}
	}

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "",
	}, nil
}

// onRcptTo handles the RCPT TO stage
func (p *ExamplePolicyPlugin) onRcptTo(ctx map[string]interface{}) (*plugin.PluginResult, error) {
	// Get the recipient address
	toVal, ok := ctx["rcpt_to"]
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}

	to, ok := toVal.(string)
	if !ok {
		return &plugin.PluginResult{
			Action:  plugin.ActionContinue,
			Message: "",
		}, nil
	}

	// Check if recipient domain is blocked
	parts := strings.Split(to, "@")
	if len(parts) == 2 {
		domain := strings.ToLower(parts[1])

		// Check blocked domains
		for _, blockedDomain := range p.config.BlockedRecipientDomains {
			if domain == strings.ToLower(blockedDomain) {
				return &plugin.PluginResult{
					Action:  plugin.ActionReject,
					Message: fmt.Sprintf("550 5.7.1 Recipient domain %s is blocked", domain),
				}, nil
			}
		}

		// Check relay permissions
		if !p.isLocalDomain(domain) {
			// This is a relay attempt, check if allowed
			allowed := false

			for _, allowedDomain := range p.config.AllowedRelayDomains {
				if domain == strings.ToLower(allowedDomain) {
					allowed = true
					break
				}
			}

			if !allowed {
				return &plugin.PluginResult{
					Action:  plugin.ActionReject,
					Message: fmt.Sprintf("550 5.7.1 Relay to domain %s not allowed", domain),
				}, nil
			}
		}
	}

	// Check recipient count
	rcptCountVal, ok := ctx["rcpt_count"]
	if ok {
		if rcptCount, ok := rcptCountVal.(int); ok {
			if rcptCount > p.config.MaxRecipientsPerMessage {
				return &plugin.PluginResult{
					Action:  plugin.ActionReject,
					Message: fmt.Sprintf("550 5.5.3 Too many recipients, maximum is %d", p.config.MaxRecipientsPerMessage),
				}, nil
			}
		}
	}

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "",
	}, nil
}

// onData handles the DATA stage
func (p *ExamplePolicyPlugin) onData(ctx map[string]interface{}) (*plugin.PluginResult, error) {
	// In a real implementation, this would check message content
	// For example, scanning for spam, viruses, or other policy violations

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "",
	}, nil
}

// isLocalDomain checks if a domain is local to this server
func (p *ExamplePolicyPlugin) isLocalDomain(domain string) bool {
	// In a real implementation, this would check if the domain is local
	// For this example, we'll just return false
	return false
}

// checkRateLimit checks if an IP has exceeded its rate limit
func (p *ExamplePolicyPlugin) checkRateLimit(ip string) bool {
	now := time.Now()

	// Get or create rate limit info for this IP
	info, ok := p.rateLimits[ip]
	if !ok {
		info = &RateLimitInfo{
			MessageCount: 0,
			WindowStart:  now,
		}
		p.rateLimits[ip] = info
	}

	// Check if the window has expired
	if now.Sub(info.WindowStart) > time.Minute {
		// Reset the window
		info.MessageCount = 1
		info.WindowStart = now
		return true
	}

	// Increment the message count
	info.MessageCount++

	// Check if the rate limit has been exceeded
	return info.MessageCount <= p.config.MaxMessagesPerMinute
}

// main is required for Go plugins
func main() {
	// This function is not used but is required for Go plugins
}
