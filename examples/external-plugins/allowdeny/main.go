package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
)

// AllowDenyPlugin implements comprehensive access control
type AllowDenyPlugin struct {
	logger     *slog.Logger
	ruleEngine *RuleEngine
	config     *Config
	metrics    *Metrics
	mu         sync.RWMutex
}

// Config represents the plugin configuration
type Config struct {
	RulesFile       string        `toml:"rules_file"`
	ReloadInterval  time.Duration `toml:"reload_interval"`
	CacheSize       int           `toml:"cache_size"`
	EnableMetrics   bool          `toml:"enable_metrics"`
	DefaultAction   string        `toml:"default_action"` // "allow" or "deny"
	EnableHotReload bool          `toml:"enable_hot_reload"`
	ExternalFeeds   []FeedConfig  `toml:"external_feeds"`
	PerformanceMode bool          `toml:"performance_mode"` // Enable optimizations for 100k+ rules
}

// FeedConfig represents external blacklist/whitelist feed configuration
type FeedConfig struct {
	Name           string        `toml:"name"`
	URL            string        `toml:"url"`
	Type           string        `toml:"type"`   // "blacklist" or "whitelist"
	Format         string        `toml:"format"` // "ip", "domain", "email"
	UpdateInterval time.Duration `toml:"update_interval"`
	Enabled        bool          `toml:"enabled"`
}

// RuleEngine handles high-performance rule evaluation
type RuleEngine struct {
	rules        []Rule
	cache        *RuleCache
	ipMatcher    *IPMatcher
	emailMatcher *EmailMatcher
	mu           sync.RWMutex
}

// Rule represents a single access control rule
type Rule struct {
	ID        string     `json:"id"`
	Action    string     `json:"action"` // "allow" or "deny"
	Priority  int        `json:"priority"`
	Source    string     `json:"source"` // "manual", "feed", "api"
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Matching criteria
	IPAddresses   []string `json:"ip_addresses,omitempty"`
	CIDRBlocks    []string `json:"cidr_blocks,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	EmailPatterns []string `json:"email_patterns,omitempty"`
	RegexPatterns []string `json:"regex_patterns,omitempty"`

	// Metadata
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RuleCache provides high-performance rule caching
type RuleCache struct {
	ipRules     map[string][]Rule
	domainRules map[string][]Rule
	emailRules  map[string][]Rule
	regexRules  []Rule
	mu          sync.RWMutex
	hitCount    int64
	missCount   int64
	maxSize     int
}

// IPMatcher handles IP address and CIDR matching
type IPMatcher struct {
	ipv4Rules map[string][]Rule
	ipv6Rules map[string][]Rule
	cidrRules []CIDRRule
	mu        sync.RWMutex
}

// CIDRRule represents a CIDR block rule
type CIDRRule struct {
	Network *net.IPNet
	Rule    Rule
}

// EmailMatcher handles email address and domain matching
type EmailMatcher struct {
	domainRules  map[string][]Rule
	emailRules   map[string][]Rule
	patternRules []PatternRule
	regexRules   []RegexRule
	mu           sync.RWMutex
}

// PatternRule represents a wildcard pattern rule
type PatternRule struct {
	Pattern string
	Rule    Rule
}

// RegexRule represents a regex pattern rule
type RegexRule struct {
	Regex *regexp.Regexp
	Rule  Rule
}

// Metrics tracks plugin performance and usage
type Metrics struct {
	RulesEvaluated    int64
	RulesMatched      int64
	RulesDenied       int64
	RulesAllowed      int64
	CacheHits         int64
	CacheMisses       int64
	EvaluationTime    time.Duration
	LastReloadTime    time.Time
	ActiveRules       int64
	ExternalFeedRules int64
}

// NewAllowDenyPlugin creates a new Allow/Deny plugin instance
func NewAllowDenyPlugin() *AllowDenyPlugin {
	return &AllowDenyPlugin{
		ruleEngine: &RuleEngine{
			cache: &RuleCache{
				ipRules:     make(map[string][]Rule),
				domainRules: make(map[string][]Rule),
				emailRules:  make(map[string][]Rule),
				maxSize:     10000,
			},
			ipMatcher: &IPMatcher{
				ipv4Rules: make(map[string][]Rule),
				ipv6Rules: make(map[string][]Rule),
			},
			emailMatcher: &EmailMatcher{
				domainRules:  make(map[string][]Rule),
				emailRules:   make(map[string][]Rule),
				patternRules: make([]PatternRule, 0),
				regexRules:   make([]RegexRule, 0),
			},
		},
		metrics: &Metrics{},
	}
}

// GetInfo returns plugin information
func (p *AllowDenyPlugin) GetInfo() plugin.PluginInfo {
	return plugin.PluginInfo{
		Name:        "Allow/Deny Access Control",
		Version:     "1.0.0",
		Description: "Comprehensive access control plugin with IP, CIDR, and email filtering",
		Author:      "Elemta Team",
		Type:        plugin.PluginTypeSecurity,
	}
}

// Init initializes the plugin
func (p *AllowDenyPlugin) Init(config map[string]interface{}) error {
	p.logger = slog.Default().With("plugin", "allowdeny")

	// Parse configuration
	p.config = &Config{
		RulesFile:       "rules.json",
		ReloadInterval:  30 * time.Second,
		CacheSize:       10000,
		EnableMetrics:   true,
		DefaultAction:   "allow",
		EnableHotReload: true,
		PerformanceMode: true,
	}

	// Load initial rules
	if err := p.loadRules(context.Background()); err != nil {
		return fmt.Errorf("failed to load initial rules: %w", err)
	}

	// Start background tasks
	if p.config.EnableHotReload {
		go p.startHotReload(context.Background())
	}

	if len(p.config.ExternalFeeds) > 0 {
		go p.startExternalFeedUpdater(context.Background())
	}

	p.logger.Info("Allow/Deny plugin initialized successfully",
		"rules_count", len(p.ruleEngine.rules),
		"cache_size", p.config.CacheSize,
		"hot_reload", p.config.EnableHotReload,
	)

	return nil
}

// Close cleans up plugin resources
func (p *AllowDenyPlugin) Close() error {
	p.logger.Info("Allow/Deny plugin cleanup completed")
	return nil
}

// EvaluateConnection evaluates connection-level access control
func (p *AllowDenyPlugin) EvaluateConnection(remoteAddr string) *EvaluationResult {
	start := time.Now()
	defer func() {
		p.metrics.EvaluationTime += time.Since(start)
		p.metrics.RulesEvaluated++
	}()

	// Extract IP address
	ip := p.extractIP(remoteAddr)
	if ip == nil {
		return &EvaluationResult{
			Action:  "allow",
			RuleID:  "default",
			Reason:  "Unable to parse IP address",
			Matched: false,
		}
	}

	// Evaluate rules
	result := p.ruleEngine.EvaluateConnection(ip, remoteAddr)

	if result.Action == "deny" {
		p.metrics.RulesDenied++
		p.logger.Warn("Connection denied by allow/deny rule",
			"remote_addr", remoteAddr,
			"rule_id", result.RuleID,
			"reason", result.Reason,
		)
	} else {
		p.metrics.RulesAllowed++
	}

	return result
}

// EvaluateMailFrom evaluates MAIL FROM command access control
func (p *AllowDenyPlugin) EvaluateMailFrom(remoteAddr, email string) *EvaluationResult {
	start := time.Now()
	defer func() {
		p.metrics.EvaluationTime += time.Since(start)
		p.metrics.RulesEvaluated++
	}()

	// Extract IP address
	ip := p.extractIP(remoteAddr)
	if ip == nil {
		return &EvaluationResult{
			Action:  "allow",
			RuleID:  "default",
			Reason:  "Unable to parse IP address",
			Matched: false,
		}
	}

	// Evaluate rules
	result := p.ruleEngine.EvaluateMailFrom(ip, remoteAddr, email)

	if result.Action == "deny" {
		p.metrics.RulesDenied++
		p.logger.Warn("MAIL FROM denied by allow/deny rule",
			"remote_addr", remoteAddr,
			"email", email,
			"rule_id", result.RuleID,
			"reason", result.Reason,
		)
	} else {
		p.metrics.RulesAllowed++
	}

	return result
}

// EvaluateRcptTo evaluates RCPT TO command access control
func (p *AllowDenyPlugin) EvaluateRcptTo(remoteAddr, email string) *EvaluationResult {
	start := time.Now()
	defer func() {
		p.metrics.EvaluationTime += time.Since(start)
		p.metrics.RulesEvaluated++
	}()

	// Extract IP address
	ip := p.extractIP(remoteAddr)
	if ip == nil {
		return &EvaluationResult{
			Action:  "allow",
			RuleID:  "default",
			Reason:  "Unable to parse IP address",
			Matched: false,
		}
	}

	// Evaluate rules
	result := p.ruleEngine.EvaluateRcptTo(ip, remoteAddr, email)

	if result.Action == "deny" {
		p.metrics.RulesDenied++
		p.logger.Warn("RCPT TO denied by allow/deny rule",
			"remote_addr", remoteAddr,
			"email", email,
			"rule_id", result.RuleID,
			"reason", result.Reason,
		)
	} else {
		p.metrics.RulesAllowed++
	}

	return result
}

// EvaluationResult represents the result of rule evaluation
type EvaluationResult struct {
	Action  string
	RuleID  string
	Reason  string
	Matched bool
}

// extractIP extracts IP address from remote address string
func (p *AllowDenyPlugin) extractIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Try parsing as IP directly
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}

// loadRules loads rules from configuration file
func (p *AllowDenyPlugin) loadRules(ctx context.Context) error {
	// For now, load some default rules
	// In a real implementation, this would load from a file or database
	defaultRules := []Rule{
		{
			ID:          "default-allow-localhost",
			Action:      "allow",
			Priority:    100,
			Source:      "default",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			IPAddresses: []string{"127.0.0.1", "::1"},
			Description: "Allow localhost connections",
		},
		{
			ID:          "default-deny-private",
			Action:      "deny",
			Priority:    50,
			Source:      "default",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			CIDRBlocks:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			Description: "Deny private network ranges",
		},
	}

	p.ruleEngine.mu.Lock()
	p.ruleEngine.rules = defaultRules
	p.ruleEngine.mu.Unlock()

	// Rebuild matchers
	return p.ruleEngine.rebuildMatchers()
}

// startHotReload starts the hot reload background task
func (p *AllowDenyPlugin) startHotReload(ctx context.Context) {
	ticker := time.NewTicker(p.config.ReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.loadRules(ctx); err != nil {
				p.logger.Error("Failed to reload rules", "error", err)
			} else {
				p.metrics.LastReloadTime = time.Now()
				p.logger.Debug("Rules reloaded successfully")
			}
		}
	}
}

// startExternalFeedUpdater starts the external feed updater
func (p *AllowDenyPlugin) startExternalFeedUpdater(ctx context.Context) {
	for _, feed := range p.config.ExternalFeeds {
		if !feed.Enabled {
			continue
		}

		go func(feed FeedConfig) {
			ticker := time.NewTicker(feed.UpdateInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := p.updateExternalFeed(ctx, feed); err != nil {
						p.logger.Error("Failed to update external feed",
							"feed", feed.Name,
							"error", err,
						)
					}
				}
			}
		}(feed)
	}
}

// updateExternalFeed updates rules from an external feed
func (p *AllowDenyPlugin) updateExternalFeed(ctx context.Context, feed FeedConfig) error {
	// Implementation would fetch from external URL and parse
	// For now, just log the attempt
	p.logger.Debug("Updating external feed", "feed", feed.Name, "url", feed.URL)
	return nil
}

// Export the plugin instance
var Plugin = NewAllowDenyPlugin()

func main() {}
