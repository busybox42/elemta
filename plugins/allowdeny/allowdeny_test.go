package main

import (
	"net"
	"testing"
	"time"
)

func TestAllowDenyPlugin_EvaluateConnection(t *testing.T) {
	plugin := NewAllowDenyPlugin()
	
	// Initialize plugin
	err := plugin.Init(map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}
	defer plugin.Close()
	
	tests := []struct {
		name        string
		remoteAddr  string
		expectAllow bool
		expectReason string
	}{
		{
			name:        "Allow localhost IPv4",
			remoteAddr:  "127.0.0.1:12345",
			expectAllow: true,
			expectReason: "Allow localhost connections",
		},
		{
			name:        "Allow localhost IPv6",
			remoteAddr:  "[::1]:12345",
			expectAllow: true,
			expectReason: "Allow localhost connections",
		},
		{
			name:        "Deny private network",
			remoteAddr:  "192.168.1.1:12345",
			expectAllow: false,
			expectReason: "Matched rule: Deny private network ranges",
		},
		{
			name:        "Deny 10.x network",
			remoteAddr:  "10.0.0.1:12345",
			expectAllow: false,
			expectReason: "Matched rule: Deny private network ranges",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.EvaluateConnection(tt.remoteAddr)
			
			expectedAction := "allow"
			if !tt.expectAllow {
				expectedAction = "deny"
			}
			
			if result.Action != expectedAction {
				t.Errorf("Expected Action=%s, got %s", expectedAction, result.Action)
			}
			
			if tt.expectReason != "" && !containsString(result.Reason, tt.expectReason) {
				t.Errorf("Expected reason to contain '%s', got '%s'", tt.expectReason, result.Reason)
			}
		})
	}
}

func TestAllowDenyPlugin_EvaluateMailFrom(t *testing.T) {
	plugin := NewAllowDenyPlugin()
	
	// Initialize plugin
	err := plugin.Init(map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}
	defer plugin.Close()
	
	tests := []struct {
		name        string
		email       string
		remoteAddr  string
		expectAllow bool
	}{
		{
			name:        "Allow MAIL FROM for example.com",
			email:       "test@example.com",
			remoteAddr:  "127.0.0.1:12345",
			expectAllow: true,
		},
		{
			name:        "Deny MAIL FROM from private network",
			email:       "test@example.com",
			remoteAddr:  "192.168.1.1:12345",
			expectAllow: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.EvaluateMailFrom(tt.remoteAddr, tt.email)
			
			expectedAction := "allow"
			if !tt.expectAllow {
				expectedAction = "deny"
			}
			
			if result.Action != expectedAction {
				t.Errorf("Expected Action=%s, got %s", expectedAction, result.Action)
			}
		})
	}
}

func TestRuleEngine_EvaluateConnection(t *testing.T) {
	engine := &RuleEngine{
		rules: []Rule{
			{
				ID:          "allow-localhost",
				Action:      "allow",
				Priority:    100,
				IPAddresses: []string{"127.0.0.1"},
			},
			{
				ID:         "deny-private",
				Action:     "deny",
				Priority:   50,
				CIDRBlocks: []string{"192.168.0.0/16"},
			},
		},
		ipMatcher: &IPMatcher{
			ipv4Rules: make(map[string][]Rule),
			ipv6Rules: make(map[string][]Rule),
			cidrRules: make([]CIDRRule, 0),
		},
		emailMatcher: &EmailMatcher{
			domainRules:  make(map[string][]Rule),
			emailRules:   make(map[string][]Rule),
			patternRules: make([]PatternRule, 0),
			regexRules:   make([]RegexRule, 0),
		},
	}
	
	// Rebuild matchers
	err := engine.rebuildMatchers()
	if err != nil {
		t.Fatalf("Failed to rebuild matchers: %v", err)
	}
	
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "Allow localhost",
			ip:       "127.0.0.1",
			expected: "allow",
		},
		{
			name:     "Deny private network",
			ip:       "192.168.1.1",
			expected: "deny",
		},
		{
			name:     "Default allow for other IPs",
			ip:       "8.8.8.8",
			expected: "allow",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}
			
			result := engine.EvaluateConnection(ip, tt.ip+":12345")
			if result.Action != tt.expected {
				t.Errorf("Expected action %s, got %s", tt.expected, result.Action)
			}
		})
	}
}

func TestRuleEngine_EvaluateMailFrom(t *testing.T) {
	engine := &RuleEngine{
		rules: []Rule{
			{
				ID:          "allow-example",
				Action:      "allow",
				Priority:    80,
				Domains:     []string{"example.com"},
			},
			{
				ID:         "deny-spam",
				Action:     "deny",
				Priority:   90,
				Domains:    []string{"spam.example"},
			},
		},
		ipMatcher: &IPMatcher{
			ipv4Rules: make(map[string][]Rule),
			ipv6Rules: make(map[string][]Rule),
			cidrRules: make([]CIDRRule, 0),
		},
		emailMatcher: &EmailMatcher{
			domainRules:  make(map[string][]Rule),
			emailRules:   make(map[string][]Rule),
			patternRules: make([]PatternRule, 0),
			regexRules:   make([]RegexRule, 0),
		},
	}
	
	// Rebuild matchers
	err := engine.rebuildMatchers()
	if err != nil {
		t.Fatalf("Failed to rebuild matchers: %v", err)
	}
	
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "Allow example.com",
			email:    "test@example.com",
			expected: "allow",
		},
		{
			name:     "Deny spam domain",
			email:    "spammer@spam.example",
			expected: "deny",
		},
		{
			name:     "Default allow for other domains",
			email:    "user@other.com",
			expected: "allow",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP("127.0.0.1")
			result := engine.EvaluateMailFrom(ip, "127.0.0.1:12345", tt.email)
			if result.Action != tt.expected {
				t.Errorf("Expected action %s, got %s", tt.expected, result.Action)
			}
		})
	}
}

func TestRuleEngine_AddRule(t *testing.T) {
	engine := &RuleEngine{
		rules: make([]Rule, 0),
		ipMatcher: &IPMatcher{
			ipv4Rules: make(map[string][]Rule),
			ipv6Rules: make(map[string][]Rule),
			cidrRules: make([]CIDRRule, 0),
		},
		emailMatcher: &EmailMatcher{
			domainRules:  make(map[string][]Rule),
			emailRules:   make(map[string][]Rule),
			patternRules: make([]PatternRule, 0),
			regexRules:   make([]RegexRule, 0),
		},
	}
	
	rule := Rule{
		ID:          "test-rule",
		Action:      "deny",
		Priority:    75,
		IPAddresses: []string{"1.2.3.4"},
		Description: "Test rule",
	}
	
	err := engine.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}
	
	if len(engine.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(engine.rules))
	}
	
	if engine.rules[0].ID != "test-rule" {
		t.Errorf("Expected rule ID 'test-rule', got '%s'", engine.rules[0].ID)
	}
}

func TestRuleEngine_RemoveRule(t *testing.T) {
	engine := &RuleEngine{
		rules: []Rule{
			{ID: "rule1", Action: "allow"},
			{ID: "rule2", Action: "deny"},
		},
		ipMatcher: &IPMatcher{
			ipv4Rules: make(map[string][]Rule),
			ipv6Rules: make(map[string][]Rule),
			cidrRules: make([]CIDRRule, 0),
		},
		emailMatcher: &EmailMatcher{
			domainRules:  make(map[string][]Rule),
			emailRules:   make(map[string][]Rule),
			patternRules: make([]PatternRule, 0),
			regexRules:   make([]RegexRule, 0),
		},
	}
	
	err := engine.RemoveRule("rule1")
	if err != nil {
		t.Fatalf("Failed to remove rule: %v", err)
	}
	
	if len(engine.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(engine.rules))
	}
	
	if engine.rules[0].ID != "rule2" {
		t.Errorf("Expected remaining rule ID 'rule2', got '%s'", engine.rules[0].ID)
	}
}

func TestRuleEngine_ClearExpiredRules(t *testing.T) {
	now := time.Now()
	expired := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	
	engine := &RuleEngine{
		rules: []Rule{
			{ID: "active1", Action: "allow"},
			{ID: "expired1", Action: "deny", ExpiresAt: &expired},
			{ID: "active2", Action: "allow"},
			{ID: "expired2", Action: "deny", ExpiresAt: &expired},
			{ID: "future", Action: "allow", ExpiresAt: &future},
		},
		ipMatcher: &IPMatcher{
			ipv4Rules: make(map[string][]Rule),
			ipv6Rules: make(map[string][]Rule),
			cidrRules: make([]CIDRRule, 0),
		},
		emailMatcher: &EmailMatcher{
			domainRules:  make(map[string][]Rule),
			emailRules:   make(map[string][]Rule),
			patternRules: make([]PatternRule, 0),
			regexRules:   make([]RegexRule, 0),
		},
	}
	
	removed := engine.ClearExpiredRules()
	if removed != 2 {
		t.Errorf("Expected 2 expired rules to be removed, got %d", removed)
	}
	
	if len(engine.rules) != 3 {
		t.Errorf("Expected 3 active rules, got %d", len(engine.rules))
	}
}

func TestRuleCache(t *testing.T) {
	cache := NewRuleCache(100)
	
	// Test IP rules caching
	ip := "192.168.1.1"
	rules := []Rule{
		{ID: "rule1", Action: "deny"},
		{ID: "rule2", Action: "allow"},
	}
	
	// Set rules
	cache.SetIPRules(ip, rules)
	
	// Get rules
	retrieved, exists := cache.GetIPRules(ip)
	if !exists {
		t.Fatal("Expected rules to exist in cache")
	}
	
	if len(retrieved) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(retrieved))
	}
	
	// Test cache stats
	stats := cache.GetStats()
	if stats.IPRules != 1 {
		t.Errorf("Expected 1 IP rule in cache, got %d", stats.IPRules)
	}
	
	if stats.HitCount != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.HitCount)
	}
}

func TestMetrics(t *testing.T) {
	plugin := NewAllowDenyPlugin()
	
	// Test initial metrics
	metrics := plugin.GetMetrics()
	if metrics.RulesEvaluated != 0 {
		t.Errorf("Expected 0 rules evaluated, got %d", metrics.RulesEvaluated)
	}
	
	// Test cache hit rate
	hitRate := plugin.GetCacheHitRate()
	if hitRate != 0.0 {
		t.Errorf("Expected 0.0 cache hit rate, got %f", hitRate)
	}
	
	// Test deny rate
	denyRate := plugin.GetDenyRate()
	if denyRate != 0.0 {
		t.Errorf("Expected 0.0 deny rate, got %f", denyRate)
	}
}

// Benchmark tests for performance validation
func BenchmarkRuleEngine_EvaluateConnection(b *testing.B) {
	engine := &RuleEngine{
		rules: []Rule{
			{
				ID:          "allow-localhost",
				Action:      "allow",
				Priority:    100,
				IPAddresses: []string{"127.0.0.1"},
			},
			{
				ID:         "deny-private",
				Action:     "deny",
				Priority:   50,
				CIDRBlocks: []string{"192.168.0.0/16"},
			},
		},
		ipMatcher: &IPMatcher{
			ipv4Rules: make(map[string][]Rule),
			ipv6Rules: make(map[string][]Rule),
		},
	}
	
	engine.rebuildMatchers()
	ip := net.ParseIP("127.0.0.1")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateConnection(ip, "127.0.0.1:12345")
	}
}

func BenchmarkRuleEngine_EvaluateMailFrom(b *testing.B) {
	engine := &RuleEngine{
		rules: []Rule{
			{
				ID:      "allow-example",
				Action:  "allow",
				Priority: 80,
				Domains: []string{"example.com"},
			},
		},
		emailMatcher: &EmailMatcher{
			domainRules:  make(map[string][]Rule),
			emailRules:   make(map[string][]Rule),
			patternRules: make([]PatternRule, 0),
			regexRules:   make([]RegexRule, 0),
		},
	}
	
	engine.rebuildMatchers()
	ip := net.ParseIP("127.0.0.1")
	email := "test@example.com"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateMailFrom(ip, "127.0.0.1:12345", email)
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
		 (s[:len(substr)] == substr || 
		  s[len(s)-len(substr):] == substr || 
		  containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
