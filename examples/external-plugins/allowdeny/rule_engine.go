package main

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// EvaluateConnection evaluates connection-level rules
func (re *RuleEngine) EvaluateConnection(ip net.IP, remoteAddr string) *EvaluationResult {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// Check IP-based rules first (fastest)
	if result := re.evaluateIPRules(ip); result != nil {
		return result
	}

	// Check CIDR rules
	if result := re.evaluateCIDRRules(ip); result != nil {
		return result
	}

	// Default action
	return &EvaluationResult{
		Action:  "allow", // Default action
		RuleID:  "default",
		Reason:  "No matching rules found",
		Matched: false,
	}
}

// EvaluateMailFrom evaluates MAIL FROM command rules
func (re *RuleEngine) EvaluateMailFrom(ip net.IP, remoteAddr, email string) *EvaluationResult {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// First check connection-level rules
	if result := re.EvaluateConnection(ip, remoteAddr); result.Action == "deny" {
		return result
	}

	// Check email-specific rules
	if result := re.evaluateEmailRules(email); result != nil {
		return result
	}

	// Check domain rules
	if result := re.evaluateDomainRules(email); result != nil {
		return result
	}

	// Check regex patterns
	if result := re.evaluateRegexRules(email); result != nil {
		return result
	}

	return &EvaluationResult{
		Action:  "allow",
		RuleID:  "default",
		Reason:  "No matching email rules found",
		Matched: false,
	}
}

// EvaluateRcptTo evaluates RCPT TO command rules
func (re *RuleEngine) EvaluateRcptTo(ip net.IP, remoteAddr, email string) *EvaluationResult {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// First check connection-level rules
	if result := re.EvaluateConnection(ip, remoteAddr); result.Action == "deny" {
		return result
	}

	// Check email-specific rules
	if result := re.evaluateEmailRules(email); result != nil {
		return result
	}

	// Check domain rules
	if result := re.evaluateDomainRules(email); result != nil {
		return result
	}

	// Check regex patterns
	if result := re.evaluateRegexRules(email); result != nil {
		return result
	}

	return &EvaluationResult{
		Action:  "allow",
		RuleID:  "default",
		Reason:  "No matching recipient rules found",
		Matched: false,
	}
}

// evaluateIPRules evaluates IP address rules
func (re *RuleEngine) evaluateIPRules(ip net.IP) *EvaluationResult {
	ipStr := ip.String()

	// Check IPv4 rules
	if ip.To4() != nil {
		if rules, exists := re.ipMatcher.ipv4Rules[ipStr]; exists {
			return re.selectHighestPriorityRule(rules)
		}
	} else {
		// Check IPv6 rules
		if rules, exists := re.ipMatcher.ipv6Rules[ipStr]; exists {
			return re.selectHighestPriorityRule(rules)
		}
	}

	return nil
}

// evaluateCIDRRules evaluates CIDR block rules
func (re *RuleEngine) evaluateCIDRRules(ip net.IP) *EvaluationResult {
	re.ipMatcher.mu.RLock()
	defer re.ipMatcher.mu.RUnlock()

	var matchingRules []Rule

	for _, cidrRule := range re.ipMatcher.cidrRules {
		if cidrRule.Network.Contains(ip) {
			matchingRules = append(matchingRules, cidrRule.Rule)
		}
	}

	if len(matchingRules) > 0 {
		return re.selectHighestPriorityRule(matchingRules)
	}

	return nil
}

// evaluateEmailRules evaluates exact email address rules
func (re *RuleEngine) evaluateEmailRules(email string) *EvaluationResult {
	re.emailMatcher.mu.RLock()
	defer re.emailMatcher.mu.RUnlock()

	if rules, exists := re.emailMatcher.emailRules[strings.ToLower(email)]; exists {
		return re.selectHighestPriorityRule(rules)
	}

	return nil
}

// evaluateDomainRules evaluates domain-based rules
func (re *RuleEngine) evaluateDomainRules(email string) *EvaluationResult {
	re.emailMatcher.mu.RLock()
	defer re.emailMatcher.mu.RUnlock()

	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}

	domain := strings.ToLower(parts[1])

	// Check exact domain match
	if rules, exists := re.emailMatcher.domainRules[domain]; exists {
		return re.selectHighestPriorityRule(rules)
	}

	// Check wildcard patterns
	for _, patternRule := range re.emailMatcher.patternRules {
		if re.matchWildcard(patternRule.Pattern, domain) {
			return &EvaluationResult{
				Action:  patternRule.Rule.Action,
				RuleID:  patternRule.Rule.ID,
				Reason:  fmt.Sprintf("Matched wildcard pattern: %s", patternRule.Pattern),
				Matched: true,
			}
		}
	}

	return nil
}

// evaluateRegexRules evaluates regex pattern rules
func (re *RuleEngine) evaluateRegexRules(email string) *EvaluationResult {
	re.emailMatcher.mu.RLock()
	defer re.emailMatcher.mu.RUnlock()

	for _, regexRule := range re.emailMatcher.regexRules {
		if regexRule.Regex.MatchString(email) {
			return &EvaluationResult{
				Action:  regexRule.Rule.Action,
				RuleID:  regexRule.Rule.ID,
				Reason:  fmt.Sprintf("Matched regex pattern: %s", regexRule.Regex.String()),
				Matched: true,
			}
		}
	}

	return nil
}

// selectHighestPriorityRule selects the rule with the highest priority
func (re *RuleEngine) selectHighestPriorityRule(rules []Rule) *EvaluationResult {
	if len(rules) == 0 {
		return nil
	}

	// Sort by priority (higher number = higher priority)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	// Deny rules take precedence over allow rules at the same priority
	selectedRule := rules[0]
	for _, rule := range rules {
		if rule.Priority == selectedRule.Priority && rule.Action == "deny" {
			selectedRule = rule
			break
		}
	}

	return &EvaluationResult{
		Action:  selectedRule.Action,
		RuleID:  selectedRule.ID,
		Reason:  fmt.Sprintf("Matched rule: %s", selectedRule.Description),
		Matched: true,
	}
}

// matchWildcard matches a wildcard pattern against a string
func (re *RuleEngine) matchWildcard(pattern, str string) bool {
	// Convert wildcard pattern to regex
	regexPattern := strings.ReplaceAll(pattern, "*", ".*")
	regexPattern = strings.ReplaceAll(regexPattern, "?", ".")
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, str)
	return err == nil && matched
}

// rebuildMatchers rebuilds all rule matchers for optimal performance
func (re *RuleEngine) rebuildMatchers() error {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Clear existing matchers
	re.ipMatcher.mu.Lock()
	re.ipMatcher.ipv4Rules = make(map[string][]Rule)
	re.ipMatcher.ipv6Rules = make(map[string][]Rule)
	re.ipMatcher.cidrRules = make([]CIDRRule, 0)
	re.ipMatcher.mu.Unlock()

	re.emailMatcher.mu.Lock()
	re.emailMatcher.domainRules = make(map[string][]Rule)
	re.emailMatcher.emailRules = make(map[string][]Rule)
	re.emailMatcher.patternRules = make([]PatternRule, 0)
	re.emailMatcher.regexRules = make([]RegexRule, 0)
	re.emailMatcher.mu.Unlock()

	// Rebuild matchers from rules
	for _, rule := range re.rules {
		// Skip expired rules
		if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
			continue
		}

		// Process IP address rules
		for _, ipStr := range rule.IPAddresses {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				if ip.To4() != nil {
					re.ipMatcher.ipv4Rules[ipStr] = append(re.ipMatcher.ipv4Rules[ipStr], rule)
				} else {
					re.ipMatcher.ipv6Rules[ipStr] = append(re.ipMatcher.ipv6Rules[ipStr], rule)
				}
			}
		}

		// Process CIDR block rules
		for _, cidrStr := range rule.CIDRBlocks {
			_, network, err := net.ParseCIDR(cidrStr)
			if err == nil {
				re.ipMatcher.cidrRules = append(re.ipMatcher.cidrRules, CIDRRule{
					Network: network,
					Rule:    rule,
				})
			}
		}

		// Process domain rules
		for _, domain := range rule.Domains {
			domain = strings.ToLower(domain)
			re.emailMatcher.domainRules[domain] = append(re.emailMatcher.domainRules[domain], rule)
		}

		// Process email pattern rules
		for _, emailPattern := range rule.EmailPatterns {
			emailPattern = strings.ToLower(emailPattern)
			if strings.Contains(emailPattern, "*") || strings.Contains(emailPattern, "?") {
				// Wildcard pattern
				re.emailMatcher.patternRules = append(re.emailMatcher.patternRules, PatternRule{
					Pattern: emailPattern,
					Rule:    rule,
				})
			} else {
				// Exact email match
				re.emailMatcher.emailRules[emailPattern] = append(re.emailMatcher.emailRules[emailPattern], rule)
			}
		}

		// Process regex pattern rules
		for _, regexStr := range rule.RegexPatterns {
			if regex, err := regexp.Compile(regexStr); err == nil {
				re.emailMatcher.regexRules = append(re.emailMatcher.regexRules, RegexRule{
					Regex: regex,
					Rule:  rule,
				})
			}
		}
	}

	return nil
}

// AddRule adds a new rule to the engine
func (re *RuleEngine) AddRule(rule Rule) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Set timestamps
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	// Add rule
	re.rules = append(re.rules, rule)

	// Rebuild matchers
	return re.rebuildMatchers()
}

// RemoveRule removes a rule by ID
func (re *RuleEngine) RemoveRule(ruleID string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Find and remove rule
	for i, rule := range re.rules {
		if rule.ID == ruleID {
			re.rules = append(re.rules[:i], re.rules[i+1:]...)
			break
		}
	}

	// Rebuild matchers
	return re.rebuildMatchers()
}

// GetRules returns all rules
func (re *RuleEngine) GetRules() []Rule {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// Return a copy to prevent external modification
	rules := make([]Rule, len(re.rules))
	copy(rules, re.rules)
	return rules
}

// GetRuleCount returns the number of active rules
func (re *RuleEngine) GetRuleCount() int {
	re.mu.RLock()
	defer re.mu.RUnlock()

	activeCount := 0
	now := time.Now()

	for _, rule := range re.rules {
		if rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt) {
			activeCount++
		}
	}

	return activeCount
}

// ClearExpiredRules removes expired rules
func (re *RuleEngine) ClearExpiredRules() int {
	re.mu.Lock()
	defer re.mu.Unlock()

	now := time.Now()
	originalCount := len(re.rules)

	// Filter out expired rules
	var activeRules []Rule
	for _, rule := range re.rules {
		if rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt) {
			activeRules = append(activeRules, rule)
		}
	}

	re.rules = activeRules
	removedCount := originalCount - len(activeRules)

	// Rebuild matchers if rules were removed
	if removedCount > 0 {
		re.rebuildMatchers()
	}

	return removedCount
}
