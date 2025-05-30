package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Router determines how messages should be delivered based on routing rules
type Router struct {
	config       *Config
	logger       *slog.Logger
	rules        []*RoutingRule
	rulesMu      sync.RWMutex
	metrics      *RouterMetrics
	localDomains map[string]bool
}

// RouterMetrics tracks routing statistics
type RouterMetrics struct {
	mu                 sync.RWMutex
	TotalMessages      int64            `json:"total_messages"`
	DirectRoutes       int64            `json:"direct_routes"`
	RelayRoutes        int64            `json:"relay_routes"`
	LocalRoutes        int64            `json:"local_routes"`
	RoutingErrors      int64            `json:"routing_errors"`
	RuleMatches        map[string]int64 `json:"rule_matches"`
	AverageRoutingTime time.Duration    `json:"average_routing_time"`
}

// NewRouter creates a new message router
func NewRouter(config *Config) *Router {
	// Build local domains map for fast lookup
	localDomains := make(map[string]bool)
	for _, domain := range config.LocalDomains {
		localDomains[strings.ToLower(domain)] = true
	}

	return &Router{
		config:       config,
		logger:       slog.Default().With("component", "router"),
		rules:        make([]*RoutingRule, 0),
		localDomains: localDomains,
		metrics: &RouterMetrics{
			RuleMatches: make(map[string]int64),
		},
	}
}

// RouteMessage determines the delivery routes for a message
func (r *Router) RouteMessage(ctx context.Context, msg *Message) ([]*Route, error) {
	startTime := time.Now()
	defer func() {
		routingTime := time.Since(startTime)
		r.updateRoutingTime(routingTime)
	}()

	r.metrics.mu.Lock()
	r.metrics.TotalMessages++
	r.metrics.mu.Unlock()

	r.logger.Debug("Routing message",
		"message_id", msg.ID,
		"from", msg.From,
		"recipients", len(msg.To))

	// Group recipients by domain and determine route type
	domainGroups := r.groupRecipientsByDomain(msg.To)
	routes := make([]*Route, 0, len(domainGroups))

	for domain, recipients := range domainGroups {
		route, err := r.determineRoute(ctx, msg, domain, recipients)
		if err != nil {
			r.metrics.mu.Lock()
			r.metrics.RoutingErrors++
			r.metrics.mu.Unlock()

			r.logger.Error("Failed to determine route",
				"domain", domain,
				"recipients", len(recipients),
				"error", err)
			return nil, fmt.Errorf("routing failed for domain %s: %w", domain, err)
		}

		routes = append(routes, route)
	}

	// Sort routes by priority (lower number = higher priority)
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Priority < routes[j].Priority
	})

	r.logger.Info("Message routing completed",
		"message_id", msg.ID,
		"routes", len(routes),
		"routing_time", time.Since(startTime))

	return routes, nil
}

// groupRecipientsByDomain groups recipients by their domain
func (r *Router) groupRecipientsByDomain(recipients []string) map[string][]string {
	groups := make(map[string][]string)

	for _, recipient := range recipients {
		parts := strings.Split(recipient, "@")
		if len(parts) != 2 {
			r.logger.Warn("Invalid email address", "recipient", recipient)
			continue
		}

		domain := strings.ToLower(parts[1])
		groups[domain] = append(groups[domain], recipient)
	}

	return groups
}

// determineRoute determines the best route for a domain
func (r *Router) determineRoute(ctx context.Context, msg *Message, domain string, recipients []string) (*Route, error) {
	// Check for matching routing rules first
	if route := r.checkRoutingRules(msg, domain, recipients); route != nil {
		return route, nil
	}

	// Check if it's a local domain
	if r.isLocalDomain(domain) {
		r.metrics.mu.Lock()
		r.metrics.LocalRoutes++
		r.metrics.mu.Unlock()

		return &Route{
			Type:       RouteTypeLocal,
			Host:       "localhost",
			Port:       25,
			Recipients: recipients,
			Priority:   PriorityHigh, // Local delivery has high priority
		}, nil
	}

	// Check if we should use a relay
	if r.config.RelayHost != "" {
		r.metrics.mu.Lock()
		r.metrics.RelayRoutes++
		r.metrics.mu.Unlock()

		route := &Route{
			Type:       RouteTypeRelay,
			Host:       r.config.RelayHost,
			Port:       r.config.RelayPort,
			Recipients: recipients,
			Priority:   PriorityNormal,
		}

		// Add authentication if configured
		if r.config.RelayAuth {
			route.Auth = &AuthInfo{
				Username: r.config.RelayUsername,
				Password: r.config.RelayPassword,
				Method:   "PLAIN", // Default method
			}
		}

		return route, nil
	}

	// Default to direct delivery via MX records
	r.metrics.mu.Lock()
	r.metrics.DirectRoutes++
	r.metrics.mu.Unlock()

	return &Route{
		Type:       RouteTypeDirect,
		Host:       domain, // Will be resolved to MX records
		Port:       25,
		Recipients: recipients,
		Priority:   PriorityNormal,
	}, nil
}

// checkRoutingRules checks if any routing rules match the message
func (r *Router) checkRoutingRules(msg *Message, domain string, recipients []string) *Route {
	r.rulesMu.RLock()
	defer r.rulesMu.RUnlock()

	// Sort rules by priority (lower number = higher priority)
	sortedRules := make([]*RoutingRule, len(r.rules))
	copy(sortedRules, r.rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})

	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}

		if r.ruleMatches(rule, msg, domain, recipients) {
			r.logger.Debug("Routing rule matched",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"domain", domain)

			r.metrics.mu.Lock()
			r.metrics.RuleMatches[rule.ID]++
			r.metrics.mu.Unlock()

			return r.createRouteFromRule(rule, domain, recipients)
		}
	}

	return nil
}

// ruleMatches checks if a routing rule matches the given message and domain
func (r *Router) ruleMatches(rule *RoutingRule, msg *Message, domain string, recipients []string) bool {
	// Check from domain conditions
	if len(rule.FromDomain) > 0 {
		fromParts := strings.Split(msg.From, "@")
		if len(fromParts) != 2 {
			return false
		}
		fromDomain := strings.ToLower(fromParts[1])

		matched := false
		for _, ruleDomain := range rule.FromDomain {
			if strings.ToLower(ruleDomain) == fromDomain {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check to domain conditions
	if len(rule.ToDomain) > 0 {
		matched := false
		for _, ruleDomain := range rule.ToDomain {
			if strings.ToLower(ruleDomain) == domain {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check from address conditions
	if len(rule.FromAddress) > 0 {
		matched := false
		for _, ruleAddr := range rule.FromAddress {
			if strings.ToLower(ruleAddr) == strings.ToLower(msg.From) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check to address conditions
	if len(rule.ToAddress) > 0 {
		matched := false
		for _, ruleAddr := range rule.ToAddress {
			for _, recipient := range recipients {
				if strings.ToLower(ruleAddr) == strings.ToLower(recipient) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check subject conditions
	if len(rule.Subject) > 0 {
		matched := false
		for _, ruleSubject := range rule.Subject {
			if strings.Contains(strings.ToLower(msg.Subject), strings.ToLower(ruleSubject)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check message size conditions
	if rule.MessageSize != nil {
		if msg.Size < rule.MessageSize.Min || (rule.MessageSize.Max > 0 && msg.Size > rule.MessageSize.Max) {
			return false
		}
	}

	// Check time range conditions
	if rule.TimeRange != nil {
		if !r.isInTimeRange(rule.TimeRange) {
			return false
		}
	}

	// Check header conditions
	if len(rule.Headers) > 0 {
		for headerName, ruleValues := range rule.Headers {
			msgValues, exists := msg.Headers[headerName]
			if !exists {
				return false
			}

			matched := false
			for _, ruleValue := range ruleValues {
				for _, msgValue := range msgValues {
					if strings.Contains(strings.ToLower(msgValue), strings.ToLower(ruleValue)) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	return true
}

// createRouteFromRule creates a route based on a routing rule
func (r *Router) createRouteFromRule(rule *RoutingRule, domain string, recipients []string) *Route {
	route := &Route{
		Type:        rule.RouteType,
		Recipients:  recipients,
		Priority:    rule.DeliveryPriority,
		TLSRequired: rule.ForceTLS,
	}

	switch rule.RouteType {
	case RouteTypeRelay:
		route.Host = rule.RelayHost
		route.Port = rule.RelayPort
		if rule.ForceAuth {
			route.Auth = &AuthInfo{
				Username: r.config.RelayUsername,
				Password: r.config.RelayPassword,
				Method:   "PLAIN",
			}
		}
	case RouteTypeDirect:
		route.Host = domain
		route.Port = 25
	case RouteTypeLocal:
		route.Host = "localhost"
		route.Port = 25
	}

	return route
}

// isInTimeRange checks if the current time is within the specified time range
func (r *Router) isInTimeRange(timeRange *TimeRange) bool {
	now := time.Now()

	// Check day of week
	if len(timeRange.Days) > 0 {
		currentDay := int(now.Weekday())
		dayMatched := false
		for _, day := range timeRange.Days {
			if day == currentDay {
				dayMatched = true
				break
			}
		}
		if !dayMatched {
			return false
		}
	}

	// Check time range
	if timeRange.Start != "" && timeRange.End != "" {
		currentTime := now.Format("15:04")
		if currentTime < timeRange.Start || currentTime > timeRange.End {
			return false
		}
	}

	return true
}

// isLocalDomain checks if a domain is configured as local
func (r *Router) isLocalDomain(domain string) bool {
	return r.localDomains[strings.ToLower(domain)]
}

// AddRoutingRule adds a new routing rule
func (r *Router) AddRoutingRule(rule *RoutingRule) {
	r.rulesMu.Lock()
	defer r.rulesMu.Unlock()

	r.rules = append(r.rules, rule)

	r.logger.Info("Routing rule added",
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"priority", rule.Priority)
}

// RemoveRoutingRule removes a routing rule by ID
func (r *Router) RemoveRoutingRule(ruleID string) {
	r.rulesMu.Lock()
	defer r.rulesMu.Unlock()

	for i, rule := range r.rules {
		if rule.ID == ruleID {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)

			r.logger.Info("Routing rule removed",
				"rule_id", ruleID)
			return
		}
	}
}

// UpdateRoutingRule updates an existing routing rule
func (r *Router) UpdateRoutingRule(rule *RoutingRule) {
	r.rulesMu.Lock()
	defer r.rulesMu.Unlock()

	for i, existingRule := range r.rules {
		if existingRule.ID == rule.ID {
			r.rules[i] = rule

			r.logger.Info("Routing rule updated",
				"rule_id", rule.ID,
				"rule_name", rule.Name)
			return
		}
	}

	// If rule doesn't exist, add it
	r.rules = append(r.rules, rule)

	r.logger.Info("Routing rule added (via update)",
		"rule_id", rule.ID,
		"rule_name", rule.Name)
}

// GetRoutingRules returns all routing rules
func (r *Router) GetRoutingRules() []*RoutingRule {
	r.rulesMu.RLock()
	defer r.rulesMu.RUnlock()

	rules := make([]*RoutingRule, len(r.rules))
	copy(rules, r.rules)

	return rules
}

// updateRoutingTime updates the average routing time metric
func (r *Router) updateRoutingTime(duration time.Duration) {
	r.metrics.mu.Lock()
	defer r.metrics.mu.Unlock()

	if r.metrics.TotalMessages == 1 {
		r.metrics.AverageRoutingTime = duration
	} else {
		r.metrics.AverageRoutingTime = (r.metrics.AverageRoutingTime + duration) / 2
	}
}

// GetStats returns current routing statistics
func (r *Router) GetStats() map[string]interface{} {
	r.metrics.mu.RLock()
	defer r.metrics.mu.RUnlock()

	return map[string]interface{}{
		"total_messages":       r.metrics.TotalMessages,
		"direct_routes":        r.metrics.DirectRoutes,
		"relay_routes":         r.metrics.RelayRoutes,
		"local_routes":         r.metrics.LocalRoutes,
		"routing_errors":       r.metrics.RoutingErrors,
		"rule_matches":         r.metrics.RuleMatches,
		"average_routing_time": r.metrics.AverageRoutingTime,
		"total_rules":          len(r.rules),
		"local_domains":        len(r.localDomains),
	}
}

// LoadDefaultRules loads default routing rules for common scenarios
func (r *Router) LoadDefaultRules() {
	// Rule for local domains
	if len(r.config.LocalDomains) > 0 {
		localRule := &RoutingRule{
			ID:          "default-local",
			Name:        "Default Local Delivery",
			Description: "Route messages to local domains for local delivery",
			Enabled:     true,
			Priority:    1,
			ToDomain:    r.config.LocalDomains,
			RouteType:   RouteTypeLocal,
		}
		r.AddRoutingRule(localRule)
	}

	// Rule for relay if configured
	if r.config.RelayHost != "" {
		relayRule := &RoutingRule{
			ID:          "default-relay",
			Name:        "Default Relay",
			Description: "Route all non-local messages through relay",
			Enabled:     false, // Disabled by default, enable manually if needed
			Priority:    100,
			RouteType:   RouteTypeRelay,
			RelayHost:   r.config.RelayHost,
			RelayPort:   r.config.RelayPort,
			ForceAuth:   r.config.RelayAuth,
		}
		r.AddRoutingRule(relayRule)
	}

	r.logger.Info("Default routing rules loaded")
}
