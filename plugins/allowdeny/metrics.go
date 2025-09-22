package main

import (
	"sync"
	"time"
)

// GetMetrics returns current plugin metrics
func (p *AllowDenyPlugin) GetMetrics() *Metrics {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Return a copy to prevent external modification
	metrics := *p.metrics
	metrics.ActiveRules = int64(p.ruleEngine.GetRuleCount())

	return &metrics
}

// ResetMetrics resets all metrics counters
func (p *AllowDenyPlugin) ResetMetrics() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.metrics = &Metrics{
		LastReloadTime: p.metrics.LastReloadTime, // Preserve reload time
	}
}

// IncrementCacheHit increments cache hit counter
func (p *AllowDenyPlugin) IncrementCacheHit() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.CacheHits++
}

// IncrementCacheMiss increments cache miss counter
func (p *AllowDenyPlugin) IncrementCacheMiss() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.CacheMisses++
}

// RecordEvaluationTime records rule evaluation time
func (p *AllowDenyPlugin) RecordEvaluationTime(duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.EvaluationTime += duration
}

// GetCacheHitRate returns the cache hit rate as a percentage
func (p *AllowDenyPlugin) GetCacheHitRate() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := p.metrics.CacheHits + p.metrics.CacheMisses
	if total == 0 {
		return 0.0
	}

	return float64(p.metrics.CacheHits) / float64(total) * 100.0
}

// GetAverageEvaluationTime returns the average rule evaluation time
func (p *AllowDenyPlugin) GetAverageEvaluationTime() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.metrics.RulesEvaluated == 0 {
		return 0
	}

	return p.metrics.EvaluationTime / time.Duration(p.metrics.RulesEvaluated)
}

// GetDenyRate returns the percentage of requests that were denied
func (p *AllowDenyPlugin) GetDenyRate() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := p.metrics.RulesDenied + p.metrics.RulesAllowed
	if total == 0 {
		return 0.0
	}

	return float64(p.metrics.RulesDenied) / float64(total) * 100.0
}

// RuleCacheStats provides statistics for rule caching
type RuleCacheStats struct {
	ipRules     map[string][]Rule
	domainRules map[string][]Rule
	emailRules  map[string][]Rule
	regexRules  []Rule
	mu          sync.RWMutex
	hitCount    int64
	missCount   int64
	maxSize     int
	lastCleanup time.Time
}

// NewRuleCache creates a new rule cache
func NewRuleCache(maxSize int) *RuleCache {
	return &RuleCache{
		ipRules:     make(map[string][]Rule),
		domainRules: make(map[string][]Rule),
		emailRules:  make(map[string][]Rule),
		regexRules:  make([]Rule, 0),
		maxSize:     maxSize,
	}
}

// GetIPRules retrieves cached IP rules
func (rc *RuleCache) GetIPRules(ip string) ([]Rule, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	rules, exists := rc.ipRules[ip]
	if exists {
		rc.hitCount++
		return rules, true
	}

	rc.missCount++
	return nil, false
}

// SetIPRules caches IP rules
func (rc *RuleCache) SetIPRules(ip string, rules []Rule) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Check if we need to clean up cache
	if len(rc.ipRules) >= rc.maxSize {
		rc.cleanup()
	}

	rc.ipRules[ip] = rules
}

// GetDomainRules retrieves cached domain rules
func (rc *RuleCache) GetDomainRules(domain string) ([]Rule, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	rules, exists := rc.domainRules[domain]
	if exists {
		rc.hitCount++
		return rules, true
	}

	rc.missCount++
	return nil, false
}

// SetDomainRules caches domain rules
func (rc *RuleCache) SetDomainRules(domain string, rules []Rule) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Check if we need to clean up cache
	if len(rc.domainRules) >= rc.maxSize {
		rc.cleanup()
	}

	rc.domainRules[domain] = rules
}

// GetEmailRules retrieves cached email rules
func (rc *RuleCache) GetEmailRules(email string) ([]Rule, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	rules, exists := rc.emailRules[email]
	if exists {
		rc.hitCount++
		return rules, true
	}

	rc.missCount++
	return nil, false
}

// SetEmailRules caches email rules
func (rc *RuleCache) SetEmailRules(email string, rules []Rule) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Check if we need to clean up cache
	if len(rc.emailRules) >= rc.maxSize {
		rc.cleanup()
	}

	rc.emailRules[email] = rules
}

// GetStats returns cache statistics
func (rc *RuleCache) GetStats() CacheStats {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	total := rc.hitCount + rc.missCount
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(rc.hitCount) / float64(total) * 100.0
	}

	return CacheStats{
		HitCount:    rc.hitCount,
		MissCount:   rc.missCount,
		HitRate:     hitRate,
		IPRules:     len(rc.ipRules),
		DomainRules: len(rc.domainRules),
		EmailRules:  len(rc.emailRules),
		RegexRules:  len(rc.regexRules),
		TotalSize:   len(rc.ipRules) + len(rc.domainRules) + len(rc.emailRules) + len(rc.regexRules),
	}
}

// CacheStats represents cache statistics
type CacheStats struct {
	HitCount    int64   `json:"hit_count"`
	MissCount   int64   `json:"miss_count"`
	HitRate     float64 `json:"hit_rate"`
	IPRules     int     `json:"ip_rules"`
	DomainRules int     `json:"domain_rules"`
	EmailRules  int     `json:"email_rules"`
	RegexRules  int     `json:"regex_rules"`
	TotalSize   int     `json:"total_size"`
}

// cleanup removes old cache entries to make room for new ones
func (rc *RuleCache) cleanup() {
	// Simple cleanup strategy: remove 25% of entries
	// In a production system, you might want to use LRU or other strategies

	// Clean IP rules
	if len(rc.ipRules) > 0 {
		removeCount := len(rc.ipRules) / 4
		count := 0
		for ip := range rc.ipRules {
			delete(rc.ipRules, ip)
			count++
			if count >= removeCount {
				break
			}
		}
	}

	// Clean domain rules
	if len(rc.domainRules) > 0 {
		removeCount := len(rc.domainRules) / 4
		count := 0
		for domain := range rc.domainRules {
			delete(rc.domainRules, domain)
			count++
			if count >= removeCount {
				break
			}
		}
	}

	// Clean email rules
	if len(rc.emailRules) > 0 {
		removeCount := len(rc.emailRules) / 4
		count := 0
		for email := range rc.emailRules {
			delete(rc.emailRules, email)
			count++
			if count >= removeCount {
				break
			}
		}
	}

	// rc.lastCleanup = time.Now() // Field not available in this context
}

// Clear clears all cache entries
func (rc *RuleCache) Clear() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.ipRules = make(map[string][]Rule)
	rc.domainRules = make(map[string][]Rule)
	rc.emailRules = make(map[string][]Rule)
	rc.regexRules = make([]Rule, 0)
	rc.hitCount = 0
	rc.missCount = 0
}

// ShouldCleanup returns true if the cache should be cleaned up
func (rc *RuleCache) ShouldCleanup() bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	// Cleanup if cache is full
	totalSize := len(rc.ipRules) + len(rc.domainRules) + len(rc.emailRules) + len(rc.regexRules)
	return totalSize >= rc.maxSize
}
