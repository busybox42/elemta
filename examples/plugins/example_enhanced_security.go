// Example Enhanced Security Plugin demonstrating the new hook system
package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo is exported and contains information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "enhanced-security",
	Description: "Enhanced security plugin with rate limiting, greylisting, and reputation checking",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeSecurity,
	Author:      "Elemta Team",
}

// EnhancedSecurityPlugin implements multiple hook interfaces
type EnhancedSecurityPlugin struct {
	logger      *slog.Logger
	config      map[string]interface{}
	rateLimiter *RateLimiter
	greylist    *Greylist
	reputation  *ReputationManager
	mu          sync.RWMutex
}

// Plugin is exported and provides the plugin instance
var Plugin = &EnhancedSecurityPlugin{
	logger:      slog.Default().With("plugin", "enhanced-security"),
	rateLimiter: NewRateLimiter(),
	greylist:    NewGreylist(),
	reputation:  NewReputationManager(),
}

// GetInfo returns plugin information
func (p *EnhancedSecurityPlugin) GetInfo() plugin.PluginInfo {
	return *PluginInfo
}

// Init initializes the plugin with configuration
func (p *EnhancedSecurityPlugin) Init(config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config
	p.logger.Info("Enhanced security plugin initialized", "config", config)

	// Configure rate limiter
	if maxConnections, ok := config["max_connections_per_minute"].(float64); ok {
		p.rateLimiter.SetLimit(int(maxConnections))
	}

	// Configure greylist TTL
	if greylistTTL, ok := config["greylist_ttl_minutes"].(float64); ok {
		p.greylist.SetTTL(time.Duration(greylistTTL) * time.Minute)
	}

	return nil
}

// Close cleans up plugin resources
func (p *EnhancedSecurityPlugin) Close() error {
	p.logger.Info("Enhanced security plugin closing")
	return nil
}

// ConnectionHook implementation
func (p *EnhancedSecurityPlugin) OnConnect(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
	ip := extractIP(remoteAddr)
	p.logger.Debug("Connection attempt", "ip", ip.String())

	// Check rate limiting
	if !p.rateLimiter.Allow(ip) {
		p.logger.Warn("Rate limit exceeded", "ip", ip.String())
		return &plugin.PluginResult{
			Action:      plugin.ActionReject,
			Message:     "Too many connections from your IP address",
			Score:       10.0,
			Annotations: map[string]string{"reason": "rate_limit"},
		}, nil
	}

	// Check reputation
	repScore := p.reputation.GetScore(ip)
	if repScore < -5.0 {
		p.logger.Warn("Bad reputation IP blocked", "ip", ip.String(), "score", repScore)
		return &plugin.PluginResult{
			Action:      plugin.ActionReject,
			Message:     "Your IP address has a poor reputation",
			Score:       repScore,
			Annotations: map[string]string{"reason": "bad_reputation"},
		}, nil
	}

	return &plugin.PluginResult{
		Action:      plugin.ActionContinue,
		Message:     "Connection allowed",
		Score:       0.0,
		Annotations: map[string]string{"reputation_score": fmt.Sprintf("%.2f", repScore)},
	}, nil
}

func (p *EnhancedSecurityPlugin) OnDisconnect(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
	ip := extractIP(remoteAddr)
	p.logger.Debug("Connection closed", "ip", ip.String())

	// Update connection statistics
	p.rateLimiter.RecordDisconnect(ip)

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "Disconnect processed",
	}, nil
}

// SecurityHook implementation
func (p *EnhancedSecurityPlugin) OnRateLimitCheck(ctx *plugin.HookContext, remoteAddr net.Addr) (*plugin.PluginResult, error) {
	ip := extractIP(remoteAddr)

	if !p.rateLimiter.Allow(ip) {
		return &plugin.PluginResult{
			Action:      plugin.ActionReject,
			Message:     "Rate limit exceeded",
			Score:       5.0,
			Annotations: map[string]string{"reason": "rate_limit"},
		}, nil
	}

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "Rate limit OK",
	}, nil
}

func (p *EnhancedSecurityPlugin) OnGreylistCheck(ctx *plugin.HookContext, sender, recipient string, remoteAddr net.Addr) (*plugin.PluginResult, error) {
	ip := extractIP(remoteAddr)

	// Create greylist key
	key := fmt.Sprintf("%s|%s|%s", ip.String(), sender, recipient)

	if p.greylist.ShouldGreylist(key) {
		p.logger.Info("Greylisting message", "ip", ip.String(), "sender", sender, "recipient", recipient)
		return &plugin.PluginResult{
			Action:      plugin.ActionDefer,
			Message:     "Greylisted - try again later",
			Score:       2.0,
			Annotations: map[string]string{"reason": "greylist"},
		}, nil
	}

	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "Greylist passed",
	}, nil
}

func (p *EnhancedSecurityPlugin) OnReputationCheck(ctx *plugin.HookContext, remoteAddr net.Addr, domain string) (*plugin.PluginResult, error) {
	ip := extractIP(remoteAddr)
	score := p.reputation.GetScore(ip)

	// Also check domain reputation if provided
	if domain != "" {
		domainScore := p.reputation.GetDomainScore(domain)
		score = (score + domainScore) / 2.0
	}

	result := &plugin.PluginResult{
		Action:      plugin.ActionContinue,
		Message:     fmt.Sprintf("Reputation score: %.2f", score),
		Score:       score,
		Annotations: map[string]string{"reputation_score": fmt.Sprintf("%.2f", score)},
	}

	if score < -5.0 {
		result.Action = plugin.ActionReject
		result.Message = "Poor reputation score"
	} else if score < 0 {
		result.Action = plugin.ActionModify
		result.Message = "Suspicious reputation score"
	}

	return result, nil
}

// MetricsHook implementation
func (p *EnhancedSecurityPlugin) OnMetricsCollect(ctx *plugin.HookContext, event string, data map[string]interface{}) error {
	// Collect security-related metrics
	if event == "connection" || event == "message" {
		if ip, ok := data["remote_ip"].(net.IP); ok {
			score := p.reputation.GetScore(ip)
			data["reputation_score"] = score
			data["rate_limit_status"] = p.rateLimiter.GetStatus(ip)
		}
	}

	return nil
}

// Helper functions and data structures

func extractIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	default:
		// Try to parse as string
		if tcpAddr, err := net.ResolveTCPAddr("tcp", addr.String()); err == nil {
			return tcpAddr.IP
		}
		return net.IPv4zero
	}
}

// RateLimiter tracks connection rates per IP
type RateLimiter struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionTracker
	maxPerMin   int
}

type ConnectionTracker struct {
	Count    int
	Window   time.Time
	Total    int64
	LastSeen time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		connections: make(map[string]*ConnectionTracker),
		maxPerMin:   60, // Default: 60 connections per minute
	}
}

func (rl *RateLimiter) SetLimit(maxPerMin int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxPerMin = maxPerMin
}

func (rl *RateLimiter) Allow(ip net.IP) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := ip.String()
	now := time.Now()

	tracker, exists := rl.connections[key]
	if !exists {
		tracker = &ConnectionTracker{
			Count:    1,
			Window:   now,
			Total:    1,
			LastSeen: now,
		}
		rl.connections[key] = tracker
		return true
	}

	// Reset window if it's been more than a minute
	if now.Sub(tracker.Window) > time.Minute {
		tracker.Count = 1
		tracker.Window = now
	} else {
		tracker.Count++
	}

	tracker.Total++
	tracker.LastSeen = now

	return tracker.Count <= rl.maxPerMin
}

func (rl *RateLimiter) RecordDisconnect(ip net.IP) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := ip.String()
	if tracker, exists := rl.connections[key]; exists {
		tracker.LastSeen = time.Now()
	}
}

func (rl *RateLimiter) GetStatus(ip net.IP) map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	key := ip.String()
	if tracker, exists := rl.connections[key]; exists {
		return map[string]interface{}{
			"current_count": tracker.Count,
			"total_count":   tracker.Total,
			"window_start":  tracker.Window,
			"last_seen":     tracker.LastSeen,
		}
	}

	return map[string]interface{}{
		"current_count": 0,
		"total_count":   0,
	}
}

// Greylist manages greylisting of email triplets
type Greylist struct {
	mu      sync.RWMutex
	entries map[string]*GreylistEntry
	ttl     time.Duration
}

type GreylistEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
	Allowed   bool
}

func NewGreylist() *Greylist {
	return &Greylist{
		entries: make(map[string]*GreylistEntry),
		ttl:     15 * time.Minute, // Default 15 minute greylist
	}
}

func (gl *Greylist) SetTTL(ttl time.Duration) {
	gl.mu.Lock()
	defer gl.mu.Unlock()
	gl.ttl = ttl
}

func (gl *Greylist) ShouldGreylist(key string) bool {
	gl.mu.Lock()
	defer gl.mu.Unlock()

	now := time.Now()
	entry, exists := gl.entries[key]

	if !exists {
		// First time seeing this triplet - greylist it
		gl.entries[key] = &GreylistEntry{
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
			Allowed:   false,
		}
		return true
	}

	entry.LastSeen = now
	entry.Count++

	// If enough time has passed since first attempt, allow it
	if now.Sub(entry.FirstSeen) >= gl.ttl {
		entry.Allowed = true
		return false
	}

	return !entry.Allowed
}

// ReputationManager manages IP and domain reputation scores
type ReputationManager struct {
	mu           sync.RWMutex
	ipScores     map[string]float64
	domainScores map[string]float64
}

func NewReputationManager() *ReputationManager {
	return &ReputationManager{
		ipScores:     make(map[string]float64),
		domainScores: make(map[string]float64),
	}
}

func (rm *ReputationManager) GetScore(ip net.IP) float64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	key := ip.String()

	// Check for known bad IPs
	if score, exists := rm.ipScores[key]; exists {
		return score
	}

	// Simple heuristics for demonstration
	if ip.IsLoopback() || ip.IsPrivate() {
		return 5.0 // Local/private IPs get good scores
	}

	// Check if it's a known cloud provider or dynamic IP
	if rm.isDynamicIP(ip) {
		return -2.0 // Slightly suspicious
	}

	return 0.0 // Neutral score for unknown IPs
}

func (rm *ReputationManager) GetDomainScore(domain string) float64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if score, exists := rm.domainScores[domain]; exists {
		return score
	}

	// Simple domain reputation heuristics
	domain = strings.ToLower(domain)

	// Check for suspicious patterns
	if strings.Contains(domain, "temp") || strings.Contains(domain, "throwaway") {
		return -3.0
	}

	// Well-known domains get good scores
	goodDomains := []string{"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}
	for _, good := range goodDomains {
		if domain == good {
			return 3.0
		}
	}

	return 0.0 // Neutral score
}

func (rm *ReputationManager) isDynamicIP(ip net.IP) bool {
	// This is a simplified check - in reality you'd use proper IP reputation databases
	str := ip.String()

	// Check for common dynamic IP patterns
	dynamicPatterns := []string{
		".dyn.", ".dynamic.", ".dhcp.", ".cable.", ".dsl.",
	}

	for _, pattern := range dynamicPatterns {
		if strings.Contains(str, pattern) {
			return true
		}
	}

	return false
}
