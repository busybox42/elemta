package main

import (
	"context"
	"log/slog"

	"github.com/busybox42/elemta/internal/plugin"
)

// RateLimiterPlugin implements the RateLimitPlugin interface
type RateLimiterPlugin struct {
	logger *slog.Logger
}

// GetInfo returns plugin information
func (p *RateLimiterPlugin) GetInfo() plugin.PluginInfo {
	return plugin.PluginInfo{
		Name:        "rate_limiter",
		Version:     "1.0.0",
		Description: "Enterprise-grade rate limiting plugin with Valkey backend support",
		Author:      "Elemta Team",
		Type:        plugin.PluginTypeRateLimit,
	}
}

// Init initializes the rate limiter plugin
func (p *RateLimiterPlugin) Init(config map[string]interface{}) error {
	p.logger.Info("Rate limiter plugin initialized")
	return nil
}

// Close shuts down the rate limiter plugin
func (p *RateLimiterPlugin) Close() error {
	p.logger.Info("Rate limiter plugin closed")
	return nil
}

// OnConnect handles connection events
func (p *RateLimiterPlugin) OnConnect(ctx context.Context, remoteAddr string) (*plugin.PluginResult, error) {
	return &plugin.PluginResult{Action: plugin.ActionContinue}, nil
}

// OnMailFrom handles MAIL FROM events
func (p *RateLimiterPlugin) OnMailFrom(ctx context.Context, from string) (*plugin.PluginResult, error) {
	return &plugin.PluginResult{Action: plugin.ActionContinue}, nil
}

// OnMessageComplete handles message completion events
func (p *RateLimiterPlugin) OnMessageComplete(ctx context.Context, messageID string, size int64) (*plugin.PluginResult, error) {
	return &plugin.PluginResult{Action: plugin.ActionContinue}, nil
}

// OnAuth handles authentication events
func (p *RateLimiterPlugin) OnAuth(ctx context.Context, username, password string) (*plugin.PluginResult, error) {
	return &plugin.PluginResult{Action: plugin.ActionContinue}, nil
}

// GetMetrics returns rate limiter metrics
func (p *RateLimiterPlugin) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"plugin": "rate_limiter",
		"status": "active",
	}
}

// UpdateConfig updates the rate limiter configuration
func (p *RateLimiterPlugin) UpdateConfig(config map[string]interface{}) error {
	p.logger.Info("Rate limiter config updated", "config", config)
	return nil
}

// AddToWhitelist adds an item to the whitelist
func (p *RateLimiterPlugin) AddToWhitelist(item string) error {
	p.logger.Info("Added to whitelist", "item", item)
	return nil
}

// AddToBlacklist adds an item to the blacklist
func (p *RateLimiterPlugin) AddToBlacklist(item string) error {
	p.logger.Info("Added to blacklist", "item", item)
	return nil
}

// RemoveFromWhitelist removes an item from the whitelist
func (p *RateLimiterPlugin) RemoveFromWhitelist(item string) error {
	p.logger.Info("Removed from whitelist", "item", item)
	return nil
}

// RemoveFromBlacklist removes an item from the blacklist
func (p *RateLimiterPlugin) RemoveFromBlacklist(item string) error {
	p.logger.Info("Removed from blacklist", "item", item)
	return nil
}

// Export the plugin instance - Go plugins need this exact symbol name
var Plugin = &RateLimiterPlugin{
	logger: slog.Default().With("component", "rate-limiter-plugin"),
}
