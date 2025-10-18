//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
)

// GreylistPlugin implements a simple greylisting plugin
type GreylistPlugin struct {
	info      plugin.PluginInfo
	firstSeen map[string]time.Time
	mu        sync.RWMutex
	delay     time.Duration
}

// PluginInfo provides information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "greylisting",
	Version:     "1.0.0",
	Description: "A simple greylisting plugin that temporarily rejects first-time senders",
	Author:      "Elemta Team",
	Type:        plugin.PluginTypeGreylist,
}

// GreylistPluginInstance is the exported plugin instance
var GreylistPluginInstance = &GreylistPlugin{
	info:      *PluginInfo,
	firstSeen: make(map[string]time.Time),
	delay:     5 * time.Minute, // Default delay of 5 minutes
}

// GetInfo returns the plugin information
func (p *GreylistPlugin) GetInfo() plugin.PluginInfo {
	return p.info
}

// Init initializes the plugin
func (p *GreylistPlugin) Init(config map[string]interface{}) error {
	// Initialize the plugin
	fmt.Println("Initializing greylisting plugin")

	// Check if delay is configured
	if delayStr, ok := config["delay"]; ok {
		if delayVal, ok := delayStr.(string); ok {
			if parsedDelay, err := time.ParseDuration(delayVal); err == nil {
				p.delay = parsedDelay
			}
		}
	}

	return nil
}

// Close cleans up resources
func (p *GreylistPlugin) Close() error {
	// Clean up resources
	fmt.Println("Closing greylisting plugin")
	return nil
}

// GetStages returns the processing stages this plugin should be executed in
func (p *GreylistPlugin) GetStages() []plugin.ProcessingStage {
	return []plugin.ProcessingStage{
		plugin.StageRcptTo, // Execute during RCPT TO command
	}
}

// GetPriority returns the plugin priority (higher values run first)
func (p *GreylistPlugin) GetPriority() plugin.PluginPriority {
	return plugin.PriorityNormal
}

// Execute implements the plugin logic
func (p *GreylistPlugin) Execute(ctx map[string]interface{}) (*plugin.PluginResult, error) {
	// Extract the sender and recipient information
	from, _ := ctx["mail_from"].(string)
	to, _ := ctx["rcpt_to"].(string)
	ip, _ := ctx["remote_ip"].(string)

	// Create a unique key for this sender-recipient pair
	key := fmt.Sprintf("%s|%s|%s", ip, from, to)

	// Check if we've seen this sender-recipient pair before
	p.mu.RLock()
	firstTime, seen := p.firstSeen[key]
	p.mu.RUnlock()

	now := time.Now()

	if !seen {
		// First time seeing this sender-recipient pair
		p.mu.Lock()
		p.firstSeen[key] = now
		p.mu.Unlock()

		// Temporarily reject with a 4xx code
		return &plugin.PluginResult{
			Action:  plugin.ActionReject,
			Message: "450 4.7.1 Please try again later (greylisting)",
		}, nil
	}

	// Check if enough time has passed since first attempt
	if now.Sub(firstTime) < p.delay {
		// Not enough time has passed, still reject
		return &plugin.PluginResult{
			Action:  plugin.ActionReject,
			Message: "450 4.7.1 Please try again later (greylisting)",
		}, nil
	}

	// Enough time has passed, allow the message
	return &plugin.PluginResult{
		Action:  plugin.ActionContinue,
		Message: "Greylisting check passed",
	}, nil
}

// Cleanup periodically removes old entries
func (p *GreylistPlugin) Cleanup() {
	// Remove entries older than 36 hours
	cutoff := time.Now().Add(-36 * time.Hour)

	p.mu.Lock()
	defer p.mu.Unlock()

	for key, timestamp := range p.firstSeen {
		if timestamp.Before(cutoff) {
			delete(p.firstSeen, key)
		}
	}
}

// main is required for Go plugins
func main() {
	// This function is not used for Go plugins but is required
}
