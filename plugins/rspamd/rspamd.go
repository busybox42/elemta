package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/busybox42/elemta/internal/antispam"
	"github.com/busybox42/elemta/internal/message"
	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo provides information about this plugin
var PluginInfo = plugin.PluginInfo{
	Name:        "rspamd",
	Description: "Rspamd antispam scanning plugin",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeAntispam,
	Author:      "Elemta Team",
}

// RspamdPlugin implements the AntispamPlugin interface
type RspamdPlugin struct {
	scanner *antispam.Rspamd
	config  *Config
}

// Config represents the plugin configuration
type Config struct {
	Enabled         bool    `toml:"enabled" json:"enabled"`
	Host            string  `toml:"host" json:"host"`
	Port            int     `toml:"port" json:"port"`
	Timeout         int     `toml:"timeout" json:"timeout"`
	RejectOnFailure bool    `toml:"reject_on_failure" json:"reject_on_failure"`
	Threshold       float64 `toml:"threshold" json:"threshold"`
	APIKey          string  `toml:"api_key" json:"api_key"`
}

// Init initializes the plugin
func (p *RspamdPlugin) Init(cfg map[string]interface{}) error {
	// Parse configuration
	config := &Config{
		Enabled:   true,
		Host:      "elemta-rspamd",
		Port:      11334,
		Timeout:   30,
		Threshold: 5.0,
	}

	// Apply config settings if available
	if v, ok := cfg["enabled"].(bool); ok {
		config.Enabled = v
	}
	if v, ok := cfg["host"].(string); ok {
		config.Host = v
	}
	if v, ok := cfg["port"].(int); ok {
		config.Port = v
	}
	if v, ok := cfg["timeout"].(int); ok {
		config.Timeout = v
	}
	if v, ok := cfg["reject_on_failure"].(bool); ok {
		config.RejectOnFailure = v
	}
	if v, ok := cfg["threshold"].(float64); ok {
		config.Threshold = v
	}
	if v, ok := cfg["api_key"].(string); ok {
		config.APIKey = v
	}

	p.config = config

	log.Printf("Initializing Rspamd plugin with host %s:%d", p.config.Host, p.config.Port)

	// Create scanner
	address := fmt.Sprintf("http://%s:%d", p.config.Host, p.config.Port)

	scannerConfig := antispam.Config{
		Type:      "rspamd",
		Address:   address,
		Threshold: p.config.Threshold,
		Options: map[string]interface{}{
			"timeout": p.config.Timeout,
			"api_key": p.config.APIKey,
		},
	}

	p.scanner = antispam.NewRspamd(scannerConfig)

	// Connect to Rspamd
	if err := p.scanner.Connect(); err != nil {
		log.Printf("Warning: Failed to connect to Rspamd: %v", err)
		return nil // Don't fail initialization if Rspamd is not available
	}

	log.Printf("Rspamd plugin initialized successfully")
	return nil
}

// ScanMessage scans a message for spam
func (p *RspamdPlugin) ScanMessage(msg *message.Message) (*plugin.Result, error) {
	if !p.config.Enabled || p.scanner == nil {
		// Plugin is disabled or scanner is not available
		return plugin.NewResult(plugin.ResultPass, "Spam scanning not available", nil), nil
	}

	// Create context with timeout
	ctx := context.Background()
	if p.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(p.config.Timeout)*time.Second)
		defer cancel()
	}

	log.Printf("Scanning message for spam: %s", msg.ID)

	// Scan message content
	result, err := p.scanner.ScanBytes(ctx, msg.Data)
	if err != nil {
		log.Printf("Error scanning message: %v", err)

		if p.config.RejectOnFailure {
			return plugin.NewResult(plugin.ResultReject, "Failed to scan message for spam", err), nil
		}

		return plugin.NewResult(plugin.ResultPass, "Spam scan failed, accepting anyway", err), nil
	}

	// Add headers to the message
	scoreStr := fmt.Sprintf("%.2f/%.2f", result.Score, result.Threshold)
	isSpam := "No"
	if !result.Clean {
		isSpam = "Yes"
	}

	msg.AddHeader("X-Spam-Scanned", "Yes")
	msg.AddHeader("X-Spam-Score", scoreStr)
	msg.AddHeader("X-Spam-Status", isSpam)

	// If rules were triggered, add them to the header
	if len(result.Rules) > 0 {
		ruleList := ""
		for i, rule := range result.Rules {
			if i > 0 {
				ruleList += " "
			}
			ruleList += rule
		}
		msg.AddHeader("X-Spam-Rules", ruleList)
	}

	// Check if the message is spam
	if !result.Clean {
		log.Printf("Spam detected, score: %.2f (threshold: %.2f)", result.Score, result.Threshold)
		return plugin.NewResult(plugin.ResultReject, fmt.Sprintf("Spam detected (score: %.2f/%.2f)", result.Score, result.Threshold), nil), nil
	}

	log.Printf("Message is not spam: %s (score: %.2f/%.2f)", msg.ID, result.Score, result.Threshold)
	return plugin.NewResult(plugin.ResultPass, "Message is not spam", nil), nil
}

// Close closes the plugin and releases any resources
func (p *RspamdPlugin) Close() error {
	// No need to close anything for now
	return nil
}

// GetInfo returns information about the plugin
func (p *RspamdPlugin) GetInfo() plugin.PluginInfo {
	return PluginInfo
}

// GetStages returns the stages that the plugin wants to process
func (p *RspamdPlugin) GetStages() []plugin.ProcessingStage {
	return []plugin.ProcessingStage{
		plugin.StageDataComplete,
	}
}

// GetPriority returns the plugin's priority
func (p *RspamdPlugin) GetPriority() plugin.PluginPriority {
	return plugin.PriorityNormal
}

// Plugin is the exported plugin instance
var Plugin RspamdPlugin
