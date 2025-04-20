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

// Plugin information
var (
	PluginName        = "rspamd"
	PluginVersion     = "1.0.0"
	PluginDescription = "Rspamd antispam scanning plugin"
	PluginAuthor      = "Elemta Team"
)

// RspamdPlugin represents the Rspamd antispam plugin
type RspamdPlugin struct {
	scanner *antispam.Rspamd
	config  *Config
}

// Config represents the plugin configuration
type Config struct {
	Enabled         bool    `toml:"enabled"`
	Host            string  `toml:"host"`
	Port            int     `toml:"port"`
	Timeout         int     `toml:"timeout"`
	RejectOnFailure bool    `toml:"reject_on_failure"`
	Threshold       float64 `toml:"threshold"`
	APIKey          string  `toml:"api_key"`
}

// Init initializes the plugin
func (p *RspamdPlugin) Init(cfg interface{}) error {
	// Parse configuration
	if cfg != nil {
		if c, ok := cfg.(*Config); ok {
			p.config = c
		} else {
			log.Printf("Warning: Invalid configuration type for Rspamd plugin")
			p.config = &Config{
				Enabled:   true,
				Host:      "elemta-rspamd",
				Port:      11334,
				Timeout:   30,
				Threshold: 6.0,
			}
		}
	} else {
		// Default configuration
		p.config = &Config{
			Enabled:   true,
			Host:      "elemta-rspamd",
			Port:      11334,
			Timeout:   30,
			Threshold: 6.0,
		}
	}

	log.Printf("Initializing Rspamd plugin with host %s:%d", p.config.Host, p.config.Port)

	// Create scanner
	address := fmt.Sprintf("http://%s:%d", p.config.Host, p.config.Port)

	scannerConfig := antispam.Config{
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
	if !p.config.Enabled || p.scanner == nil || !p.scanner.IsConnected() {
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

	// Scan message content
	result, err := p.scanner.ScanBytes(ctx, msg.Data)
	if err != nil {
		log.Printf("Error scanning message: %v", err)

		if p.config.RejectOnFailure {
			return plugin.NewResult(plugin.ResultReject, "Failed to scan message", err), nil
		}

		return plugin.NewResult(plugin.ResultPass, "Spam scan failed, accepting anyway", err), nil
	}

	// Add headers to the message
	msg.AddHeader("X-Spam-Scanned", "Yes")

	status := "No"
	if !result.Clean {
		status = "Yes"
	}

	scoreStr := fmt.Sprintf("%.1f/%.1f", result.Score, result.Threshold)
	msg.AddHeader("X-Spam-Status", fmt.Sprintf("%s, score=%s", status, scoreStr))

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
		return plugin.NewResult(plugin.ResultReject, "Spam detected", result), nil
	}

	return plugin.NewResult(plugin.ResultPass, "Message is not spam", result), nil
}

// Hooks returns the hooks that the plugin wants to register
func (p *RspamdPlugin) Hooks() []plugin.HookRegistration {
	return []plugin.HookRegistration{
		{
			Name:     "scan_message",
			Stage:    plugin.StagePostQueue,
			Priority: 30,
			Func:     p.ScanMessage,
		},
	}
}

// Name returns the name of the plugin
func (p *RspamdPlugin) Name() string {
	return PluginName
}

// Version returns the version of the plugin
func (p *RspamdPlugin) Version() string {
	return PluginVersion
}

// Description returns the description of the plugin
func (p *RspamdPlugin) Description() string {
	return PluginDescription
}

// New creates a new instance of the plugin
func New() plugin.Plugin {
	return &RspamdPlugin{}
}

// This is required for Go plugins
var Plugin RspamdPlugin
