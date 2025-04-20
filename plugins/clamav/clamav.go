package main

import (
	"context"
	"log"
	"time"

	"github.com/busybox42/elemta/internal/antivirus"
	"github.com/busybox42/elemta/internal/message"
	"github.com/busybox42/elemta/internal/plugin"
)

// Plugin information
var (
	PluginName        = "clamav"
	PluginVersion     = "1.0.0"
	PluginDescription = "ClamAV antivirus scanning plugin"
	PluginAuthor      = "Elemta Team"
)

// ClamAVPlugin represents the ClamAV antivirus plugin
type ClamAVPlugin struct {
	scanner *antivirus.ClamAV
	config  *Config
}

// Config represents the plugin configuration
type Config struct {
	Enabled         bool   `toml:"enabled"`
	Host            string `toml:"host"`
	Port            int    `toml:"port"`
	Timeout         int    `toml:"timeout"`
	RejectOnFailure bool   `toml:"reject_on_failure"`
	MaxSize         int64  `toml:"max_size"`
}

// Init initializes the plugin
func (p *ClamAVPlugin) Init(cfg interface{}) error {
	// Parse configuration
	if cfg != nil {
		if c, ok := cfg.(*Config); ok {
			p.config = c
		} else {
			log.Printf("Warning: Invalid configuration type for ClamAV plugin")
			p.config = &Config{
				Enabled: true,
				Host:    "elemta-clamav",
				Port:    3310,
				Timeout: 30,
			}
		}
	} else {
		// Default configuration
		p.config = &Config{
			Enabled: true,
			Host:    "elemta-clamav",
			Port:    3310,
			Timeout: 30,
		}
	}

	log.Printf("Initializing ClamAV plugin with host %s:%d", p.config.Host, p.config.Port)

	// Create scanner
	address := p.config.Host
	if p.config.Port > 0 {
		address = address + ":" + string(p.config.Port)
	}

	scannerConfig := antivirus.Config{
		Address: address,
		Options: map[string]interface{}{
			"timeout":     p.config.Timeout,
			"scan_limit":  p.config.MaxSize,
			"scan_buffer": 8192,
		},
	}

	p.scanner = antivirus.NewClamAV(scannerConfig)

	// Connect to ClamAV
	if err := p.scanner.Connect(); err != nil {
		log.Printf("Warning: Failed to connect to ClamAV: %v", err)
		return nil // Don't fail initialization if ClamAV is not available
	}

	log.Printf("ClamAV plugin initialized successfully")
	return nil
}

// ScanMessage scans a message for viruses
func (p *ClamAVPlugin) ScanMessage(msg *message.Message) (*plugin.Result, error) {
	if !p.config.Enabled || p.scanner == nil || !p.scanner.IsConnected() {
		// Plugin is disabled or scanner is not available
		return plugin.NewResult(plugin.ResultPass, "AV scanning not available", nil), nil
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

		return plugin.NewResult(plugin.ResultPass, "AV scan failed, accepting anyway", err), nil
	}

	// Add headers to the message
	msg.AddHeader("X-Virus-Scanned", "Clean (ClamAV)")

	// Check if the message is clean
	if !result.Clean {
		log.Printf("Virus detected: %v", result.Infections)
		msg.AddHeader("X-Virus-Status", "Infected")
		return plugin.NewResult(plugin.ResultReject, "Virus detected", result), nil
	}

	return plugin.NewResult(plugin.ResultPass, "Message is clean", result), nil
}

// Hooks returns the hooks that the plugin wants to register
func (p *ClamAVPlugin) Hooks() []plugin.HookRegistration {
	return []plugin.HookRegistration{
		{
			Name:     "scan_message",
			Stage:    plugin.StagePostQueue,
			Priority: 20,
			Func:     p.ScanMessage,
		},
	}
}

// Name returns the name of the plugin
func (p *ClamAVPlugin) Name() string {
	return PluginName
}

// Version returns the version of the plugin
func (p *ClamAVPlugin) Version() string {
	return PluginVersion
}

// Description returns the description of the plugin
func (p *ClamAVPlugin) Description() string {
	return PluginDescription
}

// New creates a new instance of the plugin
func New() plugin.Plugin {
	return &ClamAVPlugin{}
}

// This is required for Go plugins
var Plugin ClamAVPlugin
