package main

import (
	"net"

	"github.com/busybox42/elemta/internal/plugin"
)

// SPFPlugin is the main plugin struct
type SPFPlugin struct {
	plugin.SPFPluginBase
}

// NewSPFPlugin creates a new SPF plugin
func NewSPFPlugin() plugin.SPFPlugin {
	info := &plugin.PluginInfo{
		Name:        "spf",
		Description: "SPF (Sender Policy Framework) implementation",
		Version:     "1.0.0",
		Type:        plugin.PluginTypeSPF,
		Author:      "Elemta Team",
	}

	p := &SPFPlugin{
		SPFPluginBase: *plugin.NewSPFPluginBase(info),
	}

	return p
}

// Init initializes the plugin
func (p *SPFPlugin) Init(config map[string]interface{}) error {
	return p.SPFPluginBase.Init(config)
}

// Close cleans up resources
func (p *SPFPlugin) Close() error {
	return p.SPFPluginBase.Close()
}

// CheckSPF checks SPF for a domain and IP
func (p *SPFPlugin) CheckSPF(domain string, ip net.IP) (*plugin.SPFCheck, error) {
	// In a real implementation, this would check SPF records
	// For now, we'll return a neutral result
	return &plugin.SPFCheck{
		Result:      plugin.SPFNeutral,
		Domain:      domain,
		Explanation: "No SPF record found",
		Received:    "neutral",
	}, nil
}

// main is required for Go plugins
func main() {
	// This function is not used but is required for Go plugins
}
