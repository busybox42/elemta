package plugin

import (
	"net"
)

// SPFResult represents the result of an SPF check
type SPFResult string

const (
	SPFPass      SPFResult = "pass"      // The client is authorized to send mail
	SPFFail      SPFResult = "fail"      // The client is explicitly not authorized to send mail
	SPFSoftFail  SPFResult = "softfail"  // The client is probably not authorized to send mail
	SPFNeutral   SPFResult = "neutral"   // No policy statement was found
	SPFNone      SPFResult = "none"      // No SPF record was found
	SPFTempError SPFResult = "temperror" // Temporary error during processing
	SPFPermError SPFResult = "permerror" // Permanent error during processing
)

// SPFCheck represents the result of an SPF check with additional details
type SPFCheck struct {
	Result      SPFResult // The SPF result
	Domain      string    // The domain that was checked
	Explanation string    // Human-readable explanation of the result
	Received    string    // The Received-SPF header value
}

// SPFPlugin defines the interface for SPF validation plugins
type SPFPlugin interface {
	// Embed the Plugin interface
	Plugin

	// CheckSPF checks the SPF record for the given domain and IP
	// The domain is the domain from the MAIL FROM command
	// The ip is the IP address of the client
	CheckSPF(domain string, ip net.IP) (*SPFCheck, error)
}

// SPFPluginBase provides a base implementation of the SPFPlugin interface
type SPFPluginBase struct {
	info *PluginInfo
}

// NewSPFPluginBase creates a new SPFPluginBase
func NewSPFPluginBase(info *PluginInfo) *SPFPluginBase {
	return &SPFPluginBase{
		info: info,
	}
}

// GetInfo returns information about the plugin
func (p *SPFPluginBase) GetInfo() PluginInfo {
	return *p.info
}

// Init initializes the plugin with the given configuration
func (p *SPFPluginBase) Init(config map[string]interface{}) error {
	// Default implementation does nothing
	return nil
}

// Close closes the plugin and releases any resources
func (p *SPFPluginBase) Close() error {
	// Default implementation does nothing
	return nil
}

// Example of how to implement an SPF plugin:
/*
package main

import (
	"net"
	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo is exported and contains information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "my-spf",
	Description: "My custom SPF validator",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeSPF,
	Author:      "Your Name",
}

// Plugin is exported and provides the plugin instance
var Plugin = &MySPFPlugin{
	SPFPluginBase: plugin.NewSPFPluginBase(PluginInfo),
}

// MySPFPlugin implements the plugin.SPFPlugin interface
type MySPFPlugin struct {
	*plugin.SPFPluginBase
}

// CheckSPF checks the SPF record for the given domain and IP
func (p *MySPFPlugin) CheckSPF(domain string, ip net.IP) (*plugin.SPFCheck, error) {
	// Implement SPF validation logic here
	// You can use libraries like github.com/miekg/dns or github.com/blitiri/go-spf

	// Example implementation (not actually validating anything)
	return &plugin.SPFCheck{
		Result:      plugin.SPFPass,
		Domain:      domain,
		Explanation: "SPF validation passed",
		Received:    "pass (example.com: domain of " + domain + " designates " + ip.String() + " as permitted sender)",
	}, nil
}

// GetStages returns the processing stages this plugin should be executed at
func (p *MySPFPlugin) GetStages() []plugin.ProcessingStage {
	return []plugin.ProcessingStage{
		plugin.StageMailFrom,
	}
}

// GetPriority returns the execution priority of this plugin
func (p *MySPFPlugin) GetPriority() plugin.PluginPriority {
	return plugin.PriorityNormal
}
*/
