package plugin

import (
	"github.com/busybox42/elemta/internal/antispam"
)

// AntispamPlugin defines the interface for antispam plugins
type AntispamPlugin interface {
	// Embed the Plugin interface
	Plugin

	// GetScanner returns the antispam scanner
	GetScanner() antispam.Scanner
}

// AntispamPluginBase provides a base implementation of the AntispamPlugin interface
type AntispamPluginBase struct {
	info    *PluginInfo
	scanner antispam.Scanner
}

// NewAntispamPluginBase creates a new AntispamPluginBase
func NewAntispamPluginBase(info *PluginInfo, scanner antispam.Scanner) *AntispamPluginBase {
	return &AntispamPluginBase{
		info:    info,
		scanner: scanner,
	}
}

// GetScanner returns the antispam scanner
func (p *AntispamPluginBase) GetScanner() antispam.Scanner {
	return p.scanner
}

// GetInfo returns information about the plugin
func (p *AntispamPluginBase) GetInfo() PluginInfo {
	return *p.info
}

// Init initializes the plugin with the given configuration
func (p *AntispamPluginBase) Init(config map[string]interface{}) error {
	// Default implementation does nothing
	return nil
}

// Close closes the plugin and releases any resources
func (p *AntispamPluginBase) Close() error {
	// Default implementation does nothing
	return nil
}

// Example of how to implement a plugin:
/*
package main

import (
	"github.com/busybox42/elemta/internal/antispam"
	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo is exported and contains information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "my-antispam",
	Description: "My custom antispam scanner",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeAntispam,
	Author:      "Your Name",
}

// MyScanner implements the antispam.Scanner interface
type MyScanner struct {
	// Your scanner implementation
}

// Implement all methods required by the antispam.Scanner interface

// Plugin is exported and provides the plugin instance
var Plugin = &MyPlugin{
	AntispamPluginBase: plugin.NewAntispamPluginBase(
		PluginInfo,
		&MyScanner{},
	),
}

// MyPlugin implements the plugin.AntispamPlugin interface
type MyPlugin struct {
	*plugin.AntispamPluginBase
}

// You can override any methods from AntispamPluginBase if needed
*/
