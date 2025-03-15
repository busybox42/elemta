package plugin

import (
	"github.com/busybox42/elemta/internal/antivirus"
)

// AntivirusPlugin defines the interface for antivirus plugins
type AntivirusPlugin interface {
	// Embed the Plugin interface
	Plugin

	// GetScanner returns the antivirus scanner
	GetScanner() antivirus.Scanner

	// GetInfo returns information about the plugin
	GetInfo() PluginInfo
}

// AntivirusPluginBase provides a base implementation of the AntivirusPlugin interface
type AntivirusPluginBase struct {
	info    *PluginInfo
	scanner antivirus.Scanner
}

// NewAntivirusPluginBase creates a new AntivirusPluginBase
func NewAntivirusPluginBase(info *PluginInfo, scanner antivirus.Scanner) *AntivirusPluginBase {
	return &AntivirusPluginBase{
		info:    info,
		scanner: scanner,
	}
}

// GetScanner returns the antivirus scanner
func (p *AntivirusPluginBase) GetScanner() antivirus.Scanner {
	return p.scanner
}

// GetInfo returns information about the plugin
func (p *AntivirusPluginBase) GetInfo() PluginInfo {
	return *p.info
}

// Init initializes the plugin with the given configuration
func (p *AntivirusPluginBase) Init(config map[string]interface{}) error {
	// Default implementation does nothing
	return nil
}

// Close closes the plugin and releases any resources
func (p *AntivirusPluginBase) Close() error {
	// Default implementation does nothing
	return nil
}

// Example of how to implement a plugin:
/*
package main

import (
	"github.com/busybox42/elemta/internal/antivirus"
	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo is exported and contains information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "my-antivirus",
	Description: "My custom antivirus scanner",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeAntivirus,
	Author:      "Your Name",
}

// MyScanner implements the antivirus.Scanner interface
type MyScanner struct {
	// Your scanner implementation
}

// Implement all methods required by the antivirus.Scanner interface

// Plugin is exported and provides the plugin instance
var Plugin = &MyPlugin{
	AntivirusPluginBase: plugin.NewAntivirusPluginBase(
		PluginInfo,
		&MyScanner{},
	),
}

// MyPlugin implements the plugin.AntivirusPlugin interface
type MyPlugin struct {
	*plugin.AntivirusPluginBase
}

// You can override any methods from AntivirusPluginBase if needed
*/
