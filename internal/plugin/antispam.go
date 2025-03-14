package plugin

import (
	"github.com/busybox42/elemta/internal/antispam"
)

// AntispamPlugin defines the interface for antispam plugins
type AntispamPlugin interface {
	// GetScanner returns the antispam scanner
	GetScanner() antispam.Scanner

	// GetInfo returns information about the plugin
	GetInfo() *PluginInfo
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
func (p *AntispamPluginBase) GetInfo() *PluginInfo {
	return p.info
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
}

// MyScanner implements the antispam.Scanner interface
type MyScanner struct {
	// Your scanner implementation
}

// Implement all methods required by the antispam.Scanner interface

// MyPlugin implements the plugin.AntispamPlugin interface
type MyPlugin struct {
	*plugin.AntispamPluginBase
}

// Instance is exported and provides the plugin instance
var Instance = &MyPlugin{
	AntispamPluginBase: plugin.NewAntispamPluginBase(
		PluginInfo,
		&MyScanner{},
	),
}
*/
