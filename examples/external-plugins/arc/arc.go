package main

import (
	"io"

	"github.com/busybox42/elemta/internal/plugin"
)

// ARCPlugin is the main plugin struct
type ARCPlugin struct {
	plugin.ARCPluginBase
	impl *plugin.ARCImpl
}

// NewARCPlugin creates a new ARC plugin
func NewARCPlugin() plugin.ARCPlugin {
	info := &plugin.PluginInfo{
		Name:        "arc",
		Description: "ARC (Authenticated Received Chain) implementation",
		Version:     "1.0.0",
		Type:        plugin.PluginTypeARC,
		Author:      "Elemta Team",
	}

	p := &ARCPlugin{
		ARCPluginBase: *plugin.NewARCPluginBase(info),
		impl:          plugin.NewARCImpl(),
	}

	return p
}

// Init initializes the plugin
func (p *ARCPlugin) Init(config map[string]interface{}) error {
	if err := p.ARCPluginBase.Init(config); err != nil {
		return err
	}

	return p.impl.Init(config)
}

// Close cleans up resources
func (p *ARCPlugin) Close() error {
	if err := p.ARCPluginBase.Close(); err != nil {
		return err
	}

	return p.impl.Close()
}

// VerifyARC verifies an ARC chain in a message
func (p *ARCPlugin) VerifyARC(reader io.Reader) (*plugin.ARCVerifyResult, error) {
	return p.impl.VerifyARC(reader)
}

// SignARC adds an ARC instance to a message
func (p *ARCPlugin) SignARC(reader io.Reader, writer io.Writer, options *plugin.ARCSignOptions) error {
	return p.impl.SignARC(reader, writer, options)
}

// main is required for Go plugins
func main() {
	// This function is not used but is required for Go plugins
}
