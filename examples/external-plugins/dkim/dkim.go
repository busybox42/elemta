package main

import (
	"io"

	"github.com/busybox42/elemta/internal/plugin"
)

// DKIMPlugin is the main plugin struct
type DKIMPlugin struct {
	plugin.DKIMPluginBase
}

// NewDKIMPlugin creates a new DKIM plugin
func NewDKIMPlugin() plugin.DKIMPlugin {
	info := &plugin.PluginInfo{
		Name:        "dkim",
		Description: "DKIM (DomainKeys Identified Mail) implementation",
		Version:     "1.0.0",
		Type:        plugin.PluginTypeDKIM,
		Author:      "Elemta Team",
	}

	p := &DKIMPlugin{
		DKIMPluginBase: *plugin.NewDKIMPluginBase(info),
	}

	return p
}

// Init initializes the plugin
func (p *DKIMPlugin) Init(config map[string]interface{}) error {
	return p.DKIMPluginBase.Init(config)
}

// Close cleans up resources
func (p *DKIMPlugin) Close() error {
	return p.DKIMPluginBase.Close()
}

// VerifyDKIM verifies DKIM signatures in a message
func (p *DKIMPlugin) VerifyDKIM(reader io.Reader) ([]*plugin.DKIMVerifyResult, error) {
	// In a real implementation, this would verify DKIM signatures
	// For now, we'll return an empty result
	return []*plugin.DKIMVerifyResult{}, nil
}

// SignDKIM adds a DKIM signature to a message
func (p *DKIMPlugin) SignDKIM(reader io.Reader, writer io.Writer, options *plugin.DKIMSignOptions) error {
	// In a real implementation, this would sign the message with DKIM
	// For now, we'll just copy the input to output
	_, err := io.Copy(writer, reader)
	return err
}

// main is required for Go plugins
func main() {
	// This function is not used but is required for Go plugins
}
