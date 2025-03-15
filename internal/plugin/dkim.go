package plugin

import (
	"io"
)

// DKIMResult represents the result of a DKIM signature verification
type DKIMResult string

const (
	DKIMPass      DKIMResult = "pass"      // The DKIM signature is valid
	DKIMFail      DKIMResult = "fail"      // The DKIM signature is invalid
	DKIMNeutral   DKIMResult = "neutral"   // No signature was found or verification was skipped
	DKIMTempError DKIMResult = "temperror" // Temporary error during verification
	DKIMPermError DKIMResult = "permerror" // Permanent error during verification
)

// DKIMVerifyResult represents the result of a DKIM signature verification with additional details
type DKIMVerifyResult struct {
	Result           DKIMResult // The DKIM verification result
	Domain           string     // The domain that signed the message
	Selector         string     // The selector used for the signature
	Identity         string     // The identity claimed in the signature (i=)
	HeaderHash       string     // The hash algorithm used for the header
	BodyHash         string     // The hash algorithm used for the body
	Canonicalization string     // The canonicalization algorithm used
	Reason           string     // Human-readable explanation of the result
	Timestamp        int64      // The timestamp of the signature (t=)
	Expiration       int64      // The expiration time of the signature (x=)
}

// DKIMSignOptions represents options for DKIM signing
type DKIMSignOptions struct {
	Domain           string            // The domain to sign as
	Selector         string            // The selector to use
	PrivateKey       []byte            // The private key to sign with
	Headers          []string          // Headers to include in the signature
	Canonicalization string            // Canonicalization algorithm (relaxed/simple)
	HeaderHash       string            // Hash algorithm for headers (sha1/sha256)
	BodyHash         string            // Hash algorithm for body (sha1/sha256)
	Identity         string            // Identity to claim in the signature (i=)
	Expiration       int64             // Expiration time in seconds since epoch (x=)
	BodyLength       int               // Length of the body to sign (l=)
	QueryMethod      string            // Query method (dns/txt)
	ExtraHeaders     map[string]string // Extra headers to add to the signature
}

// DKIMPlugin defines the interface for DKIM validation and signing plugins
type DKIMPlugin interface {
	// Embed the Plugin interface
	Plugin

	// VerifyDKIM verifies DKIM signatures in a message
	// The reader provides the full message (headers and body)
	// Returns a slice of verification results, one for each signature found
	VerifyDKIM(reader io.Reader) ([]*DKIMVerifyResult, error)

	// SignDKIM signs a message with DKIM
	// The reader provides the original message (headers and body)
	// The writer receives the signed message
	// The options specify how to sign the message
	SignDKIM(reader io.Reader, writer io.Writer, options *DKIMSignOptions) error
}

// DKIMPluginBase provides a base implementation of the DKIMPlugin interface
type DKIMPluginBase struct {
	info *PluginInfo
}

// NewDKIMPluginBase creates a new DKIMPluginBase
func NewDKIMPluginBase(info *PluginInfo) *DKIMPluginBase {
	return &DKIMPluginBase{
		info: info,
	}
}

// GetInfo returns information about the plugin
func (p *DKIMPluginBase) GetInfo() PluginInfo {
	return *p.info
}

// Init initializes the plugin with the given configuration
func (p *DKIMPluginBase) Init(config map[string]interface{}) error {
	// Default implementation does nothing
	return nil
}

// Close closes the plugin and releases any resources
func (p *DKIMPluginBase) Close() error {
	// Default implementation does nothing
	return nil
}

// Example of how to implement a DKIM plugin:
/*
package main

import (
	"io"
	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo is exported and contains information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "my-dkim",
	Description: "My custom DKIM validator and signer",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeDKIM,
	Author:      "Your Name",
}

// Plugin is exported and provides the plugin instance
var Plugin = &MyDKIMPlugin{
	DKIMPluginBase: plugin.NewDKIMPluginBase(PluginInfo),
}

// MyDKIMPlugin implements the plugin.DKIMPlugin interface
type MyDKIMPlugin struct {
	*plugin.DKIMPluginBase
}

// VerifyDKIM verifies DKIM signatures in a message
func (p *MyDKIMPlugin) VerifyDKIM(reader io.Reader) ([]*plugin.DKIMVerifyResult, error) {
	// Implement DKIM verification logic here
	// You can use libraries like github.com/emersion/go-msgauth/dkim

	// Example implementation (not actually verifying anything)
	return []*plugin.DKIMVerifyResult{
		{
			Result:      plugin.DKIMPass,
			Domain:      "example.com",
			Selector:    "selector1",
			Identity:    "@example.com",
			HeaderHash:  "sha256",
			BodyHash:    "sha256",
			Canonicalization: "relaxed/relaxed",
			Reason:      "DKIM signature verified successfully",
			Timestamp:   0,
			Expiration:  0,
		},
	}, nil
}

// SignDKIM signs a message with DKIM
func (p *MyDKIMPlugin) SignDKIM(reader io.Reader, writer io.Writer, options *plugin.DKIMSignOptions) error {
	// Implement DKIM signing logic here
	// You can use libraries like github.com/emersion/go-msgauth/dkim

	// Example implementation (not actually signing anything)
	// Just copy the message from reader to writer
	_, err := io.Copy(writer, reader)
	return err
}

// GetStages returns the processing stages this plugin should be executed at
func (p *MyDKIMPlugin) GetStages() []plugin.ProcessingStage {
	return []plugin.ProcessingStage{
		plugin.StageDataComplete,
		plugin.StagePreDelivery,
	}
}

// GetPriority returns the execution priority of this plugin
func (p *MyDKIMPlugin) GetPriority() plugin.PluginPriority {
	return plugin.PriorityNormal
}
*/
