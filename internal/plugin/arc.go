package plugin

import (
	"io"
	"time"
)

// ARCResult represents the result of an ARC chain validation
type ARCResult string

const (
	ARCPass      ARCResult = "pass"      // The ARC chain is valid
	ARCFail      ARCResult = "fail"      // The ARC chain is invalid
	ARCNone      ARCResult = "none"      // No ARC chain was found
	ARCTempError ARCResult = "temperror" // Temporary error during validation
	ARCPermError ARCResult = "permerror" // Permanent error during validation
)

// ARCInstance represents a single instance in an ARC chain
type ARCInstance struct {
	InstanceNum      int       // The instance number (i=)
	AuthResults      string    // Authentication-Results header (ar=)
	MessageSignature string    // ARC-Message-Signature header (ams=)
	SealSignature    string    // ARC-Seal header (as=)
	Timestamp        time.Time // When this instance was created
}

// ARCVerifyResult represents the result of an ARC chain verification
type ARCVerifyResult struct {
	Result        ARCResult     // The overall ARC result
	Instances     []ARCInstance // The instances in the chain
	InstanceCount int           // Number of instances in the chain
	OldestDomain  string        // Domain of the oldest (first) instance
	LatestDomain  string        // Domain of the latest (last) instance
	Reason        string        // Human-readable explanation of the result
}

// ARCSignOptions represents options for ARC signing
type ARCSignOptions struct {
	Domain           string            // The domain to sign as
	Selector         string            // The selector to use
	PrivateKey       []byte            // The private key to sign with
	Headers          []string          // Headers to include in the signature
	Canonicalization string            // Canonicalization algorithm (relaxed/simple)
	HeaderHash       string            // Hash algorithm for headers (sha1/sha256)
	BodyHash         string            // Hash algorithm for body (sha1/sha256)
	AuthResults      string            // Authentication-Results header to include
	ChainValidation  ARCResult         // Result of validating the existing chain
	ExtraHeaders     map[string]string // Extra headers to add to the signature
}

// ARCPlugin defines the interface for ARC validation and signing plugins
type ARCPlugin interface {
	// Embed the Plugin interface
	Plugin

	// VerifyARC verifies an ARC chain in a message
	// The reader provides the full message (headers and body)
	// Returns the verification result
	VerifyARC(reader io.Reader) (*ARCVerifyResult, error)

	// SignARC adds an ARC instance to a message
	// The reader provides the original message (headers and body)
	// The writer receives the signed message
	// The options specify how to sign the message
	SignARC(reader io.Reader, writer io.Writer, options *ARCSignOptions) error
}

// ARCPluginBase provides a base implementation of the ARCPlugin interface
type ARCPluginBase struct {
	info *PluginInfo
}

// NewARCPluginBase creates a new ARCPluginBase
func NewARCPluginBase(info *PluginInfo) *ARCPluginBase {
	return &ARCPluginBase{
		info: info,
	}
}

// GetInfo returns information about the plugin
func (p *ARCPluginBase) GetInfo() PluginInfo {
	return *p.info
}

// Init initializes the plugin
func (p *ARCPluginBase) Init(config map[string]interface{}) error {
	// Base implementation does nothing
	return nil
}

// Close cleans up resources used by the plugin
func (p *ARCPluginBase) Close() error {
	// Base implementation does nothing
	return nil
}
