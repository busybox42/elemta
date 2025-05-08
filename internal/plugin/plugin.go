// Package plugin provides plugin functionality for Elemta
package plugin

import (
	"fmt"
	"log"
	"sync"

	"github.com/busybox42/elemta/internal/antispam"
	"github.com/busybox42/elemta/internal/antivirus"
	"github.com/busybox42/elemta/internal/message"
)

// ResultType is an alias for PluginAction to maintain compatibility
type ResultType = PluginAction

// Define constants compatible with the existing types
const (
	ResultPass   = ActionContinue
	ResultReject = ActionReject
	ResultHold   = ActionQuarantine
	ResultDrop   = ActionDiscard
)

// StageType is a string representation of the ProcessingStage
type StageType string

// Define string constants for stages
const (
	StagePreQueue  StageType = "pre_queue"  // Before message is queued
	StagePostQueue StageType = "post_queue" // After message is queued
	StageDelivery  StageType = "delivery"   // During message delivery
)

// Result represents the result of a plugin operation
// This version is expanded from PluginResult to maintain backward compatibility
type Result struct {
	Type    ResultType             // Result type (pass, reject, etc)
	Message string                 // Optional message or reason
	Error   error                  // Optional error
	Data    interface{}            // Optional additional data
	Headers map[string]string      // Headers to add to the message
	Tags    []string               // Tags to add to the message
	Scores  map[string]float64     // Scores to add to the message
	Actions map[string]interface{} // Actions to take
}

// NewResult creates a new plugin result
func NewResult(resultType ResultType, message string, err error) *Result {
	return &Result{
		Type:    resultType,
		Message: message,
		Error:   err,
		Headers: make(map[string]string),
		Tags:    make([]string, 0),
		Scores:  make(map[string]float64),
		Actions: make(map[string]interface{}),
	}
}

// HookRegistration represents a plugin hook registration
type HookRegistration struct {
	Name     string                                  // Name of the hook
	Stage    StageType                               // Stage at which the hook is executed
	Priority int                                     // Priority of the hook (lower values run first)
	Func     func(*message.Message) (*Result, error) // Hook function
}

// BuiltinPlugins represents the built-in plugins for various functionalities
type BuiltinPlugins struct {
	mutex            sync.RWMutex
	AntivirusOpts    map[string]interface{}
	AntispamOpts     map[string]interface{}
	AntivirusEnabled bool
	AntispamEnabled  bool
}

// NewBuiltinPlugins creates a new plugin registry
func NewBuiltinPlugins() *BuiltinPlugins {
	return &BuiltinPlugins{
		AntivirusOpts:    make(map[string]interface{}),
		AntispamOpts:     make(map[string]interface{}),
		AntivirusEnabled: false,
		AntispamEnabled:  false,
	}
}

// InitBuiltinPlugins initializes the built-in plugins
func (p *BuiltinPlugins) InitBuiltinPlugins(enabledPlugins []string, pluginConfig map[string]map[string]interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Debug output
	log.Printf("InitBuiltinPlugins called with: enabledPlugins=%v, pluginConfig=%v", enabledPlugins, pluginConfig)

	// Check if plugins are enabled
	for _, name := range enabledPlugins {
		if name == "clamav" {
			p.AntivirusEnabled = true
			if cfg, ok := pluginConfig["clamav"]; ok {
				for k, v := range cfg {
					p.AntivirusOpts[k] = v
				}
			}
			log.Printf("Enabled built-in ClamAV plugin with options: %v", p.AntivirusOpts)
		}

		if name == "rspamd" {
			p.AntispamEnabled = true
			if cfg, ok := pluginConfig["rspamd"]; ok {
				for k, v := range cfg {
					p.AntispamOpts[k] = v
				}
			}
			log.Printf("Enabled built-in Rspamd plugin with options: %v", p.AntispamOpts)
		}
	}

	return nil
}

// ScanForVirus scans a message for viruses
func (p *BuiltinPlugins) ScanForVirus(data []byte, messageID string) (bool, string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if !p.AntivirusEnabled {
		return true, "", nil
	}

	// Get default values or from config
	host := "elemta-clamav"
	if h, ok := p.AntivirusOpts["host"].(string); ok && h != "" {
		host = h
	}

	port := 3310
	if p, ok := p.AntivirusOpts["port"].(int); ok && p > 0 {
		port = p
	}

	// Create scanner with our configuration
	scannerConfig := antivirus.Config{
		Type:    "clamav",
		Address: fmt.Sprintf("%s:%d", host, port),
		Options: p.AntivirusOpts,
	}

	scanner := antivirus.NewClamAV(scannerConfig)
	if err := scanner.Connect(); err != nil {
		log.Printf("Warning: Failed to connect to AV scanner: %v", err)
		return true, "", fmt.Errorf("failed to connect to virus scanner: %w", err)
	}

	// Scan data
	result, err := scanner.ScanBytes(nil, data)
	if err != nil {
		return true, "", fmt.Errorf("failed to scan message: %w", err)
	}

	// Check if the message is clean
	if !result.Clean {
		infections := ""
		if len(result.Infections) > 0 {
			infections = result.Infections[0]
		}
		return false, infections, nil
	}

	return true, "", nil
}

// ScanForSpam scans a message for spam
func (p *BuiltinPlugins) ScanForSpam(data []byte, messageID string) (bool, float64, []string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if !p.AntispamEnabled {
		return true, 0, nil, nil
	}

	// Get default values or from config
	host := "elemta-rspamd"
	if h, ok := p.AntispamOpts["host"].(string); ok && h != "" {
		host = h
	}

	port := 11334
	if p, ok := p.AntispamOpts["port"].(int); ok && p > 0 {
		port = p
	}

	threshold := 7.0
	if t, ok := p.AntispamOpts["threshold"].(float64); ok && t > 0 {
		threshold = t
	}

	// Create scanner with our configuration
	scannerConfig := antispam.Config{
		Type:      "rspamd",
		Address:   fmt.Sprintf("http://%s:%d", host, port),
		Threshold: threshold,
		Options:   p.AntispamOpts,
	}

	scanner := antispam.NewRspamd(scannerConfig)
	if err := scanner.Connect(); err != nil {
		log.Printf("Warning: Failed to connect to spam scanner: %v", err)
		return true, 0, nil, fmt.Errorf("failed to connect to spam scanner: %w", err)
	}

	// Scan data
	result, err := scanner.ScanBytes(nil, data)
	if err != nil {
		return true, 0, nil, fmt.Errorf("failed to scan message: %w", err)
	}

	// Check if the message is clean
	if !result.Clean {
		return false, result.Score, result.Rules, nil
	}

	return true, result.Score, result.Rules, nil
}
