package plugin

// DMARCResult represents the result of a DMARC policy evaluation
type DMARCResult string

const (
	DMARCPass      DMARCResult = "pass"      // The message passed DMARC evaluation
	DMARCFail      DMARCResult = "fail"      // The message failed DMARC evaluation
	DMARCNone      DMARCResult = "none"      // No DMARC policy was found
	DMARCTempError DMARCResult = "temperror" // Temporary error during evaluation
	DMARCPermError DMARCResult = "permerror" // Permanent error during evaluation
)

// DMARCPolicy represents the policy specified in a DMARC record
type DMARCPolicy string

const (
	DMARCPolicyNone       DMARCPolicy = "none"       // Take no action
	DMARCPolicyQuarantine DMARCPolicy = "quarantine" // Treat the message as suspicious
	DMARCPolicyReject     DMARCPolicy = "reject"     // Reject the message
)

// DMARCAlignment represents the alignment mode for SPF and DKIM
type DMARCAlignment string

const (
	DMARCAlignmentStrict  DMARCAlignment = "strict"  // Exact domain match required
	DMARCAlignmentRelaxed DMARCAlignment = "relaxed" // Organizational domain match allowed
)

// DMARCRecord represents a parsed DMARC record
type DMARCRecord struct {
	Version              string         // DMARC version (v=)
	Policy               DMARCPolicy    // Policy to apply (p=)
	SubdomainPolicy      DMARCPolicy    // Policy for subdomains (sp=)
	Percentage           int            // Percentage of messages to filter (pct=)
	ReportingFormat      string         // Format for reports (rf=)
	ReportingInterval    int            // Interval between reports in seconds (ri=)
	FailureReportOptions string         // Failure reporting options (fo=)
	AggregateReportURIs  []string       // URIs for aggregate reports (rua=)
	FailureReportURIs    []string       // URIs for failure reports (ruf=)
	SPFAlignment         DMARCAlignment // SPF alignment mode (aspf=)
	DKIMAlignment        DMARCAlignment // DKIM alignment mode (adkim=)
}

// DMARCEvaluation represents the result of a DMARC evaluation
type DMARCEvaluation struct {
	Result           DMARCResult  // The overall DMARC result
	Domain           string       // The domain that was evaluated
	Record           *DMARCRecord // The DMARC record that was used
	SPFResult        SPFResult    // The SPF result
	SPFDomain        string       // The domain used for SPF
	SPFAlignment     bool         // Whether SPF alignment passed
	DKIMResults      []DKIMResult // The DKIM results
	DKIMDomains      []string     // The domains used for DKIM
	DKIMAlignment    bool         // Whether DKIM alignment passed
	AppliedPolicy    DMARCPolicy  // The policy that was applied
	FailureReason    string       // Reason for failure, if any
	ReportingEnabled bool         // Whether reporting is enabled
}

// DMARCPlugin defines the interface for DMARC validation plugins
type DMARCPlugin interface {
	// Embed the Plugin interface
	Plugin

	// GetDMARCRecord retrieves and parses the DMARC record for a domain
	GetDMARCRecord(domain string) (*DMARCRecord, error)

	// EvaluateDMARC evaluates a message against DMARC policy
	// The fromDomain is the domain from the From header
	// The spfResult is the result of SPF validation
	// The spfDomain is the domain used for SPF validation (MAIL FROM)
	// The dkimResults is a slice of DKIM validation results
	EvaluateDMARC(fromDomain string, spfResult SPFResult, spfDomain string, dkimResults []*DKIMVerifyResult) (*DMARCEvaluation, error)

	// GenerateReport generates a DMARC aggregate report
	// This is typically called periodically to send reports to domains
	GenerateReport(domain string, startTime, endTime int64) ([]byte, error)
}

// DMARCPluginBase provides a base implementation of the DMARCPlugin interface
type DMARCPluginBase struct {
	info *PluginInfo
}

// NewDMARCPluginBase creates a new DMARCPluginBase
func NewDMARCPluginBase(info *PluginInfo) *DMARCPluginBase {
	return &DMARCPluginBase{
		info: info,
	}
}

// GetInfo returns information about the plugin
func (p *DMARCPluginBase) GetInfo() PluginInfo {
	return *p.info
}

// Init initializes the plugin with the given configuration
func (p *DMARCPluginBase) Init(config map[string]interface{}) error {
	// Default implementation does nothing
	return nil
}

// Close closes the plugin and releases any resources
func (p *DMARCPluginBase) Close() error {
	// Default implementation does nothing
	return nil
}

// Example of how to implement a DMARC plugin:
/*
package main

import (
	"github.com/busybox42/elemta/internal/plugin"
)

// PluginInfo is exported and contains information about the plugin
var PluginInfo = &plugin.PluginInfo{
	Name:        "my-dmarc",
	Description: "My custom DMARC validator",
	Version:     "1.0.0",
	Type:        plugin.PluginTypeDMARC,
	Author:      "Your Name",
}

// Plugin is exported and provides the plugin instance
var Plugin = &MyDMARCPlugin{
	DMARCPluginBase: plugin.NewDMARCPluginBase(PluginInfo),
}

// MyDMARCPlugin implements the plugin.DMARCPlugin interface
type MyDMARCPlugin struct {
	*plugin.DMARCPluginBase
}

// GetDMARCRecord retrieves and parses the DMARC record for a domain
func (p *MyDMARCPlugin) GetDMARCRecord(domain string) (*plugin.DMARCRecord, error) {
	// Implement DMARC record lookup and parsing
	// You can use libraries like github.com/miekg/dns

	// Example implementation (not actually looking up anything)
	return &plugin.DMARCRecord{
		Version:           "DMARC1",
		Policy:            plugin.DMARCPolicyNone,
		SubdomainPolicy:   plugin.DMARCPolicyNone,
		Percentage:        100,
		SPFAlignment:      plugin.DMARCAlignmentRelaxed,
		DKIMAlignment:     plugin.DMARCAlignmentRelaxed,
		ReportingInterval: 86400,
	}, nil
}

// EvaluateDMARC evaluates a message against DMARC policy
func (p *MyDMARCPlugin) EvaluateDMARC(fromDomain string, spfResult plugin.SPFResult, spfDomain string, dkimResults []*plugin.DKIMVerifyResult) (*plugin.DMARCEvaluation, error) {
	// Implement DMARC evaluation logic

	// Example implementation (not actually evaluating anything)
	record, _ := p.GetDMARCRecord(fromDomain)

	// Convert DKIM results to simple results
	dkimSimpleResults := make([]plugin.DKIMResult, len(dkimResults))
	dkimDomains := make([]string, len(dkimResults))
	for i, result := range dkimResults {
		dkimSimpleResults[i] = result.Result
		dkimDomains[i] = result.Domain
	}

	return &plugin.DMARCEvaluation{
		Result:           plugin.DMARCPass,
		Domain:           fromDomain,
		Record:           record,
		SPFResult:        spfResult,
		SPFDomain:        spfDomain,
		SPFAlignment:     true,
		DKIMResults:      dkimSimpleResults,
		DKIMDomains:      dkimDomains,
		DKIMAlignment:    true,
		AppliedPolicy:    record.Policy,
		ReportingEnabled: true,
	}, nil
}

// GenerateReport generates a DMARC aggregate report
func (p *MyDMARCPlugin) GenerateReport(domain string, startTime, endTime int64) ([]byte, error) {
	// Implement DMARC report generation
	// This would typically query a database of DMARC results and generate an XML report

	// Example implementation (not actually generating anything)
	return []byte("<xml>Example DMARC Report</xml>"), nil
}

// GetStages returns the processing stages this plugin should be executed at
func (p *MyDMARCPlugin) GetStages() []plugin.ProcessingStage {
	return []plugin.ProcessingStage{
		plugin.StageDataComplete,
	}
}

// GetPriority returns the execution priority of this plugin
func (p *MyDMARCPlugin) GetPriority() plugin.PluginPriority {
	return plugin.PriorityNormal
}
*/
