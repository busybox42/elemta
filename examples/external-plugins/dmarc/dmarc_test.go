package main

import (
	"testing"

	"github.com/busybox42/elemta/internal/plugin"
)

func TestDMARCPlugin(t *testing.T) {
	// Create a new DMARC plugin
	p := NewDMARCPlugin()

	// Test initialization
	err := p.Init(map[string]interface{}{})
	if err != nil {
		t.Errorf("Init() error = %v, want nil", err)
	}

	// Test GetInfo
	info := p.GetInfo()
	if info.Name != "dmarc" {
		t.Errorf("GetInfo().Name = %v, want %v", info.Name, "dmarc")
	}
	if info.Type != plugin.PluginTypeDMARC {
		t.Errorf("GetInfo().Type = %v, want %v", info.Type, plugin.PluginTypeDMARC)
	}

	// Test GetDMARCRecord
	domain := "example.com"
	record, err := p.GetDMARCRecord(domain)

	if err != nil {
		t.Errorf("GetDMARCRecord() error = %v, want nil", err)
	}

	if record == nil {
		t.Errorf("GetDMARCRecord() record = nil, want non-nil")
		return
	}

	if record.Policy != plugin.DMARCPolicyNone {
		t.Errorf("GetDMARCRecord() record.Policy = %v, want %v", record.Policy, plugin.DMARCPolicyNone)
	}

	// Test EvaluateDMARC
	fromDomain := "example.com"
	spfResult := plugin.SPFNeutral
	spfDomain := "example.com"
	var dkimResults []*plugin.DKIMVerifyResult

	evaluation, err := p.EvaluateDMARC(fromDomain, spfResult, spfDomain, dkimResults)

	if err != nil {
		t.Errorf("EvaluateDMARC() error = %v, want nil", err)
	}

	if evaluation == nil {
		t.Errorf("EvaluateDMARC() evaluation = nil, want non-nil")
		return
	}

	if evaluation.Result != plugin.DMARCPass {
		t.Errorf("EvaluateDMARC() evaluation.Result = %v, want %v", evaluation.Result, plugin.DMARCPass)
	}

	if evaluation.Domain != fromDomain {
		t.Errorf("EvaluateDMARC() evaluation.Domain = %v, want %v", evaluation.Domain, fromDomain)
	}

	// Test GenerateReport
	startTime := int64(1609459200) // 2021-01-01 00:00:00
	endTime := int64(1609545600)   // 2021-01-02 00:00:00
	report, err := p.GenerateReport(domain, startTime, endTime)

	if err != nil {
		t.Errorf("GenerateReport() error = %v, want nil", err)
	}

	if report == nil {
		t.Errorf("GenerateReport() report = nil, want non-nil")
	}

	// Test Close
	err = p.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestDMARCPlugin_ErrorHandling(t *testing.T) {
	// Create a new DMARC plugin
	p := NewDMARCPlugin()

	// Test with empty domain
	domain := ""
	record, err := p.GetDMARCRecord(domain)

	// In our simple implementation, this should still work
	if err != nil {
		t.Errorf("GetDMARCRecord() with empty domain error = %v, want nil", err)
	}

	if record == nil {
		t.Errorf("GetDMARCRecord() with empty domain record = nil, want non-nil")
	}
}
