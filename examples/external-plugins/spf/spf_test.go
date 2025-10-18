package main

import (
	"net"
	"testing"

	"github.com/busybox42/elemta/internal/plugin"
)

func TestSPFPlugin(t *testing.T) {
	// Create a new SPF plugin
	p := NewSPFPlugin()

	// Test initialization
	err := p.Init(map[string]interface{}{})
	if err != nil {
		t.Errorf("Init() error = %v, want nil", err)
	}

	// Test GetInfo
	info := p.GetInfo()
	if info.Name != "spf" {
		t.Errorf("GetInfo().Name = %v, want %v", info.Name, "spf")
	}
	if info.Type != plugin.PluginTypeSPF {
		t.Errorf("GetInfo().Type = %v, want %v", info.Type, plugin.PluginTypeSPF)
	}

	// Test CheckSPF with a domain and IP
	domain := "example.com"
	ip := net.ParseIP("192.168.1.1")
	result, err := p.CheckSPF(domain, ip)

	if err != nil {
		t.Errorf("CheckSPF() error = %v, want nil", err)
	}

	if result == nil {
		t.Errorf("CheckSPF() result = nil, want non-nil")
		return
	}

	if result.Result != plugin.SPFNeutral {
		t.Errorf("CheckSPF() result.Result = %v, want %v", result.Result, plugin.SPFNeutral)
	}

	if result.Domain != domain {
		t.Errorf("CheckSPF() result.Domain = %v, want %v", result.Domain, domain)
	}

	if result.Explanation == "" {
		t.Errorf("CheckSPF() result.Explanation is empty, want non-empty")
	}

	if result.Received == "" {
		t.Errorf("CheckSPF() result.Received is empty, want non-empty")
	}

	// Test Close
	err = p.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestSPFPlugin_ErrorHandling(t *testing.T) {
	// Create a new SPF plugin
	p := NewSPFPlugin()

	// Test with invalid IP
	domain := "example.com"
	var ip net.IP = nil
	result, err := p.CheckSPF(domain, ip)

	// In our simple implementation, this should still work
	if err != nil {
		t.Errorf("CheckSPF() with nil IP error = %v, want nil", err)
	}

	if result == nil {
		t.Errorf("CheckSPF() with nil IP result = nil, want non-nil")
	}
}
