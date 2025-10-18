package main

import (
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/plugin"
)

func TestGreylistPlugin(t *testing.T) {
	// Create a new instance of the plugin
	p := &GreylistPlugin{
		info:      *PluginInfo,
		firstSeen: make(map[string]time.Time),
		delay:     1 * time.Second, // Short delay for testing
	}

	// Test initialization
	err := p.Init(map[string]interface{}{})
	if err != nil {
		t.Errorf("Init() error = %v, want nil", err)
	}

	// Test with custom delay
	err = p.Init(map[string]interface{}{
		"delay": "2s",
	})
	if err != nil {
		t.Errorf("Init() with custom delay error = %v, want nil", err)
	}
	if p.delay != 2*time.Second {
		t.Errorf("Init() with custom delay, got delay = %v, want %v", p.delay, 2*time.Second)
	}

	// Reset delay for testing
	p.delay = 1 * time.Second

	// Test GetInfo
	info := p.GetInfo()
	if info.Name != "greylisting" {
		t.Errorf("GetInfo().Name = %v, want %v", info.Name, "greylisting")
	}
	if info.Type != plugin.PluginTypeGreylist {
		t.Errorf("GetInfo().Type = %v, want %v", info.Type, plugin.PluginTypeGreylist)
	}

	// Test GetStages
	stages := p.GetStages()
	if len(stages) != 1 || stages[0] != plugin.StageRcptTo {
		t.Errorf("GetStages() = %v, want [%v]", stages, plugin.StageRcptTo)
	}

	// Test GetPriority
	priority := p.GetPriority()
	if priority != plugin.PriorityNormal {
		t.Errorf("GetPriority() = %v, want %v", priority, plugin.PriorityNormal)
	}

	// Test Execute - first attempt should be rejected
	ctx := map[string]interface{}{
		"mail_from": "sender@example.com",
		"rcpt_to":   "recipient@example.org",
		"remote_ip": "192.168.1.1",
	}

	result, err := p.Execute(ctx)
	if err != nil {
		t.Errorf("Execute() error = %v, want nil", err)
	}
	if result.Action != plugin.ActionReject {
		t.Errorf("Execute() first attempt, got action = %v, want %v", result.Action, plugin.ActionReject)
	}

	// Wait for the delay to pass
	time.Sleep(1100 * time.Millisecond)

	// Test Execute - second attempt after delay should pass
	result, err = p.Execute(ctx)
	if err != nil {
		t.Errorf("Execute() error = %v, want nil", err)
	}
	if result.Action != plugin.ActionContinue {
		t.Errorf("Execute() second attempt, got action = %v, want %v", result.Action, plugin.ActionContinue)
	}

	// Test Cleanup
	// Add an old entry
	oldKey := "old|entry|test"
	p.mu.Lock()
	p.firstSeen[oldKey] = time.Now().Add(-37 * time.Hour)
	p.mu.Unlock()

	// Run cleanup
	p.Cleanup()

	// Check that old entry was removed
	p.mu.RLock()
	_, exists := p.firstSeen[oldKey]
	p.mu.RUnlock()
	if exists {
		t.Errorf("Cleanup() failed to remove old entry")
	}

	// Test Close
	err = p.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestGreylistPlugin_DifferentSenders(t *testing.T) {
	// Create a new instance of the plugin
	p := &GreylistPlugin{
		info:      *PluginInfo,
		firstSeen: make(map[string]time.Time),
		delay:     1 * time.Second, // Short delay for testing
	}

	// Initialize the plugin
	p.Init(map[string]interface{}{})

	// Test with first sender
	ctx1 := map[string]interface{}{
		"mail_from": "sender1@example.com",
		"rcpt_to":   "recipient@example.org",
		"remote_ip": "192.168.1.1",
	}

	result, _ := p.Execute(ctx1)
	if result.Action != plugin.ActionReject {
		t.Errorf("Execute() first sender, got action = %v, want %v", result.Action, plugin.ActionReject)
	}

	// Test with second sender - should also be rejected
	ctx2 := map[string]interface{}{
		"mail_from": "sender2@example.com",
		"rcpt_to":   "recipient@example.org",
		"remote_ip": "192.168.1.1",
	}

	result, _ = p.Execute(ctx2)
	if result.Action != plugin.ActionReject {
		t.Errorf("Execute() second sender, got action = %v, want %v", result.Action, plugin.ActionReject)
	}

	// Wait for the delay to pass
	time.Sleep(1100 * time.Millisecond)

	// First sender should now pass
	result, _ = p.Execute(ctx1)
	if result.Action != plugin.ActionContinue {
		t.Errorf("Execute() first sender after delay, got action = %v, want %v", result.Action, plugin.ActionContinue)
	}

	// Second sender should also pass
	result, _ = p.Execute(ctx2)
	if result.Action != plugin.ActionContinue {
		t.Errorf("Execute() second sender after delay, got action = %v, want %v", result.Action, plugin.ActionContinue)
	}
}
