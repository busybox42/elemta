package tests

import (
	"testing"
	"time"

	"github.com/yourusername/elemta/internal/plugin"
	"github.com/yourusername/elemta/plugins"
)

func TestGreylistPlugin(t *testing.T) {
	// Create a new greylisting plugin
	p := &plugins.GreylistPlugin{}

	// Initialize the plugin with a short delay for testing
	config := map[string]interface{}{
		"delay": "2s", // 2 seconds delay for testing
	}
	err := p.Init(config)
	if err != nil {
		t.Fatalf("Failed to initialize greylisting plugin: %v", err)
	}

	// Create a test context
	ctx := map[string]interface{}{
		"sender":    "test@example.com",
		"recipient": "recipient@example.com",
		"ip":        "192.168.1.1",
	}

	// First attempt should be greylisted
	result, err := p.Execute(ctx)
	if err != nil {
		t.Fatalf("Failed to execute greylisting plugin: %v", err)
	}

	// Check that the result is a temporary rejection
	if result.Action != plugin.PluginResultTempFail {
		t.Errorf("Expected temporary failure action, got %v", result.Action)
	}

	// Second immediate attempt should still be greylisted
	result, err = p.Execute(ctx)
	if err != nil {
		t.Fatalf("Failed to execute greylisting plugin: %v", err)
	}

	// Check that the result is still a temporary rejection
	if result.Action != plugin.PluginResultTempFail {
		t.Errorf("Expected temporary failure action on second attempt, got %v", result.Action)
	}

	// Wait for the delay to pass
	time.Sleep(3 * time.Second)

	// Third attempt after delay should pass
	result, err = p.Execute(ctx)
	if err != nil {
		t.Fatalf("Failed to execute greylisting plugin: %v", err)
	}

	// Check that the result is now continue
	if result.Action != plugin.PluginResultContinue {
		t.Errorf("Expected continue action after delay, got %v", result.Action)
	}

	// Test cleanup
	err = p.Cleanup()
	if err != nil {
		t.Fatalf("Failed to cleanup greylisting plugin: %v", err)
	}

	// Close the plugin
	err = p.Close()
	if err != nil {
		t.Fatalf("Failed to close greylisting plugin: %v", err)
	}
}

func TestGreylistPluginMetrics(t *testing.T) {
	// Create a new greylisting plugin
	p := &plugins.GreylistPlugin{}

	// Initialize the plugin
	config := map[string]interface{}{
		"delay": "1s", // 1 second delay for testing
	}
	err := p.Init(config)
	if err != nil {
		t.Fatalf("Failed to initialize greylisting plugin: %v", err)
	}

	// Create multiple test contexts with different senders/recipients
	contexts := []map[string]interface{}{
		{
			"sender":    "test1@example.com",
			"recipient": "recipient1@example.com",
			"ip":        "192.168.1.1",
		},
		{
			"sender":    "test2@example.com",
			"recipient": "recipient2@example.com",
			"ip":        "192.168.1.2",
		},
		{
			"sender":    "test3@example.com",
			"recipient": "recipient3@example.com",
			"ip":        "192.168.1.3",
		},
	}

	// First attempt for all contexts should be greylisted
	for _, ctx := range contexts {
		_, err := p.Execute(ctx)
		if err != nil {
			t.Fatalf("Failed to execute greylisting plugin: %v", err)
		}
	}

	// Wait for the delay to pass
	time.Sleep(2 * time.Second)

	// Second attempt for all contexts should pass
	for _, ctx := range contexts {
		result, err := p.Execute(ctx)
		if err != nil {
			t.Fatalf("Failed to execute greylisting plugin: %v", err)
		}

		// Check that the result is now continue
		if result.Action != plugin.PluginResultContinue {
			t.Errorf("Expected continue action after delay, got %v", result.Action)
		}
	}

	// Test cleanup
	err = p.Cleanup()
	if err != nil {
		t.Fatalf("Failed to cleanup greylisting plugin: %v", err)
	}

	// Close the plugin
	err = p.Close()
	if err != nil {
		t.Fatalf("Failed to close greylisting plugin: %v", err)
	}

	// Note: In a real test, we would check the actual metrics values
	// This would require a metrics registry and collector
	// For simplicity, we're just testing the plugin behavior
}
