package plugin

import (
	"net"
	"testing"
)

// MockPlugin implements the Plugin interface for testing
type MockPlugin struct {
	info      PluginInfo
	initFunc  func(config map[string]interface{}) error
	closeFunc func() error
}

func (p *MockPlugin) GetInfo() PluginInfo {
	return p.info
}

func (p *MockPlugin) Init(config map[string]interface{}) error {
	if p.initFunc != nil {
		return p.initFunc(config)
	}
	return nil
}

func (p *MockPlugin) Close() error {
	if p.closeFunc != nil {
		return p.closeFunc()
	}
	return nil
}

// MockStagePlugin implements the StagePlugin interface for testing
type MockStagePlugin struct {
	MockPlugin
	stages      []ProcessingStage
	priority    PluginPriority
	executeFunc func(ctx interface{}) (PluginResult, error)
}

func (p *MockStagePlugin) GetStages() []ProcessingStage {
	return p.stages
}

func (p *MockStagePlugin) GetPriority() PluginPriority {
	return p.priority
}

func (p *MockStagePlugin) Execute(ctx interface{}) (PluginResult, error) {
	if p.executeFunc != nil {
		return p.executeFunc(ctx)
	}
	return PluginResult{Action: ActionContinue}, nil
}

// MockSPFPlugin implements the SPFPlugin interface for testing
type MockSPFPlugin struct {
	MockStagePlugin
	checkSPFFunc func(domain string, ip net.IP) (*SPFCheck, error)
}

func (p *MockSPFPlugin) CheckSPF(domain string, ip net.IP) (*SPFCheck, error) {
	if p.checkSPFFunc != nil {
		return p.checkSPFFunc(domain, ip)
	}
	return &SPFCheck{
		Result:      SPFPass,
		Domain:      domain,
		Explanation: "Mock SPF check passed",
		Received:    "pass",
	}, nil
}

func TestPluginManager(t *testing.T) {
	// Create a plugin manager
	manager := NewManager("test_plugins")

	// Test registering plugins by type
	t.Run("RegisterPluginsByType", func(t *testing.T) {
		// Create a mock plugin
		plugin := &MockPlugin{
			info: PluginInfo{
				Name:        "test-plugin",
				Description: "Test plugin",
				Version:     "1.0.0",
				Type:        "test",
				Author:      "Test Author",
			},
		}

		// Register the plugin
		manager.registerTypePlugin("test-plugin", plugin, "test")

		// Get plugins by type
		plugins := manager.GetPluginsByType("test")
		if len(plugins) != 1 {
			t.Errorf("Expected 1 plugin, got %d", len(plugins))
		}
		if plugins[0] != plugin {
			t.Errorf("Expected plugin to be registered")
		}
	})

	// Test registering plugins by stage
	t.Run("RegisterPluginsByStage", func(t *testing.T) {
		// Create a mock stage plugin
		plugin := &MockStagePlugin{
			MockPlugin: MockPlugin{
				info: PluginInfo{
					Name:        "test-stage-plugin",
					Description: "Test stage plugin",
					Version:     "1.0.0",
					Type:        "test",
					Author:      "Test Author",
				},
			},
			stages:   []ProcessingStage{StageConnect, StageHelo},
			priority: PriorityNormal,
		}

		// Register the plugin
		manager.registerStagePlugin(plugin)

		// Get plugins by stage
		connectPlugins := manager.GetPluginsByStage(StageConnect)
		if len(connectPlugins) != 1 {
			t.Errorf("Expected 1 plugin for StageConnect, got %d", len(connectPlugins))
		}
		if connectPlugins[0] != plugin {
			t.Errorf("Expected plugin to be registered for StageConnect")
		}

		heloPlugins := manager.GetPluginsByStage(StageHelo)
		if len(heloPlugins) != 1 {
			t.Errorf("Expected 1 plugin for StageHelo, got %d", len(heloPlugins))
		}
		if heloPlugins[0] != plugin {
			t.Errorf("Expected plugin to be registered for StageHelo")
		}
	})

	// Test plugin priority ordering
	t.Run("PluginPriorityOrdering", func(t *testing.T) {
		// Create high priority plugin
		highPlugin := &MockStagePlugin{
			MockPlugin: MockPlugin{
				info: PluginInfo{
					Name:        "high-priority",
					Description: "High priority plugin",
					Version:     "1.0.0",
					Type:        "test",
					Author:      "Test Author",
				},
			},
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityHigh,
		}

		// Create normal priority plugin
		normalPlugin := &MockStagePlugin{
			MockPlugin: MockPlugin{
				info: PluginInfo{
					Name:        "normal-priority",
					Description: "Normal priority plugin",
					Version:     "1.0.0",
					Type:        "test",
					Author:      "Test Author",
				},
			},
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityNormal,
		}

		// Create low priority plugin
		lowPlugin := &MockStagePlugin{
			MockPlugin: MockPlugin{
				info: PluginInfo{
					Name:        "low-priority",
					Description: "Low priority plugin",
					Version:     "1.0.0",
					Type:        "test",
					Author:      "Test Author",
				},
			},
			stages:   []ProcessingStage{StageMailFrom},
			priority: PriorityLow,
		}

		// Register plugins in reverse order
		manager.registerStagePlugin(lowPlugin)
		manager.registerStagePlugin(normalPlugin)
		manager.registerStagePlugin(highPlugin)

		// Get plugins by stage
		plugins := manager.GetPluginsByStage(StageMailFrom)
		if len(plugins) != 3 {
			t.Errorf("Expected 3 plugins, got %d", len(plugins))
		}

		// Check that plugins are ordered by priority (highest first)
		if plugins[0] != highPlugin {
			t.Errorf("Expected high priority plugin to be first")
		}
		if plugins[1] != normalPlugin {
			t.Errorf("Expected normal priority plugin to be second")
		}
		if plugins[2] != lowPlugin {
			t.Errorf("Expected low priority plugin to be third")
		}
	})

	// Test executing plugins
	t.Run("ExecutePlugins", func(t *testing.T) {
		// Clear existing plugins
		manager.stagePlugins = make(map[ProcessingStage][]StagePlugin)

		// Create plugins with different actions
		continuePlugin := &MockStagePlugin{
			MockPlugin: MockPlugin{
				info: PluginInfo{
					Name:        "continue-plugin",
					Description: "Continue plugin",
					Version:     "1.0.0",
					Type:        "test",
					Author:      "Test Author",
				},
			},
			stages:   []ProcessingStage{StageDataComplete},
			priority: PriorityHigh,
			executeFunc: func(ctx interface{}) (PluginResult, error) {
				return PluginResult{
					Action:  ActionContinue,
					Message: "Continue processing",
					Annotations: map[string]string{
						"test": "continue",
					},
				}, nil
			},
		}

		rejectPlugin := &MockStagePlugin{
			MockPlugin: MockPlugin{
				info: PluginInfo{
					Name:        "reject-plugin",
					Description: "Reject plugin",
					Version:     "1.0.0",
					Type:        "test",
					Author:      "Test Author",
				},
			},
			stages:   []ProcessingStage{StageDataComplete},
			priority: PriorityNormal,
			executeFunc: func(ctx interface{}) (PluginResult, error) {
				return PluginResult{
					Action:  ActionReject,
					Message: "Message rejected",
					Annotations: map[string]string{
						"test": "reject",
					},
				}, nil
			},
		}

		// Register plugins
		manager.registerStagePlugin(continuePlugin)
		manager.registerStagePlugin(rejectPlugin)

		// Execute plugins
		result, err := manager.ExecuteStage(StageDataComplete, nil)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		// Check that execution stopped at the reject plugin
		if result.Action != ActionReject {
			t.Errorf("Expected ActionReject, got %v", result.Action)
		}
		if result.Message != "Message rejected" {
			t.Errorf("Expected 'Message rejected', got '%s'", result.Message)
		}
		if result.Annotations["test"] != "reject" {
			t.Errorf("Expected annotation 'test: reject', got '%s'", result.Annotations["test"])
		}

		// Also check that the continue plugin's annotation was merged
		if result.Annotations["test"] != "reject" {
			t.Errorf("Expected annotation to be overridden to 'reject', got '%s'", result.Annotations["test"])
		}
	})

	// Test SPF plugin
	t.Run("SPFPlugin", func(t *testing.T) {
		// Create a mock SPF plugin
		spfPlugin := &MockSPFPlugin{
			MockStagePlugin: MockStagePlugin{
				MockPlugin: MockPlugin{
					info: PluginInfo{
						Name:        "test-spf",
						Description: "Test SPF plugin",
						Version:     "1.0.0",
						Type:        PluginTypeSPF,
						Author:      "Test Author",
					},
				},
				stages:   []ProcessingStage{StageMailFrom},
				priority: PriorityNormal,
			},
			checkSPFFunc: func(domain string, ip net.IP) (*SPFCheck, error) {
				return &SPFCheck{
					Result:      SPFPass,
					Domain:      domain,
					Explanation: "SPF check passed",
					Received:    "pass",
				}, nil
			},
		}

		// Register the plugin
		manager.registerTypePlugin("test-spf", spfPlugin, PluginTypeSPF)

		// Get plugins by type
		plugins := manager.GetPluginsByType(PluginTypeSPF)
		if len(plugins) != 1 {
			t.Errorf("Expected 1 SPF plugin, got %d", len(plugins))
		}

		// Check if plugin implements SPFPlugin interface
		if spfPluginImpl, ok := plugins[0].(SPFPlugin); ok {
			result, err := spfPluginImpl.CheckSPF("example.com", net.ParseIP("192.0.2.1"))
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result.Result != SPFPass {
				t.Errorf("Expected SPFPass, got %v", result.Result)
			}
			if result.Domain != "example.com" {
				t.Errorf("Expected domain 'example.com', got '%s'", result.Domain)
			}
		} else {
			t.Errorf("Expected plugin to implement SPFPlugin interface")
		}
	})
}
