package plugin

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEnhancedManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	config := &EnhancedConfig{
		PluginPath:          tempDir,
		Enabled:             true,
		Plugins:             []string{},
		PluginConfig:        make(map[string]map[string]interface{}),
		ExecutorConfig:      DefaultExecutorConfig(),
		AutoReload:          false,
		ReloadInterval:      5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
	}

	manager := NewEnhancedManager(config)

	t.Run("Start", func(t *testing.T) {
		if err := manager.Start(); err != nil {
			t.Fatalf("Failed to start enhanced manager: %v", err)
		}

		if !manager.started {
			t.Error("Manager should be marked as started")
		}

		if manager.lifecycleState != StateRunning {
			t.Errorf("Expected state %v, got %v", StateRunning, manager.lifecycleState)
		}
	})

	t.Run("GetStatus", func(t *testing.T) {
		status := manager.GetStatus()

		if status["lifecycle_state"] != "running" {
			t.Errorf("Expected lifecycle state 'running', got %v", status["lifecycle_state"])
		}

		if _, ok := status["executor_metrics"]; !ok {
			t.Error("Status should include executor metrics")
		}
	})

	t.Run("Stop", func(t *testing.T) {
		if err := manager.Stop(); err != nil {
			t.Fatalf("Failed to stop enhanced manager: %v", err)
		}

		if manager.started {
			t.Error("Manager should not be marked as started after stop")
		}

		if manager.lifecycleState != StateStopped {
			t.Errorf("Expected state %v, got %v", StateStopped, manager.lifecycleState)
		}
	})
}

func TestHookRegistry(t *testing.T) {
	registry := NewHookRegistry()

	// Create mock hooks
	mockConnectionHook := &MockConnectionHook{}
	mockCommandHook := &MockCommandHook{}
	mockSecurityHook := &MockSecurityHook{}

	t.Run("RegisterHooks", func(t *testing.T) {
		registry.RegisterConnectionHook(mockConnectionHook)
		registry.RegisterCommandHook(mockCommandHook)
		registry.RegisterSecurityHook(mockSecurityHook)

		connectionHooks := registry.GetConnectionHooks()
		if len(connectionHooks) != 1 {
			t.Errorf("Expected 1 connection hook, got %d", len(connectionHooks))
		}

		commandHooks := registry.GetCommandHooks()
		if len(commandHooks) != 1 {
			t.Errorf("Expected 1 command hook, got %d", len(commandHooks))
		}

		securityHooks := registry.GetSecurityHooks()
		if len(securityHooks) != 1 {
			t.Errorf("Expected 1 security hook, got %d", len(securityHooks))
		}
	})
}

func TestExecutor(t *testing.T) {
	config := DefaultExecutorConfig()
	config.Timeout = 1 * time.Second // Short timeout for testing

	executor := NewExecutor(config)

	t.Run("ExecutePlugin", func(t *testing.T) {
		// Test successful execution
		result := executor.ExecutePlugin("test-plugin", func() (*PluginResult, error) {
			return &PluginResult{
				Action:  ActionContinue,
				Message: "Success",
			}, nil
		})

		if result.Error != nil {
			t.Errorf("Expected no error, got %v", result.Error)
		}

		if result.Result == nil {
			t.Error("Expected result to be non-nil")
		}

		if result.Result.Action != ActionContinue {
			t.Errorf("Expected action %v, got %v", ActionContinue, result.Result.Action)
		}
	})

	t.Run("ExecutePluginWithTimeout", func(t *testing.T) {
		// Test timeout handling
		result := executor.ExecutePlugin("slow-plugin", func() (*PluginResult, error) {
			time.Sleep(2 * time.Second) // Longer than timeout
			return &PluginResult{
				Action:  ActionContinue,
				Message: "Should timeout",
			}, nil
		})

		if result.Error == nil {
			t.Error("Expected timeout error")
		}

		if result.Duration < 1*time.Second {
			t.Errorf("Expected duration >= 1s, got %v", result.Duration)
		}
	})

	t.Run("ExecutePluginWithPanic", func(t *testing.T) {
		// Test panic recovery
		result := executor.ExecutePlugin("panic-plugin", func() (*PluginResult, error) {
			panic("test panic")
		})

		if result.Error == nil {
			t.Error("Expected panic error")
		}

		if !result.Recovered {
			t.Error("Expected panic to be recovered")
		}

		if result.RecoverData != "test panic" {
			t.Errorf("Expected recover data 'test panic', got %v", result.RecoverData)
		}
	})

	t.Run("GetMetrics", func(t *testing.T) {
		metrics := executor.GetMetrics()

		if metrics.TotalExecutions < 3 {
			t.Errorf("Expected at least 3 executions, got %d", metrics.TotalExecutions)
		}

		if metrics.SuccessfulExecutions < 1 {
			t.Error("Expected at least 1 successful execution")
		}

		if metrics.FailedExecutions < 2 {
			t.Error("Expected at least 2 failed executions")
		}

		if metrics.PanicRecoveries < 1 {
			t.Error("Expected at least 1 panic recovery")
		}
	})
}

func TestHookContext(t *testing.T) {
	ctx := context.Background()
	sessionID := "test-session"
	messageID := "test-message"
	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:2525")
	phase := StageConnect

	hookCtx := NewHookContext(ctx, sessionID, messageID, remoteAddr, localAddr, phase)

	t.Run("BasicProperties", func(t *testing.T) {
		if hookCtx.SessionID != sessionID {
			t.Errorf("Expected session ID %s, got %s", sessionID, hookCtx.SessionID)
		}

		if hookCtx.MessageID != messageID {
			t.Errorf("Expected message ID %s, got %s", messageID, hookCtx.MessageID)
		}

		if hookCtx.Phase != phase {
			t.Errorf("Expected phase %v, got %v", phase, hookCtx.Phase)
		}
	})

	t.Run("DataStorage", func(t *testing.T) {
		key := "test-key"
		value := "test-value"

		hookCtx.Set(key, value)

		retrieved, exists := hookCtx.Get(key)
		if !exists {
			t.Error("Expected key to exist")
		}

		if retrieved != value {
			t.Errorf("Expected value %s, got %v", value, retrieved)
		}

		_, exists = hookCtx.Get("non-existent-key")
		if exists {
			t.Error("Expected non-existent key to not exist")
		}
	})
}

func TestHookExecutor(t *testing.T) {
	tempDir := t.TempDir()

	config := &EnhancedConfig{
		PluginPath:          tempDir,
		Enabled:             true,
		Plugins:             []string{},
		PluginConfig:        make(map[string]map[string]interface{}),
		ExecutorConfig:      DefaultExecutorConfig(),
		AutoReload:          false,
		ReloadInterval:      5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
	}

	manager := NewEnhancedManager(config)
	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer manager.Stop()

	executor := manager.ExecuteHooks()

	// Register mock hooks
	manager.hookRegistry.RegisterConnectionHook(&MockConnectionHook{})
	manager.hookRegistry.RegisterContentFilterHook(&MockContentFilterHook{})

	t.Run("OnConnect", func(t *testing.T) {
		remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
		localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:2525")

		results := executor.OnConnect("session-1", "message-1", remoteAddr, localAddr)

		if len(results) != 1 {
			t.Errorf("Expected 1 result, got %d", len(results))
		}

		if len(results) > 0 && results[0].Error != nil {
			t.Errorf("Expected no error, got %v", results[0].Error)
		}
	})

	t.Run("OnAntivirusScan", func(t *testing.T) {
		remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
		localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:2525")
		content := []byte("test email content")

		results := executor.OnAntivirusScan("session-1", "message-1", remoteAddr, localAddr, content)

		if len(results) != 1 {
			t.Errorf("Expected 1 result, got %d", len(results))
		}

		if len(results) > 0 && results[0].Error != nil {
			t.Errorf("Expected no error, got %v", results[0].Error)
		}
	})
}

// Mock hook implementations for testing

type MockConnectionHook struct{}

func (m *MockConnectionHook) OnConnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock connection allowed",
	}, nil
}

func (m *MockConnectionHook) OnDisconnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock disconnect processed",
	}, nil
}

type MockCommandHook struct{}

func (m *MockCommandHook) OnHelo(ctx *HookContext, hostname string) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock HELO processed",
	}, nil
}

func (m *MockCommandHook) OnEhlo(ctx *HookContext, hostname string) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock EHLO processed",
	}, nil
}

func (m *MockCommandHook) OnAuth(ctx *HookContext, mechanism, username string) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock AUTH processed",
	}, nil
}

func (m *MockCommandHook) OnStartTLS(ctx *HookContext) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock STARTTLS processed",
	}, nil
}

type MockSecurityHook struct{}

func (m *MockSecurityHook) OnRateLimitCheck(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock rate limit OK",
	}, nil
}

func (m *MockSecurityHook) OnGreylistCheck(ctx *HookContext, sender, recipient string, remoteAddr net.Addr) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock greylist OK",
	}, nil
}

func (m *MockSecurityHook) OnReputationCheck(ctx *HookContext, remoteAddr net.Addr, domain string) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock reputation OK",
		Score:   0.0,
	}, nil
}

type MockContentFilterHook struct{}

func (m *MockContentFilterHook) OnAntivirusScan(ctx *HookContext, content []byte) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock antivirus clean",
	}, nil
}

func (m *MockContentFilterHook) OnAntispamScan(ctx *HookContext, content []byte) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock antispam clean",
	}, nil
}

func (m *MockContentFilterHook) OnContentFilter(ctx *HookContext, content []byte) (*PluginResult, error) {
	return &PluginResult{
		Action:  ActionContinue,
		Message: "Mock content filter OK",
	}, nil
}
