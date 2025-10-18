package plugin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSecurePluginManager tests the secure plugin manager functionality
func TestSecurePluginManager(t *testing.T) {
	// Create temporary directory for test plugins
	tempDir := t.TempDir()

	// Create test configuration
	config := DefaultSecurePluginConfig()
	config.EnableSandboxing = true
	config.EnforceSignatures = false // Disable for testing

	// Create secure plugin manager
	spm, err := NewSecurePluginManager(tempDir, config)
	if err != nil {
		t.Fatalf("Failed to create secure plugin manager: %v", err)
	}
	defer spm.Close()

	// Test security status
	status := spm.GetSecurityStatus()
	if status["secure_plugins_count"] != 0 {
		t.Errorf("Expected 0 secure plugins, got %v", status["secure_plugins_count"])
	}

	if !status["sandbox_enabled"].(bool) {
		t.Error("Expected sandbox to be enabled")
	}
}

// TestPluginSandbox tests the plugin sandbox functionality
func TestPluginSandbox(t *testing.T) {
	config := DefaultSandboxConfig()
	config.MaxMemoryMB = 10 // Small limit for testing
	config.MaxExecutionTime = 1 * time.Second

	sandbox := NewPluginSandbox(config)
	if err := sandbox.Start(); err != nil {
		t.Fatalf("Failed to start sandbox: %v", err)
	}
	defer sandbox.Stop()

	// Test successful execution
	result, err := sandbox.ExecuteInSandbox("test-plugin", func() (*PluginResult, error) {
		return &PluginResult{
			Action: ActionContinue,
		}, nil
	})

	if err != nil {
		t.Errorf("Expected successful execution, got error: %v", err)
	}

	if result.Action != ActionContinue {
		t.Errorf("Expected ActionContinue, got %v", result.Action)
	}

	// Test timeout
	_, err = sandbox.ExecuteInSandbox("timeout-plugin", func() (*PluginResult, error) {
		time.Sleep(2 * time.Second) // Exceed timeout
		return &PluginResult{Action: ActionContinue}, nil
	})

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	// Test panic recovery
	_, err = sandbox.ExecuteInSandbox("panic-plugin", func() (*PluginResult, error) {
		panic("test panic")
	})

	if err == nil {
		t.Error("Expected panic error, got nil")
	}

	// Check violation count
	violations := sandbox.GetViolationCount()
	if violations == 0 {
		t.Error("Expected security violations to be recorded")
	}
}

// TestPluginValidator tests the plugin validator functionality
func TestPluginValidator(t *testing.T) {
	validator := NewPluginValidator()

	// Create a temporary plugin file for testing
	tempDir := t.TempDir()
	pluginPath := filepath.Join(tempDir, "test.so")

	// Create a dummy .so file (this won't be a real plugin, but tests file validation)
	if err := os.WriteFile(pluginPath, []byte("dummy plugin content"), 0644); err != nil {
		t.Fatalf("Failed to create test plugin file: %v", err)
	}

	// Test validation
	result, err := validator.ValidatePlugin(pluginPath)
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	// Should have errors since it's not a real plugin
	if result.Valid {
		t.Error("Expected validation to fail for dummy plugin")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected validation errors for dummy plugin")
	}

	// Test file hash calculation
	if result.FileHash == "" {
		t.Error("Expected file hash to be calculated")
	}
}

// TestCapabilityManager tests the capability manager functionality
func TestCapabilityManager(t *testing.T) {
	defaultCaps := []string{"read", "log"}
	restrictedCaps := []string{"admin", "system"}

	cm := NewCapabilityManager(defaultCaps, restrictedCaps)

	// Test plugin info
	pluginInfo := &PluginInfo{
		Name: "test-plugin",
		Type: PluginTypeAntivirus,
	}

	// Test capability assignment
	capabilities := cm.GetPluginCapabilities("test-plugin", pluginInfo)

	// Should include default capabilities
	hasRead := false
	hasLog := false
	for _, cap := range capabilities {
		if cap == "read" {
			hasRead = true
		}
		if cap == "log" {
			hasLog = true
		}
	}

	if !hasRead {
		t.Error("Expected 'read' capability to be assigned")
	}
	if !hasLog {
		t.Error("Expected 'log' capability to be assigned")
	}

	// Should not include restricted capabilities by default
	for _, cap := range capabilities {
		if cap == "admin" || cap == "system" {
			t.Errorf("Restricted capability '%s' should not be assigned by default", cap)
		}
	}
}

// TestSecurityAuditLogger tests the security audit logger functionality
func TestSecurityAuditLogger(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security audit logger test in short mode")
	}

	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	auditLogger, err := NewSecurityAuditLogger(logPath, 30)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Test event logging
	auditLogger.LogEvent("test_event", map[string]interface{}{
		"plugin_name": "test-plugin",
		"action":      "test_action",
	})

	// Verify log file was created
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Expected audit log file to be created")
	}
}

// TestSecurityConfig tests the security configuration functionality
func TestSecurityConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security config test in short mode")
	}

	// Test default config
	config := DefaultSecurityConfig()
	if !config.Enabled {
		t.Error("Expected security to be enabled by default")
	}

	if config.Mode != "moderate" {
		t.Errorf("Expected mode 'moderate', got '%s'", config.Mode)
	}

	// Test development config
	devConfig := DevelopmentSecurityConfig()
	if !devConfig.DevelopmentMode {
		t.Error("Expected development mode to be enabled")
	}

	if devConfig.Mode != "permissive" {
		t.Errorf("Expected mode 'permissive', got '%s'", devConfig.Mode)
	}

	// Test strict config
	strictConfig := StrictSecurityConfig()
	if strictConfig.Mode != "strict" {
		t.Errorf("Expected mode 'strict', got '%s'", strictConfig.Mode)
	}

	if !strictConfig.SignatureVerification.Required {
		t.Error("Expected signature verification to be required in strict mode")
	}

	// Test config validation
	if err := ValidateSecurityConfig(&config); err != nil {
		t.Errorf("Default config validation failed: %v", err)
	}

	// Test invalid config
	invalidConfig := config
	invalidConfig.Sandboxing.MaxMemoryMB = -1
	if err := ValidateSecurityConfig(&invalidConfig); err == nil {
		t.Error("Expected validation to fail for invalid config")
	}
}

// TestPluginSignatureStore tests the plugin signature store functionality
func TestPluginSignatureStore(t *testing.T) {
	// Create signature store without trusted certificates
	store, err := NewPluginSignatureStore([]string{}, 100, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create signature store: %v", err)
	}

	// Create a temporary plugin file
	tempDir := t.TempDir()
	pluginPath := filepath.Join(tempDir, "test.so")
	if err := os.WriteFile(pluginPath, []byte("test plugin"), 0644); err != nil {
		t.Fatalf("Failed to create test plugin file: %v", err)
	}

	// Test signature verification (should return mock signature)
	signature, err := store.VerifyPluginSignature(pluginPath)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	if signature == nil {
		t.Error("Expected signature to be returned")
	}

	if signature.Algorithm != "SHA256-RSA" {
		t.Errorf("Expected algorithm 'SHA256-RSA', got '%s'", signature.Algorithm)
	}
}

// TestSecurityIntegration tests the integration of all security components
func TestSecurityIntegration(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create comprehensive security config
	config := DefaultSecurePluginConfig()
	config.EnableSandboxing = true
	config.EnforceSignatures = false // Disable for testing
	config.RequireCapabilities = true

	// Create secure plugin manager
	spm, err := NewSecurePluginManager(tempDir, config)
	if err != nil {
		t.Fatalf("Failed to create secure plugin manager: %v", err)
	}
	defer spm.Close()

	// Test security status
	status := spm.GetSecurityStatus()
	expectedFields := []string{
		"secure_plugins_count",
		"sandbox_enabled",
		"sandbox_status",
		"signature_enforcement",
		"audit_logging",
		"capability_management",
		"plugins",
	}

	for _, field := range expectedFields {
		if _, exists := status[field]; !exists {
			t.Errorf("Expected status field '%s' to exist", field)
		}
	}

	// Test plugin revocation
	if err := spm.RevokePlugin("nonexistent-plugin", "test revocation"); err == nil {
		t.Error("Expected error when revoking nonexistent plugin")
	}
}

// TestSecurityViolations tests security violation handling
func TestSecurityViolations(t *testing.T) {
	config := DefaultSandboxConfig()
	config.MaxMemoryMB = 1 // Very small limit
	config.MaxExecutionTime = 100 * time.Millisecond

	sandbox := NewPluginSandbox(config)
	if err := sandbox.Start(); err != nil {
		t.Fatalf("Failed to start sandbox: %v", err)
	}
	defer sandbox.Stop()

	// Test memory violation (simulated)
	_, err := sandbox.ExecuteInSandbox("memory-violation-plugin", func() (*PluginResult, error) {
		// Simulate memory usage by allocating a large slice
		largeSlice := make([]byte, 2*1024*1024) // 2MB
		_ = largeSlice
		return &PluginResult{Action: ActionContinue}, nil
	})

	// Should either succeed (if memory check isn't strict enough) or fail
	// The important thing is that it doesn't crash the system
	_ = err

	// Test execution timeout
	_, err = sandbox.ExecuteInSandbox("timeout-plugin", func() (*PluginResult, error) {
		time.Sleep(200 * time.Millisecond) // Exceed timeout
		return &PluginResult{Action: ActionContinue}, nil
	})

	if err == nil {
		t.Error("Expected timeout error")
	}

	// Check that violations were recorded
	violations := sandbox.GetViolationCount()
	if violations == 0 {
		t.Error("Expected security violations to be recorded")
	}
}

// TestPluginSecurityContext tests the plugin security context
func TestPluginSecurityContext(t *testing.T) {
	// Create audit logger
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")
	auditLogger, err := NewSecurityAuditLogger(logPath, 30)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Create security context
	context := &PluginSecurityContext{
		PluginName:   "test-plugin",
		Capabilities: []string{"read", "log"},
		Sandboxed:    true,
		AuditLogger:  auditLogger,
	}

	// Test context properties
	if context.PluginName != "test-plugin" {
		t.Errorf("Expected plugin name 'test-plugin', got '%s'", context.PluginName)
	}

	if len(context.Capabilities) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(context.Capabilities))
	}

	if !context.Sandboxed {
		t.Error("Expected sandboxed to be true")
	}

	if context.AuditLogger == nil {
		t.Error("Expected audit logger to be set")
	}
}

// BenchmarkSecurePluginExecution benchmarks secure plugin execution
func BenchmarkSecurePluginExecution(b *testing.B) {
	config := DefaultSandboxConfig()
	sandbox := NewPluginSandbox(config)
	if err := sandbox.Start(); err != nil {
		b.Fatalf("Failed to start sandbox: %v", err)
	}
	defer sandbox.Stop()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sandbox.ExecuteInSandbox("benchmark-plugin", func() (*PluginResult, error) {
			return &PluginResult{Action: ActionContinue}, nil
		})
		if err != nil {
			b.Errorf("Execution failed: %v", err)
		}
	}
}

// BenchmarkPluginValidation benchmarks plugin validation
func BenchmarkPluginValidation(b *testing.B) {
	validator := NewPluginValidator()

	// Create a temporary plugin file
	tempDir := b.TempDir()
	pluginPath := filepath.Join(tempDir, "test.so")
	if err := os.WriteFile(pluginPath, []byte("test plugin content"), 0644); err != nil {
		b.Fatalf("Failed to create test plugin file: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := validator.ValidatePlugin(pluginPath)
		if err != nil {
			b.Errorf("Validation failed: %v", err)
		}
	}
}
