package plugin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewPluginValidator(t *testing.T) {
	validator := NewPluginValidator()

	if validator == nil {
		t.Fatal("NewPluginValidator returned nil")
	}

	// Check default configuration
	if validator.maxFileSize != 50*1024*1024 {
		t.Errorf("Expected max file size 50MB, got %d", validator.maxFileSize)
	}

	if validator.validationTimeout != 30*time.Second {
		t.Errorf("Expected validation timeout 30s, got %v", validator.validationTimeout)
	}

	if !validator.developmentMode {
		t.Error("Expected development mode to be enabled by default")
	}

	if validator.enforceSignatures {
		t.Error("Expected signature enforcement to be disabled in development mode")
	}
}

func TestValidatePlugin_FileBasics(t *testing.T) {
	validator := NewPluginValidator()

	tests := []struct {
		name           string
		setupFile      func() (string, func())
		expectValid    bool
		expectErrors   int
		expectWarnings int
	}{
		{
			name: "non-existent file",
			setupFile: func() (string, func()) {
				return "/nonexistent/plugin.so", func() {}
			},
			expectValid:  false,
			expectErrors: 1,
		},
		{
			name: "wrong extension",
			setupFile: func() (string, func()) {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "plugin.txt")
				os.WriteFile(path, []byte("test"), 0644)
				return path, func() {}
			},
			expectValid:  false,
			expectErrors: 1,
		},
		{
			name: "correct extension",
			setupFile: func() (string, func()) {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "plugin.so")
				os.WriteFile(path, []byte("test plugin content"), 0644)
				return path, func() {}
			},
			expectValid:  false, // Will fail on symbol validation, but file basics should pass
			expectErrors: 1,     // Symbol validation will fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, cleanup := tt.setupFile()
			defer cleanup()

			result, err := validator.ValidatePlugin(path)
			if err != nil {
				t.Fatalf("ValidatePlugin returned error: %v", err)
			}

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v", tt.expectValid, result.Valid)
			}

			if len(result.Errors) != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d: %v", tt.expectErrors, len(result.Errors), result.Errors)
			}
		})
	}
}

func TestValidatePlugin_SecurityChecks(t *testing.T) {
	validator := NewPluginValidator()

	// Test with world-writable file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "plugin.so")

	// Create file with world-writable permissions
	err := os.WriteFile(path, []byte("test content"), 0666)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Make it world-writable
	err = os.Chmod(path, 0662)
	if err != nil {
		t.Fatalf("Failed to set permissions: %v", err)
	}

	result, err := validator.ValidatePlugin(path)
	if err != nil {
		t.Fatalf("ValidatePlugin returned error: %v", err)
	}

	// Should have warning about world-writable file
	found := false
	for _, warning := range result.Warnings {
		if contains(warning, "world-writable") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected warning about world-writable file, got warnings: %v", result.Warnings)
	}
}

func TestValidatePlugin_HashCalculation(t *testing.T) {
	validator := NewPluginValidator()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "plugin.so")
	content := []byte("test plugin content for hash calculation")

	err := os.WriteFile(path, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := validator.ValidatePlugin(path)
	if err != nil {
		t.Fatalf("ValidatePlugin returned error: %v", err)
	}

	if result.FileHash == "" {
		t.Error("Expected file hash to be calculated")
	}

	if len(result.FileHash) != 64 { // SHA256 produces 64 character hex string
		t.Errorf("Expected hash length 64, got %d", len(result.FileHash))
	}
}

func TestPluginValidator_TrustedHashes(t *testing.T) {
	validator := NewPluginValidator()

	// Test updating trusted hash
	testHash := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	validator.UpdateTrustedHash("testplugin", testHash)

	if validator.trustedHashes["testplugin"] != testHash {
		t.Errorf("Expected trusted hash to be updated to %s, got %s", testHash, validator.trustedHashes["testplugin"])
	}
}

func TestPluginValidator_DevelopmentMode(t *testing.T) {
	validator := NewPluginValidator()

	// Test enabling/disabling development mode
	validator.SetDevelopmentMode(false)

	if validator.developmentMode {
		t.Error("Expected development mode to be disabled")
	}

	if !validator.enforceSignatures {
		t.Error("Expected signature enforcement to be enabled when dev mode is disabled")
	}

	validator.SetDevelopmentMode(true)

	if !validator.developmentMode {
		t.Error("Expected development mode to be enabled")
	}

	if validator.enforceSignatures {
		t.Error("Expected signature enforcement to be disabled when dev mode is enabled")
	}
}

func TestPluginValidator_GetValidationSummary(t *testing.T) {
	validator := NewPluginValidator()

	summary := validator.GetValidationSummary()

	expectedKeys := []string{
		"max_file_size",
		"validation_timeout",
		"enforce_signatures",
		"development_mode",
		"trusted_plugins",
		"allowed_symbols",
		"forbidden_symbols",
	}

	for _, key := range expectedKeys {
		if _, exists := summary[key]; !exists {
			t.Errorf("Expected summary to contain key '%s'", key)
		}
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func BenchmarkPluginValidator_ValidatePlugin(b *testing.B) {
	validator := NewPluginValidator()

	// Create test file
	tmpDir := b.TempDir()
	path := filepath.Join(tmpDir, "plugin.so")
	content := make([]byte, 1024*1024) // 1MB test file
	for i := range content {
		content[i] = byte(i % 256)
	}

	err := os.WriteFile(path, content, 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := validator.ValidatePlugin(path)
		if err != nil {
			b.Fatalf("ValidatePlugin failed: %v", err)
		}
	}
}
