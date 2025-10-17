package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFileSecurity_ContainsSensitiveData(t *testing.T) {
	cfs := NewConfigFileSecurity()

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "password field",
			content:  "password = secret123",
			expected: true,
		},
		{
			name:     "datasource_pass field",
			content:  "datasource_pass = admin",
			expected: true,
		},
		{
			name:     "api_key field",
			content:  "api_key = abc123",
			expected: true,
		},
		{
			name:     "private_key field",
			content:  "private_key = /path/to/key",
			expected: true,
		},
		{
			name:     "no sensitive data",
			content:  "hostname = localhost\nport = 2525",
			expected: false,
		},
		{
			name:     "case insensitive",
			content:  "PASSWORD = secret123",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "test-config-*.toml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write content
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("Failed to write content: %v", err)
			}
			tmpFile.Close()

			// Test
			result, err := cfs.ContainsSensitiveData(tmpFile.Name())
			if err != nil {
				t.Fatalf("ContainsSensitiveData failed: %v", err)
			}

			if result != tt.expected {
				t.Errorf("ContainsSensitiveData() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestConfigFileSecurity_SecureFilePermissions(t *testing.T) {
	cfs := NewConfigFileSecurity()

	tests := []struct {
		name                string
		content             string
		initialPermissions  os.FileMode
		expectedPermissions os.FileMode
	}{
		{
			name:                "sensitive data should be 0600",
			content:             "password = secret123",
			initialPermissions:  0644,
			expectedPermissions: 0600,
		},
		{
			name:                "non-sensitive data should be 0644",
			content:             "hostname = localhost",
			initialPermissions:  0644,
			expectedPermissions: 0644,
		},
		{
			name:                "already secure permissions",
			content:             "password = secret123",
			initialPermissions:  0600,
			expectedPermissions: 0600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "test-config-*.toml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write content
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("Failed to write content: %v", err)
			}
			tmpFile.Close()

			// Set initial permissions
			if err := os.Chmod(tmpFile.Name(), tt.initialPermissions); err != nil {
				t.Fatalf("Failed to set initial permissions: %v", err)
			}

			// Test secure permissions
			if err := cfs.SecureFilePermissions(tmpFile.Name()); err != nil {
				t.Fatalf("SecureFilePermissions failed: %v", err)
			}

			// Check final permissions
			info, err := os.Stat(tmpFile.Name())
			if err != nil {
				t.Fatalf("Failed to stat file: %v", err)
			}

			actualPermissions := info.Mode().Perm()
			if actualPermissions != tt.expectedPermissions {
				t.Errorf("Expected permissions %s, got %s", tt.expectedPermissions, actualPermissions)
			}
		})
	}
}

func TestConfigFileSecurity_ValidateConfigFileSecurity(t *testing.T) {
	cfs := NewConfigFileSecurity()

	tests := []struct {
		name        string
		content     string
		permissions os.FileMode
		expectError bool
		errorMsg    string
	}{
		{
			name:        "secure sensitive file",
			content:     "password = secret123",
			permissions: 0600,
			expectError: false,
		},
		{
			name:        "insecure sensitive file",
			content:     "password = secret123",
			permissions: 0644,
			expectError: true,
			errorMsg:    "contains sensitive data but has world/group readable permissions",
		},
		{
			name:        "secure non-sensitive file",
			content:     "hostname = localhost",
			permissions: 0644,
			expectError: false,
		},
		{
			name:        "world-writable file",
			content:     "hostname = localhost",
			permissions: 0666,
			expectError: true,
			errorMsg:    "is world-writable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile, err := os.CreateTemp("", "test-config-*.toml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			// Write content
			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("Failed to write content: %v", err)
			}
			tmpFile.Close()

			// Set permissions
			if err := os.Chmod(tmpFile.Name(), tt.permissions); err != nil {
				t.Fatalf("Failed to set permissions: %v", err)
			}

			// Test validation
			err = cfs.ValidateConfigFileSecurity(tmpFile.Name())
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !containsSubstr(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigFileSecurity_CreateSecureConfigFile(t *testing.T) {
	cfs := NewConfigFileSecurity()

	tests := []struct {
		name                string
		content             string
		containsSensitive   bool
		expectedPermissions os.FileMode
	}{
		{
			name:                "sensitive content",
			content:             "password = secret123",
			containsSensitive:   true,
			expectedPermissions: 0600,
		},
		{
			name:                "non-sensitive content",
			content:             "hostname = localhost",
			containsSensitive:   false,
			expectedPermissions: 0644,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file path
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "test-config.toml")

			// Test secure file creation
			if err := cfs.CreateSecureConfigFile(filePath, []byte(tt.content), tt.containsSensitive); err != nil {
				t.Fatalf("CreateSecureConfigFile failed: %v", err)
			}

			// Check file exists
			if _, err := os.Stat(filePath); err != nil {
				t.Fatalf("File was not created: %v", err)
			}

			// Check permissions
			info, err := os.Stat(filePath)
			if err != nil {
				t.Fatalf("Failed to stat file: %v", err)
			}

			actualPermissions := info.Mode().Perm()
			if actualPermissions != tt.expectedPermissions {
				t.Errorf("Expected permissions %s, got %s", tt.expectedPermissions, actualPermissions)
			}

			// Check content
			content, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("Failed to read file: %v", err)
			}

			if string(content) != tt.content {
				t.Errorf("Expected content %s, got %s", tt.content, string(content))
			}
		})
	}
}

func TestConfigFileSecurity_SanitizeConfigContent(t *testing.T) {
	cfs := NewConfigFileSecurity()

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "password redaction",
			content:  "password = secret123\nhostname = localhost",
			expected: "password = [REDACTED]\nhostname = localhost",
		},
		{
			name:     "api_key redaction",
			content:  "api_key = abc123\ndebug = true",
			expected: "api_key = [REDACTED]\ndebug = true",
		},
		{
			name:     "no sensitive data",
			content:  "hostname = localhost\nport = 2525",
			expected: "hostname = localhost\nport = 2525",
		},
		{
			name:     "multiple sensitive fields",
			content:  "password = secret\napi_key = key123\nhostname = localhost",
			expected: "password = [REDACTED]\napi_key = [REDACTED]\nhostname = localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfs.SanitizeConfigContent(tt.content)
			if result != tt.expected {
				t.Errorf("SanitizeConfigContent() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

func TestConfigFileSecurity_PathTraversal(t *testing.T) {
	cfs := NewConfigFileSecurity()

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "valid path",
			path:        "/app/config/elemta.toml",
			expectError: false,
		},
		{
			name:        "path traversal",
			path:        "/app/config/../../../etc/passwd",
			expectError: true,
		},
		{
			name:        "blocked pattern",
			path:        "/etc/passwd",
			expectError: true,
		},
		{
			name:        "blocked pattern shadow",
			path:        "/etc/shadow",
			expectError: true,
		},
		{
			name:        "blocked pattern proc",
			path:        "/proc/version",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfs.validateBasicPathSecurity(tt.path)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for path %s but got none", tt.path)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for path %s: %v", tt.path, err)
				}
			}
		})
	}
}

// Helper function
func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
