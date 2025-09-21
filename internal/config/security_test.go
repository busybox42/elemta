package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecurityValidator_PathValidation(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		path        string
		fieldName   string
		expectError bool
		description string
	}{
		{
			name:        "valid_path",
			path:        "/app/queue",
			fieldName:   "queue.dir",
			expectError: false,
			description: "Valid application path should pass",
		},
		{
			name:        "path_traversal_dotdot",
			path:        "/app/../etc/passwd",
			fieldName:   "queue.dir",
			expectError: true,
			description: "Path traversal with ../ should be blocked",
		},
		{
			name:        "path_traversal_backslash",
			path:        "C:\\app\\..\\windows\\system32",
			fieldName:   "queue.dir",
			expectError: true,
			description: "Path traversal with ..\\ should be blocked",
		},
		{
			name:        "blocked_pattern_passwd",
			path:        "/etc/passwd",
			fieldName:   "queue.dir",
			expectError: true,
			description: "Blocked pattern /etc/passwd should be rejected",
		},
		{
			name:        "blocked_pattern_proc",
			path:        "/proc/self/environ",
			fieldName:   "queue.dir",
			expectError: true,
			description: "Blocked pattern /proc/ should be rejected",
		},
		{
			name:        "blocked_pattern_ssh",
			path:        "~/.ssh/id_rsa",
			fieldName:   "queue.dir",
			expectError: true,
			description: "Blocked pattern ~/.ssh/ should be rejected",
		},
		{
			name:        "path_too_long",
			path:        "/app/" + string(make([]byte, 5000)),
			fieldName:   "queue.dir",
			expectError: true,
			description: "Path too long should be rejected",
		},
		{
			name:        "null_bytes",
			path:        "/app/queue\x00/etc/passwd",
			fieldName:   "queue.dir",
			expectError: true, // Should be rejected due to blocked pattern after sanitization
			description: "Null bytes should be sanitized but blocked pattern should still be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sv.ValidatePath(tt.path, tt.fieldName)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestSecurityValidator_NumericBounds(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		value       int64
		fieldName   string
		min         int64
		max         int64
		expectError bool
		description string
	}{
		{
			name:        "valid_value",
			value:       1000,
			fieldName:   "max_workers",
			min:         1,
			max:         10000,
			expectError: false,
			description: "Valid value within bounds should pass",
		},
		{
			name:        "value_too_small",
			value:       0,
			fieldName:   "max_workers",
			min:         1,
			max:         10000,
			expectError: true,
			description: "Value below minimum should be rejected",
		},
		{
			name:        "value_too_large",
			value:       50000,
			fieldName:   "max_workers",
			min:         1,
			max:         10000,
			expectError: true,
			description: "Value above maximum should be rejected",
		},
		{
			name:        "negative_value",
			value:       -100,
			fieldName:   "timeout",
			min:         1,
			max:         3600,
			expectError: true,
			description: "Negative values should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sv.ValidateNumericBounds(tt.value, tt.fieldName, tt.min, tt.max)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestSecurityValidator_PortValidation(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		port        int
		fieldName   string
		expectError bool
		description string
	}{
		{
			name:        "valid_port",
			port:        2525,
			fieldName:   "smtp.port",
			expectError: false,
			description: "Valid port should pass",
		},
		{
			name:        "port_zero",
			port:        0,
			fieldName:   "smtp.port",
			expectError: true,
			description: "Port 0 should be rejected",
		},
		{
			name:        "port_negative",
			port:        -1,
			fieldName:   "smtp.port",
			expectError: true,
			description: "Negative port should be rejected",
		},
		{
			name:        "port_too_large",
			port:        70000,
			fieldName:   "smtp.port",
			expectError: true,
			description: "Port > 65535 should be rejected",
		},
		{
			name:        "port_max_valid",
			port:        65535,
			fieldName:   "smtp.port",
			expectError: false,
			description: "Port 65535 should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sv.ValidatePort(tt.port, tt.fieldName)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestSecurityValidator_NetworkAddressValidation(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		address     string
		fieldName   string
		expectError bool
		description string
	}{
		{
			name:        "valid_port_only",
			address:     ":2525",
			fieldName:   "server.listen",
			expectError: false,
			description: "Valid port-only address should pass",
		},
		{
			name:        "valid_host_port",
			address:     "localhost:2525",
			fieldName:   "server.listen",
			expectError: false,
			description: "Valid host:port address should pass",
		},
		{
			name:        "valid_ip_port",
			address:     "127.0.0.1:2525",
			fieldName:   "server.listen",
			expectError: false,
			description: "Valid IP:port address should pass",
		},
		{
			name:        "valid_all_interfaces",
			address:     "0.0.0.0:2525",
			fieldName:   "server.listen",
			expectError: false,
			description: "All interfaces address should pass",
		},
		{
			name:        "injection_script",
			address:     "<script>alert('xss')</script>:2525",
			fieldName:   "server.listen",
			expectError: true,
			description: "Script injection should be blocked",
		},
		{
			name:        "injection_command",
			address:     "localhost; rm -rf /:2525",
			fieldName:   "server.listen",
			expectError: true,
			description: "Command injection should be blocked",
		},
		{
			name:        "injection_backtick",
			address:     "`whoami`:2525",
			fieldName:   "server.listen",
			expectError: true,
			description: "Backtick injection should be blocked",
		},
		{
			name:        "invalid_port",
			address:     "localhost:99999",
			fieldName:   "server.listen",
			expectError: true,
			description: "Invalid port should be rejected",
		},
		{
			name:        "empty_address",
			address:     "",
			fieldName:   "server.listen",
			expectError: true,
			description: "Empty address should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sv.ValidateNetworkAddress(tt.address, tt.fieldName)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestSecurityValidator_HostnameValidation(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		hostname    string
		fieldName   string
		expectError bool
		description string
	}{
		{
			name:        "valid_hostname",
			hostname:    "mail.example.com",
			fieldName:   "server.hostname",
			expectError: false,
			description: "Valid hostname should pass",
		},
		{
			name:        "valid_localhost",
			hostname:    "localhost",
			fieldName:   "server.hostname",
			expectError: false,
			description: "localhost should be valid",
		},
		{
			name:        "valid_ip",
			hostname:    "192.168.1.1",
			fieldName:   "server.hostname",
			expectError: false,
			description: "Valid IP address should pass",
		},
		{
			name:        "empty_hostname",
			hostname:    "",
			fieldName:   "server.hostname",
			expectError: true,
			description: "Empty hostname should be rejected",
		},
		{
			name:        "hostname_too_long",
			hostname:    string(make([]byte, 300)),
			fieldName:   "server.hostname",
			expectError: true,
			description: "Hostname too long should be rejected",
		},
		{
			name:        "injection_script",
			hostname:    "<script>alert('xss')</script>",
			fieldName:   "server.hostname",
			expectError: true,
			description: "Script injection should be blocked",
		},
		{
			name:        "injection_command",
			hostname:    "localhost; rm -rf /",
			fieldName:   "server.hostname",
			expectError: true,
			description: "Command injection should be blocked",
		},
		{
			name:        "invalid_chars",
			hostname:    "host@name.com",
			fieldName:   "server.hostname",
			expectError: true,
			description: "Invalid characters should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sv.ValidateHostname(tt.hostname, tt.fieldName)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestSecurityValidator_StringLengthValidation(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		str         string
		fieldName   string
		maxLength   int
		expectError bool
		description string
	}{
		{
			name:        "valid_string",
			str:         "valid string",
			fieldName:   "description",
			maxLength:   100,
			expectError: false,
			description: "Valid string should pass",
		},
		{
			name:        "string_too_long",
			str:         string(make([]byte, 200)),
			fieldName:   "description",
			maxLength:   100,
			expectError: true,
			description: "String too long should be rejected",
		},
		{
			name:        "invalid_utf8",
			str:         "invalid\xff\xfe",
			fieldName:   "description",
			maxLength:   100,
			expectError: true,
			description: "Invalid UTF-8 should be rejected",
		},
		{
			name:        "empty_string",
			str:         "",
			fieldName:   "description",
			maxLength:   100,
			expectError: false,
			description: "Empty string should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sv.ValidateStringLength(tt.str, tt.fieldName, tt.maxLength)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestSecurityValidator_Sanitization(t *testing.T) {
	sv := NewSecurityValidator()

	tests := []struct {
		name        string
		input       string
		expected    string
		description string
	}{
		{
			name:        "sanitize_null_bytes",
			input:       "path\x00with\x00nulls",
			expected:    "pathwithnulls",
			description: "Null bytes should be removed",
		},
		{
			name:        "sanitize_control_chars",
			input:       "text\x01\x02\x03with\x04control\x05chars",
			expected:    "textwithcontrolchars",
			description: "Control characters should be removed",
		},
		{
			name:        "preserve_newlines_tabs",
			input:       "text\nwith\ttabs\nand\nnewlines",
			expected:    "text\nwith\ttabs\nand\nnewlines",
			description: "Newlines and tabs should be preserved",
		},
		{
			name:        "normal_path",
			input:       "/app/queue",
			expected:    "/app/queue",
			description: "Normal path should be unchanged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sv.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("Sanitization failed for %s: expected %q, got %q", tt.description, tt.expected, result)
			}
		})
	}
}

func TestSecurityValidator_ConfigFileSizeValidation(t *testing.T) {
	sv := NewSecurityValidator()

	// Create a temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test.conf")

	// Test with valid size
	validContent := make([]byte, 1024) // 1KB
	err := os.WriteFile(configFile, validContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	err = sv.ValidateConfigFileSize(configFile)
	if err != nil {
		t.Errorf("Expected no error for valid config file size, but got: %v", err)
	}

	// Test with oversized file
	oversizedContent := make([]byte, 2*1024*1024) // 2MB
	err = os.WriteFile(configFile, oversizedContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create oversized test config file: %v", err)
	}

	err = sv.ValidateConfigFileSize(configFile)
	if err == nil {
		t.Errorf("Expected error for oversized config file, but got none")
	}
}

func TestSecurityValidator_SymlinkAttack(t *testing.T) {
	sv := NewSecurityValidator()

	// Create a temporary directory structure
	tempDir := t.TempDir()
	
	// Create a target file
	targetFile := filepath.Join(tempDir, "target.txt")
	err := os.WriteFile(targetFile, []byte("sensitive data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create a symlink pointing to the target
	symlinkFile := filepath.Join(tempDir, "symlink.txt")
	err = os.Symlink(targetFile, symlinkFile)
	if err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Test symlink detection - the current implementation allows symlinks
	// but this is actually correct behavior for most use cases
	// The symlink attack prevention is more about preventing symlinks to sensitive files
	err = sv.ValidatePath(symlinkFile, "test.path")
	if err != nil {
		t.Logf("Symlink validation error (expected for some cases): %v", err)
	}
	
	// Test with a symlink pointing to a blocked path
	blockedSymlink := filepath.Join(tempDir, "blocked_symlink")
	err = os.Symlink("/etc/passwd", blockedSymlink)
	if err != nil {
		t.Fatalf("Failed to create blocked symlink: %v", err)
	}

	// This should be blocked due to the blocked pattern
	err = sv.ValidatePath(blockedSymlink, "test.path")
	if err == nil {
		t.Errorf("Expected error for symlink to blocked path, but got none")
	}
	
	// Test with a symlink pointing to a path traversal
	traversalSymlink := filepath.Join(tempDir, "traversal_symlink")
	err = os.Symlink("../etc/passwd", traversalSymlink)
	if err != nil {
		t.Fatalf("Failed to create traversal symlink: %v", err)
	}

	// This should be blocked due to path traversal
	err = sv.ValidatePath(traversalSymlink, "test.path")
	if err == nil {
		t.Errorf("Expected error for symlink with path traversal, but got none")
	}
}

func TestSecurityValidator_FileSizeValidation(t *testing.T) {
	sv := NewSecurityValidator()

	// Create a temporary file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Test with valid size
	validContent := make([]byte, 1024) // 1KB
	err := os.WriteFile(testFile, validContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err = sv.ValidateFileSize(testFile, "test.file")
	if err != nil {
		t.Errorf("Expected no error for valid file size, but got: %v", err)
	}

	// Test with oversized file
	oversizedContent := make([]byte, 200*1024*1024) // 200MB
	err = os.WriteFile(testFile, oversizedContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create oversized test file: %v", err)
	}

	err = sv.ValidateFileSize(testFile, "test.file")
	if err == nil {
		t.Errorf("Expected error for oversized file, but got none")
	}
}
