package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaliciousConfigFiles(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		expectError bool
		description string
	}{
		{
			name: "path_traversal_queue_dir",
			content: `[server]
hostname = "localhost"
listen = ":2525"

[queue]
dir = "/app/../etc/passwd"`,
			expectError: true,
			description: "Path traversal in queue directory should be blocked",
		},
		{
			name: "path_traversal_cert_file",
			content: `[server]
hostname = "localhost"
listen = ":2525"
tls = true
cert_file = "/app/../etc/ssl/private/server.key"
key_file = "/app/../etc/ssl/private/server.key"`,
			expectError: true,
			description: "Path traversal in certificate files should be blocked",
		},
		{
			name: "injection_in_hostname",
			content: `[server]
hostname = "localhost; rm -rf /"
listen = ":2525"`,
			expectError: true,
			description: "Command injection in hostname should be blocked",
		},
		{
			name: "injection_in_listen_address",
			content: `[server]
hostname = "localhost"
listen = "localhost:2525; cat /etc/passwd"`,
			expectError: true,
			description: "Command injection in listen address should be blocked",
		},
		{
			name: "oversized_max_size",
			content: `[server]
hostname = "localhost"
listen = ":2525"
max_size = 999999999999999999`,
			expectError: true,
			description: "Oversized max_size should be blocked",
		},
		{
			name: "negative_workers",
			content: `[queue_processor]
enabled = true
workers = -100
interval = 10`,
			expectError: true,
			description: "Negative workers should be blocked",
		},
		{
			name: "invalid_port",
			content: `[server]
hostname = "localhost"
listen = "localhost:99999"`,
			expectError: true,
			description: "Invalid port should be blocked",
		},
		{
			name: "blocked_path_pattern",
			content: `[queue]
dir = "/etc/passwd"`,
			expectError: true,
			description: "Blocked path patterns should be rejected",
		},
		{
			name: "script_injection_hostname",
			content: `[server]
hostname = "<script>alert('xss')</script>"
listen = ":2525"`,
			expectError: true,
			description: "Script injection in hostname should be blocked",
		},
		{
			name: "backtick_injection",
			content: `[server]
hostname = "` + "`whoami`" + `"
listen = ":2525"`,
			expectError: true,
			description: "Backtick injection should be blocked",
		},
		{
			name: "null_bytes_in_path",
			content: `[queue]
dir = "/app/queue\x00/etc/passwd"`,
			expectError: true,
			description: "Null bytes in paths should be blocked",
		},
		{
			name: "oversized_config_file",
			content: func() string {
				// Create a config with a very large string
				largeString := make([]byte, 2*1024*1024) // 2MB
				for i := range largeString {
					largeString[i] = 'a'
				}
				return `[server]
hostname = "` + string(largeString) + `"
listen = ":2525"`
			}(),
			expectError: true,
			description: "Oversized config file should be blocked",
		},
		{
			name: "valid_config",
			content: func() string {
				return `[server]
hostname = "mail.example.com"
listen = ":2525"
max_size = 10485760

[queue]
dir = "` + tempDir + `/queue"

[logging]
type = "console"
level = "info"
format = "text"`
			}(),
			expectError: false,
			description: "Valid configuration should pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			configFile := filepath.Join(tempDir, tt.name+".conf")
			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			// Try to load the configuration
			_, err = LoadConfig(configFile)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestConfigurationValidationIntegration(t *testing.T) {
	tempDir := t.TempDir()

	// Create a valid config file
	validConfig := `[server]
hostname = "mail.example.com"
listen = ":2525"
listen_submission = ":587"
max_size = 10485760
local_domains = ["example.com", "mail.example.com"]

[tls]
enabled = true
enable_starttls = true
cert_file = "` + tempDir + `/certs/test.crt"
key_file = "` + tempDir + `/certs/test.key"

[queue]
dir = "` + tempDir + `/queue"

[logging]
type = "console"
level = "info"
format = "json"

[plugins]
directory = "` + tempDir + `/plugins"
enabled = ["clamav", "rspamd"]

[auth]
enabled = true
required = false
datasource_type = "ldap"
datasource_host = "ldap.example.com"
datasource_port = 389
datasource_user = "cn=admin,dc=example,dc=com"
datasource_pass = "admin"
datasource_db = "dc=example,dc=com"

[queue_processor]
enabled = true
interval = 10
workers = 5
debug = false

[delivery]
mode = "lmtp"
host = "dovecot.example.com"
port = 2424
timeout = 30
max_retries = 3
retry_delay = 60

[metrics]
enabled = true
listen_addr = ":8080"`

	configFile := filepath.Join(tempDir, "valid.conf")
	err := os.WriteFile(configFile, []byte(validConfig), 0600) // Use 0600 for security validation
	if err != nil {
		t.Fatalf("Failed to create valid config file: %v", err)
	}

	// Load and validate the configuration
	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load valid configuration: %v", err)
	}

	// Verify the configuration was loaded correctly
	if cfg.Server.Hostname != "mail.example.com" {
		t.Errorf("Expected hostname 'mail.example.com', got '%s'", cfg.Server.Hostname)
	}

	if cfg.Server.Listen != ":2525" {
		t.Errorf("Expected listen address ':2525', got '%s'", cfg.Server.Listen)
	}

	if cfg.Server.MaxSize != 10485760 {
		t.Errorf("Expected max size 10485760, got %d", cfg.Server.MaxSize)
	}

	if len(cfg.Server.LocalDomains) != 2 {
		t.Errorf("Expected 2 local domains, got %d", len(cfg.Server.LocalDomains))
	}

	if cfg.TLS == nil || !cfg.TLS.Enabled {
		t.Error("Expected TLS to be enabled")
	}

	expectedQueueDir := tempDir + "/queue"
	if cfg.Queue.Dir != expectedQueueDir {
		t.Errorf("Expected queue dir '%s', got '%s'", expectedQueueDir, cfg.Queue.Dir)
	}

	if cfg.Auth == nil || !cfg.Auth.Enabled {
		t.Error("Expected authentication to be enabled")
	}

	if cfg.QueueProcessor.Workers != 5 {
		t.Errorf("Expected 5 queue processor workers, got %d", cfg.QueueProcessor.Workers)
	}
}

func TestConfigurationSecurityBoundaries(t *testing.T) {
	tempDir := t.TempDir()

	// Test various boundary conditions
	boundaryTests := []struct {
		name        string
		content     string
		expectError bool
		description string
	}{
		{
			name: "max_size_boundary_valid",
			content: func() string {
				return `[server]
hostname = "localhost"
listen = ":2525"
max_size = 104857600

[queue]
dir = "` + tempDir + `/queue"`
			}(),
			expectError: false,
			description: "Max size at boundary should be valid",
		},
		{
			name: "max_size_boundary_invalid",
			content: `[server]
hostname = "localhost"
listen = ":2525"
max_size = 104857601`,
			expectError: true,
			description: "Max size over boundary should be invalid",
		},
		{
			name: "workers_boundary_valid",
			content: func() string {
				return `[queue_processor]
enabled = true
workers = 1000
interval = 10

[queue]
dir = "` + tempDir + `/queue"`
			}(),
			expectError: false,
			description: "Workers at boundary should be valid",
		},
		{
			name: "workers_boundary_invalid",
			content: `[queue_processor]
enabled = true
workers = 1001
interval = 10`,
			expectError: true,
			description: "Workers over boundary should be invalid",
		},
		{
			name: "port_boundary_valid",
			content: func() string {
				return `[server]
hostname = "localhost"
listen = "localhost:65535"

[queue]
dir = "` + tempDir + `/queue"`
			}(),
			expectError: false,
			description: "Port at boundary should be valid",
		},
		{
			name: "port_boundary_invalid",
			content: `[server]
hostname = "localhost"
listen = "localhost:65536"`,
			expectError: true,
			description: "Port over boundary should be invalid",
		},
	}

	for _, tt := range boundaryTests {
		t.Run(tt.name, func(t *testing.T) {
			configFile := filepath.Join(tempDir, tt.name+".conf")
			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			_, err = LoadConfig(configFile)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}
