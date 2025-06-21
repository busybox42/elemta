package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/busybox42/elemta/internal/smtp"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server struct {
		Hostname string `yaml:"hostname" toml:"hostname"`
		Listen   string `yaml:"listen" toml:"listen"`
		MaxSize  int64  `yaml:"max_size" toml:"max_size"`
		TLS      bool   `yaml:"tls" toml:"tls"`
		CertFile string `yaml:"cert_file" toml:"cert_file"`
		KeyFile  string `yaml:"key_file" toml:"key_file"`
	} `yaml:"server" toml:"server"`

	// Enhanced TLS configuration
	TLS *smtp.TLSConfig `yaml:"tls" toml:"tls"`

	// Queue configuration
	Queue struct {
		Dir string `yaml:"dir" toml:"dir"`
	} `yaml:"queue" toml:"queue"`

	// Logging configuration
	Logging struct {
		Level  string `yaml:"level" toml:"level"`
		Format string `yaml:"format" toml:"format"`
		File   string `yaml:"file" toml:"file"`
	} `yaml:"logging" toml:"logging"`

	// Plugins configuration
	Plugins struct {
		Directory string   `yaml:"directory" toml:"directory"`
		Enabled   []string `yaml:"enabled" toml:"enabled"`
	} `yaml:"plugins" toml:"plugins"`

	// Modern SMTP authentication config for Go SMTP server
	Auth *smtp.AuthConfig `yaml:"auth" toml:"auth"`

	// Queue processor configuration
	QueueProcessor struct {
		Enabled  bool `yaml:"enabled" toml:"enabled"`
		Interval int  `yaml:"interval" toml:"interval"`
		Workers  int  `yaml:"workers" toml:"workers"`
		Debug    bool `yaml:"debug" toml:"debug"`
	} `yaml:"queue_processor" toml:"queue_processor"`

	// Delivery configuration
	Delivery *smtp.DeliveryConfig `yaml:"delivery" toml:"delivery"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	cfg := &Config{}

	// Set default server configuration
	cfg.Server.Hostname = "localhost"
	cfg.Server.Listen = ":2525"
	cfg.Server.MaxSize = 25 * 1024 * 1024 // 25MB default
	cfg.Server.TLS = false

	// Set default queue directory
	cfg.Queue.Dir = "/app/queue"

	// Set default logging
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "text"

	// Set default plugins directory
	cfg.Plugins.Directory = "/app/plugins"

	// Set default queue processor configuration
	cfg.QueueProcessor.Enabled = true
	cfg.QueueProcessor.Interval = 10
	cfg.QueueProcessor.Workers = 5
	cfg.QueueProcessor.Debug = false

	return cfg
}

// FindConfigFile looks for a configuration file in common locations
func FindConfigFile(configPath string) (string, error) {
	// If a specific path is provided, check only that
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
		return "", fmt.Errorf("config file not found at specified path: %s", configPath)
	}

	// List of places to check for config
	locations := []string{
		"./elemta.conf",
		"./config/elemta.conf",
		"../config/elemta.conf",
		os.ExpandEnv("$HOME/.elemta.conf"),
		"/etc/elemta/elemta.conf",
	}

	for _, loc := range locations {
		fmt.Printf("Checking for config at: %s\n", loc)
		if _, err := os.Stat(loc); err == nil {
			fmt.Printf("Found config at: %s\n", loc)
			return loc, nil
		}
	}

	return "", fmt.Errorf("no config file found")
}

// LoadConfig loads a configuration from a file
func LoadConfig(configPath string) (*Config, error) {
	// Get default configuration
	cfg := DefaultConfig()

	// Try to find the config file
	configFile, err := FindConfigFile(configPath)
	if err != nil {
		fmt.Println("No config file found, using defaults")
		return cfg, nil
	}

	// Read the file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	fmt.Printf("[DEBUG] Raw config file contents:\n%s\n", string(data))

	// Pre-initialize TLS pointer for TOML mapping
	cfg.TLS = &smtp.TLSConfig{}

	// Try to parse the file as TOML first (preferred format)
	tomlErr := toml.Unmarshal(data, cfg)
	if tomlErr == nil {
		fmt.Println("Configuration loaded successfully (TOML format)")
	} else {
		// If TOML parsing fails, try YAML for backward compatibility
		yamlErr := yaml.Unmarshal(data, cfg)
		if yamlErr == nil {
			fmt.Println("Configuration loaded successfully (YAML format - consider migrating to TOML)")
		} else {
			// For better debugging, print the exact errors
			fmt.Printf("TOML error: %v\n", tomlErr)
			fmt.Printf("YAML error: %v\n", yamlErr)

			// Include both errors in the returned error
			return nil, fmt.Errorf("error loading configuration: error parsing config (tried TOML and YAML): %v", tomlErr)
		}
	}

	// Make sure queue directory is set
	if cfg.Queue.Dir == "" {
		cfg.Queue.Dir = "/app/queue"
	}

	// Use absolute path for queue directory
	if !filepath.IsAbs(cfg.Queue.Dir) {
		// If it's relative to the config file, make it absolute
		configDir := filepath.Dir(configFile)
		cfg.Queue.Dir = filepath.Join(configDir, cfg.Queue.Dir)
	}

	// After parsing config, ensure TLS config is non-nil
	if cfg.TLS == nil {
		cfg.TLS = &smtp.TLSConfig{}
	}
	if cfg.TLS.LetsEncrypt == nil {
		cfg.TLS.LetsEncrypt = &smtp.LetsEncryptConfig{}
	}
	if cfg.TLS.RenewalConfig == nil {
		cfg.TLS.RenewalConfig = &smtp.CertRenewalConfig{}
	}

	fmt.Printf("Configuration loaded successfully. Hostname: %s, Listen: %s\n",
		cfg.Server.Hostname, cfg.Server.Listen)

	return cfg, nil
}

// EnsureQueueDirectory ensures that the queue directories exist
func (c *Config) EnsureQueueDirectory() error {
	// Make sure the main queue directory exists
	if err := os.MkdirAll(c.Queue.Dir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Create subdirectories for different queue types
	queueTypes := []string{"active", "deferred", "hold", "failed"}
	for _, qType := range queueTypes {
		qDir := filepath.Join(c.Queue.Dir, qType)
		if err := os.MkdirAll(qDir, 0755); err != nil {
			return fmt.Errorf("failed to create %s queue directory: %w", qType, err)
		}
	}

	return nil
}

// SaveConfig saves the configuration to a file in TOML format
func (c *Config) SaveConfig(configPath string) error {
	// Create proper TOML format manually since marshaling has issues with nested structs
	tomlContent := fmt.Sprintf(`# Elemta SMTP Server Configuration

[server]
hostname = "%s"
listen = "%s"
tls = %t
cert_file = "%s"
key_file = "%s"

[queue]
dir = "%s"

[logging]
level = "%s"
format = "%s"
file = "%s"

[plugins]
directory = "%s"
enabled = []

[queue_processor]
enabled = %t
interval = %d
workers = %d
debug = %t

# TLS Configuration (uncomment and configure as needed)
# [tls]
# enabled = false
# enable_starttls = true

# Authentication Configuration (uncomment and configure as needed)
# [auth] 
# enabled = true
# required = false
# datasource_type = "file"       # Options: file, ldap, mysql, postgres, sqlite
# datasource_path = "/app/config/users.txt"

# For LDAP authentication:
# [auth]
# enabled = true
# datasource_type = "ldap"
# datasource_host = "localhost" 
# datasource_port = 1389
# datasource_user = "cn=admin,dc=example,dc=com"
# datasource_pass = "admin"

# Delivery Configuration (uncomment and configure as needed)
# [delivery]
# mode = "smtp"
# timeout = 30
`,
		c.Server.Hostname,
		c.Server.Listen,
		c.Server.TLS,
		c.Server.CertFile,
		c.Server.KeyFile,
		c.Queue.Dir,
		c.Logging.Level,
		c.Logging.Format,
		c.Logging.File,
		c.Plugins.Directory,
		c.QueueProcessor.Enabled,
		c.QueueProcessor.Interval,
		c.QueueProcessor.Workers,
		c.QueueProcessor.Debug,
	)

	// Make sure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("config validation error in field '%s': %s (current value: %v)", e.Field, e.Message, e.Value)
}

// ValidationResult holds the results of configuration validation
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
	Valid    bool
}

// AddError adds a validation error
func (vr *ValidationResult) AddError(field string, value interface{}, message string) {
	vr.Errors = append(vr.Errors, ValidationError{Field: field, Value: value, Message: message})
	vr.Valid = false
}

// AddWarning adds a validation warning
func (vr *ValidationResult) AddWarning(field string, value interface{}, message string) {
	vr.Warnings = append(vr.Warnings, ValidationError{Field: field, Value: value, Message: message})
}

// Validate performs comprehensive validation of the configuration
func (c *Config) Validate() *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Validate server configuration
	c.validateServer(result)

	// Validate TLS configuration
	c.validateTLS(result)

	// Validate queue configuration
	c.validateQueue(result)

	// Validate logging configuration
	c.validateLogging(result)

	// Validate plugins configuration
	c.validatePlugins(result)

	// Validate authentication configuration
	c.validateAuth(result)

	// Validate queue processor configuration
	c.validateQueueProcessor(result)

	// Validate delivery configuration
	c.validateDelivery(result)

	return result
}

// validateServer validates server configuration
func (c *Config) validateServer(result *ValidationResult) {
	// Validate hostname
	if c.Server.Hostname == "" {
		result.AddError("server.hostname", c.Server.Hostname, "hostname is required")
	} else {
		// Check if hostname is valid
		if !isValidHostname(c.Server.Hostname) {
			result.AddError("server.hostname", c.Server.Hostname, "invalid hostname format")
		}
	}

	// Validate listen address
	if c.Server.Listen == "" {
		result.AddError("server.listen", c.Server.Listen, "listen address is required")
	} else {
		if !isValidListenAddress(c.Server.Listen) {
			result.AddError("server.listen", c.Server.Listen, "invalid listen address format (expected :port or host:port)")
		}
	}

	// Validate TLS certificate files if TLS is enabled
	if c.Server.TLS {
		if c.Server.CertFile == "" {
			result.AddError("server.cert_file", c.Server.CertFile, "cert_file is required when TLS is enabled")
		} else if !fileExists(c.Server.CertFile) {
			result.AddWarning("server.cert_file", c.Server.CertFile, "certificate file does not exist")
		}

		if c.Server.KeyFile == "" {
			result.AddError("server.key_file", c.Server.KeyFile, "key_file is required when TLS is enabled")
		} else if !fileExists(c.Server.KeyFile) {
			result.AddWarning("server.key_file", c.Server.KeyFile, "private key file does not exist")
		}
	}
}

// validateTLS validates TLS configuration
func (c *Config) validateTLS(result *ValidationResult) {
	if c.TLS == nil {
		return // TLS config is optional
	}

	// If Let's Encrypt is configured, validate settings
	if c.TLS.LetsEncrypt != nil && c.TLS.LetsEncrypt.Enabled {
		if c.TLS.LetsEncrypt.Email == "" {
			result.AddError("tls.letsencrypt.email", c.TLS.LetsEncrypt.Email, "email is required for Let's Encrypt")
		} else if !isValidEmail(c.TLS.LetsEncrypt.Email) {
			result.AddError("tls.letsencrypt.email", c.TLS.LetsEncrypt.Email, "invalid email format")
		}

		if c.TLS.LetsEncrypt.Domain == "" {
			result.AddError("tls.letsencrypt.domain", c.TLS.LetsEncrypt.Domain, "domain is required for Let's Encrypt")
		} else if !isValidHostname(c.TLS.LetsEncrypt.Domain) {
			result.AddError("tls.letsencrypt.domain", c.TLS.LetsEncrypt.Domain, "invalid domain format")
		}

		if c.TLS.LetsEncrypt.CacheDir == "" {
			result.AddWarning("tls.letsencrypt.cache_dir", c.TLS.LetsEncrypt.CacheDir, "cache_dir not set, using default")
		}
	}
}

// validateQueue validates queue configuration
func (c *Config) validateQueue(result *ValidationResult) {
	if c.Queue.Dir == "" {
		result.AddError("queue.dir", c.Queue.Dir, "queue directory is required")
		return
	}

	// Check if queue directory exists or can be created
	if !dirExists(c.Queue.Dir) {
		// Try to create it
		if err := os.MkdirAll(c.Queue.Dir, 0755); err != nil {
			result.AddError("queue.dir", c.Queue.Dir, fmt.Sprintf("cannot create queue directory: %v", err))
		} else {
			result.AddWarning("queue.dir", c.Queue.Dir, "queue directory was created")
		}
	}

	// Check if directory is writable
	if !isWritableDir(c.Queue.Dir) {
		result.AddError("queue.dir", c.Queue.Dir, "queue directory is not writable")
	}
}

// validateLogging validates logging configuration
func (c *Config) validateLogging(result *ValidationResult) {
	// Validate log level
	validLevels := []string{"debug", "info", "warn", "error"}
	if c.Logging.Level != "" && !contains(validLevels, c.Logging.Level) {
		result.AddError("logging.level", c.Logging.Level, fmt.Sprintf("invalid log level, must be one of: %s", strings.Join(validLevels, ", ")))
	}

	// Validate log format
	validFormats := []string{"text", "json"}
	if c.Logging.Format != "" && !contains(validFormats, c.Logging.Format) {
		result.AddError("logging.format", c.Logging.Format, fmt.Sprintf("invalid log format, must be one of: %s", strings.Join(validFormats, ", ")))
	}

	// Validate log file path if specified
	if c.Logging.File != "" {
		logDir := filepath.Dir(c.Logging.File)
		if !dirExists(logDir) {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				result.AddError("logging.file", c.Logging.File, fmt.Sprintf("cannot create log directory: %v", err))
			}
		}
	}
}

// validatePlugins validates plugins configuration
func (c *Config) validatePlugins(result *ValidationResult) {
	if c.Plugins.Directory == "" {
		result.AddWarning("plugins.directory", c.Plugins.Directory, "plugins directory not set, plugins will be disabled")
		return
	}

	// Check if plugins directory exists
	if !dirExists(c.Plugins.Directory) {
		result.AddWarning("plugins.directory", c.Plugins.Directory, "plugins directory does not exist")
	}

	// Validate enabled plugins
	for i, plugin := range c.Plugins.Enabled {
		if plugin == "" {
			result.AddError(fmt.Sprintf("plugins.enabled[%d]", i), plugin, "plugin name cannot be empty")
		}

		// Check if plugin file exists
		pluginPath := filepath.Join(c.Plugins.Directory, plugin+".so")
		if !fileExists(pluginPath) {
			result.AddWarning(fmt.Sprintf("plugins.enabled[%d]", i), plugin, fmt.Sprintf("plugin file not found: %s", pluginPath))
		}
	}
}

// validateAuth validates authentication configuration
func (c *Config) validateAuth(result *ValidationResult) {
	if c.Auth == nil {
		result.AddWarning("auth", nil, "authentication not configured, server will run without authentication")
		return
	}

	// Validate datasource type
	validTypes := []string{"file", "ldap", "mysql", "postgres", "sqlite"}
	if c.Auth.DataSourceType != "" && !contains(validTypes, c.Auth.DataSourceType) {
		result.AddError("auth.datasource_type", c.Auth.DataSourceType, fmt.Sprintf("invalid datasource type, must be one of: %s", strings.Join(validTypes, ", ")))
	}

	// Validate datasource-specific settings
	switch c.Auth.DataSourceType {
	case "file":
		if c.Auth.DataSourcePath == "" {
			result.AddError("auth.datasource_path", c.Auth.DataSourcePath, "datasource_path is required for file authentication")
		} else if !fileExists(c.Auth.DataSourcePath) {
			result.AddWarning("auth.datasource_path", c.Auth.DataSourcePath, "authentication file does not exist")
		}

	case "ldap":
		if c.Auth.DataSourceHost == "" {
			result.AddError("auth.datasource_host", c.Auth.DataSourceHost, "datasource_host is required for LDAP authentication")
		}
		if c.Auth.DataSourcePort <= 0 || c.Auth.DataSourcePort > 65535 {
			result.AddError("auth.datasource_port", c.Auth.DataSourcePort, "invalid LDAP port (must be 1-65535)")
		}

	case "mysql", "postgres":
		if c.Auth.DataSourceHost == "" {
			result.AddError("auth.datasource_host", c.Auth.DataSourceHost, fmt.Sprintf("datasource_host is required for %s authentication", c.Auth.DataSourceType))
		}
		if c.Auth.DataSourcePort <= 0 || c.Auth.DataSourcePort > 65535 {
			result.AddError("auth.datasource_port", c.Auth.DataSourcePort, "invalid database port (must be 1-65535)")
		}
		if c.Auth.DataSourceUser == "" {
			result.AddError("auth.datasource_user", c.Auth.DataSourceUser, fmt.Sprintf("datasource_user is required for %s authentication", c.Auth.DataSourceType))
		}

	case "sqlite":
		if c.Auth.DataSourcePath == "" {
			result.AddError("auth.datasource_path", c.Auth.DataSourcePath, "datasource_path is required for SQLite authentication")
		}
	}
}

// validateQueueProcessor validates queue processor configuration
func (c *Config) validateQueueProcessor(result *ValidationResult) {
	if c.QueueProcessor.Workers <= 0 {
		result.AddError("queue_processor.workers", c.QueueProcessor.Workers, "workers must be greater than 0")
	} else if c.QueueProcessor.Workers > 100 {
		result.AddWarning("queue_processor.workers", c.QueueProcessor.Workers, "high number of workers may impact performance")
	}

	if c.QueueProcessor.Interval <= 0 {
		result.AddError("queue_processor.interval", c.QueueProcessor.Interval, "interval must be greater than 0")
	} else if c.QueueProcessor.Interval < 5 {
		result.AddWarning("queue_processor.interval", c.QueueProcessor.Interval, "very short interval may impact performance")
	}
}

// validateDelivery validates delivery configuration
func (c *Config) validateDelivery(result *ValidationResult) {
	if c.Delivery == nil {
		return // Delivery config is optional
	}

	// Validate delivery mode
	validModes := []string{"smtp", "lmtp", "local"}
	if c.Delivery.Mode != "" && !contains(validModes, c.Delivery.Mode) {
		result.AddError("delivery.mode", c.Delivery.Mode, fmt.Sprintf("invalid delivery mode, must be one of: %s", strings.Join(validModes, ", ")))
	}

	// Validate timeout
	if c.Delivery.Timeout <= 0 {
		result.AddError("delivery.timeout", c.Delivery.Timeout, "timeout must be greater than 0")
	} else if c.Delivery.Timeout > 300 {
		result.AddWarning("delivery.timeout", c.Delivery.Timeout, "very long timeout may cause delays")
	}
}

// Helper functions for validation

func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Allow localhost and IP addresses
	if hostname == "localhost" || net.ParseIP(hostname) != nil {
		return true
	}

	// Validate domain name format
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return hostnameRegex.MatchString(hostname)
}

func isValidListenAddress(addr string) bool {
	// Handle :port format
	if strings.HasPrefix(addr, ":") {
		portStr := addr[1:]
		port, err := strconv.Atoi(portStr)
		return err == nil && port > 0 && port <= 65535
	}

	// Handle host:port format
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return false
	}

	// Validate host (can be empty for all interfaces)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}

	return isValidHostname(host) || net.ParseIP(host) != nil
}

func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isWritableDir(path string) bool {
	// Try to create a temporary file
	testFile := filepath.Join(path, ".write_test")
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(testFile)
	return true
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CreateDefaultConfig creates a default configuration file
func CreateDefaultConfig(configPath string) error {
	// Check if file already exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists at %s", configPath)
	}

	// Create default config
	cfg := DefaultConfig()

	// Save to file
	return cfg.SaveConfig(configPath)
}
