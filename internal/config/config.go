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

	toml "github.com/pelletier/go-toml/v2"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server struct {
		Hostname         string   `toml:"hostname"`
		Listen           string   `toml:"listen"`
		ListenSubmission string   `toml:"listen_submission"`
		MaxSize          int64    `toml:"max_size"`
		LocalDomains     []string `toml:"local_domains"`
		TLS              bool     `toml:"tls"`
		CertFile         string   `toml:"cert_file"`
		KeyFile          string   `toml:"key_file"`
	} `toml:"server"`

	// Enhanced TLS configuration
	TLS *smtp.TLSConfig `toml:"tls"`

	// Queue configuration
	Queue struct {
		Dir string `toml:"dir"`
	} `toml:"queue"`

	// Logging configuration
	Logging struct {
		Type    string                 `toml:"type"` // "console", "file", "elastic"
		Level   string                 `toml:"level"`
		Format  string                 `toml:"format"`
		File    string                 `toml:"file"`
		Output  string                 `toml:"output"`  // For elastic: URL, for file: path
		Options map[string]interface{} `toml:"options"` // Additional options like index, bufferSize
	} `toml:"logging"`

	// Plugins configuration
	Plugins struct {
		Directory string   `toml:"directory"`
		Enabled   []string `toml:"enabled"`
	} `toml:"plugins"`

	// Modern SMTP authentication config for Go SMTP server
	Auth *smtp.AuthConfig `toml:"auth"`

	// Queue processor configuration
	QueueProcessor struct {
		Enabled  bool `toml:"enabled"`
		Interval int  `toml:"interval"`
		Workers  int  `toml:"workers"`
		Debug    bool `toml:"debug"`
	} `toml:"queue_processor"`

	// Delivery configuration
	Delivery *smtp.DeliveryConfig `toml:"delivery"`

	// Metrics configuration
	Metrics *smtp.MetricsConfig `toml:"metrics"`
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
	cfg.Logging.Type = "console"
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
	securityValidator := NewSecurityValidator()

	// Try to find the config file
	configFile, err := FindConfigFile(configPath)
	if err != nil {
		fmt.Println("No config file found, using defaults")
		return cfg, nil
	}

	// Validate config file size before reading
	if err := securityValidator.ValidateConfigFileSize(configFile); err != nil {
		return nil, fmt.Errorf("config file security validation failed: %w", err)
	}

	// Read the file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Validate config file content size
	if len(data) > int(securityValidator.config.MaxConfigFileSize) {
		return nil, fmt.Errorf("config file too large: %d bytes (max: %d)", len(data), securityValidator.config.MaxConfigFileSize)
	}

	fmt.Printf("[DEBUG] Raw config file contents:\n%s\n", string(data))

	// Pre-initialize TLS pointer for TOML mapping
	cfg.TLS = &smtp.TLSConfig{}

	// Parse TOML configuration only
	err = toml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("error parsing TOML configuration: %w", err)
	}

	fmt.Println("Configuration loaded successfully (TOML format)")

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

	// Perform comprehensive security validation
	validationResult := cfg.Validate()
	if !validationResult.Valid {
		var errorMessages []string
		for _, err := range validationResult.Errors {
			errorMessages = append(errorMessages, err.Error())
		}
		return nil, fmt.Errorf("configuration validation failed: %s", strings.Join(errorMessages, "; "))
	}

	// Log warnings if any
	if len(validationResult.Warnings) > 0 {
		fmt.Println("Configuration warnings:")
		for _, warning := range validationResult.Warnings {
			fmt.Printf("  WARNING: %s\n", warning.Error())
		}
	}

	fmt.Printf("Configuration loaded successfully. Hostname: %s, Listen: %s\n",
		cfg.Server.Hostname, cfg.Server.Listen)

	return cfg, nil
}

// EnsureQueueDirectory ensures that the queue directories exist with secure permissions
func (c *Config) EnsureQueueDirectory() error {
	// Make sure the main queue directory exists with secure permissions (0700)
	if err := os.MkdirAll(c.Queue.Dir, 0700); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Create subdirectories for different queue types with secure permissions
	queueTypes := []string{"active", "deferred", "hold", "failed", "data", "tmp", "quarantine"}
	for _, qType := range queueTypes {
		qDir := filepath.Join(c.Queue.Dir, qType)
		if err := os.MkdirAll(qDir, 0700); err != nil {
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
	securityValidator := NewSecurityValidator()

	// Validate server configuration
	c.validateServer(result, securityValidator)

	// Validate TLS configuration
	c.validateTLS(result, securityValidator)

	// Validate queue configuration
	c.validateQueue(result, securityValidator)

	// Validate logging configuration
	c.validateLogging(result, securityValidator)

	// Validate plugins configuration
	c.validatePlugins(result, securityValidator)

	// Validate authentication configuration
	c.validateAuth(result, securityValidator)

	// Validate queue processor configuration
	c.validateQueueProcessor(result, securityValidator)

	// Validate delivery configuration
	c.validateDelivery(result, securityValidator)

	return result
}

// validateServer validates server configuration
func (c *Config) validateServer(result *ValidationResult, sv *SecurityValidator) {
	// Validate hostname
	if c.Server.Hostname == "" {
		result.AddError("server.hostname", c.Server.Hostname, "hostname is required")
	} else {
		// Sanitize hostname
		c.Server.Hostname = sv.SanitizeString(c.Server.Hostname)

		// Validate hostname security
		if err := sv.ValidateHostname(c.Server.Hostname, "server.hostname"); err != nil {
			result.AddError("server.hostname", c.Server.Hostname, err.Error())
		}
	}

	// Validate listen address
	if c.Server.Listen == "" {
		result.AddError("server.listen", c.Server.Listen, "listen address is required")
	} else {
		// Sanitize listen address
		c.Server.Listen = sv.SanitizeString(c.Server.Listen)

		// Validate network address security
		if err := sv.ValidateNetworkAddress(c.Server.Listen, "server.listen"); err != nil {
			result.AddError("server.listen", c.Server.Listen, err.Error())
		}
	}

	// Validate listen submission address if provided
	if c.Server.ListenSubmission != "" {
		// Sanitize listen submission address
		c.Server.ListenSubmission = sv.SanitizeString(c.Server.ListenSubmission)

		// Validate network address security
		if err := sv.ValidateNetworkAddress(c.Server.ListenSubmission, "server.listen_submission"); err != nil {
			result.AddError("server.listen_submission", c.Server.ListenSubmission, err.Error())
		}
	}

	// Validate max size
	if err := sv.ValidateNumericBounds(c.Server.MaxSize, "server.max_size", 1024, sv.config.MaxFileSize); err != nil {
		result.AddError("server.max_size", c.Server.MaxSize, err.Error())
	}

	// Validate local domains
	for i, domain := range c.Server.LocalDomains {
		// Sanitize domain
		c.Server.LocalDomains[i] = sv.SanitizeString(domain)

		// Validate hostname security
		if err := sv.ValidateHostname(domain, fmt.Sprintf("server.local_domains[%d]", i)); err != nil {
			result.AddError(fmt.Sprintf("server.local_domains[%d]", i), domain, err.Error())
		}
	}

	// Validate TLS certificate files if TLS is enabled
	if c.Server.TLS {
		if c.Server.CertFile == "" {
			result.AddError("server.cert_file", c.Server.CertFile, "cert_file is required when TLS is enabled")
		} else {
			// Sanitize cert file path
			c.Server.CertFile = sv.SanitizePath(c.Server.CertFile)

			// Validate path security
			if err := sv.ValidatePath(c.Server.CertFile, "server.cert_file"); err != nil {
				result.AddError("server.cert_file", c.Server.CertFile, err.Error())
			} else if !fileExists(c.Server.CertFile) {
				result.AddWarning("server.cert_file", c.Server.CertFile, "certificate file does not exist")
			} else {
				// Validate file size
				if err := sv.ValidateFileSize(c.Server.CertFile, "server.cert_file"); err != nil {
					result.AddError("server.cert_file", c.Server.CertFile, err.Error())
				}
			}
		}

		if c.Server.KeyFile == "" {
			result.AddError("server.key_file", c.Server.KeyFile, "key_file is required when TLS is enabled")
		} else {
			// Sanitize key file path
			c.Server.KeyFile = sv.SanitizePath(c.Server.KeyFile)

			// Validate path security
			if err := sv.ValidatePath(c.Server.KeyFile, "server.key_file"); err != nil {
				result.AddError("server.key_file", c.Server.KeyFile, err.Error())
			} else if !fileExists(c.Server.KeyFile) {
				result.AddWarning("server.key_file", c.Server.KeyFile, "private key file does not exist")
			} else {
				// Validate file size
				if err := sv.ValidateFileSize(c.Server.KeyFile, "server.key_file"); err != nil {
					result.AddError("server.key_file", c.Server.KeyFile, err.Error())
				}
			}
		}
	}
}

// validateTLS validates TLS configuration
func (c *Config) validateTLS(result *ValidationResult, sv *SecurityValidator) {
	if c.TLS == nil {
		return // TLS config is optional
	}

	// Validate TLS listen address if provided
	if c.TLS.ListenAddr != "" {
		// Sanitize TLS listen address
		c.TLS.ListenAddr = sv.SanitizeString(c.TLS.ListenAddr)

		// Validate network address security
		if err := sv.ValidateNetworkAddress(c.TLS.ListenAddr, "tls.listen_addr"); err != nil {
			result.AddError("tls.listen_addr", c.TLS.ListenAddr, err.Error())
		}
	}

	// Validate TLS certificate files if provided
	if c.TLS.CertFile != "" {
		// Sanitize cert file path
		c.TLS.CertFile = sv.SanitizePath(c.TLS.CertFile)

		// Validate path security
		if err := sv.ValidatePath(c.TLS.CertFile, "tls.cert_file"); err != nil {
			result.AddError("tls.cert_file", c.TLS.CertFile, err.Error())
		} else if !fileExists(c.TLS.CertFile) {
			result.AddWarning("tls.cert_file", c.TLS.CertFile, "certificate file does not exist")
		} else {
			// Validate file size
			if err := sv.ValidateFileSize(c.TLS.CertFile, "tls.cert_file"); err != nil {
				result.AddError("tls.cert_file", c.TLS.CertFile, err.Error())
			}
		}
	}

	if c.TLS.KeyFile != "" {
		// Sanitize key file path
		c.TLS.KeyFile = sv.SanitizePath(c.TLS.KeyFile)

		// Validate path security
		if err := sv.ValidatePath(c.TLS.KeyFile, "tls.key_file"); err != nil {
			result.AddError("tls.key_file", c.TLS.KeyFile, err.Error())
		} else if !fileExists(c.TLS.KeyFile) {
			result.AddWarning("tls.key_file", c.TLS.KeyFile, "private key file does not exist")
		} else {
			// Validate file size
			if err := sv.ValidateFileSize(c.TLS.KeyFile, "tls.key_file"); err != nil {
				result.AddError("tls.key_file", c.TLS.KeyFile, err.Error())
			}
		}
	}

	// If Let's Encrypt is configured, validate settings
	if c.TLS.LetsEncrypt != nil && c.TLS.LetsEncrypt.Enabled {
		if c.TLS.LetsEncrypt.Email == "" {
			result.AddError("tls.letsencrypt.email", c.TLS.LetsEncrypt.Email, "email is required for Let's Encrypt")
		} else {
			// Sanitize email
			c.TLS.LetsEncrypt.Email = sv.SanitizeString(c.TLS.LetsEncrypt.Email)

			// Validate email format
			if !isValidEmail(c.TLS.LetsEncrypt.Email) {
				result.AddError("tls.letsencrypt.email", c.TLS.LetsEncrypt.Email, "invalid email format")
			}
		}

		if c.TLS.LetsEncrypt.Domain == "" {
			result.AddError("tls.letsencrypt.domain", c.TLS.LetsEncrypt.Domain, "domain is required for Let's Encrypt")
		} else {
			// Sanitize domain
			c.TLS.LetsEncrypt.Domain = sv.SanitizeString(c.TLS.LetsEncrypt.Domain)

			// Validate hostname security
			if err := sv.ValidateHostname(c.TLS.LetsEncrypt.Domain, "tls.letsencrypt.domain"); err != nil {
				result.AddError("tls.letsencrypt.domain", c.TLS.LetsEncrypt.Domain, err.Error())
			}
		}

		if c.TLS.LetsEncrypt.CacheDir != "" {
			// Sanitize cache directory path
			c.TLS.LetsEncrypt.CacheDir = sv.SanitizePath(c.TLS.LetsEncrypt.CacheDir)

			// Validate path security
			if err := sv.ValidatePath(c.TLS.LetsEncrypt.CacheDir, "tls.letsencrypt.cache_dir"); err != nil {
				result.AddError("tls.letsencrypt.cache_dir", c.TLS.LetsEncrypt.CacheDir, err.Error())
			}
		} else {
			result.AddWarning("tls.letsencrypt.cache_dir", c.TLS.LetsEncrypt.CacheDir, "cache_dir not set, using default")
		}
	}
}

// validateQueue validates queue configuration
func (c *Config) validateQueue(result *ValidationResult, sv *SecurityValidator) {
	if c.Queue.Dir == "" {
		result.AddError("queue.dir", c.Queue.Dir, "queue directory is required")
		return
	}

	// Sanitize queue directory path
	c.Queue.Dir = sv.SanitizePath(c.Queue.Dir)

	// Validate path security
	if err := sv.ValidatePath(c.Queue.Dir, "queue.dir"); err != nil {
		result.AddError("queue.dir", c.Queue.Dir, err.Error())
		return
	}

	// Check if queue directory exists or can be created
	if !dirExists(c.Queue.Dir) {
		// Try to create it
		if err := os.MkdirAll(c.Queue.Dir, 0700); err != nil { // Use secure permissions
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
func (c *Config) validateLogging(result *ValidationResult, sv *SecurityValidator) {
	// Validate log type
	validTypes := []string{"console", "file", "elastic"}
	if c.Logging.Type != "" && !contains(validTypes, c.Logging.Type) {
		result.AddError("logging.type", c.Logging.Type, fmt.Sprintf("invalid log type, must be one of: %s", strings.Join(validTypes, ", ")))
	}

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

	// Type-specific validation
	switch c.Logging.Type {
	case "file":
		if c.Logging.File != "" {
			// Sanitize log file path
			c.Logging.File = sv.SanitizePath(c.Logging.File)

			// Validate path security
			if err := sv.ValidatePath(c.Logging.File, "logging.file"); err != nil {
				result.AddError("logging.file", c.Logging.File, err.Error())
			} else {
				logDir := filepath.Dir(c.Logging.File)
				if !dirExists(logDir) {
					if err := os.MkdirAll(logDir, 0755); err != nil {
						result.AddError("logging.file", c.Logging.File, fmt.Sprintf("cannot create log directory: %v", err))
					}
				}

				// Validate file size if file exists
				if err := sv.ValidateFileSize(c.Logging.File, "logging.file"); err != nil {
					result.AddError("logging.file", c.Logging.File, err.Error())
				}
			}
		}
	case "elastic":
		if c.Logging.Output == "" {
			result.AddError("logging.output", c.Logging.Output, "Elasticsearch URL must be specified for elastic logging")
		} else {
			// Sanitize output URL
			c.Logging.Output = sv.SanitizeString(c.Logging.Output)

			// Validate URL format (basic validation)
			if !strings.HasPrefix(c.Logging.Output, "http://") && !strings.HasPrefix(c.Logging.Output, "https://") {
				result.AddError("logging.output", c.Logging.Output, "Elasticsearch URL must start with http:// or https://")
			}
		}
	}
}

// validatePlugins validates plugins configuration
func (c *Config) validatePlugins(result *ValidationResult, sv *SecurityValidator) {
	if c.Plugins.Directory == "" {
		result.AddWarning("plugins.directory", c.Plugins.Directory, "plugins directory not set, plugins will be disabled")
		return
	}

	// Sanitize plugins directory path
	c.Plugins.Directory = sv.SanitizePath(c.Plugins.Directory)

	// Validate path security
	if err := sv.ValidatePath(c.Plugins.Directory, "plugins.directory"); err != nil {
		result.AddError("plugins.directory", c.Plugins.Directory, err.Error())
		return
	}

	// Check if plugins directory exists
	if !dirExists(c.Plugins.Directory) {
		result.AddWarning("plugins.directory", c.Plugins.Directory, "plugins directory does not exist")
	}

	// Validate enabled plugins
	for i, plugin := range c.Plugins.Enabled {
		// Sanitize plugin name
		c.Plugins.Enabled[i] = sv.SanitizeString(plugin)

		if plugin == "" {
			result.AddError(fmt.Sprintf("plugins.enabled[%d]", i), plugin, "plugin name cannot be empty")
		} else {
			// Validate plugin name format (no path traversal, no special characters)
			if strings.Contains(plugin, "/") || strings.Contains(plugin, "\\") || strings.Contains(plugin, "..") {
				result.AddError(fmt.Sprintf("plugins.enabled[%d]", i), plugin, "plugin name contains invalid characters")
			}
		}

		// Check if plugin file exists
		pluginPath := filepath.Join(c.Plugins.Directory, plugin+".so")
		if !fileExists(pluginPath) {
			result.AddWarning(fmt.Sprintf("plugins.enabled[%d]", i), plugin, fmt.Sprintf("plugin file not found: %s", pluginPath))
		} else {
			// Validate plugin file size
			if err := sv.ValidateFileSize(pluginPath, fmt.Sprintf("plugins.enabled[%d]", i)); err != nil {
				result.AddError(fmt.Sprintf("plugins.enabled[%d]", i), plugin, err.Error())
			}
		}
	}
}

// validateAuth validates authentication configuration
func (c *Config) validateAuth(result *ValidationResult, sv *SecurityValidator) {
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
		} else {
			// Sanitize datasource path
			c.Auth.DataSourcePath = sv.SanitizePath(c.Auth.DataSourcePath)

			// Validate path security
			if err := sv.ValidatePath(c.Auth.DataSourcePath, "auth.datasource_path"); err != nil {
				result.AddError("auth.datasource_path", c.Auth.DataSourcePath, err.Error())
			} else if !fileExists(c.Auth.DataSourcePath) {
				result.AddWarning("auth.datasource_path", c.Auth.DataSourcePath, "authentication file does not exist")
			} else {
				// Validate file size
				if err := sv.ValidateFileSize(c.Auth.DataSourcePath, "auth.datasource_path"); err != nil {
					result.AddError("auth.datasource_path", c.Auth.DataSourcePath, err.Error())
				}
			}
		}

	case "ldap":
		if c.Auth.DataSourceHost == "" {
			result.AddError("auth.datasource_host", c.Auth.DataSourceHost, "datasource_host is required for LDAP authentication")
		} else {
			// Sanitize hostname
			c.Auth.DataSourceHost = sv.SanitizeString(c.Auth.DataSourceHost)

			// Validate hostname security
			if err := sv.ValidateHostname(c.Auth.DataSourceHost, "auth.datasource_host"); err != nil {
				result.AddError("auth.datasource_host", c.Auth.DataSourceHost, err.Error())
			}
		}
		if err := sv.ValidatePort(c.Auth.DataSourcePort, "auth.datasource_port"); err != nil {
			result.AddError("auth.datasource_port", c.Auth.DataSourcePort, err.Error())
		}

	case "mysql", "postgres":
		if c.Auth.DataSourceHost == "" {
			result.AddError("auth.datasource_host", c.Auth.DataSourceHost, fmt.Sprintf("datasource_host is required for %s authentication", c.Auth.DataSourceType))
		} else {
			// Sanitize hostname
			c.Auth.DataSourceHost = sv.SanitizeString(c.Auth.DataSourceHost)

			// Validate hostname security
			if err := sv.ValidateHostname(c.Auth.DataSourceHost, "auth.datasource_host"); err != nil {
				result.AddError("auth.datasource_host", c.Auth.DataSourceHost, err.Error())
			}
		}
		if err := sv.ValidatePort(c.Auth.DataSourcePort, "auth.datasource_port"); err != nil {
			result.AddError("auth.datasource_port", c.Auth.DataSourcePort, err.Error())
		}
		if c.Auth.DataSourceUser == "" {
			result.AddError("auth.datasource_user", c.Auth.DataSourceUser, fmt.Sprintf("datasource_user is required for %s authentication", c.Auth.DataSourceType))
		} else {
			// Sanitize username
			c.Auth.DataSourceUser = sv.SanitizeString(c.Auth.DataSourceUser)
		}

	case "sqlite":
		if c.Auth.DataSourcePath == "" {
			result.AddError("auth.datasource_path", c.Auth.DataSourcePath, "datasource_path is required for SQLite authentication")
		} else {
			// Sanitize datasource path
			c.Auth.DataSourcePath = sv.SanitizePath(c.Auth.DataSourcePath)

			// Validate path security
			if err := sv.ValidatePath(c.Auth.DataSourcePath, "auth.datasource_path"); err != nil {
				result.AddError("auth.datasource_path", c.Auth.DataSourcePath, err.Error())
			} else if !fileExists(c.Auth.DataSourcePath) {
				result.AddWarning("auth.datasource_path", c.Auth.DataSourcePath, "SQLite database file does not exist")
			} else {
				// Validate file size
				if err := sv.ValidateFileSize(c.Auth.DataSourcePath, "auth.datasource_path"); err != nil {
					result.AddError("auth.datasource_path", c.Auth.DataSourcePath, err.Error())
				}
			}
		}
	}
}

// validateQueueProcessor validates queue processor configuration
func (c *Config) validateQueueProcessor(result *ValidationResult, sv *SecurityValidator) {
	if err := sv.ValidateNumericBounds(int64(c.QueueProcessor.Workers), "queue_processor.workers", 1, int64(sv.config.MaxWorkers)); err != nil {
		result.AddError("queue_processor.workers", c.QueueProcessor.Workers, err.Error())
	} else if c.QueueProcessor.Workers > 100 {
		result.AddWarning("queue_processor.workers", c.QueueProcessor.Workers, "high number of workers may impact performance")
	}

	if err := sv.ValidateNumericBounds(int64(c.QueueProcessor.Interval), "queue_processor.interval", 1, 3600); err != nil {
		result.AddError("queue_processor.interval", c.QueueProcessor.Interval, err.Error())
	} else if c.QueueProcessor.Interval < 5 {
		result.AddWarning("queue_processor.interval", c.QueueProcessor.Interval, "very short interval may impact performance")
	}
}

// validateDelivery validates delivery configuration
func (c *Config) validateDelivery(result *ValidationResult, sv *SecurityValidator) {
	if c.Delivery == nil {
		return // Delivery config is optional
	}

	// Validate delivery mode
	validModes := []string{"smtp", "lmtp", "local"}
	if c.Delivery.Mode != "" && !contains(validModes, c.Delivery.Mode) {
		result.AddError("delivery.mode", c.Delivery.Mode, fmt.Sprintf("invalid delivery mode, must be one of: %s", strings.Join(validModes, ", ")))
	}

	// Validate delivery host if provided
	if c.Delivery.Host != "" {
		// Sanitize hostname
		c.Delivery.Host = sv.SanitizeString(c.Delivery.Host)

		// Validate hostname security
		if err := sv.ValidateHostname(c.Delivery.Host, "delivery.host"); err != nil {
			result.AddError("delivery.host", c.Delivery.Host, err.Error())
		}
	}

	// Validate delivery port if provided
	if c.Delivery.Port > 0 {
		if err := sv.ValidatePort(c.Delivery.Port, "delivery.port"); err != nil {
			result.AddError("delivery.port", c.Delivery.Port, err.Error())
		}
	}

	// Validate timeout
	if err := sv.ValidateNumericBounds(int64(c.Delivery.Timeout), "delivery.timeout", 1, 300); err != nil {
		result.AddError("delivery.timeout", c.Delivery.Timeout, err.Error())
	} else if c.Delivery.Timeout > 300 {
		result.AddWarning("delivery.timeout", c.Delivery.Timeout, "very long timeout may cause delays")
	}

	// Validate max retries
	if err := sv.ValidateNumericBounds(int64(c.Delivery.MaxRetries), "delivery.max_retries", 0, 100); err != nil {
		result.AddError("delivery.max_retries", c.Delivery.MaxRetries, err.Error())
	}

	// Validate retry delay
	if err := sv.ValidateNumericBounds(int64(c.Delivery.RetryDelay), "delivery.retry_delay", 1, 3600); err != nil {
		result.AddError("delivery.retry_delay", c.Delivery.RetryDelay, err.Error())
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
