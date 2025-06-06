package config

import (
	"fmt"
	"os"
	"path/filepath"

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
		TLS      bool   `yaml:"tls" toml:"tls"`
		CertFile string `yaml:"cert_file" toml:"cert_file"`
		KeyFile  string `yaml:"key_file" toml:"key_file"`
	} `yaml:"server" toml:"server"`

	// Enhanced TLS configuration
	TLS *smtp.TLSConfig `yaml:"tls" toml:"tls"`

	// Queue configuration
	QueueDir string `yaml:"queue_dir" toml:"queue_dir"`

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
	cfg.Server.TLS = false

	// Set default queue directory
	cfg.QueueDir = "/app/queue"

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
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	fmt.Printf("[DEBUG] Raw config file contents:\n%s\n", string(data))

	// Pre-initialize TLS pointer for TOML mapping
	cfg.TLS = &smtp.TLSConfig{}
	// Try to parse the file as YAML first
	yamlErr := yaml.Unmarshal(data, cfg)
	if yamlErr == nil {
		fmt.Println("Configuration loaded successfully (YAML format)")
	} else {
		// If YAML parsing fails, try TOML
		tomlErr := toml.Unmarshal(data, cfg)
		if tomlErr == nil {
			fmt.Println("Configuration loaded successfully (TOML format)")
			fmt.Printf("[DEBUG] Loaded cfg struct after TOML unmarshal: %+v\n", cfg)
		} else {
			// For better debugging, print the exact errors
			fmt.Printf("YAML error: %v\n", yamlErr)
			fmt.Printf("TOML error: %v\n", tomlErr)

			// Include both errors in the returned error
			return nil, fmt.Errorf("error loading configuration: error parsing config (tried YAML and TOML): %v", tomlErr)
		}
	}

	// Make sure queue directory is set
	if cfg.QueueDir == "" {
		cfg.QueueDir = "/app/queue"
	}

	// Use absolute path for queue directory
	if !filepath.IsAbs(cfg.QueueDir) {
		// If it's relative to the config file, make it absolute
		configDir := filepath.Dir(configFile)
		cfg.QueueDir = filepath.Join(configDir, cfg.QueueDir)
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
	if err := os.MkdirAll(c.QueueDir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %v", err)
	}

	// Create subdirectories for different queue types
	queueTypes := []string{"active", "deferred", "hold", "failed"}
	for _, qType := range queueTypes {
		qDir := filepath.Join(c.QueueDir, qType)
		if err := os.MkdirAll(qDir, 0755); err != nil {
			return fmt.Errorf("failed to create %s queue directory: %v", qType, err)
		}
	}

	return nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(configPath string) error {
	// Convert to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %v", err)
	}

	// Make sure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
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
