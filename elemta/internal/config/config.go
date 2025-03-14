package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	SMTP     SMTPConfig     `yaml:"smtp"`
	TLS      TLSConfig      `yaml:"tls"`
	Queue    QueueConfig    `yaml:"queue"`
	Delivery DeliveryConfig `yaml:"delivery"`
	Scanner  ScannerConfig  `yaml:"scanner"`
	Rules    RulesConfig    `yaml:"rules"`
	Logging  LoggingConfig  `yaml:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Web      WebConfig      `yaml:"web"`
}

// SMTPConfig represents SMTP server configuration
type SMTPConfig struct {
	ListenAddress     string       `yaml:"listen_address"`
	Port              int          `yaml:"port"`
	Hostname          string       `yaml:"hostname"`
	MaxConnections    int          `yaml:"max_connections"`
	MaxMessageSize    int64        `yaml:"max_message_size"`
	AllowInsecureAuth bool         `yaml:"allow_insecure_auth"`
	Timeouts          SMTPTimeouts `yaml:"timeouts"`
}

// SMTPTimeouts represents SMTP timeout settings
type SMTPTimeouts struct {
	Connection int `yaml:"connection"`
	Command    int `yaml:"command"`
	Data       int `yaml:"data"`
	Idle       int `yaml:"idle"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// QueueConfig represents message queue configuration
type QueueConfig struct {
	Path            string `yaml:"path"`
	MaxSize         int64  `yaml:"max_size"`
	RetryInterval   int    `yaml:"retry_interval"`
	MaxRetries      int    `yaml:"max_retries"`
	CleanupInterval int    `yaml:"cleanup_interval"`
}

// DeliveryConfig represents message delivery configuration
type DeliveryConfig struct {
	MaxConcurrent int      `yaml:"max_concurrent"`
	Timeout       int      `yaml:"timeout"`
	RetryInterval int      `yaml:"retry_interval"`
	MaxRetries    int      `yaml:"max_retries"`
	DNSServers    []string `yaml:"dns_servers"`
}

// ScannerConfig represents content scanner configuration
type ScannerConfig struct {
	ClamAV       ClamAVConfig       `yaml:"clamav"`
	Rspamd       RspamdConfig       `yaml:"rspamd"`
	SpamAssassin SpamAssassinConfig `yaml:"spamassassin"`
	Timeout      int                `yaml:"timeout"`
}

// ClamAVConfig represents ClamAV configuration
type ClamAVConfig struct {
	Enabled bool   `yaml:"enabled"`
	Socket  string `yaml:"socket"`
	Timeout int    `yaml:"timeout"`
}

// RspamdConfig represents Rspamd configuration
type RspamdConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Timeout int    `yaml:"timeout"`
}

// SpamAssassinConfig represents SpamAssassin configuration
type SpamAssassinConfig struct {
	Enabled bool   `yaml:"enabled"`
	Socket  string `yaml:"socket"`
	Timeout int    `yaml:"timeout"`
}

// RulesConfig represents rule engine configuration
type RulesConfig struct {
	Path       string `yaml:"path"`
	ScriptPath string `yaml:"script_path"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Path   string `yaml:"path"`
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// WebConfig represents web interface configuration
type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	TLS     bool   `yaml:"tls"`
}

// LoadConfig loads the configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	setDefaults(&cfg)

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default values for configuration
func setDefaults(cfg *Config) {
	// SMTP defaults
	if cfg.SMTP.ListenAddress == "" {
		cfg.SMTP.ListenAddress = "0.0.0.0"
	}
	if cfg.SMTP.Port == 0 {
		cfg.SMTP.Port = 25
	}
	if cfg.SMTP.Hostname == "" {
		hostname, err := os.Hostname()
		if err == nil {
			cfg.SMTP.Hostname = hostname
		} else {
			cfg.SMTP.Hostname = "localhost"
		}
	}
	if cfg.SMTP.MaxConnections == 0 {
		cfg.SMTP.MaxConnections = 100
	}
	if cfg.SMTP.MaxMessageSize == 0 {
		cfg.SMTP.MaxMessageSize = 52428800 // 50MB
	}

	// SMTP timeouts
	if cfg.SMTP.Timeouts.Connection == 0 {
		cfg.SMTP.Timeouts.Connection = 60
	}
	if cfg.SMTP.Timeouts.Command == 0 {
		cfg.SMTP.Timeouts.Command = 30
	}
	if cfg.SMTP.Timeouts.Data == 0 {
		cfg.SMTP.Timeouts.Data = 300
	}
	if cfg.SMTP.Timeouts.Idle == 0 {
		cfg.SMTP.Timeouts.Idle = 300
	}

	// Queue defaults
	if cfg.Queue.Path == "" {
		cfg.Queue.Path = "queue"
	}
	if cfg.Queue.MaxSize == 0 {
		cfg.Queue.MaxSize = 1073741824 // 1GB
	}
	if cfg.Queue.RetryInterval == 0 {
		cfg.Queue.RetryInterval = 300 // 5 minutes
	}
	if cfg.Queue.MaxRetries == 0 {
		cfg.Queue.MaxRetries = 10
	}
	if cfg.Queue.CleanupInterval == 0 {
		cfg.Queue.CleanupInterval = 3600 // 1 hour
	}

	// Delivery defaults
	if cfg.Delivery.MaxConcurrent == 0 {
		cfg.Delivery.MaxConcurrent = 10
	}
	if cfg.Delivery.Timeout == 0 {
		cfg.Delivery.Timeout = 60
	}
	if cfg.Delivery.RetryInterval == 0 {
		cfg.Delivery.RetryInterval = 300 // 5 minutes
	}
	if cfg.Delivery.MaxRetries == 0 {
		cfg.Delivery.MaxRetries = 10
	}

	// Scanner defaults
	if cfg.Scanner.Timeout == 0 {
		cfg.Scanner.Timeout = 5
	}

	// ClamAV defaults
	if cfg.Scanner.ClamAV.Enabled && cfg.Scanner.ClamAV.Socket == "" {
		cfg.Scanner.ClamAV.Socket = "/var/run/clamav/clamd.sock"
	}
	if cfg.Scanner.ClamAV.Timeout == 0 {
		cfg.Scanner.ClamAV.Timeout = 5
	}

	// Rspamd defaults
	if cfg.Scanner.Rspamd.Enabled && cfg.Scanner.Rspamd.URL == "" {
		cfg.Scanner.Rspamd.URL = "http://localhost:11333"
	}
	if cfg.Scanner.Rspamd.Timeout == 0 {
		cfg.Scanner.Rspamd.Timeout = 5
	}

	// SpamAssassin defaults
	if cfg.Scanner.SpamAssassin.Enabled && cfg.Scanner.SpamAssassin.Socket == "" {
		cfg.Scanner.SpamAssassin.Socket = "/var/run/spamassassin/spamd.sock"
	}
	if cfg.Scanner.SpamAssassin.Timeout == 0 {
		cfg.Scanner.SpamAssassin.Timeout = 5
	}

	// Rules defaults
	if cfg.Rules.Path == "" {
		cfg.Rules.Path = "rules"
	}
	if cfg.Rules.ScriptPath == "" {
		cfg.Rules.ScriptPath = "scripts"
	}

	// Logging defaults
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}

	// Metrics defaults
	if cfg.Metrics.Enabled && cfg.Metrics.Address == "" {
		cfg.Metrics.Address = "0.0.0.0"
	}
	if cfg.Metrics.Enabled && cfg.Metrics.Port == 0 {
		cfg.Metrics.Port = 9090
	}

	// Web defaults
	if cfg.Web.Enabled && cfg.Web.Address == "" {
		cfg.Web.Address = "0.0.0.0"
	}
	if cfg.Web.Enabled && cfg.Web.Port == 0 {
		cfg.Web.Port = 8080
	}
}

// validateConfig validates the configuration
func validateConfig(cfg *Config) error {
	// Validate SMTP configuration
	if cfg.SMTP.Port < 0 || cfg.SMTP.Port > 65535 {
		return fmt.Errorf("invalid SMTP port: %d", cfg.SMTP.Port)
	}

	// Validate TLS configuration
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		if _, err := os.Stat(cfg.TLS.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file not found: %s", cfg.TLS.CertFile)
		}
		if _, err := os.Stat(cfg.TLS.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", cfg.TLS.KeyFile)
		}
	}

	// Validate queue configuration
	if cfg.Queue.Path != "" {
		if err := os.MkdirAll(cfg.Queue.Path, 0755); err != nil {
			return fmt.Errorf("failed to create queue directory: %w", err)
		}
	}

	// Validate rules configuration
	if cfg.Rules.Path != "" {
		if err := os.MkdirAll(cfg.Rules.Path, 0755); err != nil {
			return fmt.Errorf("failed to create rules directory: %w", err)
		}
	}
	if cfg.Rules.ScriptPath != "" {
		if err := os.MkdirAll(cfg.Rules.ScriptPath, 0755); err != nil {
			return fmt.Errorf("failed to create scripts directory: %w", err)
		}
	}

	return nil
}

// SaveConfig saves the configuration to a file
func SaveConfig(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	cfg := &Config{}
	setDefaults(cfg)
	return cfg
}
