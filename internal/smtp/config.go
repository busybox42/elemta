package smtp

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config represents the main configuration for the SMTP server
type Config struct {
	ListenAddr    string   `toml:"listen_addr" json:"listen_addr"`
	QueueDir      string   `toml:"queue_dir" json:"queue_dir"`
	MaxSize       int64    `toml:"max_size" json:"max_size"`
	DevMode       bool     `toml:"dev_mode" json:"dev_mode"`
	AllowedRelays []string `toml:"allowed_relays" json:"allowed_relays"`
	LocalDomains  []string `toml:"local_domains" json:"local_domains"`
	Hostname      string   `toml:"hostname" json:"hostname"`
	MaxWorkers    int      `toml:"max_workers" json:"max_workers"`
	MaxRetries    int      `toml:"max_retries" json:"max_retries"`
	MaxQueueTime  int      `toml:"max_queue_time" json:"max_queue_time"`
	RetrySchedule []int    `toml:"retry_schedule" json:"retry_schedule"`

	// Queue management options
	KeepDeliveredMessages   bool `toml:"keep_delivered_messages" json:"keep_delivered_messages"`       // Whether to keep delivered messages for archiving
	KeepMessageData         bool `toml:"keep_message_data" json:"keep_message_data"`                   // Whether to keep message data after delivery
	QueuePriorityEnabled    bool `toml:"queue_priority_enabled" json:"queue_priority_enabled"`         // Whether to enable queue prioritization
	QueueWorkers            int  `toml:"queue_workers" json:"queue_workers"`                           // Number of queue worker goroutines
	MessageRetentionHours   int  `toml:"message_retention_hours" json:"message_retention_hours"`       // How long to keep messages before expiry
	ConnectTimeout          int  `toml:"connect_timeout" json:"connect_timeout"`                       // Timeout for connecting to remote servers
	SMTPTimeout             int  `toml:"smtp_timeout" json:"smtp_timeout"`                             // Timeout for SMTP operations
	MaxConnectionsPerDomain int  `toml:"max_connections_per_domain" json:"max_connections_per_domain"` // Maximum concurrent connections per domain

	// Queue processor options
	QueueProcessorEnabled bool `toml:"queue_processor_enabled" json:"queue_processor_enabled"` // Whether queue processing is enabled
	QueueProcessInterval  int  `toml:"queue_process_interval" json:"queue_process_interval"`   // How often to process the queue in seconds

	// Authentication configuration
	Auth *AuthConfig `toml:"auth" json:"auth"`

	// TLS configuration
	TLS *TLSConfig `toml:"tls" json:"tls"`

	// Resource limits
	Resources *ResourceConfig `toml:"resources" json:"resources"`

	// Caching configuration
	Cache *CacheConfig `toml:"cache" json:"cache"`

	// Antivirus configuration
	Antivirus *AntivirusConfig `toml:"antivirus" json:"antivirus"`

	// Rules configuration
	Rules *RulesConfig `toml:"rules" json:"rules"`

	// Antispam configuration
	Antispam *AntispamConfig `toml:"antispam" json:"antispam"`

	// Plugin configuration
	Plugins *PluginConfig `toml:"plugins" json:"plugins"`

	// Metrics configuration
	Metrics *MetricsConfig `toml:"metrics" json:"metrics"`

	// API server configuration
	API *APIConfig `toml:"api" json:"api"`

	// Delivery configuration
	Delivery *DeliveryConfig `toml:"delivery" json:"delivery"`

	// Memory management configuration
	Memory *MemoryConfig `toml:"memory" json:"memory"`

	SessionTimeout time.Duration `yaml:"session_timeout" toml:"session_timeout"`
}

// DeliveryConfig represents configuration for message delivery
type DeliveryConfig struct {
	Mode          string `toml:"mode" json:"mode"`                     // Delivery mode (smtp, lmtp, etc.)
	Host          string `toml:"host" json:"host"`                     // Host to deliver to
	Port          int    `toml:"port" json:"port"`                     // Port to deliver to
	Timeout       int    `toml:"timeout" json:"timeout"`               // Timeout for delivery operations
	MaxRetries    int    `toml:"max_retries" json:"max_retries"`       // Maximum number of delivery retries
	RetryDelay    int    `toml:"retry_delay" json:"retry_delay"`       // Delay between retries in seconds
	TestMode      bool   `toml:"test_mode" json:"test_mode"`           // Whether to use test mode delivery
	DefaultDomain string `toml:"default_domain" json:"default_domain"` // Default domain for local delivery
	Debug         bool   `toml:"debug" json:"debug"`                   // Enable debug logging for delivery
}

// MetricsConfig represents the configuration for metrics collection
type MetricsConfig struct {
	Enabled    bool   `toml:"enabled" json:"enabled"`         // Whether metrics collection is enabled
	ListenAddr string `toml:"listen_addr" json:"listen_addr"` // Address to listen on for metrics HTTP server
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Enabled        bool   `json:"enabled" toml:"enabled"`
	Required       bool   `json:"required" toml:"required"`
	DataSourceType string `json:"datasource_type" toml:"datasource_type"`
	DataSourceName string `json:"datasource_name" toml:"datasource_name"`
	DataSourcePath string `json:"datasource_path" toml:"datasource_path"`
	DataSourceHost string `json:"datasource_host" toml:"datasource_host"`
	DataSourcePort int    `json:"datasource_port" toml:"datasource_port"`
	DataSourceUser string `json:"datasource_user" toml:"datasource_user"`
	DataSourcePass string `json:"datasource_pass" toml:"datasource_pass"`
	DataSourceDB   string `json:"datasource_db" toml:"datasource_db"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled        bool               `yaml:"enabled" toml:"enabled"`
	ListenAddr     string             `yaml:"listen_addr" toml:"listen_addr"`
	CertFile       string             `yaml:"cert_file" toml:"cert_file"`
	KeyFile        string             `yaml:"key_file" toml:"key_file"`
	LetsEncrypt    *LetsEncryptConfig `yaml:"letsencrypt" toml:"letsencrypt"`
	MinVersion     string             `yaml:"min_version" toml:"min_version"`
	MaxVersion     string             `yaml:"max_version" toml:"max_version"`
	Ciphers        []string           `yaml:"ciphers" toml:"ciphers"`
	Curves         []string           `yaml:"curves" toml:"curves"`
	ClientAuth     string             `yaml:"client_auth" toml:"client_auth"`
	RenewalConfig  *CertRenewalConfig `yaml:"renewal" toml:"renewal"`
	EnableStartTLS bool               `yaml:"enable_starttls" toml:"enable_starttls"` // Enable STARTTLS on standard ports
}

// LetsEncryptConfig represents Let's Encrypt configuration
type LetsEncryptConfig struct {
	Enabled  bool   `yaml:"enabled" toml:"enabled"`
	Domain   string `yaml:"domain" toml:"domain"`
	Email    string `yaml:"email" toml:"email"`
	CacheDir string `yaml:"cache_dir" toml:"cache_dir"`
	Staging  bool   `yaml:"staging" toml:"staging"`
}

// CertRenewalConfig represents certificate renewal configuration
type CertRenewalConfig struct {
	AutoRenew      bool          `yaml:"auto_renew" toml:"auto_renew"`
	RenewalDays    int           `yaml:"renewal_days" toml:"renewal_days"`       // Renew this many days before expiration
	CheckInterval  time.Duration `yaml:"check_interval" toml:"check_interval"`   // How often to check certificate status
	ForceRenewal   bool          `yaml:"force_renewal" toml:"force_renewal"`     // Force renewal on startup
	RenewalTimeout time.Duration `yaml:"renewal_timeout" toml:"renewal_timeout"` // Timeout for renewal operations
}

// ResourceConfig represents resource limits
type ResourceConfig struct {
	MaxCPU            int    `json:"max_cpu" toml:"max_cpu"`
	MaxMemory         int64  `json:"max_memory" toml:"max_memory"`
	MaxConnections    int    `json:"max_connections" toml:"max_connections"`
	MaxConcurrent     int    `json:"max_concurrent" toml:"max_concurrent"`
	ConnectionTimeout int    `json:"connection_timeout" toml:"connection_timeout"`
	ReadTimeout       int    `json:"read_timeout" toml:"read_timeout"`
	WriteTimeout      int    `json:"write_timeout" toml:"write_timeout"`
	ValkeyURL         string `json:"valkey_url" toml:"valkey_url"`
	ValkeyKeyPrefix   string `json:"valkey_key_prefix" toml:"valkey_key_prefix"`
}

// CacheConfig represents caching configuration
type CacheConfig struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Password string `json:"password"`
	Database int    `json:"database"`
	MaxItems int    `json:"max_items"`
	MaxSize  int64  `json:"max_size"`
	TTL      int    `json:"ttl"`
}

// AntivirusConfig represents antivirus configuration
type AntivirusConfig struct {
	Enabled         bool          `toml:"enabled" json:"enabled"`
	RejectOnFailure bool          `toml:"reject_on_failure" json:"reject_on_failure"`
	ClamAV          *ClamAVConfig `toml:"clamav" json:"clamav"`
}

// ClamAVConfig represents ClamAV configuration
type ClamAVConfig struct {
	Enabled   bool   `json:"enabled"`
	Address   string `json:"address"`
	Timeout   int    `json:"timeout"`
	ScanLimit int64  `json:"scan_limit"`
}

// AntispamConfig represents antispam configuration
type AntispamConfig struct {
	Enabled      bool                `toml:"enabled" json:"enabled"`
	RejectOnSpam bool                `toml:"reject_on_spam" json:"reject_on_spam"`
	SpamAssassin *SpamAssassinConfig `toml:"spamassassin" json:"spamassassin"`
	Rspamd       *RspamdConfig       `toml:"rspamd" json:"rspamd"`
}

// SpamAssassinConfig represents SpamAssassin configuration
type SpamAssassinConfig struct {
	Enabled   bool    `json:"enabled"`
	Address   string  `json:"address"`
	Timeout   int     `json:"timeout"`
	ScanLimit int64   `json:"scan_limit"`
	Threshold float64 `json:"threshold"`
}

// RspamdConfig represents Rspamd configuration
type RspamdConfig struct {
	Enabled   bool    `json:"enabled"`
	Address   string  `json:"address"`
	Timeout   int     `json:"timeout"`
	ScanLimit int64   `json:"scan_limit"`
	Threshold float64 `json:"threshold"`
	APIKey    string  `json:"api_key"`
}

// RulesConfig represents rules configuration
type RulesConfig struct {
	Enabled       bool   `json:"enabled"`
	Path          string `json:"path"`
	DefaultAction string `json:"default_action"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled    bool     `json:"enabled"`
	PluginPath string   `json:"plugin_path"`
	Plugins    []string `json:"plugins"`
}

// APIConfig represents the configuration for the API server
type APIConfig struct {
	Enabled    bool   `toml:"enabled" json:"enabled"`         // Whether API server is enabled
	ListenAddr string `toml:"listen_addr" json:"listen_addr"` // Address to listen on for API server
}

func findConfigFile(configPath string) (string, error) {
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("Using config from explicit path: %s\n", configPath)
			return configPath, nil
		}
		return "", fmt.Errorf("config file not found at %s", configPath)
	}

	searchPaths := []string{
		"./elemta.conf",
		"./config/elemta.conf",
		"../config/elemta.conf",
		os.ExpandEnv("$HOME/.elemta.conf"),
		"/etc/elemta/elemta.conf",
	}

	for _, path := range searchPaths {
		fmt.Printf("Checking for config at: %s\n", path)
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Found config at: %s\n", path)
			return path, nil
		}
	}

	fmt.Println("No config file found, using defaults")
	return "", fmt.Errorf("no config file found in search paths")
}

func LoadConfig(configPath string) (*Config, error) {
	// Check for environment variable if configPath is empty
	if configPath == "" {
		envPath := os.Getenv("ELEMTA_CONFIG_PATH")
		if envPath != "" {
			configPath = envPath
		}
	}

	path, err := findConfigFile(configPath)
	if err != nil {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if _, err := toml.Decode(string(data), &config); err != nil {
		// Try JSON as fallback
		if jsonErr := json.Unmarshal(data, &config); jsonErr != nil {
			return nil, fmt.Errorf("error parsing config (tried TOML and JSON): %w", err)
		}
	}

	if config.Hostname == "" {
		hostname, err := os.Hostname()
		if err == nil {
			config.Hostname = hostname
		} else {
			config.Hostname = "localhost.localdomain"
		}
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":2525"
	}
	if config.QueueDir == "" {
		config.QueueDir = "./queue"
	}
	if config.MaxSize == 0 {
		config.MaxSize = 50 * 1024 * 1024 // 50MB - increased default
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 10
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 10
	}
	if config.MaxQueueTime == 0 {
		config.MaxQueueTime = 172800
	}
	if len(config.RetrySchedule) == 0 {
		config.RetrySchedule = []int{60, 300, 900, 3600, 10800, 21600, 43200}
	}

	// Set default TLS configuration if not provided
	if config.TLS == nil {
		config.TLS = &TLSConfig{
			Enabled:    false,
			ListenAddr: ":2465",
			MinVersion: "tls1.2",
			RenewalConfig: &CertRenewalConfig{
				AutoRenew:      true,
				RenewalDays:    30,
				CheckInterval:  24 * time.Hour,
				ForceRenewal:   false,
				RenewalTimeout: 5 * time.Minute,
			},
		}
	}

	// Set default authentication configuration if not provided
	if config.Auth == nil {
		config.Auth = &AuthConfig{
			Enabled:        false,
			Required:       false,
			DataSourceType: "sqlite",
			DataSourcePath: "./elemta.db",
		}
	}

	// Set default resource configuration if not provided
	if config.Resources == nil {
		config.Resources = &ResourceConfig{
			MaxCPU:            0, // Use all available CPUs
			MaxMemory:         0, // No memory limit
			MaxConnections:    1000,
			MaxConcurrent:     100,
			ConnectionTimeout: 60,
			ReadTimeout:       60,
			WriteTimeout:      60,
		}
	}

	// Set default cache configuration if not provided
	if config.Cache == nil {
		config.Cache = &CacheConfig{
			Enabled:  false,
			Type:     "memory",
			MaxItems: 10000,
			MaxSize:  100 * 1024 * 1024, // 100 MB
			TTL:      3600,              // 1 hour
		}
	}

	// Set default antivirus configuration if not provided
	if config.Antivirus == nil {
		config.Antivirus = &AntivirusConfig{
			Enabled:         true,
			RejectOnFailure: false,
			ClamAV: &ClamAVConfig{
				Enabled:   true,
				Address:   "localhost:3310",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
			},
		}
	}

	// Set default antispam configuration if not provided
	if config.Antispam == nil {
		config.Antispam = &AntispamConfig{
			Enabled:      true,
			RejectOnSpam: false,
			SpamAssassin: &SpamAssassinConfig{
				Enabled:   false,
				Address:   "localhost:783",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 5.0,
			},
			Rspamd: &RspamdConfig{
				Enabled:   true,
				Address:   "http://localhost:11333",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 6.0,
				APIKey:    "",
			},
		}
	}

	// Set default rules configuration if not provided
	if config.Rules == nil {
		config.Rules = &RulesConfig{
			Enabled:       false,
			Path:          "./rules",
			DefaultAction: "accept",
		}
	}

	// Set default plugin configuration if not provided
	if config.Plugins == nil {
		config.Plugins = &PluginConfig{
			Enabled:    false,
			PluginPath: "./plugins",
			Plugins:    []string{},
		}
	}

	// Set default metrics configuration if not provided
	if config.Metrics == nil {
		config.Metrics = &MetricsConfig{
			Enabled:    true,
			ListenAddr: ":8080",
		}
	}

	// Set default API configuration if not provided
	if config.API == nil {
		config.API = &APIConfig{
			Enabled:    false,
			ListenAddr: ":8081",
		}
	}

	if err := os.MkdirAll(config.QueueDir, 0755); err != nil {
		return nil, err
	}

	if config.SessionTimeout == 0 {
		config.SessionTimeout = 5 * time.Minute
	}

	return &config, nil
}

// DefaultConfig returns a default configuration with sane defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:            ":2525",
		Hostname:              "localhost",
		MaxSize:               50 * 1024 * 1024, // 50MB
		QueueDir:              "./queue",
		QueueProcessorEnabled: true,
		QueueProcessInterval:  30, // 30 seconds
		MaxRetries:            10,
		MaxQueueTime:          86400,                             // 24 hours
		RetrySchedule:         []int{300, 600, 1200, 1800, 3600}, // 5m, 10m, 20m, 30m, 1h
		MaxWorkers:            5,

		// TLS configuration with enhanced certificate management
		TLS: &TLSConfig{
			Enabled:        false,
			ListenAddr:     ":2465",
			MinVersion:     "tls1.2",
			EnableStartTLS: true, // Enable STARTTLS by default when TLS is enabled
			RenewalConfig: &CertRenewalConfig{
				AutoRenew:      true,
				RenewalDays:    30,
				CheckInterval:  24 * time.Hour,
				ForceRenewal:   false,
				RenewalTimeout: 5 * time.Minute,
			},
		},

		Auth: &AuthConfig{
			Enabled:  false,
			Required: false,
		},

		Delivery: &DeliveryConfig{
			Mode:       "smtp",
			Timeout:    30,
			MaxRetries: 5,
			RetryDelay: 300, // 5 minutes
		},

		Plugins: &PluginConfig{
			Enabled:    false,
			PluginPath: "./plugins",
		},

		Metrics: &MetricsConfig{
			Enabled:    true,
			ListenAddr: ":8080",
		},

		API: &APIConfig{
			Enabled:    false,
			ListenAddr: ":8081",
		},

		Resources: &ResourceConfig{
			MaxConnections:    100,
			MaxConcurrent:     20,
			ConnectionTimeout: 60,
			ReadTimeout:       30,
			WriteTimeout:      30,
		},

		SessionTimeout: 5 * time.Minute,
	}
}
