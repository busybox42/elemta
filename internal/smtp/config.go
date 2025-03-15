package smtp

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the main configuration for the SMTP server
type Config struct {
	ListenAddr    string   `toml:"listen_addr" json:"listen_addr"`
	QueueDir      string   `toml:"queue_dir" json:"queue_dir"`
	MaxSize       int64    `toml:"max_size" json:"max_size"`
	DevMode       bool     `toml:"dev_mode" json:"dev_mode"`
	AllowedRelays []string `toml:"allowed_relays" json:"allowed_relays"`
	Hostname      string   `toml:"hostname" json:"hostname"`
	MaxWorkers    int      `toml:"max_workers" json:"max_workers"`
	MaxRetries    int      `toml:"max_retries" json:"max_retries"`
	MaxQueueTime  int      `toml:"max_queue_time" json:"max_queue_time"`
	RetrySchedule []int    `toml:"retry_schedule" json:"retry_schedule"`

	// Queue management options
	KeepDeliveredMessages bool `toml:"keep_delivered_messages" json:"keep_delivered_messages"` // Whether to keep delivered messages for archiving
	KeepMessageData       bool `toml:"keep_message_data" json:"keep_message_data"`             // Whether to keep message data after delivery
	QueuePriorityEnabled  bool `toml:"queue_priority_enabled" json:"queue_priority_enabled"`   // Whether to enable queue prioritization

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
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Enabled        bool   `json:"enabled"`
	Required       bool   `json:"required"`
	DataSourceType string `json:"datasource_type"`
	DataSourceName string `json:"datasource_name"`
	DataSourcePath string `json:"datasource_path"`
	DataSourceHost string `json:"datasource_host"`
	DataSourcePort int    `json:"datasource_port"`
	DataSourceUser string `json:"datasource_user"`
	DataSourcePass string `json:"datasource_pass"`
	DataSourceDB   string `json:"datasource_db"`
}

// TLSConfig represents TLS/SSL configuration
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ListenAddr string `json:"listen_addr"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`

	// Let's Encrypt configuration
	LetsEncrypt *LetsEncryptConfig `json:"lets_encrypt"`
}

// LetsEncryptConfig represents Let's Encrypt configuration
type LetsEncryptConfig struct {
	Enabled  bool   `json:"enabled"`
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	CacheDir string `json:"cache_dir"`
	Staging  bool   `json:"staging"`
}

// ResourceConfig represents resource limits
type ResourceConfig struct {
	MaxCPU            int   `json:"max_cpu"`
	MaxMemory         int64 `json:"max_memory"`
	MaxConnections    int   `json:"max_connections"`
	MaxConcurrent     int   `json:"max_concurrent"`
	ConnectionTimeout int   `json:"connection_timeout"`
	ReadTimeout       int   `json:"read_timeout"`
	WriteTimeout      int   `json:"write_timeout"`
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
	ClamAV *ClamAVConfig `json:"clamav"`
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
	SpamAssassin *SpamAssassinConfig `json:"spamassassin"`
	Rspamd       *RspamdConfig       `json:"rspamd"`
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
		config.ListenAddr = ":25"
	}
	if config.QueueDir == "" {
		config.QueueDir = "./queue"
	}
	if config.MaxSize == 0 {
		config.MaxSize = 25 * 1024 * 1024
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
			ListenAddr: ":465",
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
			ClamAV: &ClamAVConfig{
				Enabled:   false,
				Address:   "localhost:3310",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
			},
		}
	}

	// Set default antispam configuration if not provided
	if config.Antispam == nil {
		config.Antispam = &AntispamConfig{
			SpamAssassin: &SpamAssassinConfig{
				Enabled:   false,
				Address:   "localhost:783",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 5.0,
			},
			Rspamd: &RspamdConfig{
				Enabled:   false,
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

	if err := os.MkdirAll(config.QueueDir, 0755); err != nil {
		return nil, err
	}

	return &config, nil
}

func DefaultConfig() *Config {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost.localdomain"
	}

	return &Config{
		ListenAddr:    ":25",
		QueueDir:      "./queue",
		MaxSize:       25 * 1024 * 1024,
		DevMode:       false,
		AllowedRelays: []string{},
		Hostname:      hostname,
		MaxWorkers:    10,
		MaxRetries:    10,
		MaxQueueTime:  172800,
		RetrySchedule: []int{60, 300, 900, 3600, 10800, 21600, 43200},
		Auth: &AuthConfig{
			Enabled:        false,
			Required:       false,
			DataSourceType: "sqlite",
			DataSourcePath: "./elemta.db",
		},
		TLS: &TLSConfig{
			Enabled:    false,
			ListenAddr: ":465",
		},
		Resources: &ResourceConfig{
			MaxCPU:            0, // Use all available CPUs
			MaxMemory:         0, // No memory limit
			MaxConnections:    1000,
			MaxConcurrent:     100,
			ConnectionTimeout: 60,
			ReadTimeout:       60,
			WriteTimeout:      60,
		},
		Cache: &CacheConfig{
			Enabled:  false,
			Type:     "memory",
			MaxItems: 10000,
			MaxSize:  100 * 1024 * 1024, // 100 MB
			TTL:      3600,              // 1 hour
		},
		Antivirus: &AntivirusConfig{
			ClamAV: &ClamAVConfig{
				Enabled:   false,
				Address:   "localhost:3310",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
			},
		},
		Antispam: &AntispamConfig{
			SpamAssassin: &SpamAssassinConfig{
				Enabled:   false,
				Address:   "localhost:783",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 5.0,
			},
			Rspamd: &RspamdConfig{
				Enabled:   false,
				Address:   "http://localhost:11333",
				Timeout:   30,
				ScanLimit: 25 * 1024 * 1024, // 25 MB
				Threshold: 6.0,
				APIKey:    "",
			},
		},
		Rules: &RulesConfig{
			Enabled:       false,
			Path:          "./rules",
			DefaultAction: "accept",
		},
		Plugins: &PluginConfig{
			Enabled:    false,
			PluginPath: "./plugins",
			Plugins:    []string{},
		},
	}
}
