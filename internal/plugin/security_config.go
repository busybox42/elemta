package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SecurityConfig represents the complete security configuration for plugins
type SecurityConfig struct {
	// Global security settings
	Enabled                bool   `toml:"enabled" json:"enabled" yaml:"enabled"`
	Mode                   string `toml:"mode" json:"mode" yaml:"mode"` // "strict", "moderate", "permissive"
	DevelopmentMode        bool   `toml:"development_mode" json:"development_mode" yaml:"development_mode"`
	
	// Signature verification
	SignatureVerification  SignatureConfig `toml:"signature_verification" json:"signature_verification" yaml:"signature_verification"`
	
	// Sandboxing
	Sandboxing            SandboxingConfig `toml:"sandboxing" json:"sandboxing" yaml:"sandboxing"`
	
	// Capability management
	Capabilities          CapabilityConfig `toml:"capabilities" json:"capabilities" yaml:"capabilities"`
	
	// Audit logging
	AuditLogging          AuditConfig      `toml:"audit_logging" json:"audit_logging" yaml:"audit_logging"`
	
	// Hot reload security
	HotReload             HotReloadSecurityConfig `toml:"hot_reload" json:"hot_reload" yaml:"hot_reload"`
	
	// Plugin-specific policies
	PluginPolicies        map[string]PluginPolicy `toml:"plugin_policies" json:"plugin_policies" yaml:"plugin_policies"`
}

// SignatureConfig configures plugin signature verification
type SignatureConfig struct {
	Enabled                bool     `toml:"enabled" json:"enabled" yaml:"enabled"`
	Required               bool     `toml:"required" json:"required" yaml:"required"`
	TrustedCertificates    []string `toml:"trusted_certificates" json:"trusted_certificates" yaml:"trusted_certificates"`
	TrustedKeys            []string `toml:"trusted_keys" json:"trusted_keys" yaml:"trusted_keys"`
	SignatureCacheSize     int      `toml:"signature_cache_size" json:"signature_cache_size" yaml:"signature_cache_size"`
	SignatureCacheTTL      string   `toml:"signature_cache_ttl" json:"signature_cache_ttl" yaml:"signature_cache_ttl"`
	AllowUnsignedInDev     bool     `toml:"allow_unsigned_in_dev" json:"allow_unsigned_in_dev" yaml:"allow_unsigned_in_dev"`
	RequireTimestamp       bool     `toml:"require_timestamp" json:"require_timestamp" yaml:"require_timestamp"`
	MaxSignatureAge        string   `toml:"max_signature_age" json:"max_signature_age" yaml:"max_signature_age"`
}

// SandboxingConfig configures plugin sandboxing
type SandboxingConfig struct {
	Enabled                bool     `toml:"enabled" json:"enabled" yaml:"enabled"`
	MaxMemoryMB            int64    `toml:"max_memory_mb" json:"max_memory_mb" yaml:"max_memory_mb"`
	MaxCPUPercent          float64  `toml:"max_cpu_percent" json:"max_cpu_percent" yaml:"max_cpu_percent"`
	MaxExecutionTime       string   `toml:"max_execution_time" json:"max_execution_time" yaml:"max_execution_time"`
	MaxGoroutines          int      `toml:"max_goroutines" json:"max_goroutines" yaml:"max_goroutines"`
	MaxFileDescriptors     int      `toml:"max_file_descriptors" json:"max_file_descriptors" yaml:"max_file_descriptors"`
	AllowNetworkAccess     bool     `toml:"allow_network_access" json:"allow_network_access" yaml:"allow_network_access"`
	AllowFileSystem        bool     `toml:"allow_file_system" json:"allow_file_system" yaml:"allow_file_system"`
	AllowedPaths           []string `toml:"allowed_paths" json:"allowed_paths" yaml:"allowed_paths"`
	BlockedSyscalls        []string `toml:"blocked_syscalls" json:"blocked_syscalls" yaml:"blocked_syscalls"`
	EnableProcessIsolation bool     `toml:"enable_process_isolation" json:"enable_process_isolation" yaml:"enable_process_isolation"`
}

// CapabilityConfig configures plugin capabilities
type CapabilityConfig struct {
	Enabled                bool     `toml:"enabled" json:"enabled" yaml:"enabled"`
	DefaultCapabilities    []string `toml:"default_capabilities" json:"default_capabilities" yaml:"default_capabilities"`
	RestrictedCapabilities []string `toml:"restricted_capabilities" json:"restricted_capabilities" yaml:"restricted_capabilities"`
	CapabilityPolicies     map[string]CapabilityPolicy `toml:"capability_policies" json:"capability_policies" yaml:"capability_policies"`
	RequireExplicitGrant   bool     `toml:"require_explicit_grant" json:"require_explicit_grant" yaml:"require_explicit_grant"`
}

// AuditConfig configures security audit logging
type AuditConfig struct {
	Enabled                bool   `toml:"enabled" json:"enabled" yaml:"enabled"`
	LogPath                string `toml:"log_path" json:"log_path" yaml:"log_path"`
	LogLevel               string `toml:"log_level" json:"log_level" yaml:"log_level"`
	RetentionDays          int    `toml:"retention_days" json:"retention_days" yaml:"retention_days"`
	MaxLogSize             string `toml:"max_log_size" json:"max_log_size" yaml:"max_log_size"`
	LogRotation            bool   `toml:"log_rotation" json:"log_rotation" yaml:"log_rotation"`
	IncludeStackTraces     bool   `toml:"include_stack_traces" json:"include_stack_traces" yaml:"include_stack_traces"`
	AlertOnViolations      bool   `toml:"alert_on_violations" json:"alert_on_violations" yaml:"alert_on_violations"`
	AlertThreshold         int    `toml:"alert_threshold" json:"alert_threshold" yaml:"alert_threshold"`
}

// HotReloadSecurityConfig configures hot reload security
type HotReloadSecurityConfig struct {
	Enabled                bool   `toml:"enabled" json:"enabled" yaml:"enabled"`
	ValidateBeforeReload   bool   `toml:"validate_before_reload" json:"validate_before_reload" yaml:"validate_before_reload"`
	RequireSignatureCheck  bool   `toml:"require_signature_check" json:"require_signature_check" yaml:"require_signature_check"`
	BackupBeforeReload     bool   `toml:"backup_before_reload" json:"backup_before_reload" yaml:"backup_before_reload"`
	MaxReloadAttempts      int    `toml:"max_reload_attempts" json:"max_reload_attempts" yaml:"max_reload_attempts"`
	ReloadCooldown         string `toml:"reload_cooldown" json:"reload_cooldown" yaml:"reload_cooldown"`
	AllowRollback          bool   `toml:"allow_rollback" json:"allow_rollback" yaml:"allow_rollback"`
}

// PluginPolicy defines security policy for a specific plugin
type PluginPolicy struct {
	PluginName             string   `toml:"plugin_name" json:"plugin_name" yaml:"plugin_name"`
	AllowedCapabilities    []string `toml:"allowed_capabilities" json:"allowed_capabilities" yaml:"allowed_capabilities"`
	DeniedCapabilities     []string `toml:"denied_capabilities" json:"denied_capabilities" yaml:"denied_capabilities"`
	SandboxConfig          SandboxingConfig `toml:"sandbox_config" json:"sandbox_config" yaml:"sandbox_config"`
	SignatureRequired      bool     `toml:"signature_required" json:"signature_required" yaml:"signature_required"`
	TrustedSigners         []string `toml:"trusted_signers" json:"trusted_signers" yaml:"trusted_signers"`
	MaxViolations          int      `toml:"max_violations" json:"max_violations" yaml:"max_violations"`
	AutoRevokeOnViolations bool     `toml:"auto_revoke_on_violations" json:"auto_revoke_on_violations" yaml:"auto_revoke_on_violations"`
}

// CapabilityPolicy defines policy for a specific capability
type CapabilityPolicy struct {
	CapabilityName         string   `toml:"capability_name" json:"capability_name" yaml:"capability_name"`
	RequiredLevel          int      `toml:"required_level" json:"required_level" yaml:"required_level"`
	AllowedPlugins         []string `toml:"allowed_plugins" json:"allowed_plugins" yaml:"allowed_plugins"`
	DeniedPlugins          []string `toml:"denied_plugins" json:"denied_plugins" yaml:"denied_plugins"`
	RequireApproval        bool     `toml:"require_approval" json:"require_approval" yaml:"require_approval"`
	MaxUsagePerHour        int      `toml:"max_usage_per_hour" json:"max_usage_per_hour" yaml:"max_usage_per_hour"`
	AuditAllUsage          bool     `toml:"audit_all_usage" json:"audit_all_usage" yaml:"audit_all_usage"`
}

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Enabled:         true,
		Mode:           "moderate",
		DevelopmentMode: false,
		
		SignatureVerification: SignatureConfig{
			Enabled:             true,
			Required:            true,
			TrustedCertificates: []string{},
			TrustedKeys:         []string{},
			SignatureCacheSize:  1000,
			SignatureCacheTTL:   "24h",
			AllowUnsignedInDev:  true,
			RequireTimestamp:    true,
			MaxSignatureAge:     "30d",
		},
		
		Sandboxing: SandboxingConfig{
			Enabled:                true,
			MaxMemoryMB:            100,
			MaxCPUPercent:          25.0,
			MaxExecutionTime:       "30s",
			MaxGoroutines:          10,
			MaxFileDescriptors:     10,
			AllowNetworkAccess:     true,
			AllowFileSystem:        false,
			AllowedPaths:           []string{"/tmp", "/var/log"},
			BlockedSyscalls:        []string{"execve", "fork", "clone", "mount", "umount"},
			EnableProcessIsolation: false, // Requires more complex implementation
		},
		
		Capabilities: CapabilityConfig{
			Enabled:                true,
			DefaultCapabilities:    []string{"read", "log"},
			RestrictedCapabilities: []string{"admin", "system", "network", "file"},
			CapabilityPolicies:     make(map[string]CapabilityPolicy),
			RequireExplicitGrant:   true,
		},
		
		AuditLogging: AuditConfig{
			Enabled:                true,
			LogPath:                "./logs/plugin_security_audit.log",
			LogLevel:               "info",
			RetentionDays:          30,
			MaxLogSize:             "100MB",
			LogRotation:            true,
			IncludeStackTraces:     true,
			AlertOnViolations:      true,
			AlertThreshold:         5,
		},
		
		HotReload: HotReloadSecurityConfig{
			Enabled:                true,
			ValidateBeforeReload:   true,
			RequireSignatureCheck:  true,
			BackupBeforeReload:     true,
			MaxReloadAttempts:      3,
			ReloadCooldown:         "5m",
			AllowRollback:          true,
		},
		
		PluginPolicies: make(map[string]PluginPolicy),
	}
}

// DevelopmentSecurityConfig returns a more permissive configuration for development
func DevelopmentSecurityConfig() SecurityConfig {
	config := DefaultSecurityConfig()
	config.DevelopmentMode = true
	config.Mode = "permissive"
	
	// Relax signature requirements in development
	config.SignatureVerification.Required = false
	config.SignatureVerification.AllowUnsignedInDev = true
	
	// Relax sandboxing in development
	config.Sandboxing.MaxMemoryMB = 500
	config.Sandboxing.MaxCPUPercent = 50.0
	config.Sandboxing.AllowFileSystem = true
	config.Sandboxing.AllowedPaths = []string{"/tmp", "/var/log", "/home", "/opt"}
	
	// Relax capability restrictions in development
	config.Capabilities.RequireExplicitGrant = false
	config.Capabilities.DefaultCapabilities = []string{"read", "log", "network", "file"}
	
	// Reduce audit verbosity in development
	config.AuditLogging.LogLevel = "warn"
	config.AuditLogging.AlertOnViolations = false
	
	return config
}

// StrictSecurityConfig returns a very restrictive configuration for production
func StrictSecurityConfig() SecurityConfig {
	config := DefaultSecurityConfig()
	config.Mode = "strict"
	config.DevelopmentMode = false
	
	// Strict signature requirements
	config.SignatureVerification.Required = true
	config.SignatureVerification.AllowUnsignedInDev = false
	config.SignatureVerification.RequireTimestamp = true
	config.SignatureVerification.MaxSignatureAge = "7d"
	
	// Strict sandboxing
	config.Sandboxing.MaxMemoryMB = 50
	config.Sandboxing.MaxCPUPercent = 10.0
	config.Sandboxing.MaxExecutionTime = "10s"
	config.Sandboxing.AllowNetworkAccess = false
	config.Sandboxing.AllowFileSystem = false
	config.Sandboxing.EnableProcessIsolation = true
	
	// Strict capability management
	config.Capabilities.RequireExplicitGrant = true
	config.Capabilities.DefaultCapabilities = []string{"read"}
	config.Capabilities.RestrictedCapabilities = []string{"admin", "system", "network", "file", "log"}
	
	// Comprehensive audit logging
	config.AuditLogging.LogLevel = "debug"
	config.AuditLogging.IncludeStackTraces = true
	config.AuditLogging.AlertOnViolations = true
	config.AuditLogging.AlertThreshold = 1
	
	// Strict hot reload
	config.HotReload.ValidateBeforeReload = true
	config.HotReload.RequireSignatureCheck = true
	config.HotReload.MaxReloadAttempts = 1
	config.HotReload.ReloadCooldown = "1h"
	
	return config
}

// LoadSecurityConfig loads security configuration from file
func LoadSecurityConfig(configPath string) (*SecurityConfig, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return default config if file doesn't exist
		config := DefaultSecurityConfig()
		return &config, nil
	}
	
	// TODO: Implement actual TOML/JSON/YAML loading
	// For now, return default config
	config := DefaultSecurityConfig()
	return &config, nil
}

// SaveSecurityConfig saves security configuration to file
func SaveSecurityConfig(config *SecurityConfig, configPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// TODO: Implement actual TOML/JSON/YAML saving
	// For now, just return success
	return nil
}

// ValidateSecurityConfig validates the security configuration
func ValidateSecurityConfig(config *SecurityConfig) error {
	// Validate signature configuration
	if config.SignatureVerification.Enabled {
		if config.SignatureVerification.Required && len(config.SignatureVerification.TrustedCertificates) == 0 {
			return fmt.Errorf("signature verification is required but no trusted certificates are configured")
		}
		
		// Validate certificate files exist
		for _, certPath := range config.SignatureVerification.TrustedCertificates {
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				return fmt.Errorf("trusted certificate file not found: %s", certPath)
			}
		}
		
		// Validate key files exist
		for _, keyPath := range config.SignatureVerification.TrustedKeys {
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				return fmt.Errorf("trusted key file not found: %s", keyPath)
			}
		}
	}
	
	// Validate sandboxing configuration
	if config.Sandboxing.Enabled {
		if config.Sandboxing.MaxMemoryMB <= 0 {
			return fmt.Errorf("max_memory_mb must be positive")
		}
		if config.Sandboxing.MaxCPUPercent <= 0 || config.Sandboxing.MaxCPUPercent > 100 {
			return fmt.Errorf("max_cpu_percent must be between 0 and 100")
		}
		if config.Sandboxing.MaxGoroutines <= 0 {
			return fmt.Errorf("max_goroutines must be positive")
		}
	}
	
	// Validate audit logging configuration
	if config.AuditLogging.Enabled {
		if config.AuditLogging.LogPath == "" {
			return fmt.Errorf("audit log path is required when audit logging is enabled")
		}
		if config.AuditLogging.RetentionDays <= 0 {
			return fmt.Errorf("retention_days must be positive")
		}
	}
	
	// Validate plugin policies
	for pluginName, policy := range config.PluginPolicies {
		if policy.PluginName == "" {
			policy.PluginName = pluginName
		}
		if policy.MaxViolations <= 0 {
			policy.MaxViolations = 10 // Default value
		}
	}
	
	return nil
}

// GetSecurityConfigForMode returns a security configuration based on the specified mode
func GetSecurityConfigForMode(mode string) SecurityConfig {
	switch mode {
	case "strict":
		return StrictSecurityConfig()
	case "development", "dev":
		return DevelopmentSecurityConfig()
	case "moderate", "production":
		return DefaultSecurityConfig()
	default:
		return DefaultSecurityConfig()
	}
}

// SecurityConfigManager manages security configuration
type SecurityConfigManager struct {
	config     *SecurityConfig
	configPath string
	mu         sync.RWMutex
}

// NewSecurityConfigManager creates a new security configuration manager
func NewSecurityConfigManager(configPath string) (*SecurityConfigManager, error) {
	config, err := LoadSecurityConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load security config: %w", err)
	}
	
	if err := ValidateSecurityConfig(config); err != nil {
		return nil, fmt.Errorf("invalid security config: %w", err)
	}
	
	return &SecurityConfigManager{
		config:     config,
		configPath: configPath,
	}, nil
}

// GetConfig returns the current security configuration
func (scm *SecurityConfigManager) GetConfig() *SecurityConfig {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	return scm.config
}

// UpdateConfig updates the security configuration
func (scm *SecurityConfigManager) UpdateConfig(newConfig *SecurityConfig) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	
	if err := ValidateSecurityConfig(newConfig); err != nil {
		return fmt.Errorf("invalid security config: %w", err)
	}
	
	scm.config = newConfig
	
	// Save to file
	if err := SaveSecurityConfig(newConfig, scm.configPath); err != nil {
		return fmt.Errorf("failed to save security config: %w", err)
	}
	
	return nil
}

// ReloadConfig reloads the security configuration from file
func (scm *SecurityConfigManager) ReloadConfig() error {
	config, err := LoadSecurityConfig(scm.configPath)
	if err != nil {
		return fmt.Errorf("failed to reload security config: %w", err)
	}
	
	if err := ValidateSecurityConfig(config); err != nil {
		return fmt.Errorf("invalid reloaded security config: %w", err)
	}
	
	scm.mu.Lock()
	scm.config = config
	scm.mu.Unlock()
	
	return nil
}
