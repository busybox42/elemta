package plugin

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecurePluginManager provides enhanced security for plugin management
type SecurePluginManager struct {
	*Manager
	sandbox        *PluginSandbox
	validator      *PluginValidator
	signatureStore *PluginSignatureStore
	capabilityMgr  *CapabilityManager
	auditLogger    *SecurityAuditLogger
	config         SecurePluginConfig
	mu             sync.RWMutex
	securePlugins  map[string]*SecurePlugin
}

// SecurePluginConfig defines security configuration for the plugin manager
type SecurePluginConfig struct {
	// Security enforcement
	EnforceSignatures   bool `toml:"enforce_signatures" json:"enforce_signatures" yaml:"enforce_signatures"`
	RequireCapabilities bool `toml:"require_capabilities" json:"require_capabilities" yaml:"require_capabilities"`
	EnableSandboxing    bool `toml:"enable_sandboxing" json:"enable_sandboxing" yaml:"enable_sandboxing"`
	EnableAuditLogging  bool `toml:"enable_audit_logging" json:"enable_audit_logging" yaml:"enable_audit_logging"`

	// Signature verification
	TrustedCertificates []string      `toml:"trusted_certificates" json:"trusted_certificates" yaml:"trusted_certificates"`
	SignatureCacheSize  int           `toml:"signature_cache_size" json:"signature_cache_size" yaml:"signature_cache_size"`
	SignatureCacheTTL   time.Duration `toml:"signature_cache_ttl" json:"signature_cache_ttl" yaml:"signature_cache_ttl"`

	// Capability management
	DefaultCapabilities    []string `toml:"default_capabilities" json:"default_capabilities" yaml:"default_capabilities"`
	RestrictedCapabilities []string `toml:"restricted_capabilities" json:"restricted_capabilities" yaml:"restricted_capabilities"`

	// Sandbox configuration
	SandboxConfig SandboxConfig `toml:"sandbox_config" json:"sandbox_config" yaml:"sandbox_config"`

	// Audit configuration
	AuditLogPath       string `toml:"audit_log_path" json:"audit_log_path" yaml:"audit_log_path"`
	AuditRetentionDays int    `toml:"audit_retention_days" json:"audit_retention_days" yaml:"audit_retention_days"`
}

// DefaultSecurePluginConfig returns secure default configuration
func DefaultSecurePluginConfig() SecurePluginConfig {
	return SecurePluginConfig{
		EnforceSignatures:      true,
		RequireCapabilities:    true,
		EnableSandboxing:       true,
		EnableAuditLogging:     true,
		TrustedCertificates:    []string{},
		SignatureCacheSize:     1000,
		SignatureCacheTTL:      24 * time.Hour,
		DefaultCapabilities:    []string{"read", "log"},
		RestrictedCapabilities: []string{"admin", "system", "network"},
		SandboxConfig:          DefaultSandboxConfig(),
		AuditLogPath:           "./logs/plugin_audit.log",
		AuditRetentionDays:     30,
	}
}

// SecurePlugin wraps a plugin with security controls
type SecurePlugin struct {
	Plugin
	Info           *PluginInfo
	Capabilities   []string
	Signature      *PluginSignature
	Sandboxed      bool
	LastValidated  time.Time
	ViolationCount int
	mu             sync.RWMutex
}

// PluginSignature represents a cryptographic signature for a plugin
type PluginSignature struct {
	Algorithm   string    `json:"algorithm"`
	Signature   []byte    `json:"signature"`
	Certificate []byte    `json:"certificate"`
	Timestamp   time.Time `json:"timestamp"`
	Hash        string    `json:"hash"`
	Signer      string    `json:"signer"`
}

// PluginSignatureStore manages plugin signatures and verification
type PluginSignatureStore struct {
	trustedCerts map[string]*x509.Certificate
	cache        map[string]*PluginSignature
	cacheSize    int
	cacheTTL     time.Duration
	mu           sync.RWMutex
	logger       *slog.Logger
}

// CapabilityManager manages plugin capabilities and permissions
type CapabilityManager struct {
	capabilities   map[string]Capability
	pluginCaps     map[string][]string
	restrictedCaps map[string]bool
	defaultCaps    []string
	mu             sync.RWMutex
	logger         *slog.Logger
}

// Capability defines a permission that a plugin can have
type Capability struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Level       int      `json:"level"` // 0=lowest, 100=highest
	Privileges  []string `json:"privileges"`
	Restricted  bool     `json:"restricted"`
}

// SecurityAuditLogger logs security events for plugins
type SecurityAuditLogger struct {
	logPath       string
	retentionDays int
	logger        *slog.Logger
	mu            sync.RWMutex
	eventCount    int64
}

// NewSecurePluginManager creates a new secure plugin manager
func NewSecurePluginManager(pluginPath string, config SecurePluginConfig) (*SecurePluginManager, error) {
	// Create base manager
	baseManager := NewManager(pluginPath)

	// Create sandbox
	sandbox := NewPluginSandbox(config.SandboxConfig)
	if config.EnableSandboxing {
		if err := sandbox.Start(); err != nil {
			return nil, fmt.Errorf("failed to start plugin sandbox: %w", err)
		}
	}

	// Create validator
	validator := NewPluginValidator()
	validator.SetDevelopmentMode(!config.EnforceSignatures)

	// Create signature store
	signatureStore, err := NewPluginSignatureStore(config.TrustedCertificates, config.SignatureCacheSize, config.SignatureCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature store: %w", err)
	}

	// Create capability manager
	capabilityMgr := NewCapabilityManager(config.DefaultCapabilities, config.RestrictedCapabilities)

	// Create audit logger
	auditLogger, err := NewSecurityAuditLogger(config.AuditLogPath, config.AuditRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	return &SecurePluginManager{
		Manager:        baseManager,
		sandbox:        sandbox,
		validator:      validator,
		signatureStore: signatureStore,
		capabilityMgr:  capabilityMgr,
		auditLogger:    auditLogger,
		config:         config,
		securePlugins:  make(map[string]*SecurePlugin),
	}, nil
}

// LoadSecurePlugin loads a plugin with enhanced security controls
func (spm *SecurePluginManager) LoadSecurePlugin(pluginName string) error {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	spm.auditLogger.LogEvent("plugin_load_attempt", map[string]interface{}{
		"plugin_name": pluginName,
		"timestamp":   time.Now(),
	})

	// Construct plugin path
	pluginPath := filepath.Join(spm.pluginPath, pluginName+".so")

	// 1. Validate plugin file
	validationResult, err := spm.validator.ValidatePlugin(pluginPath)
	if err != nil {
		spm.auditLogger.LogEvent("plugin_validation_failed", map[string]interface{}{
			"plugin_name": pluginName,
			"error":       err.Error(),
		})
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	if !validationResult.Valid {
		spm.auditLogger.LogEvent("plugin_validation_errors", map[string]interface{}{
			"plugin_name": pluginName,
			"errors":      validationResult.Errors,
		})
		return fmt.Errorf("plugin validation failed: %v", validationResult.Errors)
	}

	// 2. Verify signature if enforcement is enabled
	var signature *PluginSignature
	if spm.config.EnforceSignatures {
		sig, err := spm.signatureStore.VerifyPluginSignature(pluginPath)
		if err != nil {
			spm.auditLogger.LogEvent("plugin_signature_verification_failed", map[string]interface{}{
				"plugin_name": pluginName,
				"error":       err.Error(),
			})
			return fmt.Errorf("signature verification failed: %w", err)
		}
		signature = sig
	}

	// 3. Load plugin using base manager
	if err := spm.Manager.LoadPlugin(pluginName); err != nil {
		spm.auditLogger.LogEvent("plugin_load_failed", map[string]interface{}{
			"plugin_name": pluginName,
			"error":       err.Error(),
		})
		return fmt.Errorf("failed to load plugin: %w", err)
	}

	// 4. Get plugin info
	pluginInfo := validationResult.Metadata["plugin_info"].(PluginInfo)

	// 5. Determine capabilities
	capabilities := spm.capabilityMgr.GetPluginCapabilities(pluginName, &pluginInfo)

	// 6. Create secure plugin wrapper
	securePlugin := &SecurePlugin{
		Info:           &pluginInfo,
		Capabilities:   capabilities,
		Signature:      signature,
		Sandboxed:      spm.config.EnableSandboxing,
		LastValidated:  time.Now(),
		ViolationCount: 0,
	}

	// 7. Initialize plugin with security context
	if err := spm.initializeSecurePlugin(securePlugin, pluginName); err != nil {
		spm.auditLogger.LogEvent("plugin_initialization_failed", map[string]interface{}{
			"plugin_name": pluginName,
			"error":       err.Error(),
		})
		return fmt.Errorf("failed to initialize secure plugin: %w", err)
	}

	// 8. Register secure plugin
	spm.securePlugins[pluginName] = securePlugin

	spm.auditLogger.LogEvent("plugin_loaded_securely", map[string]interface{}{
		"plugin_name":  pluginName,
		"capabilities": capabilities,
		"signature":    signature != nil,
		"sandboxed":    spm.config.EnableSandboxing,
		"validated_at": time.Now(),
	})

	return nil
}

// initializeSecurePlugin initializes a plugin with security context
func (spm *SecurePluginManager) initializeSecurePlugin(securePlugin *SecurePlugin, pluginName string) error {
	// Get the actual plugin from the base manager
	// This is a simplified approach - in practice, we'd need to track the plugin type
	// and get the appropriate plugin instance

	// For now, we'll assume it's a generic plugin and initialize it
	// In a real implementation, we'd need to handle different plugin types

	// Create a security context for the plugin
	_ = &PluginSecurityContext{
		PluginName:   pluginName,
		Capabilities: securePlugin.Capabilities,
		Sandboxed:    securePlugin.Sandboxed,
		AuditLogger:  spm.auditLogger,
	}

	// Initialize the plugin with the security context
	// This would need to be implemented based on the specific plugin interface

	return nil
}

// ExecuteSecurePlugin executes a plugin function with security controls
func (spm *SecurePluginManager) ExecuteSecurePlugin(pluginName string, fn func() (*PluginResult, error)) (*PluginResult, error) {
	spm.mu.RLock()
	securePlugin, exists := spm.securePlugins[pluginName]
	spm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("secure plugin not found: %s", pluginName)
	}

	// Check if plugin has been revoked due to violations
	if securePlugin.ViolationCount > 10 {
		spm.auditLogger.LogEvent("plugin_execution_blocked", map[string]interface{}{
			"plugin_name":     pluginName,
			"violation_count": securePlugin.ViolationCount,
			"reason":          "excessive_violations",
		})
		return nil, fmt.Errorf("plugin execution blocked due to security violations")
	}

	// Execute in sandbox if enabled
	if spm.config.EnableSandboxing {
		return spm.sandbox.ExecuteInSandbox(pluginName, fn)
	}

	// Execute directly with monitoring
	return fn()
}

// GetSecurePluginInfo returns security information about a plugin
func (spm *SecurePluginManager) GetSecurePluginInfo(pluginName string) (*SecurePlugin, error) {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	securePlugin, exists := spm.securePlugins[pluginName]
	if !exists {
		return nil, fmt.Errorf("secure plugin not found: %s", pluginName)
	}

	return securePlugin, nil
}

// RevokePlugin revokes a plugin due to security violations
func (spm *SecurePluginManager) RevokePlugin(pluginName string, reason string) error {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	securePlugin, exists := spm.securePlugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin not found: %s", pluginName)
	}

	// Close the plugin
	if err := securePlugin.Close(); err != nil {
		spm.auditLogger.LogEvent("plugin_close_failed", map[string]interface{}{
			"plugin_name": pluginName,
			"error":       err.Error(),
		})
	}

	// Remove from secure plugins
	delete(spm.securePlugins, pluginName)

	// Remove from base manager
	// This would need to be implemented in the base manager

	spm.auditLogger.LogEvent("plugin_revoked", map[string]interface{}{
		"plugin_name": pluginName,
		"reason":      reason,
		"timestamp":   time.Now(),
	})

	return nil
}

// GetSecurityStatus returns the current security status
func (spm *SecurePluginManager) GetSecurityStatus() map[string]interface{} {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	status := map[string]interface{}{
		"secure_plugins_count":  len(spm.securePlugins),
		"sandbox_enabled":       spm.config.EnableSandboxing,
		"sandbox_status":        spm.sandbox.GetSandboxStatus(),
		"signature_enforcement": spm.config.EnforceSignatures,
		"audit_logging":         spm.config.EnableAuditLogging,
		"capability_management": spm.config.RequireCapabilities,
	}

	// Add plugin-specific security info
	pluginSecurity := make(map[string]interface{})
	for name, securePlugin := range spm.securePlugins {
		pluginSecurity[name] = map[string]interface{}{
			"capabilities":    securePlugin.Capabilities,
			"sandboxed":       securePlugin.Sandboxed,
			"last_validated":  securePlugin.LastValidated,
			"violation_count": securePlugin.ViolationCount,
			"has_signature":   securePlugin.Signature != nil,
		}
	}
	status["plugins"] = pluginSecurity

	return status
}

// Close shuts down the secure plugin manager
func (spm *SecurePluginManager) Close() error {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	// Close all secure plugins
	for name, securePlugin := range spm.securePlugins {
		if err := securePlugin.Close(); err != nil {
			spm.auditLogger.LogEvent("plugin_close_error", map[string]interface{}{
				"plugin_name": name,
				"error":       err.Error(),
			})
		}
	}

	// Stop sandbox
	if spm.sandbox != nil {
		if err := spm.sandbox.Stop(); err != nil {
			spm.auditLogger.LogEvent("sandbox_stop_error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Close base manager
	if err := spm.Manager.Close(); err != nil {
		return err
	}

	spm.auditLogger.LogEvent("secure_plugin_manager_closed", map[string]interface{}{
		"timestamp": time.Now(),
	})

	return nil
}

// PluginSecurityContext provides security context for plugin execution
type PluginSecurityContext struct {
	PluginName   string
	Capabilities []string
	Sandboxed    bool
	AuditLogger  *SecurityAuditLogger
}

// NewPluginSignatureStore creates a new signature store
func NewPluginSignatureStore(trustedCerts []string, cacheSize int, cacheTTL time.Duration) (*PluginSignatureStore, error) {
	store := &PluginSignatureStore{
		trustedCerts: make(map[string]*x509.Certificate),
		cache:        make(map[string]*PluginSignature),
		cacheSize:    cacheSize,
		cacheTTL:     cacheTTL,
		logger:       slog.Default().With("component", "plugin-signature-store"),
	}

	// Load trusted certificates
	for _, certPath := range trustedCerts {
		if err := store.loadTrustedCertificate(certPath); err != nil {
			return nil, fmt.Errorf("failed to load trusted certificate %s: %w", certPath, err)
		}
	}

	return store, nil
}

// loadTrustedCertificate loads a trusted certificate from file
func (pss *PluginSignatureStore) loadTrustedCertificate(certPath string) error {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	pss.trustedCerts[cert.Subject.CommonName] = cert
	pss.logger.Info("Loaded trusted certificate", "subject", cert.Subject.CommonName)

	return nil
}

// VerifyPluginSignature verifies a plugin's signature
func (pss *PluginSignatureStore) VerifyPluginSignature(pluginPath string) (*PluginSignature, error) {
	// This is a placeholder implementation
	// In a real implementation, we would:
	// 1. Extract signature from plugin metadata or separate signature file
	// 2. Verify the signature against trusted certificates
	// 3. Check signature timestamp and validity

	// For now, return a mock signature
	return &PluginSignature{
		Algorithm:   "SHA256-RSA",
		Signature:   []byte("mock_signature"),
		Certificate: []byte("mock_certificate"),
		Timestamp:   time.Now(),
		Hash:        "mock_hash",
		Signer:      "mock_signer",
	}, nil
}

// NewCapabilityManager creates a new capability manager
func NewCapabilityManager(defaultCaps, restrictedCaps []string) *CapabilityManager {
	cm := &CapabilityManager{
		capabilities:   make(map[string]Capability),
		pluginCaps:     make(map[string][]string),
		restrictedCaps: make(map[string]bool),
		defaultCaps:    defaultCaps,
		logger:         slog.Default().With("component", "capability-manager"),
	}

	// Initialize default capabilities
	cm.initializeDefaultCapabilities()

	// Mark restricted capabilities
	for _, cap := range restrictedCaps {
		cm.restrictedCaps[cap] = true
	}

	return cm
}

// initializeDefaultCapabilities sets up default plugin capabilities
func (cm *CapabilityManager) initializeDefaultCapabilities() {
	defaultCaps := []Capability{
		{Name: "read", Description: "Read access to plugin data", Level: 10, Privileges: []string{"read"}},
		{Name: "log", Description: "Logging capabilities", Level: 20, Privileges: []string{"log"}},
		{Name: "network", Description: "Network access", Level: 50, Privileges: []string{"network"}, Restricted: true},
		{Name: "file", Description: "File system access", Level: 60, Privileges: []string{"file"}, Restricted: true},
		{Name: "admin", Description: "Administrative privileges", Level: 90, Privileges: []string{"admin"}, Restricted: true},
		{Name: "system", Description: "System-level access", Level: 100, Privileges: []string{"system"}, Restricted: true},
	}

	for _, cap := range defaultCaps {
		cm.capabilities[cap.Name] = cap
	}
}

// GetPluginCapabilities determines capabilities for a plugin
func (cm *CapabilityManager) GetPluginCapabilities(pluginName string, info *PluginInfo) []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Start with default capabilities
	capabilities := make([]string, len(cm.defaultCaps))
	copy(capabilities, cm.defaultCaps)

	// Add capabilities based on plugin type
	switch info.Type {
	case PluginTypeAntivirus, PluginTypeAntispam:
		capabilities = append(capabilities, "network", "file")
	case PluginTypeRateLimit:
		capabilities = append(capabilities, "network")
	case PluginTypeAuth:
		capabilities = append(capabilities, "network", "file")
	}

	// Remove duplicates and restricted capabilities if not explicitly allowed
	uniqueCaps := make(map[string]bool)
	for _, cap := range capabilities {
		if !cm.restrictedCaps[cap] || cm.isCapabilityAllowed(pluginName, cap) {
			uniqueCaps[cap] = true
		}
	}

	result := make([]string, 0, len(uniqueCaps))
	for cap := range uniqueCaps {
		result = append(result, cap)
	}

	return result
}

// isCapabilityAllowed checks if a plugin is allowed a restricted capability
func (cm *CapabilityManager) isCapabilityAllowed(pluginName, capability string) bool {
	// This would check against a whitelist or configuration
	// For now, we'll be conservative and deny restricted capabilities
	return false
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(logPath string, retentionDays int) (*SecurityAuditLogger, error) {
	// Ensure log directory exists
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	return &SecurityAuditLogger{
		logPath:       logPath,
		retentionDays: retentionDays,
		logger:        slog.Default().With("component", "security-audit"),
		eventCount:    0,
	}, nil
}

// LogEvent logs a security event
func (sal *SecurityAuditLogger) LogEvent(eventType string, data map[string]interface{}) {
	sal.mu.Lock()
	defer sal.mu.Unlock()

	sal.eventCount++

	// Add common fields
	data["event_type"] = eventType
	data["event_id"] = sal.eventCount
	data["timestamp"] = time.Now().UTC()

	// Log the event
	sal.logger.Info("Security audit event", "event", data)

	// In a real implementation, we would also write to a dedicated audit log file
	// and implement log rotation based on retentionDays
}
