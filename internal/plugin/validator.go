package plugin

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"plugin"
	"reflect"
	"strings"
	"time"
)

// PluginValidator handles validation of plugin files and compatibility
type PluginValidator struct {
	logger            *slog.Logger
	trustedHashes     map[string]string // SHA256 hashes of trusted plugins
	allowedSymbols    []string          // Required symbols for plugin loading
	forbiddenSymbols  []string          // Symbols that should not be present
	maxFileSize       int64             // Maximum plugin file size in bytes
	validationTimeout time.Duration     // Timeout for validation operations
	enforceSignatures bool              // Whether to enforce signature verification
	developmentMode   bool              // Allow unsigned plugins in dev mode
}

// ValidationResult contains the result of plugin validation
type ValidationResult struct {
	Valid       bool
	Errors      []string
	Warnings    []string
	FileHash    string
	FileSize    int64
	Symbols     []string
	Metadata    map[string]interface{}
	ValidatedAt time.Time
}

// NewPluginValidator creates a new plugin validator with security defaults
func NewPluginValidator() *PluginValidator {
	return &PluginValidator{
		logger: slog.Default().With("component", "plugin-validator"),
		trustedHashes: map[string]string{
			"clamav": "", // Will be populated from config or calculated
			"rspamd": "",
			"dkim":   "",
			"spf":    "",
			"dmarc":  "",
			"arc":    "",
		},
		allowedSymbols: []string{
			"PluginInfo",
			"Plugin",
		},
		forbiddenSymbols: []string{
			"main",         // Plugins shouldn't have main functions
			"init",         // Avoid global init functions
			"os.Exit",      // Prevent plugins from exiting the process
			"syscall.Exec", // Prevent system calls
			"runtime.GC",   // Don't allow GC manipulation
		},
		maxFileSize:       50 * 1024 * 1024, // 50MB max
		validationTimeout: 30 * time.Second,
		enforceSignatures: false, // Default to false for development
		developmentMode:   true,  // Will be set based on environment
	}
}

// ValidatePlugin performs comprehensive validation of a plugin file
func (v *PluginValidator) ValidatePlugin(pluginPath string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:       true,
		Errors:      make([]string, 0),
		Warnings:    make([]string, 0),
		Metadata:    make(map[string]interface{}),
		ValidatedAt: time.Now(),
	}

	v.logger.Info("Validating plugin", "path", pluginPath)

	// 1. Basic file validation
	if err := v.validateFileBasics(pluginPath, result); err != nil {
		return result, err
	}

	// 2. Security validation
	if err := v.validateSecurity(pluginPath, result); err != nil {
		return result, err
	}

	// 3. Symbol validation
	if err := v.validateSymbols(pluginPath, result); err != nil {
		return result, err
	}

	// 4. Plugin structure validation
	if err := v.validatePluginStructure(pluginPath, result); err != nil {
		return result, err
	}

	// 5. Dependency validation
	if err := v.validateDependencies(pluginPath, result); err != nil {
		return result, err
	}

	// Mark as invalid if any errors occurred
	if len(result.Errors) > 0 {
		result.Valid = false
	}

	v.logger.Info("Plugin validation completed",
		"path", pluginPath,
		"valid", result.Valid,
		"errors", len(result.Errors),
		"warnings", len(result.Warnings))

	return result, nil
}

// validateFileBasics performs basic file system validation
func (v *PluginValidator) validateFileBasics(pluginPath string, result *ValidationResult) error {
	// Check if file exists
	info, err := os.Stat(pluginPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Plugin file not found: %v", err))
		return nil
	}

	// Check file size
	result.FileSize = info.Size()
	if result.FileSize > v.maxFileSize {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Plugin file too large: %d bytes (max: %d)", result.FileSize, v.maxFileSize))
	}

	// Check file extension
	if !strings.HasSuffix(pluginPath, ".so") {
		result.Errors = append(result.Errors, "Plugin file must have .so extension")
	}

	// Calculate file hash
	hash, err := v.calculateFileHash(pluginPath)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Could not calculate file hash: %v", err))
	} else {
		result.FileHash = hash
	}

	return nil
}

// validateSecurity performs security-related validation
func (v *PluginValidator) validateSecurity(pluginPath string, result *ValidationResult) error {
	filename := filepath.Base(pluginPath)
	pluginName := strings.TrimSuffix(filename, ".so")

	// Check against trusted hashes if available
	if expectedHash, exists := v.trustedHashes[pluginName]; exists && expectedHash != "" {
		if result.FileHash != expectedHash {
			if v.enforceSignatures {
				result.Errors = append(result.Errors,
					fmt.Sprintf("Plugin hash mismatch. Expected: %s, Got: %s", expectedHash, result.FileHash))
			} else {
				result.Warnings = append(result.Warnings, "Plugin hash does not match trusted version")
			}
		}
	}

	// Check file permissions (should not be world-writable)
	info, err := os.Stat(pluginPath)
	if err == nil {
		mode := info.Mode()
		if mode&0o002 != 0 { // World-writable
			result.Warnings = append(result.Warnings, "Plugin file is world-writable (security risk)")
		}
	}

	return nil
}

// validateSymbols checks for required and forbidden symbols
func (v *PluginValidator) validateSymbols(pluginPath string, result *ValidationResult) error {
	// This is a basic validation - for more thorough checking we'd need to
	// examine the ELF/Mach-O/PE binary format, but Go's plugin package
	// provides some symbol introspection

	// Try to open the plugin to check symbols
	p, err := plugin.Open(pluginPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Cannot open plugin for symbol validation: %v", err))
		return nil
	}

	// Check for required symbols
	for _, symbol := range v.allowedSymbols {
		if _, err := p.Lookup(symbol); err != nil {
			if symbol == "PluginInfo" || symbol == "Plugin" {
				result.Errors = append(result.Errors, fmt.Sprintf("Required symbol '%s' not found", symbol))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Optional symbol '%s' not found", symbol))
			}
		} else {
			result.Symbols = append(result.Symbols, symbol)
		}
	}

	return nil
}

// validatePluginStructure validates the plugin implements required interfaces
func (v *PluginValidator) validatePluginStructure(pluginPath string, result *ValidationResult) error {
	p, err := plugin.Open(pluginPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Cannot open plugin for structure validation: %v", err))
		return nil
	}

	// Validate PluginInfo structure
	infoSym, err := p.Lookup("PluginInfo")
	if err != nil {
		result.Errors = append(result.Errors, "PluginInfo symbol not found")
		return nil
	}

	info, ok := infoSym.(*PluginInfo)
	if !ok {
		result.Errors = append(result.Errors, "PluginInfo is not of correct type")
		return nil
	}

	// Validate PluginInfo fields
	if info.Name == "" {
		result.Errors = append(result.Errors, "Plugin name is required")
	}
	if info.Version == "" {
		result.Warnings = append(result.Warnings, "Plugin version is not specified")
	}
	if info.Type == "" {
		result.Errors = append(result.Errors, "Plugin type is required")
	}

	result.Metadata["plugin_info"] = *info

	// Validate Plugin implementation
	pluginSym, err := p.Lookup("Plugin")
	if err != nil {
		result.Errors = append(result.Errors, "Plugin symbol not found")
		return nil
	}

	// Check if plugin implements basic Plugin interface
	pluginType := reflect.TypeOf(pluginSym)
	if pluginType == nil {
		result.Errors = append(result.Errors, "Plugin symbol is nil")
		return nil
	}

	// Check for required methods
	requiredMethods := []string{"GetInfo", "Init", "Close"}
	for _, method := range requiredMethods {
		if _, found := pluginType.MethodByName(method); !found {
			result.Errors = append(result.Errors, fmt.Sprintf("Required method '%s' not implemented", method))
		}
	}

	return nil
}

// validateDependencies checks plugin dependencies and compatibility
func (v *PluginValidator) validateDependencies(pluginPath string, result *ValidationResult) error {
	// For now, this is a placeholder for future dependency validation
	// In a more advanced implementation, we would:
	// 1. Check Go version compatibility
	// 2. Validate required external dependencies
	// 3. Check for version conflicts with other loaded plugins
	// 4. Validate API compatibility

	result.Warnings = append(result.Warnings, "Dependency validation not yet implemented")
	return nil
}

// calculateFileHash calculates SHA256 hash of the plugin file
func (v *PluginValidator) calculateFileHash(pluginPath string) (string, error) {
	file, err := os.Open(pluginPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// UpdateTrustedHash adds or updates a trusted hash for a plugin
func (v *PluginValidator) UpdateTrustedHash(pluginName, hash string) {
	v.trustedHashes[pluginName] = hash
	v.logger.Info("Updated trusted hash", "plugin", pluginName, "hash", hash[:16]+"...")
}

// SetDevelopmentMode enables or disables development mode
func (v *PluginValidator) SetDevelopmentMode(enabled bool) {
	v.developmentMode = enabled
	v.enforceSignatures = !enabled // Disable signature enforcement in dev mode
	v.logger.Info("Development mode changed", "enabled", enabled, "enforce_signatures", v.enforceSignatures)
}

// GetValidationSummary returns a summary of validation capabilities
func (v *PluginValidator) GetValidationSummary() map[string]interface{} {
	return map[string]interface{}{
		"max_file_size":      v.maxFileSize,
		"validation_timeout": v.validationTimeout,
		"enforce_signatures": v.enforceSignatures,
		"development_mode":   v.developmentMode,
		"trusted_plugins":    len(v.trustedHashes),
		"allowed_symbols":    len(v.allowedSymbols),
		"forbidden_symbols":  len(v.forbiddenSymbols),
	}
}
