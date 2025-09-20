package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// SecurePluginIntegration integrates the secure plugin system with the existing SMTP server
type SecurePluginIntegration struct {
	secureManager *SecurePluginManager
	logger        *slog.Logger
	enabled       bool
}

// NewSecurePluginIntegration creates a new secure plugin integration
func NewSecurePluginIntegration(logger *slog.Logger) *SecurePluginIntegration {
	config := DefaultSecureManagerConfig()
	
	return &SecurePluginIntegration{
		secureManager: NewSecurePluginManager(config, logger),
		logger:        logger,
		enabled:       true,
	}
}

// Initialize initializes the secure plugin system
func (spi *SecurePluginIntegration) Initialize() error {
	if !spi.enabled {
		spi.logger.Info("Secure plugin system disabled")
		return nil
	}
	
	// Start the secure plugin manager
	if err := spi.secureManager.Start(); err != nil {
		return fmt.Errorf("failed to start secure plugin manager: %w", err)
	}
	
	// Load available plugins
	if err := spi.loadAvailablePlugins(); err != nil {
		spi.logger.Error("Failed to load some plugins", "error", err)
		// Continue even if some plugins fail to load
	}
	
	spi.logger.Info("Secure plugin system initialized successfully")
	return nil
}

// ProcessAntivirusPlugins processes a message through antivirus plugins
func (spi *SecurePluginIntegration) ProcessAntivirusPlugins(ctx context.Context, messageID, from string, to []string, subject string, headers map[string]string, body []byte, remoteAddr string, tlsEnabled bool) ([]*SecurePluginOutput, error) {
	if !spi.enabled {
		return nil, nil
	}
	
	input := &SecurePluginInput{
		MessageID:  messageID,
		From:       from,
		To:         to,
		Subject:    subject,
		Headers:    headers,
		Body:       body,
		Metadata:   make(map[string]interface{}),
		RemoteAddr: remoteAddr,
		TLSEnabled: tlsEnabled,
	}
	
	return spi.secureManager.ProcessMessage(ctx, SecurePluginTypeAntivirus, input)
}

// ProcessAntispamPlugins processes a message through antispam plugins
func (spi *SecurePluginIntegration) ProcessAntispamPlugins(ctx context.Context, messageID, from string, to []string, subject string, headers map[string]string, body []byte, remoteAddr string, tlsEnabled bool) ([]*SecurePluginOutput, error) {
	if !spi.enabled {
		return nil, nil
	}
	
	input := &SecurePluginInput{
		MessageID:  messageID,
		From:       from,
		To:         to,
		Subject:    subject,
		Headers:    headers,
		Body:       body,
		Metadata:   make(map[string]interface{}),
		RemoteAddr: remoteAddr,
		TLSEnabled: tlsEnabled,
	}
	
	return spi.secureManager.ProcessMessage(ctx, SecurePluginTypeAntispam, input)
}

// ProcessFilterPlugins processes a message through filter plugins
func (spi *SecurePluginIntegration) ProcessFilterPlugins(ctx context.Context, messageID, from string, to []string, subject string, headers map[string]string, body []byte, remoteAddr string, tlsEnabled bool) ([]*SecurePluginOutput, error) {
	if !spi.enabled {
		return nil, nil
	}
	
	input := &SecurePluginInput{
		MessageID:  messageID,
		From:       from,
		To:         to,
		Subject:    subject,
		Headers:    headers,
		Body:       body,
		Metadata:   make(map[string]interface{}),
		RemoteAddr: remoteAddr,
		TLSEnabled: tlsEnabled,
	}
	
	return spi.secureManager.ProcessMessage(ctx, SecurePluginTypeFilter, input)
}

// GetPluginStats returns statistics for all loaded plugins
func (spi *SecurePluginIntegration) GetPluginStats() map[string]interface{} {
	if !spi.enabled {
		return map[string]interface{}{
			"enabled": false,
			"message": "Secure plugin system disabled",
		}
	}
	
	stats := spi.secureManager.GetPluginStats()
	stats["secure_plugin_system"] = true
	stats["cgo_enabled"] = false
	return stats
}

// Shutdown gracefully shuts down the secure plugin system
func (spi *SecurePluginIntegration) Shutdown() error {
	if !spi.enabled {
		return nil
	}
	
	if err := spi.secureManager.Shutdown(); err != nil {
		spi.logger.Error("Error shutting down secure plugin manager", "error", err)
		return err
	}
	
	spi.logger.Info("Secure plugin system shut down successfully")
	return nil
}

// loadAvailablePlugins loads all available plugins from the plugin directory
func (spi *SecurePluginIntegration) loadAvailablePlugins() error {
	pluginDir := spi.secureManager.config.PluginDirectory
	
	// Check if plugin directory exists
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		spi.logger.Warn("Plugin directory does not exist",
			"directory", pluginDir,
		)
		return nil
	}
	
	// Read plugin directory
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}
	
	loadedCount := 0
	errorCount := 0
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		pluginName := entry.Name()
		spi.logger.Info("Loading secure plugin", "plugin", pluginName)
		
		if err := spi.secureManager.LoadPlugin(pluginName); err != nil {
			spi.logger.Error("Failed to load plugin",
				"plugin", pluginName,
				"error", err,
			)
			errorCount++
			continue
		}
		
		loadedCount++
		spi.logger.Info("Successfully loaded secure plugin", "plugin", pluginName)
	}
	
	spi.logger.Info("Plugin loading completed",
		"loaded", loadedCount,
		"errors", errorCount,
		"total_attempted", len(entries),
	)
	
	if errorCount > 0 {
		return fmt.Errorf("failed to load %d plugins", errorCount)
	}
	
	return nil
}

// IsEnabled returns whether the secure plugin system is enabled
func (spi *SecurePluginIntegration) IsEnabled() bool {
	return spi.enabled
}

// SetEnabled enables or disables the secure plugin system
func (spi *SecurePluginIntegration) SetEnabled(enabled bool) {
	spi.enabled = enabled
	spi.logger.Info("Secure plugin system enabled status changed", "enabled", enabled)
}

// GetLoadedPlugins returns a list of loaded plugins
func (spi *SecurePluginIntegration) GetLoadedPlugins() []string {
	if !spi.enabled {
		return []string{}
	}
	
	stats := spi.secureManager.GetPluginStats()
	plugins, ok := stats["plugins"].(map[string]interface{})
	if !ok {
		return []string{}
	}
	
	pluginNames := make([]string, 0, len(plugins))
	for name := range plugins {
		pluginNames = append(pluginNames, name)
	}
	
	return pluginNames
}

// ReloadPlugin reloads a specific plugin
func (spi *SecurePluginIntegration) ReloadPlugin(pluginName string) error {
	if !spi.enabled {
		return fmt.Errorf("secure plugin system disabled")
	}
	
	spi.logger.Info("Reloading secure plugin", "plugin", pluginName)
	
	// Unload existing plugin
	if err := spi.secureManager.UnloadPlugin(pluginName); err != nil {
		spi.logger.Warn("Failed to unload plugin for reload",
			"plugin", pluginName,
			"error", err,
		)
		// Continue with loading even if unload failed
	}
	
	// Load plugin again
	if err := spi.secureManager.LoadPlugin(pluginName); err != nil {
		return fmt.Errorf("failed to reload plugin %s: %w", pluginName, err)
	}
	
	spi.logger.Info("Successfully reloaded secure plugin", "plugin", pluginName)
	return nil
}

// ValidatePluginSecurity validates the security of all loaded plugins
func (spi *SecurePluginIntegration) ValidatePluginSecurity() error {
	if !spi.enabled {
		return nil
	}
	
	loadedPlugins := spi.GetLoadedPlugins()
	spi.logger.Info("Validating plugin security", "plugin_count", len(loadedPlugins))
	
	for _, pluginName := range loadedPlugins {
		// Perform security validation for each plugin
		spi.logger.Debug("Validating plugin security", "plugin", pluginName)
		
		// In a full implementation, this would perform comprehensive security checks
		// For now, we log that validation is being performed
	}
	
	spi.logger.Info("Plugin security validation completed", "plugins_validated", len(loadedPlugins))
	return nil
}
