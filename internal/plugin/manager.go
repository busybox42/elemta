package plugin

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"sync"
)

var (
	// ErrPluginNotFound is returned when a plugin is not found
	ErrPluginNotFound = errors.New("plugin not found")

	// ErrPluginAlreadyLoaded is returned when a plugin is already loaded
	ErrPluginAlreadyLoaded = errors.New("plugin already loaded")

	// ErrPluginSymbolNotFound is returned when a plugin symbol is not found
	ErrPluginSymbolNotFound = errors.New("plugin symbol not found")

	// ErrPluginInvalidType is returned when a plugin is not of the expected type
	ErrPluginInvalidType = errors.New("plugin is not of the expected type")
)

// Manager handles loading and managing plugins
type Manager struct {
	pluginPath       string
	antivirusPlugins map[string]AntivirusPlugin
	antispamPlugins  map[string]AntispamPlugin
	loadedPlugins    map[string]*plugin.Plugin
	mu               sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager(pluginPath string) *Manager {
	return &Manager{
		pluginPath:       pluginPath,
		antivirusPlugins: make(map[string]AntivirusPlugin),
		antispamPlugins:  make(map[string]AntispamPlugin),
		loadedPlugins:    make(map[string]*plugin.Plugin),
		mu:               sync.RWMutex{},
	}
}

// LoadPlugin loads a plugin from the plugin path
func (m *Manager) LoadPlugin(pluginName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if plugin is already loaded
	if _, ok := m.loadedPlugins[pluginName]; ok {
		return ErrPluginAlreadyLoaded
	}

	// Construct plugin path
	pluginPath := filepath.Join(m.pluginPath, pluginName+".so")

	// Check if plugin file exists
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin file %s not found: %w", pluginPath, ErrPluginNotFound)
	}

	// Load plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to load plugin %s: %w", pluginName, err)
	}

	// Store loaded plugin
	m.loadedPlugins[pluginName] = p

	// Try to load as antivirus plugin
	if err := m.loadAntivirusPlugin(pluginName, p); err == nil {
		return nil
	}

	// Try to load as antispam plugin
	if err := m.loadAntispamPlugin(pluginName, p); err == nil {
		return nil
	}

	// If we get here, the plugin didn't have any recognized symbols
	return fmt.Errorf("plugin %s does not contain any recognized plugin symbols", pluginName)
}

// loadAntivirusPlugin attempts to load an antivirus plugin
func (m *Manager) loadAntivirusPlugin(pluginName string, p *plugin.Plugin) error {
	// Look for AntivirusPlugin symbol
	sym, err := p.Lookup("AntivirusPlugin")
	if err != nil {
		return ErrPluginSymbolNotFound
	}

	// Check if symbol is of the expected type
	avPlugin, ok := sym.(AntivirusPlugin)
	if !ok {
		return ErrPluginInvalidType
	}

	// Store antivirus plugin
	m.antivirusPlugins[pluginName] = avPlugin
	return nil
}

// loadAntispamPlugin attempts to load an antispam plugin
func (m *Manager) loadAntispamPlugin(pluginName string, p *plugin.Plugin) error {
	// Look for AntispamPlugin symbol
	sym, err := p.Lookup("AntispamPlugin")
	if err != nil {
		return ErrPluginSymbolNotFound
	}

	// Check if symbol is of the expected type
	asPlugin, ok := sym.(AntispamPlugin)
	if !ok {
		return ErrPluginInvalidType
	}

	// Store antispam plugin
	m.antispamPlugins[pluginName] = asPlugin
	return nil
}

// LoadPlugins loads all plugins from the plugin path
func (m *Manager) LoadPlugins() error {
	// Check if plugin path exists
	if _, err := os.Stat(m.pluginPath); os.IsNotExist(err) {
		// Create plugin directory if it doesn't exist
		if err := os.MkdirAll(m.pluginPath, 0755); err != nil {
			return fmt.Errorf("failed to create plugin directory: %w", err)
		}
		return nil // No plugins to load yet
	}

	// Walk plugin directory
	err := filepath.WalkDir(m.pluginPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Skip non-plugin files
		if filepath.Ext(path) != ".so" {
			return nil
		}

		// Get plugin name
		pluginName := filepath.Base(path)
		pluginName = pluginName[:len(pluginName)-3] // Remove .so extension

		// Load plugin
		if err := m.LoadPlugin(pluginName); err != nil {
			// Log error but continue loading other plugins
			fmt.Printf("Error loading plugin %s: %v\n", pluginName, err)
		}

		return nil
	})

	return err
}

// GetAntivirusPlugin returns an antivirus plugin by name
func (m *Manager) GetAntivirusPlugin(name string) (AntivirusPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.antivirusPlugins[name]
	if !ok {
		return nil, ErrPluginNotFound
	}

	return plugin, nil
}

// GetAntispamPlugin returns an antispam plugin by name
func (m *Manager) GetAntispamPlugin(name string) (AntispamPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.antispamPlugins[name]
	if !ok {
		return nil, ErrPluginNotFound
	}

	return plugin, nil
}

// ListAntivirusPlugins returns a list of loaded antivirus plugins
func (m *Manager) ListAntivirusPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.antivirusPlugins))
	for name := range m.antivirusPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// ListAntispamPlugins returns a list of loaded antispam plugins
func (m *Manager) ListAntispamPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.antispamPlugins))
	for name := range m.antispamPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// Close closes all plugins
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear all plugin maps
	m.antivirusPlugins = make(map[string]AntivirusPlugin)
	m.antispamPlugins = make(map[string]AntispamPlugin)
	m.loadedPlugins = make(map[string]*plugin.Plugin)

	return nil
}
