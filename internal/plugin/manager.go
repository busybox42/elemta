package plugin

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"sort"
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
	dkimPlugins      map[string]DKIMPlugin
	spfPlugins       map[string]SPFPlugin
	dmarcPlugins     map[string]DMARCPlugin
	arcPlugins       map[string]ARCPlugin
	stagePlugins     map[ProcessingStage][]StagePlugin
	typePlugins      map[string][]Plugin
	loadedPlugins    map[string]*plugin.Plugin
	mu               sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager(pluginPath string) *Manager {
	return &Manager{
		pluginPath:       pluginPath,
		antivirusPlugins: make(map[string]AntivirusPlugin),
		antispamPlugins:  make(map[string]AntispamPlugin),
		dkimPlugins:      make(map[string]DKIMPlugin),
		spfPlugins:       make(map[string]SPFPlugin),
		dmarcPlugins:     make(map[string]DMARCPlugin),
		arcPlugins:       make(map[string]ARCPlugin),
		stagePlugins:     make(map[ProcessingStage][]StagePlugin),
		typePlugins:      make(map[string][]Plugin),
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
		return fmt.Errorf("%w: %s", ErrPluginNotFound, pluginPath)
	}

	// Load plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	// Get plugin info
	infoSym, err := p.Lookup("PluginInfo")
	if err != nil {
		return fmt.Errorf("%w: PluginInfo", ErrPluginSymbolNotFound)
	}

	info, ok := infoSym.(*PluginInfo)
	if !ok {
		return fmt.Errorf("%w: PluginInfo", ErrPluginInvalidType)
	}

	// Register plugin based on its type
	switch info.Type {
	case PluginTypeAntivirus:
		if err := m.loadAntivirusPlugin(pluginName, p); err != nil {
			return err
		}
	case PluginTypeAntispam:
		if err := m.loadAntispamPlugin(pluginName, p); err != nil {
			return err
		}
	case PluginTypeDKIM:
		if err := m.loadDKIMPlugin(pluginName, p); err != nil {
			return err
		}
	case PluginTypeSPF:
		if err := m.loadSPFPlugin(pluginName, p); err != nil {
			return err
		}
	case PluginTypeDMARC:
		if err := m.loadDMARCPlugin(pluginName, p); err != nil {
			return err
		}
	case PluginTypeARC:
		if err := m.loadARCPlugin(pluginName, p); err != nil {
			return err
		}
	default:
		// Try to load as a generic plugin
		if err := m.loadGenericPlugin(pluginName, p, info.Type); err != nil {
			return err
		}
	}

	// Store loaded plugin
	m.loadedPlugins[pluginName] = p
	return nil
}

// loadAntivirusPlugin loads an antivirus plugin
func (m *Manager) loadAntivirusPlugin(pluginName string, p *plugin.Plugin) error {
	// Lookup plugin symbol
	sym, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("%w: Plugin", ErrPluginSymbolNotFound)
	}

	// Check if plugin is of the correct type
	plugin, ok := sym.(AntivirusPlugin)
	if !ok {
		return fmt.Errorf("%w: expected AntivirusPlugin", ErrPluginInvalidType)
	}

	// Register plugin
	m.antivirusPlugins[pluginName] = plugin

	// Also register as a type plugin
	m.registerTypePlugin(pluginName, plugin, PluginTypeAntivirus)

	// If it implements StagePlugin, register it for its stages
	if stagePlugin, ok := sym.(StagePlugin); ok {
		m.registerStagePlugin(stagePlugin)
	}

	return nil
}

// loadAntispamPlugin loads an antispam plugin
func (m *Manager) loadAntispamPlugin(pluginName string, p *plugin.Plugin) error {
	// Lookup plugin symbol
	sym, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("%w: Plugin", ErrPluginSymbolNotFound)
	}

	// Check if plugin is of the correct type
	plugin, ok := sym.(AntispamPlugin)
	if !ok {
		return fmt.Errorf("%w: expected AntispamPlugin", ErrPluginInvalidType)
	}

	// Register plugin
	m.antispamPlugins[pluginName] = plugin

	// Also register as a type plugin
	m.registerTypePlugin(pluginName, plugin, PluginTypeAntispam)

	// If it implements StagePlugin, register it for its stages
	if stagePlugin, ok := sym.(StagePlugin); ok {
		m.registerStagePlugin(stagePlugin)
	}

	return nil
}

// loadDKIMPlugin loads a DKIM plugin
func (m *Manager) loadDKIMPlugin(pluginName string, p *plugin.Plugin) error {
	// Look up the "NewDKIMPlugin" symbol
	sym, err := p.Lookup("NewDKIMPlugin")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPluginSymbolNotFound, err)
	}

	// Assert that the symbol is a function that returns a DKIMPlugin
	newPlugin, ok := sym.(func() DKIMPlugin)
	if !ok {
		return fmt.Errorf("%w: %v", ErrPluginInvalidType, "NewDKIMPlugin is not a function that returns a DKIMPlugin")
	}

	// Call the function to get the plugin instance
	plugin := newPlugin()

	// Register the plugin
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the plugin
	m.dkimPlugins[pluginName] = plugin
	m.registerTypePlugin(pluginName, plugin, PluginTypeDKIM)

	return nil
}

// loadSPFPlugin loads an SPF plugin
func (m *Manager) loadSPFPlugin(pluginName string, p *plugin.Plugin) error {
	// Look up the "NewSPFPlugin" symbol
	sym, err := p.Lookup("NewSPFPlugin")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPluginSymbolNotFound, err)
	}

	// Assert that the symbol is a function that returns an SPFPlugin
	newPlugin, ok := sym.(func() SPFPlugin)
	if !ok {
		return fmt.Errorf("%w: %v", ErrPluginInvalidType, "NewSPFPlugin is not a function that returns an SPFPlugin")
	}

	// Call the function to get the plugin instance
	plugin := newPlugin()

	// Register the plugin
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the plugin
	m.spfPlugins[pluginName] = plugin
	m.registerTypePlugin(pluginName, plugin, PluginTypeSPF)

	return nil
}

// loadDMARCPlugin loads a DMARC plugin
func (m *Manager) loadDMARCPlugin(pluginName string, p *plugin.Plugin) error {
	// Look up the "NewDMARCPlugin" symbol
	sym, err := p.Lookup("NewDMARCPlugin")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPluginSymbolNotFound, err)
	}

	// Assert that the symbol is a function that returns a DMARCPlugin
	newPlugin, ok := sym.(func() DMARCPlugin)
	if !ok {
		return fmt.Errorf("%w: %v", ErrPluginInvalidType, "NewDMARCPlugin is not a function that returns a DMARCPlugin")
	}

	// Call the function to get the plugin instance
	plugin := newPlugin()

	// Register the plugin
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the plugin
	m.dmarcPlugins[pluginName] = plugin
	m.registerTypePlugin(pluginName, plugin, PluginTypeDMARC)

	return nil
}

// loadARCPlugin loads an ARC plugin
func (m *Manager) loadARCPlugin(pluginName string, p *plugin.Plugin) error {
	// Look up the "NewARCPlugin" symbol
	sym, err := p.Lookup("NewARCPlugin")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPluginSymbolNotFound, err)
	}

	// Assert that the symbol is a function that returns an ARCPlugin
	newPlugin, ok := sym.(func() ARCPlugin)
	if !ok {
		return fmt.Errorf("%w: %v", ErrPluginInvalidType, "NewARCPlugin is not a function that returns an ARCPlugin")
	}

	// Call the function to get the plugin instance
	plugin := newPlugin()

	// Register the plugin
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the plugin
	m.arcPlugins[pluginName] = plugin
	m.registerTypePlugin(pluginName, plugin, PluginTypeARC)

	return nil
}

// loadGenericPlugin loads a generic plugin
func (m *Manager) loadGenericPlugin(pluginName string, p *plugin.Plugin, pluginType string) error {
	// Lookup plugin symbol
	sym, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("%w: Plugin", ErrPluginSymbolNotFound)
	}

	// Check if plugin implements the Plugin interface
	plugin, ok := sym.(Plugin)
	if !ok {
		return fmt.Errorf("%w: expected Plugin interface", ErrPluginInvalidType)
	}

	// Register as a type plugin
	m.registerTypePlugin(pluginName, plugin, pluginType)

	// If it implements StagePlugin, register it for its stages
	if stagePlugin, ok := sym.(StagePlugin); ok {
		m.registerStagePlugin(stagePlugin)
	}

	return nil
}

// registerTypePlugin registers a plugin by its type
func (m *Manager) registerTypePlugin(pluginName string, plugin Plugin, pluginType string) {
	if _, ok := m.typePlugins[pluginType]; !ok {
		m.typePlugins[pluginType] = make([]Plugin, 0)
	}
	m.typePlugins[pluginType] = append(m.typePlugins[pluginType], plugin)
}

// registerStagePlugin registers a plugin for its processing stages
func (m *Manager) registerStagePlugin(plugin StagePlugin) {
	for _, stage := range plugin.GetStages() {
		if _, ok := m.stagePlugins[stage]; !ok {
			m.stagePlugins[stage] = make([]StagePlugin, 0)
		}
		m.stagePlugins[stage] = append(m.stagePlugins[stage], plugin)

		// Sort plugins by priority (highest first)
		sort.Slice(m.stagePlugins[stage], func(i, j int) bool {
			return m.stagePlugins[stage][i].GetPriority() > m.stagePlugins[stage][j].GetPriority()
		})
	}
}

// LoadPlugins loads all plugins from the plugin path
func (m *Manager) LoadPlugins() error {
	// Check if plugin directory exists
	if _, err := os.Stat(m.pluginPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin directory not found: %s", m.pluginPath)
	}

	// Collect plugin names to load
	pluginNames := []string{}
	err := filepath.WalkDir(m.pluginPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".so" {
			return nil
		}
		pluginName := filepath.Base(path)
		pluginName = pluginName[:len(pluginName)-3] // Remove .so extension
		pluginNames = append(pluginNames, pluginName)
		return nil
	})
	if err != nil {
		return err
	}

	// Now load each plugin (each call will take the lock as needed)
	for _, pluginName := range pluginNames {
		if err := m.LoadPlugin(pluginName); err != nil {
			fmt.Printf("Failed to load plugin %s: %v\n", pluginName, err)
		}
	}

	return nil
}

// GetAntivirusPlugin returns an antivirus plugin by name
func (m *Manager) GetAntivirusPlugin(name string) (AntivirusPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.antivirusPlugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// GetAntispamPlugin returns an antispam plugin by name
func (m *Manager) GetAntispamPlugin(name string) (AntispamPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.antispamPlugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// GetDKIMPlugin returns a DKIM plugin by name
func (m *Manager) GetDKIMPlugin(name string) (DKIMPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.dkimPlugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// GetSPFPlugin returns an SPF plugin by name
func (m *Manager) GetSPFPlugin(name string) (SPFPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.spfPlugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// GetDMARCPlugin returns a DMARC plugin by name
func (m *Manager) GetDMARCPlugin(name string) (DMARCPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.dmarcPlugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// GetARCPlugin returns an ARC plugin by name
func (m *Manager) GetARCPlugin(name string) (ARCPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.arcPlugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return plugin, nil
}

// GetPluginsByType returns all plugins of a specific type
func (m *Manager) GetPluginsByType(pluginType string) []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins, ok := m.typePlugins[pluginType]
	if !ok {
		return []Plugin{}
	}

	return plugins
}

// GetPluginsByStage returns all plugins for a specific processing stage
func (m *Manager) GetPluginsByStage(stage ProcessingStage) []StagePlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins, ok := m.stagePlugins[stage]
	if !ok {
		return []StagePlugin{}
	}

	return plugins
}

// ExecuteStage runs all plugins for a specific stage and returns the combined result
func (m *Manager) ExecuteStage(stage ProcessingStage, ctx interface{}) (PluginResult, error) {
	plugins := m.GetPluginsByStage(stage)

	// Default result is to continue processing
	result := PluginResult{
		Action:      ActionContinue,
		Annotations: make(map[string]string),
	}

	for _, p := range plugins {
		// Execute plugin
		// This is a simplified example - in a real implementation, you would need to
		// define a proper interface for executing plugins with the right context
		// For now, we'll just assume there's an Execute method
		if execPlugin, ok := p.(interface {
			Execute(ctx interface{}) (PluginResult, error)
		}); ok {
			pluginResult, err := execPlugin.Execute(ctx)
			if err != nil {
				return result, fmt.Errorf("plugin execution error: %w", err)
			}

			// Merge annotations
			for k, v := range pluginResult.Annotations {
				result.Annotations[k] = v
			}

			// If plugin wants to stop processing, respect that
			if pluginResult.Action != ActionContinue {
				result.Action = pluginResult.Action
				result.Message = pluginResult.Message
				break
			}
		}
	}

	return result, nil
}

// ListAntivirusPlugins returns a list of all loaded antivirus plugins
func (m *Manager) ListAntivirusPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.antivirusPlugins))
	for name := range m.antivirusPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// ListAntispamPlugins returns a list of all loaded antispam plugins
func (m *Manager) ListAntispamPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.antispamPlugins))
	for name := range m.antispamPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// ListDKIMPlugins returns a list of all loaded DKIM plugins
func (m *Manager) ListDKIMPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.dkimPlugins))
	for name := range m.dkimPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// ListSPFPlugins returns a list of all loaded SPF plugins
func (m *Manager) ListSPFPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.spfPlugins))
	for name := range m.spfPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// ListDMARCPlugins returns a list of all loaded DMARC plugins
func (m *Manager) ListDMARCPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]string, 0, len(m.dmarcPlugins))
	for name := range m.dmarcPlugins {
		plugins = append(plugins, name)
	}

	return plugins
}

// ListARCPlugins returns a list of loaded ARC plugins
func (m *Manager) ListARCPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var plugins []string
	for name := range m.arcPlugins {
		plugins = append(plugins, name)
	}

	sort.Strings(plugins)
	return plugins
}

// ListPluginTypes returns a list of all plugin types with loaded plugins
func (m *Manager) ListPluginTypes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	types := make([]string, 0, len(m.typePlugins))
	for t := range m.typePlugins {
		types = append(types, t)
	}

	return types
}

// Close closes all loaded plugins
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error

	// Close all plugins
	for _, plugins := range m.typePlugins {
		for _, p := range plugins {
			if err := p.Close(); err != nil {
				lastErr = err
			}
		}
	}

	// Clear plugin maps
	m.antivirusPlugins = make(map[string]AntivirusPlugin)
	m.antispamPlugins = make(map[string]AntispamPlugin)
	m.dkimPlugins = make(map[string]DKIMPlugin)
	m.spfPlugins = make(map[string]SPFPlugin)
	m.dmarcPlugins = make(map[string]DMARCPlugin)
	m.arcPlugins = make(map[string]ARCPlugin)
	m.stagePlugins = make(map[ProcessingStage][]StagePlugin)
	m.typePlugins = make(map[string][]Plugin)
	m.loadedPlugins = make(map[string]*plugin.Plugin)

	return lastErr
}
