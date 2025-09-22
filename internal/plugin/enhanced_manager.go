package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// EnhancedManager provides comprehensive plugin management with hooks, lifecycle, and isolation
type EnhancedManager struct {
	*Manager // Embed existing manager for compatibility

	config         *EnhancedConfig
	logger         *slog.Logger
	hookRegistry   *HookRegistry
	executor       *Executor
	lifecycleState LifecycleState

	// Plugin lifecycle management
	mu             sync.RWMutex
	plugins        map[string]EnhancedPlugin
	pluginOrder    []string // Order of plugin loading for dependency management
	enabledPlugins map[string]bool

	// Runtime state
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	// Secure plugin integration (disabled for now due to naming conflicts)
	// secureIntegration *SecurePluginIntegration
	// useSecurePlugins  bool
}

// EnhancedConfig extends the basic plugin configuration
type EnhancedConfig struct {
	PluginPath          string                            `yaml:"plugin_path" json:"plugin_path" toml:"plugin_path"`
	Enabled             bool                              `yaml:"enabled" json:"enabled" toml:"enabled"`
	Plugins             []string                          `yaml:"plugins" json:"plugins" toml:"plugins"`
	PluginConfig        map[string]map[string]interface{} `yaml:"plugin_config" json:"plugin_config" toml:"plugin_config"`
	ExecutorConfig      ExecutorConfig                    `yaml:"executor" json:"executor" toml:"executor"`
	AutoReload          bool                              `yaml:"auto_reload" json:"auto_reload" toml:"auto_reload"`
	ReloadInterval      time.Duration                     `yaml:"reload_interval" json:"reload_interval" toml:"reload_interval"`
	HealthCheckInterval time.Duration                     `yaml:"health_check_interval" json:"health_check_interval" toml:"health_check_interval"`
}

// DefaultEnhancedConfig returns sensible defaults
func DefaultEnhancedConfig() *EnhancedConfig {
	return &EnhancedConfig{
		PluginPath:          "./plugins",
		Enabled:             true,
		Plugins:             []string{},
		PluginConfig:        make(map[string]map[string]interface{}),
		ExecutorConfig:      DefaultExecutorConfig(),
		AutoReload:          false,
		ReloadInterval:      5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
	}
}

// LifecycleState represents the current state of the plugin manager
type LifecycleState int

const (
	StateUninitialized LifecycleState = iota
	StateInitializing
	StateRunning
	StateStopping
	StateStopped
	StateError
)

func (s LifecycleState) String() string {
	switch s {
	case StateUninitialized:
		return "uninitialized"
	case StateInitializing:
		return "initializing"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// EnhancedPlugin wraps a plugin with additional metadata and lifecycle management
type EnhancedPlugin struct {
	Plugin      Plugin
	Name        string
	Info        PluginInfo
	Config      map[string]interface{}
	State       PluginState
	LoadTime    time.Time
	LastError   error
	HealthCheck func() error
}

// PluginState represents the current state of an individual plugin
type PluginState int

const (
	PluginStateUnloaded PluginState = iota
	PluginStateLoading
	PluginStateLoaded
	PluginStateInitializing
	PluginStateRunning
	PluginStateError
	PluginStateUnloading
)

func (s PluginState) String() string {
	switch s {
	case PluginStateUnloaded:
		return "unloaded"
	case PluginStateLoading:
		return "loading"
	case PluginStateLoaded:
		return "loaded"
	case PluginStateInitializing:
		return "initializing"
	case PluginStateRunning:
		return "running"
	case PluginStateError:
		return "error"
	case PluginStateUnloading:
		return "unloading"
	default:
		return "unknown"
	}
}

// NewEnhancedManager creates a new enhanced plugin manager
func NewEnhancedManager(config *EnhancedConfig) *EnhancedManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &EnhancedManager{
		Manager:        NewManager(config.PluginPath),
		config:         config,
		logger:         slog.Default().With("component", "enhanced-plugin-manager"),
		hookRegistry:   NewHookRegistry(),
		executor:       NewExecutor(config.ExecutorConfig),
		lifecycleState: StateUninitialized,
		plugins:        make(map[string]EnhancedPlugin),
		pluginOrder:    make([]string, 0),
		enabledPlugins: make(map[string]bool),
		ctx:            ctx,
		cancel:         cancel,
		started:        false,
	}
}

// Start initializes and starts the enhanced plugin manager
func (em *EnhancedManager) Start() error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.started {
		return fmt.Errorf("plugin manager already started")
	}

	em.lifecycleState = StateInitializing
	em.logger.Info("Starting enhanced plugin manager", "config", em.config)

	if !em.config.Enabled {
		em.logger.Info("Plugin system disabled")
		em.lifecycleState = StateStopped
		return nil
	}

	// Load and initialize plugins
	if err := em.loadPlugins(); err != nil {
		em.lifecycleState = StateError
		return fmt.Errorf("failed to load plugins: %w", err)
	}

	// Start background services
	go em.backgroundServices()

	em.lifecycleState = StateRunning
	em.started = true

	em.logger.Info("Enhanced plugin manager started successfully",
		"loaded_plugins", len(em.plugins),
		"enabled_plugins", len(em.enabledPlugins))

	return nil
}

// Stop gracefully shuts down the plugin manager
func (em *EnhancedManager) Stop() error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if !em.started {
		return nil
	}

	em.lifecycleState = StateStopping
	em.logger.Info("Stopping enhanced plugin manager")

	// Cancel background services
	em.cancel()

	// Unload all plugins in reverse order
	for i := len(em.pluginOrder) - 1; i >= 0; i-- {
		pluginName := em.pluginOrder[i]
		if err := em.unloadPlugin(pluginName); err != nil {
			em.logger.Error("Failed to unload plugin", "plugin", pluginName, "error", err)
		}
	}

	em.lifecycleState = StateStopped
	em.started = false

	em.logger.Info("Enhanced plugin manager stopped")
	return nil
}

// loadPlugins loads all configured plugins
func (em *EnhancedManager) loadPlugins() error {
	for _, pluginName := range em.config.Plugins {
		em.enabledPlugins[pluginName] = true

		if err := em.loadAndInitializePlugin(pluginName); err != nil {
			em.logger.Error("Failed to load plugin", "plugin", pluginName, "error", err)
			// Continue loading other plugins even if one fails
			continue
		}

		em.pluginOrder = append(em.pluginOrder, pluginName)
		em.logger.Info("Successfully loaded plugin", "plugin", pluginName)
	}

	return nil
}

// loadAndInitializePlugin loads and initializes a single plugin
func (em *EnhancedManager) loadAndInitializePlugin(pluginName string) error {
	enhanced := EnhancedPlugin{
		Name:     pluginName,
		State:    PluginStateLoading,
		LoadTime: time.Now(),
	}

	// Load the plugin using the existing manager
	if err := em.Manager.LoadPlugin(pluginName); err != nil {
		enhanced.State = PluginStateError
		enhanced.LastError = err
		em.plugins[pluginName] = enhanced
		return fmt.Errorf("failed to load plugin %s: %w", pluginName, err)
	}

	enhanced.State = PluginStateLoaded

	// Get plugin configuration
	if config, exists := em.config.PluginConfig[pluginName]; exists {
		enhanced.Config = config
	} else {
		enhanced.Config = make(map[string]interface{})
	}

	// Try to get plugin from various registries
	var plugin Plugin
	if avPlugin, err := em.Manager.GetAntivirusPlugin(pluginName); err == nil {
		plugin = avPlugin
	} else if asPlugin, err := em.Manager.GetAntispamPlugin(pluginName); err == nil {
		plugin = asPlugin
	} else if dkimPlugin, err := em.Manager.GetDKIMPlugin(pluginName); err == nil {
		plugin = dkimPlugin
	} else if spfPlugin, err := em.Manager.GetSPFPlugin(pluginName); err == nil {
		plugin = spfPlugin
	} else if dmarcPlugin, err := em.Manager.GetDMARCPlugin(pluginName); err == nil {
		plugin = dmarcPlugin
	} else if arcPlugin, err := em.Manager.GetARCPlugin(pluginName); err == nil {
		plugin = arcPlugin
	} else if rateLimitPlugin, err := em.Manager.GetRateLimitPlugin(pluginName); err == nil {
		plugin = rateLimitPlugin
	}

	if plugin != nil {
		enhanced.Plugin = plugin
		enhanced.Info = plugin.GetInfo()
		enhanced.State = PluginStateInitializing

		// Initialize the plugin
		if err := plugin.Init(enhanced.Config); err != nil {
			enhanced.State = PluginStateError
			enhanced.LastError = err
			em.plugins[pluginName] = enhanced
			return fmt.Errorf("failed to initialize plugin %s: %w", pluginName, err)
		}

		enhanced.State = PluginStateRunning

		// Register hooks based on plugin type
		em.registerPluginHooks(plugin, pluginName)
	}

	em.plugins[pluginName] = enhanced
	return nil
}

// registerPluginHooks registers hooks for a plugin based on its interfaces
func (em *EnhancedManager) registerPluginHooks(plugin Plugin, pluginName string) {
	em.logger.Debug("Registering hooks for plugin", "plugin", pluginName)

	// Register hooks based on implemented interfaces
	if hook, ok := plugin.(ConnectionHook); ok {
		em.hookRegistry.RegisterConnectionHook(hook)
		em.logger.Debug("Registered connection hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(SMTPCommandHook); ok {
		em.hookRegistry.RegisterCommandHook(hook)
		em.logger.Debug("Registered command hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(MailTransactionHook); ok {
		em.hookRegistry.RegisterTransactionHook(hook)
		em.logger.Debug("Registered transaction hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(MessageProcessingHook); ok {
		em.hookRegistry.RegisterProcessingHook(hook)
		em.logger.Debug("Registered processing hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(QueueHook); ok {
		em.hookRegistry.RegisterQueueHook(hook)
		em.logger.Debug("Registered queue hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(DeliveryHook); ok {
		em.hookRegistry.RegisterDeliveryHook(hook)
		em.logger.Debug("Registered delivery hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(SecurityHook); ok {
		em.hookRegistry.RegisterSecurityHook(hook)
		em.logger.Debug("Registered security hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(ContentFilterHook); ok {
		em.hookRegistry.RegisterContentFilterHook(hook)
		em.logger.Debug("Registered content filter hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(AuthenticationHook); ok {
		em.hookRegistry.RegisterAuthenticationHook(hook)
		em.logger.Debug("Registered authentication hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(MetricsHook); ok {
		em.hookRegistry.RegisterMetricsHook(hook)
		em.logger.Debug("Registered metrics hook", "plugin", pluginName)
	}

	if hook, ok := plugin.(ErrorHook); ok {
		em.hookRegistry.RegisterErrorHook(hook)
		em.logger.Debug("Registered error hook", "plugin", pluginName)
	}
}

// unloadPlugin unloads a single plugin
func (em *EnhancedManager) unloadPlugin(pluginName string) error {
	enhanced, exists := em.plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	enhanced.State = PluginStateUnloading
	em.plugins[pluginName] = enhanced

	if enhanced.Plugin != nil {
		if err := enhanced.Plugin.Close(); err != nil {
			em.logger.Error("Failed to close plugin", "plugin", pluginName, "error", err)
		}
	}

	enhanced.State = PluginStateUnloaded
	em.plugins[pluginName] = enhanced

	return nil
}

// backgroundServices runs background maintenance tasks
func (em *EnhancedManager) backgroundServices() {
	healthTicker := time.NewTicker(em.config.HealthCheckInterval)
	defer healthTicker.Stop()

	var reloadTicker *time.Ticker
	if em.config.AutoReload {
		reloadTicker = time.NewTicker(em.config.ReloadInterval)
		defer reloadTicker.Stop()
	}

	metricsTicker := time.NewTicker(5 * time.Minute)
	defer metricsTicker.Stop()

	for {
		select {
		case <-em.ctx.Done():
			return

		case <-healthTicker.C:
			em.performHealthChecks()

		case <-metricsTicker.C:
			em.executor.LogMetrics()

		case <-func() <-chan time.Time {
			if reloadTicker != nil {
				return reloadTicker.C
			}
			return make(chan time.Time) // Never fires if auto-reload is disabled
		}():
			em.checkForPluginUpdates()
		}
	}
}

// performHealthChecks checks the health of all loaded plugins
func (em *EnhancedManager) performHealthChecks() {
	em.mu.RLock()
	defer em.mu.RUnlock()

	for name, enhanced := range em.plugins {
		if enhanced.State == PluginStateRunning && enhanced.HealthCheck != nil {
			if err := enhanced.HealthCheck(); err != nil {
				em.logger.Warn("Plugin health check failed", "plugin", name, "error", err)
				enhanced.LastError = err
				enhanced.State = PluginStateError
				em.plugins[name] = enhanced
			}
		}
	}
}

// checkForPluginUpdates checks for plugin file updates and reloads if necessary
func (em *EnhancedManager) checkForPluginUpdates() {
	// This is a placeholder for auto-reload functionality
	// Implementation would check file modification times and reload changed plugins
	em.logger.Debug("Checking for plugin updates")
}

// ExecuteHooks provides a unified interface for executing hooks
func (em *EnhancedManager) ExecuteHooks() *HookExecutor {
	return &HookExecutor{
		manager:      em,
		hookRegistry: em.hookRegistry,
		executor:     em.executor,
		logger:       em.logger,
	}
}

// GetStatus returns the current status of the plugin manager
func (em *EnhancedManager) GetStatus() map[string]interface{} {
	em.mu.RLock()
	defer em.mu.RUnlock()

	pluginStates := make(map[string]string)
	for name, plugin := range em.plugins {
		pluginStates[name] = plugin.State.String()
	}

	return map[string]interface{}{
		"lifecycle_state":  em.lifecycleState.String(),
		"loaded_plugins":   len(em.plugins),
		"enabled_plugins":  len(em.enabledPlugins),
		"plugin_states":    pluginStates,
		"executor_metrics": em.executor.GetMetrics(),
	}
}

// HookExecutor provides methods for executing different types of hooks
type HookExecutor struct {
	manager      *EnhancedManager
	hookRegistry *HookRegistry
	executor     *Executor
	logger       *slog.Logger
}

// OnConnect executes connection hooks
func (he *HookExecutor) OnConnect(sessionID, messageID string, remoteAddr, localAddr net.Addr) []*ExecutionResult {
	hookCtx := NewHookContext(he.manager.ctx, sessionID, messageID, remoteAddr, localAddr, StageConnect)
	hooks := he.hookRegistry.GetConnectionHooks()
	return he.executor.ExecuteConnectionHooks(hooks, hookCtx, remoteAddr, "connect")
}

// OnDisconnect executes disconnection hooks
func (he *HookExecutor) OnDisconnect(sessionID, messageID string, remoteAddr, localAddr net.Addr) []*ExecutionResult {
	hookCtx := NewHookContext(he.manager.ctx, sessionID, messageID, remoteAddr, localAddr, StageDisconnect)
	hooks := he.hookRegistry.GetConnectionHooks()
	return he.executor.ExecuteConnectionHooks(hooks, hookCtx, remoteAddr, "disconnect")
}

// OnAntivirusScan executes antivirus scanning hooks
func (he *HookExecutor) OnAntivirusScan(sessionID, messageID string, remoteAddr, localAddr net.Addr, content []byte) []*ExecutionResult {
	hookCtx := NewHookContext(he.manager.ctx, sessionID, messageID, remoteAddr, localAddr, StageDataComplete)
	hooks := he.hookRegistry.GetContentFilterHooks()
	return he.executor.ExecuteContentFilterHooks(hooks, hookCtx, content, "antivirus")
}

// OnAntispamScan executes antispam scanning hooks
func (he *HookExecutor) OnAntispamScan(sessionID, messageID string, remoteAddr, localAddr net.Addr, content []byte) []*ExecutionResult {
	hookCtx := NewHookContext(he.manager.ctx, sessionID, messageID, remoteAddr, localAddr, StageDataComplete)
	hooks := he.hookRegistry.GetContentFilterHooks()
	return he.executor.ExecuteContentFilterHooks(hooks, hookCtx, content, "antispam")
}
