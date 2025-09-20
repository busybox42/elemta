package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SecurePluginInterface defines the secure API for plugins without CGO dependencies
type SecurePluginInterface interface {
	// Plugin identification and lifecycle
	GetInfo() *SecurePluginInfo
	Initialize(config *SecurePluginConfig) error
	Shutdown() error
	
	// Plugin execution with input/output validation
	ProcessMessage(ctx context.Context, input *SecurePluginInput) (*SecurePluginOutput, error)
	HealthCheck(ctx context.Context) error
	
	// Resource monitoring
	GetResourceUsage() *ResourceUsage
}

// SecurePluginInfo provides plugin metadata
type SecurePluginInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Type         SecurePluginType  `json:"type"`
	Capabilities []string          `json:"capabilities"`
	Dependencies []string          `json:"dependencies"`
	APIVersion   string            `json:"api_version"`
	Checksum     string            `json:"checksum"`
}

// SecurePluginType defines the type of plugin
type SecurePluginType string

const (
	SecurePluginTypeAntivirus   SecurePluginType = "antivirus"
	SecurePluginTypeAntispam    SecurePluginType = "antispam"
	SecurePluginTypeAuth        SecurePluginType = "auth"
	SecurePluginTypeFilter      SecurePluginType = "filter"
	SecurePluginTypeDelivery    SecurePluginType = "delivery"
	SecurePluginTypeLogger      SecurePluginType = "logger"
	SecurePluginTypeCustom      SecurePluginType = "custom"
)

// SecurePluginConfig provides configuration for plugins
type SecurePluginConfig struct {
	PluginID      string                 `json:"plugin_id"`
	Config        map[string]interface{} `json:"config"`
	ResourceLimits *PluginResourceLimits `json:"resource_limits"`
	Capabilities  []string               `json:"capabilities"`
	Environment   map[string]string      `json:"environment"`
}

// PluginResourceLimits defines resource constraints for plugin execution
type PluginResourceLimits struct {
	MaxMemoryMB      int64         `json:"max_memory_mb"`
	MaxCPUPercent    float64       `json:"max_cpu_percent"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	MaxFileSize      int64         `json:"max_file_size"`
	MaxNetworkOps    int           `json:"max_network_ops"`
	AllowedPaths     []string      `json:"allowed_paths"`
	BlockedSyscalls  []string      `json:"blocked_syscalls"`
}

// DefaultPluginResourceLimits returns secure default resource limits
func DefaultPluginResourceLimits() *PluginResourceLimits {
	return &PluginResourceLimits{
		MaxMemoryMB:      50,                 // 50MB memory limit
		MaxCPUPercent:    10.0,               // 10% CPU limit
		MaxExecutionTime: 30 * time.Second,   // 30 second timeout
		MaxFileSize:      10 * 1024 * 1024,   // 10MB file size limit
		MaxNetworkOps:    100,                // 100 network operations
		AllowedPaths: []string{
			"/tmp/elemta-plugin",  // Plugin temporary directory
		},
		BlockedSyscalls: []string{
			"execve", "fork", "clone", "mount", "umount", "ptrace",
			"setuid", "setgid", "chroot", "pivot_root",
		},
	}
}

// SecurePluginInput represents validated input to plugins
type SecurePluginInput struct {
	MessageID    string            `json:"message_id"`
	From         string            `json:"from"`
	To           []string          `json:"to"`
	Subject      string            `json:"subject"`
	Headers      map[string]string `json:"headers"`
	Body         []byte            `json:"body"`
	Metadata     map[string]interface{} `json:"metadata"`
	Timestamp    time.Time         `json:"timestamp"`
	RemoteAddr   string            `json:"remote_addr"`
	TLSEnabled   bool              `json:"tls_enabled"`
}

// SecurePluginOutput represents validated output from plugins
type SecurePluginOutput struct {
	Action       PluginAction      `json:"action"`
	Score        float64           `json:"score"`
	Message      string            `json:"message"`
	Headers      map[string]string `json:"headers"`
	ModifiedBody []byte            `json:"modified_body,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
	Errors       []string          `json:"errors,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
}

// PluginAction defines the action a plugin recommends
type PluginAction string

const (
	PluginActionAccept   PluginAction = "accept"
	PluginActionReject   PluginAction = "reject"
	PluginActionQuarantine PluginAction = "quarantine"
	PluginActionModify   PluginAction = "modify"
	PluginActionContinue PluginAction = "continue"
	PluginActionDefer    PluginAction = "defer"
)

// ResourceUsage tracks plugin resource consumption
type ResourceUsage struct {
	MemoryUsageMB    float64       `json:"memory_usage_mb"`
	CPUPercent       float64       `json:"cpu_percent"`
	ExecutionTime    time.Duration `json:"execution_time"`
	NetworkOps       int64         `json:"network_ops"`
	FileOps          int64         `json:"file_ops"`
	GoroutineCount   int           `json:"goroutine_count"`
	LastUpdated      time.Time     `json:"last_updated"`
}

// SecurePluginManager manages secure plugins without CGO dependencies
type SecurePluginManager struct {
	config          *SecureManagerConfig
	logger          *slog.Logger
	plugins         map[string]*SecurePluginInstance
	pluginTypes     map[SecurePluginType][]*SecurePluginInstance
	mutex           sync.RWMutex
	resourceMonitor *PluginResourceMonitor
	validator       *PluginValidator
	sandboxManager  *PluginSandboxManager
	
	// Runtime state
	ctx     context.Context
	cancel  context.CancelFunc
	running int32
}

// SecureManagerConfig configures the secure plugin manager
type SecureManagerConfig struct {
	PluginDirectory     string                     `json:"plugin_directory"`
	MaxPlugins          int                        `json:"max_plugins"`
	DefaultResourceLimits *PluginResourceLimits    `json:"default_resource_limits"`
	ValidationEnabled   bool                       `json:"validation_enabled"`
	SandboxEnabled      bool                       `json:"sandbox_enabled"`
	MonitoringInterval  time.Duration              `json:"monitoring_interval"`
	HealthCheckInterval time.Duration              `json:"health_check_interval"`
	PluginTimeout       time.Duration              `json:"plugin_timeout"`
	AllowedPluginTypes  []SecurePluginType         `json:"allowed_plugin_types"`
}

// DefaultSecureManagerConfig returns secure default configuration
func DefaultSecureManagerConfig() *SecureManagerConfig {
	return &SecureManagerConfig{
		PluginDirectory:     "/app/secure-plugins",
		MaxPlugins:          10,
		DefaultResourceLimits: DefaultPluginResourceLimits(),
		ValidationEnabled:   true,
		SandboxEnabled:      true,
		MonitoringInterval:  30 * time.Second,
		HealthCheckInterval: 60 * time.Second,
		PluginTimeout:       30 * time.Second,
		AllowedPluginTypes: []SecurePluginType{
			SecurePluginTypeAntivirus,
			SecurePluginTypeAntispam,
			SecurePluginTypeFilter,
		},
	}
}

// SecurePluginInstance represents a running plugin instance
type SecurePluginInstance struct {
	info           *SecurePluginInfo
	config         *SecurePluginConfig
	process        *PluginProcess
	resourceUsage  *ResourceUsage
	healthStatus   PluginHealthStatus
	lastHealthCheck time.Time
	startTime      time.Time
	requestCount   int64
	errorCount     int64
	mutex          sync.RWMutex
}

// PluginHealthStatus represents the health status of a plugin
type PluginHealthStatus string

const (
	PluginHealthHealthy     PluginHealthStatus = "healthy"
	PluginHealthDegraded    PluginHealthStatus = "degraded"
	PluginHealthUnhealthy   PluginHealthStatus = "unhealthy"
	PluginHealthStopped     PluginHealthStatus = "stopped"
)

// NewSecurePluginManager creates a new secure plugin manager
func NewSecurePluginManager(config *SecureManagerConfig, logger *slog.Logger) *SecurePluginManager {
	if config == nil {
		config = DefaultSecureManagerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &SecurePluginManager{
		config:          config,
		logger:          logger,
		plugins:         make(map[string]*SecurePluginInstance),
		pluginTypes:     make(map[SecurePluginType][]*SecurePluginInstance),
		resourceMonitor: NewPluginResourceMonitor(logger),
		validator:       NewPluginValidator(logger),
		sandboxManager:  NewPluginSandboxManager(config, logger),
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Start background monitoring
	go manager.startMonitoring()
	
	logger.Info("Secure plugin manager initialized",
		"max_plugins", config.MaxPlugins,
		"sandbox_enabled", config.SandboxEnabled,
		"validation_enabled", config.ValidationEnabled,
	)
	
	return manager
}

// LoadPlugin loads a secure plugin from the plugin directory
func (m *SecurePluginManager) LoadPlugin(pluginName string) error {
	if atomic.LoadInt32(&m.running) == 0 {
		return fmt.Errorf("plugin manager not running")
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if plugin is already loaded
	if _, exists := m.plugins[pluginName]; exists {
		return fmt.Errorf("plugin %s already loaded", pluginName)
	}
	
	// Check plugin limit
	if len(m.plugins) >= m.config.MaxPlugins {
		return fmt.Errorf("maximum number of plugins (%d) reached", m.config.MaxPlugins)
	}
	
	// Load plugin info and validate
	pluginPath := fmt.Sprintf("%s/%s", m.config.PluginDirectory, pluginName)
	info, err := m.loadPluginInfo(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to load plugin info: %w", err)
	}
	
	// Validate plugin
	if m.config.ValidationEnabled {
		if err := m.validator.ValidatePlugin(info, pluginPath); err != nil {
			return fmt.Errorf("plugin validation failed: %w", err)
		}
	}
	
	// Check if plugin type is allowed
	if !m.isPluginTypeAllowed(info.Type) {
		return fmt.Errorf("plugin type %s not allowed", info.Type)
	}
	
	// Create plugin configuration
	pluginConfig := &SecurePluginConfig{
		PluginID:       pluginName,
		Config:         make(map[string]interface{}),
		ResourceLimits: m.config.DefaultResourceLimits,
		Capabilities:   info.Capabilities,
		Environment:    make(map[string]string),
	}
	
	// Create plugin process with sandboxing
	process, err := m.sandboxManager.CreatePluginProcess(info, pluginConfig, pluginPath)
	if err != nil {
		return fmt.Errorf("failed to create plugin process: %w", err)
	}
	
	// Create plugin instance
	instance := &SecurePluginInstance{
		info:            info,
		config:          pluginConfig,
		process:         process,
		resourceUsage:   &ResourceUsage{},
		healthStatus:    PluginHealthHealthy,
		lastHealthCheck: time.Now(),
		startTime:       time.Now(),
	}
	
	// Start the plugin
	if err := instance.process.Start(); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}
	
	// Initialize plugin
	if err := instance.initialize(); err != nil {
		instance.process.Stop()
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}
	
	// Register plugin
	m.plugins[pluginName] = instance
	m.pluginTypes[info.Type] = append(m.pluginTypes[info.Type], instance)
	
	m.logger.Info("Plugin loaded successfully",
		"plugin", pluginName,
		"type", info.Type,
		"version", info.Version,
	)
	
	return nil
}

// UnloadPlugin safely unloads a plugin
func (m *SecurePluginManager) UnloadPlugin(pluginName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	instance, exists := m.plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	
	// Shutdown plugin
	if err := instance.shutdown(); err != nil {
		m.logger.Error("Error shutting down plugin",
			"plugin", pluginName,
			"error", err,
		)
	}
	
	// Stop process
	if err := instance.process.Stop(); err != nil {
		m.logger.Error("Error stopping plugin process",
			"plugin", pluginName,
			"error", err,
		)
	}
	
	// Remove from registry
	delete(m.plugins, pluginName)
	
	// Remove from type registry
	pluginType := instance.info.Type
	instances := m.pluginTypes[pluginType]
	for i, inst := range instances {
		if inst == instance {
			m.pluginTypes[pluginType] = append(instances[:i], instances[i+1:]...)
			break
		}
	}
	
	m.logger.Info("Plugin unloaded successfully",
		"plugin", pluginName,
		"uptime", time.Since(instance.startTime),
		"requests_processed", instance.requestCount,
		"errors", instance.errorCount,
	)
	
	return nil
}

// ProcessMessage processes a message through plugins of a specific type
func (m *SecurePluginManager) ProcessMessage(ctx context.Context, pluginType SecurePluginType, input *SecurePluginInput) ([]*SecurePluginOutput, error) {
	m.mutex.RLock()
	instances := make([]*SecurePluginInstance, len(m.pluginTypes[pluginType]))
	copy(instances, m.pluginTypes[pluginType])
	m.mutex.RUnlock()
	
	if len(instances) == 0 {
		return nil, fmt.Errorf("no plugins of type %s available", pluginType)
	}
	
	// Validate input
	if m.config.ValidationEnabled {
		if err := m.validator.ValidateInput(input); err != nil {
			return nil, fmt.Errorf("input validation failed: %w", err)
		}
	}
	
	// Process through all plugins of this type
	outputs := make([]*SecurePluginOutput, 0, len(instances))
	
	for _, instance := range instances {
		// Check plugin health
		if instance.healthStatus != PluginHealthHealthy {
			m.logger.Warn("Skipping unhealthy plugin",
				"plugin", instance.info.Name,
				"status", instance.healthStatus,
			)
			continue
		}
		
		// Create context with timeout
		pluginCtx, cancel := context.WithTimeout(ctx, m.config.PluginTimeout)
		
		// Process message
		output, err := instance.processMessage(pluginCtx, input)
		cancel()
		
		if err != nil {
			atomic.AddInt64(&instance.errorCount, 1)
			m.logger.Error("Plugin processing failed",
				"plugin", instance.info.Name,
				"error", err,
			)
			
			// Mark plugin as degraded
			instance.mutex.Lock()
			instance.healthStatus = PluginHealthDegraded
			instance.mutex.Unlock()
			
			continue
		}
		
		// Validate output
		if m.config.ValidationEnabled {
			if err := m.validator.ValidateOutput(output); err != nil {
				m.logger.Error("Plugin output validation failed",
					"plugin", instance.info.Name,
					"error", err,
				)
				continue
			}
		}
		
		outputs = append(outputs, output)
		atomic.AddInt64(&instance.requestCount, 1)
	}
	
	return outputs, nil
}

// GetPluginStats returns statistics for all loaded plugins
func (m *SecurePluginManager) GetPluginStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	stats := map[string]interface{}{
		"total_plugins": len(m.plugins),
		"max_plugins":   m.config.MaxPlugins,
		"plugin_types":  make(map[string]int),
		"health_status": make(map[string]int),
		"plugins":       make(map[string]interface{}),
	}
	
	// Count by type and health status
	typeCount := make(map[string]int)
	healthCount := make(map[string]int)
	
	for name, instance := range m.plugins {
		instance.mutex.RLock()
		
		typeCount[string(instance.info.Type)]++
		healthCount[string(instance.healthStatus)]++
		
		stats["plugins"].(map[string]interface{})[name] = map[string]interface{}{
			"type":             instance.info.Type,
			"version":          instance.info.Version,
			"health_status":    instance.healthStatus,
			"uptime":           time.Since(instance.startTime).Seconds(),
			"request_count":    instance.requestCount,
			"error_count":      instance.errorCount,
			"resource_usage":   instance.resourceUsage,
			"last_health_check": instance.lastHealthCheck,
		}
		
		instance.mutex.RUnlock()
	}
	
	stats["plugin_types"] = typeCount
	stats["health_status"] = healthCount
	
	return stats
}

// Shutdown gracefully shuts down the plugin manager
func (m *SecurePluginManager) Shutdown() error {
	if !atomic.CompareAndSwapInt32(&m.running, 1, 0) {
		return fmt.Errorf("plugin manager not running")
	}
	
	// Cancel background monitoring
	m.cancel()
	
	// Unload all plugins
	m.mutex.Lock()
	pluginNames := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		pluginNames = append(pluginNames, name)
	}
	m.mutex.Unlock()
	
	for _, name := range pluginNames {
		if err := m.UnloadPlugin(name); err != nil {
			m.logger.Error("Error unloading plugin during shutdown",
				"plugin", name,
				"error", err,
			)
		}
	}
	
	m.logger.Info("Secure plugin manager shut down")
	return nil
}

// loadPluginInfo loads plugin information from the plugin directory
func (m *SecurePluginManager) loadPluginInfo(pluginPath string) (*SecurePluginInfo, error) {
	infoFile := fmt.Sprintf("%s/plugin.json", pluginPath)
	
	data, err := os.ReadFile(infoFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin info: %w", err)
	}
	
	var info SecurePluginInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse plugin info: %w", err)
	}
	
	return &info, nil
}

// isPluginTypeAllowed checks if a plugin type is allowed
func (m *SecurePluginManager) isPluginTypeAllowed(pluginType SecurePluginType) bool {
	for _, allowedType := range m.config.AllowedPluginTypes {
		if allowedType == pluginType {
			return true
		}
	}
	return false
}

// startMonitoring starts background monitoring goroutines
func (m *SecurePluginManager) startMonitoring() {
	atomic.StoreInt32(&m.running, 1)
	
	monitorTicker := time.NewTicker(m.config.MonitoringInterval)
	healthTicker := time.NewTicker(m.config.HealthCheckInterval)
	
	defer monitorTicker.Stop()
	defer healthTicker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
			
		case <-monitorTicker.C:
			m.updateResourceUsage()
			
		case <-healthTicker.C:
			m.performHealthChecks()
		}
	}
}

// updateResourceUsage updates resource usage for all plugins
func (m *SecurePluginManager) updateResourceUsage() {
	m.mutex.RLock()
	instances := make([]*SecurePluginInstance, 0, len(m.plugins))
	for _, instance := range m.plugins {
		instances = append(instances, instance)
	}
	m.mutex.RUnlock()
	
	for _, instance := range instances {
		usage, err := m.resourceMonitor.GetResourceUsage(instance.process)
		if err != nil {
			m.logger.Error("Failed to get resource usage",
				"plugin", instance.info.Name,
				"error", err,
			)
			continue
		}
		
		instance.mutex.Lock()
		instance.resourceUsage = usage
		instance.mutex.Unlock()
		
		// Check resource limits
		if m.checkResourceLimits(instance, usage) {
			m.logger.Warn("Plugin exceeding resource limits",
				"plugin", instance.info.Name,
				"memory_mb", usage.MemoryUsageMB,
				"cpu_percent", usage.CPUPercent,
			)
		}
	}
}

// performHealthChecks performs health checks on all plugins
func (m *SecurePluginManager) performHealthChecks() {
	m.mutex.RLock()
	instances := make([]*SecurePluginInstance, 0, len(m.plugins))
	for _, instance := range instances {
		instances = append(instances, instance)
	}
	m.mutex.RUnlock()
	
	for _, instance := range instances {
		ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
		err := instance.healthCheck(ctx)
		cancel()
		
		instance.mutex.Lock()
		instance.lastHealthCheck = time.Now()
		
		if err != nil {
			if instance.healthStatus == PluginHealthHealthy {
				instance.healthStatus = PluginHealthDegraded
			} else if instance.healthStatus == PluginHealthDegraded {
				instance.healthStatus = PluginHealthUnhealthy
			}
			
			m.logger.Error("Plugin health check failed",
				"plugin", instance.info.Name,
				"status", instance.healthStatus,
				"error", err,
			)
		} else {
			instance.healthStatus = PluginHealthHealthy
		}
		
		instance.mutex.Unlock()
	}
}

// checkResourceLimits checks if a plugin is exceeding resource limits
func (m *SecurePluginManager) checkResourceLimits(instance *SecurePluginInstance, usage *ResourceUsage) bool {
	limits := instance.config.ResourceLimits
	
	if usage.MemoryUsageMB > float64(limits.MaxMemoryMB) {
		return true
	}
	
	if usage.CPUPercent > limits.MaxCPUPercent {
		return true
	}
	
	return false
}

// initialize initializes a plugin instance
func (instance *SecurePluginInstance) initialize() error {
	return instance.process.SendCommand("initialize", instance.config)
}

// shutdown shuts down a plugin instance
func (instance *SecurePluginInstance) shutdown() error {
	return instance.process.SendCommand("shutdown", nil)
}

// processMessage processes a message through the plugin
func (instance *SecurePluginInstance) processMessage(ctx context.Context, input *SecurePluginInput) (*SecurePluginOutput, error) {
	return instance.process.ProcessMessage(ctx, input)
}

// healthCheck performs a health check on the plugin
func (instance *SecurePluginInstance) healthCheck(ctx context.Context) error {
	return instance.process.HealthCheck(ctx)
}

// Start starts the secure plugin manager
func (m *SecurePluginManager) Start() error {
	if atomic.LoadInt32(&m.running) == 1 {
		return fmt.Errorf("plugin manager already running")
	}
	
	// Ensure plugin directory exists
	if err := os.MkdirAll(m.config.PluginDirectory, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}
	
	m.logger.Info("Secure plugin manager started",
		"plugin_directory", m.config.PluginDirectory,
	)
	
	return nil
}
