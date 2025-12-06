package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// SandboxConfig defines resource limits and restrictions for plugin execution
type SandboxConfig struct {
	MaxMemoryMB        int64         // Maximum memory usage in MB
	MaxCPUPercent      float64       // Maximum CPU usage percentage
	MaxExecutionTime   time.Duration // Maximum execution time per operation
	MaxGoroutines      int           // Maximum number of goroutines
	MaxFileDescriptors int           // Maximum number of file descriptors
	AllowNetworkAccess bool          // Whether to allow network operations
	AllowFileSystem    bool          // Whether to allow file system access
	AllowedPaths       []string      // Allowed file system paths
	BlockedSyscalls    []string      // System calls to block (placeholder)
}

// DefaultSandboxConfig returns secure default sandbox settings
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		MaxMemoryMB:        100,              // 100MB max
		MaxCPUPercent:      25.0,             // 25% CPU max
		MaxExecutionTime:   30 * time.Second, // 30 second timeout
		MaxGoroutines:      10,               // 10 goroutines max
		MaxFileDescriptors: 10,               // 10 file descriptors max
		AllowNetworkAccess: true,             // Allow network (for antivirus/antispam)
		AllowFileSystem:    false,            // Block file system by default
		AllowedPaths: []string{
			"/tmp",     // Temporary files
			"/var/log", // Log files (read-only)
		},
		BlockedSyscalls: []string{
			"execve", // Prevent process execution
			"fork",   // Prevent forking
			"clone",  // Prevent cloning
			"mount",  // Prevent mounting
			"umount", // Prevent unmounting
		},
	}
}

// PluginSandbox manages resource limits and security restrictions for plugins
type PluginSandbox struct {
	config           SandboxConfig
	logger           *slog.Logger
	mu               sync.RWMutex
	activeExecutions map[string]*SandboxedExecution
	resourceMonitor  *ResourceMonitor
}

// SandboxedExecution tracks a single plugin execution within the sandbox
type SandboxedExecution struct {
	ID            string
	PluginName    string
	StartTime     time.Time
	Context       context.Context
	CancelFunc    context.CancelFunc
	ResourceUsage *ResourceUsage
	Violations    []SecurityViolation
	mu            sync.RWMutex
}

// ResourceUsage tracks current resource consumption
type ResourceUsage struct {
	MemoryMB           int64
	CPUPercent         float64
	Goroutines         int
	FileDescriptors    int
	NetworkConnections int
	LastUpdated        time.Time
}

// SecurityViolation represents a sandbox security violation
type SecurityViolation struct {
	Type        string
	Description string
	Severity    string
	Timestamp   time.Time
	StackTrace  string
}

// ResourceMonitor continuously monitors resource usage
type ResourceMonitor struct {
	sandbox    *PluginSandbox
	ctx        context.Context
	cancel     context.CancelFunc
	interval   time.Duration
	mu         sync.RWMutex
	running    bool
	violations int64
}

// NewPluginSandbox creates a new plugin sandbox with the given configuration
func NewPluginSandbox(config SandboxConfig) *PluginSandbox {
	return &PluginSandbox{
		config:           config,
		logger:           slog.Default().With("component", "plugin-sandbox"),
		activeExecutions: make(map[string]*SandboxedExecution),
		resourceMonitor:  nil, // Will be initialized when started
	}
}

// Start initializes and starts the sandbox monitoring
func (s *PluginSandbox) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.resourceMonitor != nil && s.resourceMonitor.running {
		return fmt.Errorf("sandbox already running")
	}

	// Initialize resource monitor
	ctx, cancel := context.WithCancel(context.Background())
	s.resourceMonitor = &ResourceMonitor{
		sandbox:  s,
		ctx:      ctx,
		cancel:   cancel,
		interval: 1 * time.Second, // Monitor every second
		running:  false,
	}

	// Start monitoring goroutine
	go s.resourceMonitor.start()

	s.logger.Info("Plugin sandbox started", "config", s.config)
	return nil
}

// Stop shuts down the sandbox and terminates all running executions
func (s *PluginSandbox) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop resource monitor
	if s.resourceMonitor != nil {
		s.resourceMonitor.stop()
	}

	// Cancel all active executions
	for _, execution := range s.activeExecutions {
		execution.CancelFunc()
	}
	s.activeExecutions = make(map[string]*SandboxedExecution)

	s.logger.Info("Plugin sandbox stopped")
	return nil
}

// ExecuteInSandbox runs a plugin function within the sandbox constraints
func (s *PluginSandbox) ExecuteInSandbox(pluginName string, fn func() (*PluginResult, error)) (*PluginResult, error) {
	executionID := fmt.Sprintf("%s-%d", pluginName, time.Now().UnixNano())

	s.logger.Debug("Starting sandboxed execution", "plugin", pluginName, "execution_id", executionID)

	// Create execution context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.MaxExecutionTime)
	defer cancel()

	// Create sandboxed execution tracker
	execution := &SandboxedExecution{
		ID:         executionID,
		PluginName: pluginName,
		StartTime:  time.Now(),
		Context:    ctx,
		CancelFunc: cancel,
		ResourceUsage: &ResourceUsage{
			LastUpdated: time.Now(),
		},
		Violations: make([]SecurityViolation, 0),
	}

	// Register execution
	s.mu.Lock()
	s.activeExecutions[executionID] = execution
	s.mu.Unlock()

	// Cleanup when done
	defer func() {
		s.mu.Lock()
		delete(s.activeExecutions, executionID)
		s.mu.Unlock()
	}()

	// Pre-execution resource check
	if err := s.checkResourceLimits(execution); err != nil {
		return nil, fmt.Errorf("pre-execution resource check failed: %w", err)
	}

	// Execute with monitoring
	resultChan := make(chan *PluginResult, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.recordViolation(execution, "panic", fmt.Sprintf("Plugin panic: %v", r), "critical")
				errorChan <- fmt.Errorf("plugin panic: %v", r)
			}
		}()

		result, err := fn()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()

	// Wait for completion or timeout/cancellation
	select {
	case result := <-resultChan:
		s.logger.Debug("Sandboxed execution completed successfully",
			"plugin", pluginName,
			"execution_id", executionID,
			"duration", time.Since(execution.StartTime))
		return result, nil

	case err := <-errorChan:
		s.logger.Warn("Sandboxed execution failed",
			"plugin", pluginName,
			"execution_id", executionID,
			"error", err,
			"duration", time.Since(execution.StartTime))
		return nil, err

	case <-ctx.Done():
		s.recordViolation(execution, "timeout", "Execution exceeded time limit", "high")
		s.logger.Warn("Sandboxed execution timed out",
			"plugin", pluginName,
			"execution_id", executionID,
			"timeout", s.config.MaxExecutionTime)
		return nil, fmt.Errorf("plugin execution timeout after %v", s.config.MaxExecutionTime)
	}
}

// checkResourceLimits verifies that current system resources are within limits
func (s *PluginSandbox) checkResourceLimits(execution *SandboxedExecution) error {
	// Update resource usage
	s.updateResourceUsage(execution)

	// Check memory limit
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentMemoryMB := int64(m.Alloc / 1024 / 1024)

	if currentMemoryMB > s.config.MaxMemoryMB {
		s.recordViolation(execution, "memory",
			fmt.Sprintf("Memory usage %dMB exceeds limit %dMB", currentMemoryMB, s.config.MaxMemoryMB),
			"high")
		return fmt.Errorf("memory limit exceeded: %dMB > %dMB", currentMemoryMB, s.config.MaxMemoryMB)
	}

	// Check goroutine limit
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > s.config.MaxGoroutines {
		s.recordViolation(execution, "goroutines",
			fmt.Sprintf("Goroutine count %d exceeds limit %d", numGoroutines, s.config.MaxGoroutines),
			"medium")
		return fmt.Errorf("goroutine limit exceeded: %d > %d", numGoroutines, s.config.MaxGoroutines)
	}

	return nil
}

// updateResourceUsage updates the resource usage statistics for an execution
func (s *PluginSandbox) updateResourceUsage(execution *SandboxedExecution) {
	execution.mu.Lock()
	defer execution.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	execution.ResourceUsage.MemoryMB = int64(m.Alloc / 1024 / 1024)
	execution.ResourceUsage.Goroutines = runtime.NumGoroutine()
	execution.ResourceUsage.LastUpdated = time.Now()

	// CPU percentage calculation would require more sophisticated monitoring
	// For now, we'll use a placeholder
	execution.ResourceUsage.CPUPercent = 0.0 // TODO: Implement CPU monitoring
}

// recordViolation logs a security violation
func (s *PluginSandbox) recordViolation(execution *SandboxedExecution, violationType, description, severity string) {
	execution.mu.Lock()
	defer execution.mu.Unlock()

	violation := SecurityViolation{
		Type:        violationType,
		Description: description,
		Severity:    severity,
		Timestamp:   time.Now(),
		StackTrace:  "", // TODO: Capture stack trace
	}

	execution.Violations = append(execution.Violations, violation)
	atomic.AddInt64(&s.resourceMonitor.violations, 1)

	s.logger.Warn("Security violation detected",
		"plugin", execution.PluginName,
		"execution_id", execution.ID,
		"type", violationType,
		"description", description,
		"severity", severity)
}

// GetActiveExecutions returns information about currently running executions
func (s *PluginSandbox) GetActiveExecutions() map[string]*SandboxedExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*SandboxedExecution)
	for id, execution := range s.activeExecutions {
		// Create a copy of values to avoid race conditions (don't copy mutex)
		execution.mu.RLock()
		execCopy := &SandboxedExecution{
			ID:            execution.ID,
			PluginName:    execution.PluginName,
			StartTime:     execution.StartTime,
			Context:       execution.Context,
			CancelFunc:    execution.CancelFunc,
			ResourceUsage: execution.ResourceUsage,
			Violations:    append([]SecurityViolation{}, execution.Violations...),
		}
		execution.mu.RUnlock()
		result[id] = execCopy
	}

	return result
}

// GetViolationCount returns the total number of security violations
func (s *PluginSandbox) GetViolationCount() int64 {
	if s.resourceMonitor == nil {
		return 0
	}
	return atomic.LoadInt64(&s.resourceMonitor.violations)
}

// start begins the resource monitoring loop
func (rm *ResourceMonitor) start() {
	rm.mu.Lock()
	rm.running = true
	rm.mu.Unlock()

	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			rm.mu.Lock()
			rm.running = false
			rm.mu.Unlock()
			return

		case <-ticker.C:
			rm.monitorResources()
		}
	}
}

// stop shuts down the resource monitor
func (rm *ResourceMonitor) stop() {
	if rm.cancel != nil {
		rm.cancel()
	}
}

// monitorResources checks resource usage for all active executions
func (rm *ResourceMonitor) monitorResources() {
	rm.sandbox.mu.RLock()
	executions := make([]*SandboxedExecution, 0, len(rm.sandbox.activeExecutions))
	for _, execution := range rm.sandbox.activeExecutions {
		executions = append(executions, execution)
	}
	rm.sandbox.mu.RUnlock()

	// Check each active execution
	for _, execution := range executions {
		if err := rm.sandbox.checkResourceLimits(execution); err != nil {
			// Resource limit exceeded - cancel execution
			rm.sandbox.logger.Warn("Canceling execution due to resource violation",
				"plugin", execution.PluginName,
				"execution_id", execution.ID,
				"error", err)
			execution.CancelFunc()
		}
	}
}

// GetSandboxStatus returns current sandbox status and statistics
func (s *PluginSandbox) GetSandboxStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"active_executions":  len(s.activeExecutions),
		"total_violations":   s.GetViolationCount(),
		"current_memory_mb":  m.Alloc / 1024 / 1024,
		"max_memory_mb":      s.config.MaxMemoryMB,
		"current_goroutines": runtime.NumGoroutine(),
		"max_goroutines":     s.config.MaxGoroutines,
		"network_allowed":    s.config.AllowNetworkAccess,
		"filesystem_allowed": s.config.AllowFileSystem,
		"monitor_running":    s.resourceMonitor != nil && s.resourceMonitor.running,
	}
}
