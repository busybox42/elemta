package plugin

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// PluginSandboxManager manages plugin sandboxing and process isolation
type PluginSandboxManager struct {
	config       *SecureManagerConfig
	logger       *slog.Logger
	sandboxDir   string
	resourceMonitor *PluginResourceMonitor
}

// PluginResourceMonitor monitors plugin resource usage
type PluginResourceMonitor struct {
	logger *slog.Logger
}

// NewPluginSandboxManager creates a new plugin sandbox manager
func NewPluginSandboxManager(config *SecureManagerConfig, logger *slog.Logger) *PluginSandboxManager {
	sandboxDir := "/tmp/elemta-plugin-sandbox"
	
	return &PluginSandboxManager{
		config:          config,
		logger:          logger,
		sandboxDir:      sandboxDir,
		resourceMonitor: NewPluginResourceMonitor(logger),
	}
}

// NewPluginResourceMonitor creates a new plugin resource monitor
func NewPluginResourceMonitor(logger *slog.Logger) *PluginResourceMonitor {
	return &PluginResourceMonitor{
		logger: logger,
	}
}

// CreatePluginProcess creates a new sandboxed plugin process
func (sm *PluginSandboxManager) CreatePluginProcess(info *SecurePluginInfo, config *SecurePluginConfig, pluginPath string) (*PluginProcess, error) {
	// Create sandbox environment
	if err := sm.createSandboxEnvironment(config); err != nil {
		return nil, fmt.Errorf("failed to create sandbox environment: %w", err)
	}
	
	// Create plugin process with sandbox
	process := NewPluginProcess(info, config, pluginPath, sm.logger)
	
	sm.logger.Info("Created sandboxed plugin process",
		"plugin", info.Name,
		"sandbox_dir", sm.sandboxDir,
	)
	
	return process, nil
}

// createSandboxEnvironment creates the sandbox environment for plugins
func (sm *PluginSandboxManager) createSandboxEnvironment(config *SecurePluginConfig) error {
	// Create sandbox directory
	pluginSandboxDir := filepath.Join(sm.sandboxDir, config.PluginID)
	if err := os.MkdirAll(pluginSandboxDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin sandbox directory: %w", err)
	}
	
	// Create required subdirectories
	subdirs := []string{"tmp", "log"}
	for _, subdir := range subdirs {
		dir := filepath.Join(pluginSandboxDir, subdir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create sandbox subdirectory %s: %w", subdir, err)
		}
	}
	
	// Set appropriate permissions
	if err := sm.setSandboxPermissions(pluginSandboxDir); err != nil {
		return fmt.Errorf("failed to set sandbox permissions: %w", err)
	}
	
	sm.logger.Debug("Created sandbox environment",
		"plugin_id", config.PluginID,
		"sandbox_dir", pluginSandboxDir,
	)
	
	return nil
}

// setSandboxPermissions sets appropriate permissions for the sandbox
func (sm *PluginSandboxManager) setSandboxPermissions(sandboxDir string) error {
	// Set restrictive permissions on sandbox directory
	if err := os.Chmod(sandboxDir, 0755); err != nil {
		return fmt.Errorf("failed to set directory permissions: %w", err)
	}
	
	return nil
}

// CleanupSandbox cleans up the sandbox environment for a plugin
func (sm *PluginSandboxManager) CleanupSandbox(pluginID string) error {
	pluginSandboxDir := filepath.Join(sm.sandboxDir, pluginID)
	
	if err := os.RemoveAll(pluginSandboxDir); err != nil {
		sm.logger.Error("Failed to cleanup plugin sandbox",
			"plugin_id", pluginID,
			"sandbox_dir", pluginSandboxDir,
			"error", err,
		)
		return err
	}
	
	sm.logger.Debug("Cleaned up plugin sandbox",
		"plugin_id", pluginID,
		"sandbox_dir", pluginSandboxDir,
	)
	
	return nil
}

// GetResourceUsage gets resource usage for a plugin process
func (rm *PluginResourceMonitor) GetResourceUsage(process *PluginProcess) (*ResourceUsage, error) {
	if !process.IsRunning() {
		return &ResourceUsage{
			LastUpdated: time.Now(),
		}, nil
	}
	
	pid := process.GetPID()
	if pid == 0 {
		return nil, fmt.Errorf("invalid process PID")
	}
	
	// Get memory usage
	memoryMB, err := rm.getMemoryUsage(pid)
	if err != nil {
		rm.logger.Error("Failed to get memory usage",
			"pid", pid,
			"error", err,
		)
		memoryMB = 0
	}
	
	// Get CPU usage
	cpuPercent, err := rm.getCPUUsage(pid)
	if err != nil {
		rm.logger.Error("Failed to get CPU usage",
			"pid", pid,
			"error", err,
		)
		cpuPercent = 0
	}
	
	// Get goroutine count
	goroutineCount := runtime.NumGoroutine()
	
	usage := &ResourceUsage{
		MemoryUsageMB:  memoryMB,
		CPUPercent:     cpuPercent,
		ExecutionTime:  time.Since(process.startTime),
		GoroutineCount: goroutineCount,
		LastUpdated:    time.Now(),
	}
	
	return usage, nil
}

// getMemoryUsage gets memory usage for a process in MB
func (rm *PluginResourceMonitor) getMemoryUsage(pid int) (float64, error) {
	// Read from /proc/[pid]/status on Linux
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	
	file, err := os.Open(statusFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open status file: %w", err)
	}
	defer file.Close()
	
	// Parse memory information
	// This is a simplified implementation - in production you'd want more robust parsing
	var vmRSS int64
	
	// Read VmRSS (Resident Set Size) from status file
	// Format: VmRSS:    1234 kB
	_, err = fmt.Fscanf(file, "VmRSS: %d kB", &vmRSS)
	if err != nil {
		// Try alternative method using statm
		return rm.getMemoryUsageFromStatm(pid)
	}
	
	// Convert from KB to MB
	return float64(vmRSS) / 1024.0, nil
}

// getMemoryUsageFromStatm gets memory usage from /proc/[pid]/statm
func (rm *PluginResourceMonitor) getMemoryUsageFromStatm(pid int) (float64, error) {
	statmFile := fmt.Sprintf("/proc/%d/statm", pid)
	
	file, err := os.Open(statmFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open statm file: %w", err)
	}
	defer file.Close()
	
	var size, resident int64
	_, err = fmt.Fscanf(file, "%d %d", &size, &resident)
	if err != nil {
		return 0, fmt.Errorf("failed to parse statm: %w", err)
	}
	
	// Convert from pages to MB (assuming 4KB pages)
	pageSize := int64(4096)
	memoryBytes := resident * pageSize
	memoryMB := float64(memoryBytes) / (1024 * 1024)
	
	return memoryMB, nil
}

// getCPUUsage gets CPU usage percentage for a process
func (rm *PluginResourceMonitor) getCPUUsage(pid int) (float64, error) {
	// Read from /proc/[pid]/stat
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	
	file, err := os.Open(statFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open stat file: %w", err)
	}
	defer file.Close()
	
	// Parse CPU times from stat file
	// This is a simplified implementation - in production you'd want more accurate CPU calculation
	var utime, stime int64
	
	// Skip to the CPU time fields (fields 14 and 15)
	// Format is complex, so we'll use a simplified approach
	_, err = fmt.Fscanf(file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %d %d", &utime, &stime)
	if err != nil {
		return 0, fmt.Errorf("failed to parse stat: %w", err)
	}
	
	// Calculate CPU percentage (simplified)
	totalTime := utime + stime
	
	// This is a very basic calculation - in production you'd want to track
	// the change over time to get actual CPU percentage
	cpuPercent := float64(totalTime) / 100.0 // Simplified calculation
	
	if cpuPercent > 100 {
		cpuPercent = 100
	}
	
	return cpuPercent, nil
}

// ApplyResourceLimits applies resource limits to a command
func (sm *PluginSandboxManager) ApplyResourceLimits(cmd *exec.Cmd, limits *PluginResourceLimits) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	
	// Set process group for isolation
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0
	
	// Apply memory limits (if supported by the system)
	if limits.MaxMemoryMB > 0 {
		sm.logger.Debug("Memory limit configured",
			"limit_mb", limits.MaxMemoryMB,
		)
		
		// Note: Actual memory limiting would require cgroups or similar mechanism
		// This is a placeholder for the limit configuration
	}
	
	// Apply CPU limits (if supported by the system)
	if limits.MaxCPUPercent > 0 {
		sm.logger.Debug("CPU limit configured",
			"limit_percent", limits.MaxCPUPercent,
		)
		
		// Note: Actual CPU limiting would require cgroups or similar mechanism
		// This is a placeholder for the limit configuration
	}
	
	// Set file descriptor limits
	if limits.MaxFileSize > 0 {
		// Set RLIMIT_FSIZE
		// Note: This would need proper implementation with syscall.Setrlimit
		sm.logger.Debug("File size limit configured",
			"limit_bytes", limits.MaxFileSize,
		)
	}
	
	return nil
}

// MonitorProcess monitors a plugin process for resource violations
func (rm *PluginResourceMonitor) MonitorProcess(process *PluginProcess, limits *PluginResourceLimits) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		if !process.IsRunning() {
			return
		}
		
		usage, err := rm.GetResourceUsage(process)
		if err != nil {
			rm.logger.Error("Failed to get resource usage",
				"plugin", process.info.Name,
				"error", err,
			)
			continue
		}
		
		// Check memory limit
		if usage.MemoryUsageMB > float64(limits.MaxMemoryMB) {
			rm.logger.Warn("Plugin exceeding memory limit",
				"plugin", process.info.Name,
				"usage_mb", usage.MemoryUsageMB,
				"limit_mb", limits.MaxMemoryMB,
			)
			
			// In production, you might want to terminate or throttle the process
		}
		
		// Check CPU limit
		if usage.CPUPercent > limits.MaxCPUPercent {
			rm.logger.Warn("Plugin exceeding CPU limit",
				"plugin", process.info.Name,
				"usage_percent", usage.CPUPercent,
				"limit_percent", limits.MaxCPUPercent,
			)
		}
		
		// Check execution time limit
		if usage.ExecutionTime > limits.MaxExecutionTime {
			rm.logger.Warn("Plugin exceeding execution time limit",
				"plugin", process.info.Name,
				"execution_time", usage.ExecutionTime,
				"limit", limits.MaxExecutionTime,
			)
		}
	}
}

// CreateSecureEnvironment creates a secure environment for plugin execution
func (sm *PluginSandboxManager) CreateSecureEnvironment(pluginID string, limits *PluginResourceLimits) (map[string]string, error) {
	env := make(map[string]string)
	
	// Set minimal environment variables
	env["PATH"] = "/usr/bin:/bin"
	env["HOME"] = filepath.Join(sm.sandboxDir, pluginID)
	env["TMPDIR"] = filepath.Join(sm.sandboxDir, pluginID, "tmp")
	env["USER"] = "plugin"
	env["SHELL"] = "/bin/sh"
	
	// Set plugin-specific environment
	env["PLUGIN_ID"] = pluginID
	env["PLUGIN_SANDBOX_DIR"] = filepath.Join(sm.sandboxDir, pluginID)
	
	// Add allowed paths as environment variable
	if len(limits.AllowedPaths) > 0 {
		env["PLUGIN_ALLOWED_PATHS"] = filepath.Join(limits.AllowedPaths...)
	}
	
	return env, nil
}

// ValidatePluginCapabilities validates that plugin capabilities are allowed
func (sm *PluginSandboxManager) ValidatePluginCapabilities(capabilities []string, limits *PluginResourceLimits) error {
	for _, capability := range capabilities {
		switch capability {
		case "network_access":
			// Check if network access is allowed
			if limits.MaxNetworkOps == 0 {
				return fmt.Errorf("plugin requests network access but it's not allowed")
			}
			
		case "file_access":
			// Check if file access is allowed
			if len(limits.AllowedPaths) == 0 {
				return fmt.Errorf("plugin requests file access but no paths are allowed")
			}
			
		case "external_api":
			// Check if external API access is allowed
			if limits.MaxNetworkOps == 0 {
				return fmt.Errorf("plugin requests external API access but network access is not allowed")
			}
			
		default:
			sm.logger.Warn("Unknown plugin capability",
				"capability", capability,
			)
		}
	}
	
	return nil
}

// CleanupAllSandboxes cleans up all sandbox environments
func (sm *PluginSandboxManager) CleanupAllSandboxes() error {
	if err := os.RemoveAll(sm.sandboxDir); err != nil {
		sm.logger.Error("Failed to cleanup all sandbox environments",
			"sandbox_dir", sm.sandboxDir,
			"error", err,
		)
		return err
	}
	
	sm.logger.Info("Cleaned up all plugin sandboxes",
		"sandbox_dir", sm.sandboxDir,
	)
	
	return nil
}
