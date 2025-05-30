package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

// ExecutorConfig holds configuration for the plugin executor
type ExecutorConfig struct {
	Timeout             time.Duration // Maximum execution time per plugin
	MaxConcurrent       int           // Maximum concurrent plugin executions
	EnablePanicRecovery bool          // Whether to recover from panics
	LogLevel            slog.Level    // Logging level for plugin execution
}

// DefaultExecutorConfig returns sensible defaults
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		Timeout:             30 * time.Second,
		MaxConcurrent:       10,
		EnablePanicRecovery: true,
		LogLevel:            slog.LevelInfo,
	}
}

// ExecutionResult holds the result of plugin execution with timing and error info
type ExecutionResult struct {
	PluginName  string
	StartTime   time.Time
	Duration    time.Duration
	Result      *PluginResult
	Error       error
	Recovered   bool
	RecoverData interface{}
}

// Executor provides safe, isolated execution of plugins
type Executor struct {
	config    ExecutorConfig
	logger    *slog.Logger
	semaphore chan struct{} // Controls concurrency
	metrics   *ExecutorMetrics
}

// ExecutorMetrics tracks plugin execution statistics
type ExecutorMetrics struct {
	mu                   sync.RWMutex
	TotalExecutions      int64
	SuccessfulExecutions int64
	FailedExecutions     int64
	PanicRecoveries      int64
	TimeoutErrors        int64
	AverageExecutionTime time.Duration
	MaxExecutionTime     time.Duration
	PluginStats          map[string]*PluginStats
}

// PluginStats tracks statistics for individual plugins
type PluginStats struct {
	Executions  int64
	Successes   int64
	Failures    int64
	Panics      int64
	Timeouts    int64
	TotalTime   time.Duration
	AverageTime time.Duration
	MaxTime     time.Duration
}

// NewExecutor creates a new plugin executor
func NewExecutor(config ExecutorConfig) *Executor {
	return &Executor{
		config:    config,
		logger:    slog.Default().With("component", "plugin-executor"),
		semaphore: make(chan struct{}, config.MaxConcurrent),
		metrics: &ExecutorMetrics{
			PluginStats: make(map[string]*PluginStats),
		},
	}
}

// ExecutePlugin safely executes a plugin with error isolation and timeout
func (e *Executor) ExecutePlugin(pluginName string, fn func() (*PluginResult, error)) *ExecutionResult {
	result := &ExecutionResult{
		PluginName: pluginName,
		StartTime:  time.Now(),
	}

	// Acquire semaphore for concurrency control
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	default:
		result.Error = fmt.Errorf("plugin executor at max concurrency (%d)", e.config.MaxConcurrent)
		e.updateMetrics(result)
		return result
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Execute plugin in goroutine with panic recovery
	done := make(chan struct{})

	go func() {
		defer close(done)

		if e.config.EnablePanicRecovery {
			defer func() {
				if recovered := recover(); recovered != nil {
					result.Recovered = true
					result.RecoverData = recovered
					result.Error = fmt.Errorf("plugin panic: %v", recovered)

					// Log stack trace for debugging
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					e.logger.Error("Plugin panic recovered",
						"plugin", pluginName,
						"panic", recovered,
						"stack", string(buf[:n]))
				}
			}()
		}

		// Execute the actual plugin function
		result.Result, result.Error = fn()
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		// Plugin completed normally
	case <-ctx.Done():
		// Plugin timed out
		result.Error = fmt.Errorf("plugin execution timeout after %v", e.config.Timeout)
		e.logger.Warn("Plugin execution timeout",
			"plugin", pluginName,
			"timeout", e.config.Timeout)
	}

	result.Duration = time.Since(result.StartTime)
	e.updateMetrics(result)

	return result
}

// ExecuteConnectionHooks executes all connection hooks
func (e *Executor) ExecuteConnectionHooks(hooks []ConnectionHook, hookCtx *HookContext, remoteAddr interface{}, hookType string) []*ExecutionResult {
	results := make([]*ExecutionResult, 0, len(hooks))

	for _, hook := range hooks {
		pluginName := fmt.Sprintf("connection-%s", hookType)

		var execResult *ExecutionResult
		switch hookType {
		case "connect":
			execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
				return hook.OnConnect(hookCtx, hookCtx.RemoteAddr)
			})
		case "disconnect":
			execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
				return hook.OnDisconnect(hookCtx, hookCtx.RemoteAddr)
			})
		}

		results = append(results, execResult)

		// If plugin wants to stop processing, break early
		if execResult.Result != nil && execResult.Result.Action != ActionContinue {
			break
		}
	}

	return results
}

// ExecuteCommandHooks executes SMTP command hooks
func (e *Executor) ExecuteCommandHooks(hooks []SMTPCommandHook, hookCtx *HookContext, command string, params ...interface{}) []*ExecutionResult {
	results := make([]*ExecutionResult, 0, len(hooks))

	for _, hook := range hooks {
		pluginName := fmt.Sprintf("command-%s", command)

		var execResult *ExecutionResult
		switch command {
		case "helo":
			if len(params) > 0 {
				if hostname, ok := params[0].(string); ok {
					execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
						return hook.OnHelo(hookCtx, hostname)
					})
				}
			}
		case "ehlo":
			if len(params) > 0 {
				if hostname, ok := params[0].(string); ok {
					execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
						return hook.OnEhlo(hookCtx, hostname)
					})
				}
			}
		case "auth":
			if len(params) >= 2 {
				if mechanism, ok := params[0].(string); ok {
					if username, ok := params[1].(string); ok {
						execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
							return hook.OnAuth(hookCtx, mechanism, username)
						})
					}
				}
			}
		case "starttls":
			execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
				return hook.OnStartTLS(hookCtx)
			})
		}

		if execResult != nil {
			results = append(results, execResult)

			// If plugin wants to stop processing, break early
			if execResult.Result != nil && execResult.Result.Action != ActionContinue {
				break
			}
		}
	}

	return results
}

// ExecuteContentFilterHooks executes content filter hooks
func (e *Executor) ExecuteContentFilterHooks(hooks []ContentFilterHook, hookCtx *HookContext, content []byte, filterType string) []*ExecutionResult {
	results := make([]*ExecutionResult, 0, len(hooks))

	for _, hook := range hooks {
		pluginName := fmt.Sprintf("filter-%s", filterType)

		var execResult *ExecutionResult
		switch filterType {
		case "antivirus":
			execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
				return hook.OnAntivirusScan(hookCtx, content)
			})
		case "antispam":
			execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
				return hook.OnAntispamScan(hookCtx, content)
			})
		case "content":
			execResult = e.ExecutePlugin(pluginName, func() (*PluginResult, error) {
				return hook.OnContentFilter(hookCtx, content)
			})
		}

		if execResult != nil {
			results = append(results, execResult)

			// If plugin wants to stop processing, break early
			if execResult.Result != nil && execResult.Result.Action != ActionContinue {
				break
			}
		}
	}

	return results
}

// updateMetrics updates execution metrics
func (e *Executor) updateMetrics(result *ExecutionResult) {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	// Update global metrics
	e.metrics.TotalExecutions++

	if result.Error != nil {
		e.metrics.FailedExecutions++
		if result.Recovered {
			e.metrics.PanicRecoveries++
		}
		if result.Duration >= e.config.Timeout {
			e.metrics.TimeoutErrors++
		}
	} else {
		e.metrics.SuccessfulExecutions++
	}

	// Update timing metrics
	if result.Duration > e.metrics.MaxExecutionTime {
		e.metrics.MaxExecutionTime = result.Duration
	}

	// Calculate average execution time
	if e.metrics.TotalExecutions > 0 {
		totalTime := time.Duration(e.metrics.TotalExecutions) * e.metrics.AverageExecutionTime
		totalTime += result.Duration
		e.metrics.AverageExecutionTime = totalTime / time.Duration(e.metrics.TotalExecutions)
	}

	// Update plugin-specific metrics
	if _, exists := e.metrics.PluginStats[result.PluginName]; !exists {
		e.metrics.PluginStats[result.PluginName] = &PluginStats{}
	}

	stats := e.metrics.PluginStats[result.PluginName]
	stats.Executions++
	stats.TotalTime += result.Duration

	if result.Error != nil {
		stats.Failures++
		if result.Recovered {
			stats.Panics++
		}
		if result.Duration >= e.config.Timeout {
			stats.Timeouts++
		}
	} else {
		stats.Successes++
	}

	if result.Duration > stats.MaxTime {
		stats.MaxTime = result.Duration
	}

	if stats.Executions > 0 {
		stats.AverageTime = stats.TotalTime / time.Duration(stats.Executions)
	}
}

// GetMetrics returns current executor metrics
func (e *Executor) GetMetrics() ExecutorMetrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := ExecutorMetrics{
		TotalExecutions:      e.metrics.TotalExecutions,
		SuccessfulExecutions: e.metrics.SuccessfulExecutions,
		FailedExecutions:     e.metrics.FailedExecutions,
		PanicRecoveries:      e.metrics.PanicRecoveries,
		TimeoutErrors:        e.metrics.TimeoutErrors,
		AverageExecutionTime: e.metrics.AverageExecutionTime,
		MaxExecutionTime:     e.metrics.MaxExecutionTime,
		PluginStats:          make(map[string]*PluginStats),
	}

	// Copy plugin stats
	for name, stats := range e.metrics.PluginStats {
		metrics.PluginStats[name] = &PluginStats{
			Executions:  stats.Executions,
			Successes:   stats.Successes,
			Failures:    stats.Failures,
			Panics:      stats.Panics,
			Timeouts:    stats.Timeouts,
			TotalTime:   stats.TotalTime,
			AverageTime: stats.AverageTime,
			MaxTime:     stats.MaxTime,
		}
	}

	return metrics
}

// LogMetrics logs current executor metrics
func (e *Executor) LogMetrics() {
	metrics := e.GetMetrics()

	e.logger.Info("Plugin executor metrics",
		"total_executions", metrics.TotalExecutions,
		"successful_executions", metrics.SuccessfulExecutions,
		"failed_executions", metrics.FailedExecutions,
		"panic_recoveries", metrics.PanicRecoveries,
		"timeout_errors", metrics.TimeoutErrors,
		"avg_execution_time", metrics.AverageExecutionTime,
		"max_execution_time", metrics.MaxExecutionTime)

	// Log individual plugin statistics
	for name, stats := range metrics.PluginStats {
		e.logger.Debug("Plugin statistics",
			"plugin", name,
			"executions", stats.Executions,
			"successes", stats.Successes,
			"failures", stats.Failures,
			"panics", stats.Panics,
			"timeouts", stats.Timeouts,
			"avg_time", stats.AverageTime,
			"max_time", stats.MaxTime)
	}
}
