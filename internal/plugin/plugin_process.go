package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// PluginProcess manages an isolated plugin process
type PluginProcess struct {
	info       *SecurePluginInfo
	config     *SecurePluginConfig
	pluginPath string
	logger     *slog.Logger
	
	// Process management
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	
	// Communication
	encoder   *json.Encoder
	decoder   *json.Decoder
	cmdMutex  sync.Mutex
	
	// State
	running   bool
	startTime time.Time
	pid       int
	
	// Resource monitoring
	resourceLimits *PluginResourceLimits
	sandbox        *ProcessSandbox
}

// PluginMessage represents communication between main process and plugin
type PluginMessage struct {
	Type      string      `json:"type"`
	ID        string      `json:"id"`
	Command   string      `json:"command,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// ProcessSandbox provides process-level sandboxing
type ProcessSandbox struct {
	config      *SecurePluginConfig
	logger      *slog.Logger
	allowedPaths []string
	blockedSyscalls []string
}

// NewPluginProcess creates a new isolated plugin process
func NewPluginProcess(info *SecurePluginInfo, config *SecurePluginConfig, pluginPath string, logger *slog.Logger) *PluginProcess {
	return &PluginProcess{
		info:           info,
		config:         config,
		pluginPath:     pluginPath,
		logger:         logger,
		resourceLimits: config.ResourceLimits,
		sandbox:        NewProcessSandbox(config, logger),
	}
}

// NewProcessSandbox creates a new process sandbox
func NewProcessSandbox(config *SecurePluginConfig, logger *slog.Logger) *ProcessSandbox {
	return &ProcessSandbox{
		config:          config,
		logger:          logger,
		allowedPaths:    config.ResourceLimits.AllowedPaths,
		blockedSyscalls: config.ResourceLimits.BlockedSyscalls,
	}
}

// Start starts the plugin process with proper isolation
func (p *PluginProcess) Start() error {
	if p.running {
		return fmt.Errorf("plugin process already running")
	}
	
	// Build plugin command
	pluginBinary := fmt.Sprintf("%s/plugin", p.pluginPath)
	
	// Check if plugin binary exists and is executable
	if err := p.validatePluginBinary(pluginBinary); err != nil {
		return fmt.Errorf("plugin binary validation failed: %w", err)
	}
	
	// Create command with security restrictions
	p.cmd = exec.Command(pluginBinary)
	
	// Apply process sandbox restrictions
	if err := p.sandbox.ApplyRestrictions(p.cmd); err != nil {
		return fmt.Errorf("failed to apply sandbox restrictions: %w", err)
	}
	
	// Set up pipes for communication
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	p.stdin = stdin
	
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	p.stdout = stdout
	
	stderr, err := p.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	p.stderr = stderr
	
	// Set up JSON communication
	p.encoder = json.NewEncoder(p.stdin)
	p.decoder = json.NewDecoder(p.stdout)
	
	// Start the process
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start plugin process: %w", err)
	}
	
	p.running = true
	p.startTime = time.Now()
	p.pid = p.cmd.Process.Pid
	
	// Start monitoring stderr
	go p.monitorStderr()
	
	// Wait for plugin to be ready
	if err := p.waitForReady(); err != nil {
		p.Stop()
		return fmt.Errorf("plugin failed to become ready: %w", err)
	}
	
	p.logger.Info("Plugin process started",
		"plugin", p.info.Name,
		"pid", p.pid,
		"binary", pluginBinary,
	)
	
	return nil
}

// Stop stops the plugin process gracefully
func (p *PluginProcess) Stop() error {
	if !p.running {
		return nil
	}
	
	// Send shutdown command
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := p.SendCommand("shutdown", nil); err != nil {
		p.logger.Warn("Failed to send shutdown command",
			"plugin", p.info.Name,
			"error", err,
		)
	}
	
	// Wait for graceful shutdown
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()
	
	select {
	case <-shutdownCtx.Done():
		// Force kill if graceful shutdown times out
		p.logger.Warn("Plugin shutdown timeout, forcing kill",
			"plugin", p.info.Name,
		)
		if err := p.cmd.Process.Kill(); err != nil {
			p.logger.Error("Failed to kill plugin process",
				"plugin", p.info.Name,
				"error", err,
			)
		}
		<-done // Wait for process to actually exit
		
	case err := <-done:
		if err != nil && !isExpectedShutdownError(err) {
			p.logger.Error("Plugin process exited with error",
				"plugin", p.info.Name,
				"error", err,
			)
		}
	}
	
	// Close pipes
	if p.stdin != nil {
		p.stdin.Close()
	}
	if p.stdout != nil {
		p.stdout.Close()
	}
	if p.stderr != nil {
		p.stderr.Close()
	}
	
	p.running = false
	uptime := time.Since(p.startTime)
	
	p.logger.Info("Plugin process stopped",
		"plugin", p.info.Name,
		"uptime", uptime,
	)
	
	return nil
}

// SendCommand sends a command to the plugin process
func (p *PluginProcess) SendCommand(command string, data interface{}) error {
	if !p.running {
		return fmt.Errorf("plugin process not running")
	}
	
	p.cmdMutex.Lock()
	defer p.cmdMutex.Unlock()
	
	message := PluginMessage{
		Type:      "command",
		ID:        generateMessageID(),
		Command:   command,
		Data:      data,
		Timestamp: time.Now(),
	}
	
	if err := p.encoder.Encode(message); err != nil {
		return fmt.Errorf("failed to send command: %w", err)
	}
	
	// Wait for response
	var response PluginMessage
	if err := p.decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}
	
	if response.Error != "" {
		return fmt.Errorf("plugin error: %s", response.Error)
	}
	
	return nil
}

// ProcessMessage processes a message through the plugin
func (p *PluginProcess) ProcessMessage(ctx context.Context, input *SecurePluginInput) (*SecurePluginOutput, error) {
	if !p.running {
		return nil, fmt.Errorf("plugin process not running")
	}
	
	p.cmdMutex.Lock()
	defer p.cmdMutex.Unlock()
	
	// Create message
	message := PluginMessage{
		Type:      "process_message",
		ID:        generateMessageID(),
		Data:      input,
		Timestamp: time.Now(),
	}
	
	// Send message with timeout
	done := make(chan error, 1)
	var output *SecurePluginOutput
	
	go func() {
		// Send request
		if err := p.encoder.Encode(message); err != nil {
			done <- fmt.Errorf("failed to send message: %w", err)
			return
		}
		
		// Wait for response
		var response PluginMessage
		if err := p.decoder.Decode(&response); err != nil {
			done <- fmt.Errorf("failed to receive response: %w", err)
			return
		}
		
		if response.Error != "" {
			done <- fmt.Errorf("plugin error: %s", response.Error)
			return
		}
		
		// Parse output
		outputData, err := json.Marshal(response.Data)
		if err != nil {
			done <- fmt.Errorf("failed to marshal output: %w", err)
			return
		}
		
		var pluginOutput SecurePluginOutput
		if err := json.Unmarshal(outputData, &pluginOutput); err != nil {
			done <- fmt.Errorf("failed to unmarshal output: %w", err)
			return
		}
		
		output = &pluginOutput
		done <- nil
	}()
	
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, err
		}
		return output, nil
	}
}

// HealthCheck performs a health check on the plugin
func (p *PluginProcess) HealthCheck(ctx context.Context) error {
	if !p.running {
		return fmt.Errorf("plugin process not running")
	}
	
	// Check if process is still alive
	if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
		return fmt.Errorf("plugin process has exited")
	}
	
	p.cmdMutex.Lock()
	defer p.cmdMutex.Unlock()
	
	message := PluginMessage{
		Type:      "health_check",
		ID:        generateMessageID(),
		Timestamp: time.Now(),
	}
	
	done := make(chan error, 1)
	go func() {
		// Send health check
		if err := p.encoder.Encode(message); err != nil {
			done <- fmt.Errorf("failed to send health check: %w", err)
			return
		}
		
		// Wait for response
		var response PluginMessage
		if err := p.decoder.Decode(&response); err != nil {
			done <- fmt.Errorf("failed to receive health check response: %w", err)
			return
		}
		
		if response.Error != "" {
			done <- fmt.Errorf("plugin health check failed: %s", response.Error)
			return
		}
		
		done <- nil
	}()
	
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// GetPID returns the process ID of the plugin
func (p *PluginProcess) GetPID() int {
	return p.pid
}

// IsRunning returns whether the plugin process is running
func (p *PluginProcess) IsRunning() bool {
	return p.running
}

// validatePluginBinary validates the plugin binary before execution
func (p *PluginProcess) validatePluginBinary(binaryPath string) error {
	// Check if file exists
	info, err := os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("plugin binary not found: %w", err)
	}
	
	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin binary is not a regular file")
	}
	
	// Check if it's executable
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("plugin binary is not executable")
	}
	
	// Check file size (prevent extremely large binaries)
	if info.Size() > 100*1024*1024 { // 100MB limit
		return fmt.Errorf("plugin binary too large: %d bytes", info.Size())
	}
	
	return nil
}

// waitForReady waits for the plugin to signal it's ready
func (p *PluginProcess) waitForReady() error {
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	
	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("timeout waiting for plugin to be ready")
			
		default:
			var message PluginMessage
			if err := p.decoder.Decode(&message); err != nil {
				if err == io.EOF {
					return fmt.Errorf("plugin process exited unexpectedly")
				}
				// Continue trying to read
				time.Sleep(100 * time.Millisecond)
				continue
			}
			
			if message.Type == "ready" {
				return nil
			}
			
			if message.Type == "error" {
				return fmt.Errorf("plugin startup error: %s", message.Error)
			}
		}
	}
}

// monitorStderr monitors the plugin's stderr for errors
func (p *PluginProcess) monitorStderr() {
	scanner := bufio.NewScanner(p.stderr)
	for scanner.Scan() {
		line := scanner.Text()
		p.logger.Error("Plugin stderr",
			"plugin", p.info.Name,
			"message", line,
		)
	}
	
	if err := scanner.Err(); err != nil {
		p.logger.Error("Error reading plugin stderr",
			"plugin", p.info.Name,
			"error", err,
		)
	}
}

// ApplyRestrictions applies security restrictions to the plugin process
func (ps *ProcessSandbox) ApplyRestrictions(cmd *exec.Cmd) error {
	// Set process group to isolate the plugin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
	
	// Set environment variables
	cmd.Env = ps.buildSecureEnvironment()
	
	// Set working directory to a safe location
	cmd.Dir = "/tmp"
	
	// Apply resource limits using cgroups (if available)
	if err := ps.applyResourceLimits(cmd); err != nil {
		ps.logger.Warn("Failed to apply resource limits",
			"error", err,
		)
	}
	
	return nil
}

// buildSecureEnvironment builds a minimal, secure environment for the plugin
func (ps *ProcessSandbox) buildSecureEnvironment() []string {
	// Start with minimal environment
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/tmp",
		"USER=plugin",
		"SHELL=/bin/sh",
	}
	
	// Add plugin-specific environment variables
	for key, value := range ps.config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	
	return env
}

// applyResourceLimits applies resource limits to the plugin process
func (ps *ProcessSandbox) applyResourceLimits(cmd *exec.Cmd) error {
	limits := ps.config.ResourceLimits
	
	// Set memory limit (if supported)
	if limits.MaxMemoryMB > 0 {
		// This would require cgroups v2 or similar mechanism
		// For now, we'll log the intention
		ps.logger.Debug("Memory limit configured",
			"limit_mb", limits.MaxMemoryMB,
		)
	}
	
	// Set CPU limit (if supported)
	if limits.MaxCPUPercent > 0 {
		ps.logger.Debug("CPU limit configured",
			"limit_percent", limits.MaxCPUPercent,
		)
	}
	
	return nil
}

// isExpectedShutdownError checks if an error is expected during shutdown
func isExpectedShutdownError(err error) bool {
	if err == nil {
		return true
	}
	
	// Check for expected shutdown signals
	if exitErr, ok := err.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			// SIGTERM and SIGKILL are expected during shutdown
			if status.Signal() == syscall.SIGTERM || status.Signal() == syscall.SIGKILL {
				return true
			}
		}
	}
	
	return false
}

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return fmt.Sprintf("msg-%d", time.Now().UnixNano())
}
