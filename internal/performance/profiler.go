package performance

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"sync/atomic"
	"time"
)

// Profiler manages performance profiling and monitoring
type Profiler struct {
	// Configuration
	enabled    bool
	profileDir string
	logger     *slog.Logger

	// State
	running atomic.Bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Active profiles
	cpuProfile *os.File
	memProfile *os.File
	traceFile  *os.File
	mu         sync.RWMutex

	// Metrics
	metrics ProfileMetrics
}

// ProfileMetrics tracks profiling metrics
type ProfileMetrics struct {
	Goroutines        atomic.Int32
	CPUSamples        atomic.Uint64
	HeapObjects       atomic.Uint64
	StackSamples      atomic.Uint64
	ProfilesGenerated atomic.Uint32
	LastProfileTime   atomic.Int64 // unix nano
}

// ProfilerConfig configures the profiler
type ProfilerConfig struct {
	Enabled     bool
	ProfileDir  string
	AutoProfile bool
	ProfileInt  time.Duration
	Logger      *slog.Logger
}

// NewProfiler creates a new profiler
func NewProfiler(config ProfilerConfig) *Profiler {
	if config.ProfileDir == "" {
		config.ProfileDir = "./profiles"
	}
	if config.ProfileInt == 0 {
		config.ProfileInt = 5 * time.Minute
	}

	// Create profile directory
	if err := os.MkdirAll(config.ProfileDir, 0755); err != nil {
		config.Logger.Error("failed to create profile directory",
			"dir", config.ProfileDir,
			"error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Profiler{
		enabled:    config.Enabled,
		profileDir: config.ProfileDir,
		logger:     config.Logger,
		ctx:        ctx,
		cancel:     cancel,
	}

	if config.Enabled && config.AutoProfile {
		p.running.Store(true)
		p.wg.Add(1)
		go p.autoProfileLoop(config.ProfileInt)
	}

	return p
}

// autoProfileLoop automatically generates profiles
func (p *Profiler) autoProfileLoop(interval time.Duration) {
	defer p.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return

		case <-ticker.C:
			p.logger.Info("generating automatic profiles")

			if err := p.GenerateHeapProfile(); err != nil {
				p.logger.Error("failed to generate heap profile", "error", err)
			}

			if err := p.GenerateGoroutineProfile(); err != nil {
				p.logger.Error("failed to generate goroutine profile", "error", err)
			}
		}
	}
}

// StartCPUProfile starts CPU profiling
func (p *Profiler) StartCPUProfile() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cpuProfile != nil {
		return fmt.Errorf("CPU profiling already active")
	}

	filename := fmt.Sprintf("%s/cpu-%s.prof", p.profileDir, time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CPU profile: %w", err)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return fmt.Errorf("failed to start CPU profile: %w", err)
	}

	p.cpuProfile = f
	p.logger.Info("CPU profiling started", "file", filename)
	return nil
}

// StopCPUProfile stops CPU profiling
func (p *Profiler) StopCPUProfile() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cpuProfile == nil {
		return fmt.Errorf("CPU profiling not active")
	}

	pprof.StopCPUProfile()

	filename := p.cpuProfile.Name()
	if err := p.cpuProfile.Close(); err != nil {
		p.logger.Error("failed to close CPU profile", "error", err)
	}

	p.cpuProfile = nil
	p.metrics.ProfilesGenerated.Add(1)
	p.metrics.LastProfileTime.Store(time.Now().UnixNano())

	p.logger.Info("CPU profiling stopped", "file", filename)
	return nil
}

// GenerateHeapProfile generates a heap memory profile
func (p *Profiler) GenerateHeapProfile() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	filename := fmt.Sprintf("%s/heap-%s.prof", p.profileDir, time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create heap profile: %w", err)
	}
	defer func() { _ = f.Close() }()

	runtime.GC() // Get up-to-date statistics

	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("failed to write heap profile: %w", err)
	}

	p.metrics.ProfilesGenerated.Add(1)
	p.metrics.LastProfileTime.Store(time.Now().UnixNano())

	p.logger.Info("heap profile generated", "file", filename)
	return nil
}

// GenerateGoroutineProfile generates a goroutine profile
func (p *Profiler) GenerateGoroutineProfile() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	filename := fmt.Sprintf("%s/goroutine-%s.prof", p.profileDir, time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create goroutine profile: %w", err)
	}
	defer func() { _ = f.Close() }()

	profile := pprof.Lookup("goroutine")
	if profile == nil {
		return fmt.Errorf("goroutine profile not available")
	}

	if err := profile.WriteTo(f, 2); err != nil {
		return fmt.Errorf("failed to write goroutine profile: %w", err)
	}

	p.metrics.Goroutines.Store(int32(runtime.NumGoroutine()))
	p.metrics.ProfilesGenerated.Add(1)
	p.metrics.LastProfileTime.Store(time.Now().UnixNano())

	p.logger.Info("goroutine profile generated",
		"file", filename,
		"goroutines", runtime.NumGoroutine())
	return nil
}

// GenerateBlockProfile generates a blocking profile
func (p *Profiler) GenerateBlockProfile() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)

	filename := fmt.Sprintf("%s/block-%s.prof", p.profileDir, time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create block profile: %w", err)
	}
	defer func() { _ = f.Close() }()

	profile := pprof.Lookup("block")
	if profile == nil {
		return fmt.Errorf("block profile not available")
	}

	if err := profile.WriteTo(f, 0); err != nil {
		return fmt.Errorf("failed to write block profile: %w", err)
	}

	p.metrics.ProfilesGenerated.Add(1)
	p.metrics.LastProfileTime.Store(time.Now().UnixNano())

	p.logger.Info("block profile generated", "file", filename)
	return nil
}

// GenerateMutexProfile generates a mutex contention profile
func (p *Profiler) GenerateMutexProfile() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(0)

	filename := fmt.Sprintf("%s/mutex-%s.prof", p.profileDir, time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create mutex profile: %w", err)
	}
	defer func() { _ = f.Close() }()

	profile := pprof.Lookup("mutex")
	if profile == nil {
		return fmt.Errorf("mutex profile not available")
	}

	if err := profile.WriteTo(f, 0); err != nil {
		return fmt.Errorf("failed to write mutex profile: %w", err)
	}

	p.metrics.ProfilesGenerated.Add(1)
	p.metrics.LastProfileTime.Store(time.Now().UnixNano())

	p.logger.Info("mutex profile generated", "file", filename)
	return nil
}

// StartTrace starts execution tracing
func (p *Profiler) StartTrace() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.traceFile != nil {
		return fmt.Errorf("tracing already active")
	}

	filename := fmt.Sprintf("%s/trace-%s.out", p.profileDir, time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}

	if err := trace.Start(f); err != nil {
		f.Close()
		return fmt.Errorf("failed to start trace: %w", err)
	}

	p.traceFile = f
	p.logger.Info("execution tracing started", "file", filename)
	return nil
}

// StopTrace stops execution tracing
func (p *Profiler) StopTrace() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.traceFile == nil {
		return fmt.Errorf("tracing not active")
	}

	trace.Stop()

	filename := p.traceFile.Name()
	if err := p.traceFile.Close(); err != nil {
		p.logger.Error("failed to close trace file", "error", err)
	}

	p.traceFile = nil
	p.metrics.ProfilesGenerated.Add(1)
	p.metrics.LastProfileTime.Store(time.Now().UnixNano())

	p.logger.Info("execution tracing stopped", "file", filename)
	return nil
}

// GenerateAllProfiles generates all available profiles
func (p *Profiler) GenerateAllProfiles() error {
	if !p.enabled {
		return fmt.Errorf("profiler not enabled")
	}

	p.logger.Info("generating all profiles")

	errors := make([]error, 0)

	if err := p.GenerateHeapProfile(); err != nil {
		errors = append(errors, fmt.Errorf("heap profile: %w", err))
	}

	if err := p.GenerateGoroutineProfile(); err != nil {
		errors = append(errors, fmt.Errorf("goroutine profile: %w", err))
	}

	if err := p.GenerateBlockProfile(); err != nil {
		errors = append(errors, fmt.Errorf("block profile: %w", err))
	}

	if err := p.GenerateMutexProfile(); err != nil {
		errors = append(errors, fmt.Errorf("mutex profile: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to generate some profiles: %v", errors)
	}

	p.logger.Info("all profiles generated successfully")
	return nil
}

// GetMetrics returns profiler metrics
func (p *Profiler) GetMetrics() map[string]interface{} {
	lastProfile := time.Unix(0, p.metrics.LastProfileTime.Load())
	lastProfileStr := "never"
	if !lastProfile.IsZero() {
		lastProfileStr = lastProfile.Format(time.RFC3339)
	}

	return map[string]interface{}{
		"enabled":            p.enabled,
		"profile_dir":        p.profileDir,
		"goroutines":         runtime.NumGoroutine(),
		"profiles_generated": p.metrics.ProfilesGenerated.Load(),
		"last_profile":       lastProfileStr,
		"cpu_profile_active": p.cpuProfile != nil,
		"trace_active":       p.traceFile != nil,
	}
}

// GetRuntimeStats returns detailed runtime statistics
func (p *Profiler) GetRuntimeStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"goroutines":    runtime.NumGoroutine(),
		"cgo_calls":     runtime.NumCgoCall(),
		"cpus":          runtime.NumCPU(),
		"gomaxprocs":    runtime.GOMAXPROCS(-1),
		"heap_alloc_mb": m.HeapAlloc / (1024 * 1024),
		"sys_mb":        m.Sys / (1024 * 1024),
		"gc_runs":       m.NumGC,
		"gc_pause_ms":   m.PauseTotalNs / 1000000,
		"malloc_count":  m.Mallocs,
		"free_count":    m.Frees,
		"live_objects":  m.Mallocs - m.Frees,
	}
}

// EnableProfiling enables profiling
func (p *Profiler) EnableProfiling() {
	p.enabled = true
	p.logger.Info("profiling enabled")
}

// DisableProfiling disables profiling
func (p *Profiler) DisableProfiling() {
	p.enabled = false
	p.logger.Info("profiling disabled")
}

// IsEnabled returns whether profiling is enabled
func (p *Profiler) IsEnabled() bool {
	return p.enabled
}

// Close stops the profiler
func (p *Profiler) Close() error {
	if !p.running.Load() {
		return nil
	}

	p.running.Store(false)
	p.cancel()
	p.wg.Wait()

	// Stop active profiling
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cpuProfile != nil {
		pprof.StopCPUProfile()
		p.cpuProfile.Close()
		p.cpuProfile = nil
	}

	if p.traceFile != nil {
		trace.Stop()
		p.traceFile.Close()
		p.traceFile = nil
	}

	p.logger.Info("profiler stopped")
	return nil
}
