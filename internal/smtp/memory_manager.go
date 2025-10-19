package smtp

import (
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryManager provides comprehensive memory management and exhaustion protection
type MemoryManager struct {
	config           *MemoryConfig
	logger           *slog.Logger
	stats            *MemoryStats
	circuitBreaker   *MemoryCircuitBreaker
	monitoringTicker *time.Ticker
	shutdownChan     chan struct{}
	mu               sync.RWMutex
}

// MemoryConfig holds configuration for memory management
type MemoryConfig struct {
	MaxMemoryUsage             int64         `toml:"max_memory_usage" json:"max_memory_usage"`                         // Maximum memory usage in bytes
	MemoryWarningThreshold     float64       `toml:"memory_warning_threshold" json:"memory_warning_threshold"`         // Warning threshold (0.0-1.0)
	MemoryCriticalThreshold    float64       `toml:"memory_critical_threshold" json:"memory_critical_threshold"`       // Critical threshold (0.0-1.0)
	GCThreshold                float64       `toml:"gc_threshold" json:"gc_threshold"`                                 // Force GC threshold (0.0-1.0)
	MonitoringInterval         time.Duration `toml:"monitoring_interval" json:"monitoring_interval"`                   // Memory monitoring interval
	PerConnectionMemoryLimit   int64         `toml:"per_connection_memory_limit" json:"per_connection_memory_limit"`   // Per-connection memory limit
	MaxGoroutines              int           `toml:"max_goroutines" json:"max_goroutines"`                             // Maximum goroutines
	GoroutineLeakDetection     bool          `toml:"goroutine_leak_detection" json:"goroutine_leak_detection"`         // Enable goroutine leak detection
	MemoryExhaustionProtection bool          `toml:"memory_exhaustion_protection" json:"memory_exhaustion_protection"` // Enable memory exhaustion protection
}

// DefaultMemoryConfig returns sensible default memory configuration
func DefaultMemoryConfig() *MemoryConfig {
	return &MemoryConfig{
		MaxMemoryUsage:             1024 * 1024 * 1024, // 1GB default
		MemoryWarningThreshold:     0.75,               // 75% warning
		MemoryCriticalThreshold:    0.90,               // 90% critical
		GCThreshold:                0.80,               // 80% force GC
		MonitoringInterval:         5 * time.Second,    // Monitor every 5 seconds
		PerConnectionMemoryLimit:   10 * 1024 * 1024,   // 10MB per connection
		MaxGoroutines:              2000,               // 2000 goroutines max
		GoroutineLeakDetection:     true,               // Enable leak detection
		MemoryExhaustionProtection: true,               // Enable exhaustion protection
	}
}

// MemoryStats tracks memory usage statistics
type MemoryStats struct {
	CurrentMemoryUsage    int64     `json:"current_memory_usage"`
	PeakMemoryUsage       int64     `json:"peak_memory_usage"`
	MemoryUtilization     float64   `json:"memory_utilization"`
	GoroutineCount        int       `json:"goroutine_count"`
	PeakGoroutineCount    int       `json:"peak_goroutine_count"`
	GCCollections         int64     `json:"gc_collections"`
	ForcedGCCollections   int64     `json:"forced_gc_collections"`
	MemoryWarnings        int64     `json:"memory_warnings"`
	MemoryCriticalAlerts  int64     `json:"memory_critical_alerts"`
	ConnectionMemoryUsage int64     `json:"connection_memory_usage"`
	LastGC                time.Time `json:"last_gc"`
	LastUpdate            time.Time `json:"last_update"`
}

// MemoryCircuitBreaker implements circuit breaker pattern for memory exhaustion protection
type MemoryCircuitBreaker struct {
	state         MemoryCircuitBreakerState
	threshold     float64
	timeout       time.Duration
	lastTriggered time.Time
	triggerCount  int64
	maxTriggers   int64
	mu            sync.RWMutex
	logger        *slog.Logger
}

// MemoryCircuitBreakerState represents the state of the memory circuit breaker
type MemoryCircuitBreakerState int

const (
	MemoryCircuitBreakerClosed MemoryCircuitBreakerState = iota
	MemoryCircuitBreakerOpen
	MemoryCircuitBreakerHalfOpen
)

// NewMemoryManager creates a new memory manager
func NewMemoryManager(config *MemoryConfig, logger *slog.Logger) *MemoryManager {
	if config == nil {
		config = DefaultMemoryConfig()
	}

	mm := &MemoryManager{
		config:       config,
		logger:       logger.With("component", "memory-manager"),
		stats:        &MemoryStats{},
		shutdownChan: make(chan struct{}),
	}

	// Initialize circuit breaker
	mm.circuitBreaker = &MemoryCircuitBreaker{
		state:       MemoryCircuitBreakerClosed,
		threshold:   config.MemoryCriticalThreshold,
		timeout:     30 * time.Second,
		maxTriggers: 5,
		logger:      mm.logger,
	}

	// Start monitoring if enabled
	if config.MemoryExhaustionProtection {
		go mm.startMemoryMonitoring()
	}

	mm.logger.Info("Memory manager initialized",
		"max_memory_usage", config.MaxMemoryUsage,
		"warning_threshold", config.MemoryWarningThreshold,
		"critical_threshold", config.MemoryCriticalThreshold,
		"gc_threshold", config.GCThreshold,
		"monitoring_interval", config.MonitoringInterval,
		"per_connection_limit", config.PerConnectionMemoryLimit,
		"max_goroutines", config.MaxGoroutines,
	)

	return mm
}

// CheckMemoryLimit checks if current memory usage is within limits
func (mm *MemoryManager) CheckMemoryLimit() error {
	// Check circuit breaker first (without holding the main lock to avoid deadlock)
	mm.logger.Debug("Checking circuit breaker state")
	if !mm.circuitBreaker.AllowRequest() {
		mm.logger.Debug("Circuit breaker is OPEN - rejecting connection")
		return fmt.Errorf("memory circuit breaker is open - memory exhaustion protection active")
	}
	mm.logger.Debug("Circuit breaker is CLOSED - allowing connection")

	// Get current memory stats (this doesn't need the main lock)
	stats := mm.getCurrentMemoryStats()
	mm.logger.Debug("Memory stats", "utilization_pct", stats.MemoryUtilization*100, "current_bytes", stats.CurrentMemoryUsage, "max_bytes", mm.config.MaxMemoryUsage, "critical_threshold_pct", mm.config.MemoryCriticalThreshold*100)

	// Check if we're approaching memory limits
	if stats.MemoryUtilization >= mm.config.MemoryCriticalThreshold {
		// Record trigger (without holding the main lock to avoid deadlock)
		mm.circuitBreaker.RecordTrigger()
		atomic.AddInt64(&mm.stats.MemoryCriticalAlerts, 1)

		mm.logger.Error("Memory critical threshold exceeded",
			"utilization", stats.MemoryUtilization,
			"current_usage", stats.CurrentMemoryUsage,
			"max_usage", mm.config.MaxMemoryUsage,
			"threshold", mm.config.MemoryCriticalThreshold,
		)

		return fmt.Errorf("memory critical threshold exceeded: %.2f%% utilization", stats.MemoryUtilization*100)
	}

	// Check warning threshold
	if stats.MemoryUtilization >= mm.config.MemoryWarningThreshold {
		atomic.AddInt64(&mm.stats.MemoryWarnings, 1)

		mm.logger.Warn("Memory warning threshold exceeded",
			"utilization", stats.MemoryUtilization,
			"current_usage", stats.CurrentMemoryUsage,
			"max_usage", mm.config.MaxMemoryUsage,
			"threshold", mm.config.MemoryWarningThreshold,
		)
	}

	return nil
}

// CheckConnectionMemoryLimit checks if a connection can consume additional memory
func (mm *MemoryManager) CheckConnectionMemoryLimit(connectionID string, additionalMemory int64) error {
	mm.logger.Debug("CheckConnectionMemoryLimit called", "connection_id", connectionID, "memory_bytes", additionalMemory)

	// Check overall memory limit first (this method doesn't hold locks)
	mm.logger.Debug("Calling CheckMemoryLimit from CheckConnectionMemoryLimit")
	if err := mm.CheckMemoryLimit(); err != nil {
		mm.logger.Debug("CheckMemoryLimit failed", "error", err)
		return err
	}
	mm.logger.Debug("CheckMemoryLimit passed")

	// Check per-connection memory limit (use cached config to avoid lock contention)
	perConnectionLimit := mm.config.PerConnectionMemoryLimit
	mm.logger.Debug("Per-connection memory limit", "limit_bytes", perConnectionLimit, "requested_bytes", additionalMemory)

	if additionalMemory > perConnectionLimit {
		mm.logger.Debug("Connection memory limit exceeded")
		mm.logger.Warn("Connection memory limit exceeded",
			"connection_id", connectionID,
			"requested_memory", additionalMemory,
			"per_connection_limit", perConnectionLimit,
		)
		return fmt.Errorf("connection memory limit exceeded: %d bytes requested, %d bytes limit",
			additionalMemory, perConnectionLimit)
	}

	mm.logger.Debug("CheckConnectionMemoryLimit passed")
	return nil
}

// CheckGoroutineLimit checks if we can create additional goroutines
func (mm *MemoryManager) CheckGoroutineLimit() error {
	mm.logger.Debug("CheckGoroutineLimit called")

	// Get current goroutine count (this is thread-safe)
	numGoroutines := runtime.NumGoroutine()
	mm.logger.Debug("Current goroutine count", "count", numGoroutines)

	// Use cached config value to avoid lock contention
	// The config is set during initialization and rarely changes
	maxGoroutines := mm.config.MaxGoroutines
	mm.logger.Debug("Max goroutines config", "max", maxGoroutines)

	if numGoroutines >= maxGoroutines {
		mm.logger.Debug("Goroutine limit exceeded", "current", numGoroutines, "max", maxGoroutines)
		mm.logger.Warn("Goroutine limit exceeded",
			"current_goroutines", numGoroutines,
			"max_goroutines", maxGoroutines,
		)
		return fmt.Errorf("goroutine limit exceeded: %d current, %d max", numGoroutines, maxGoroutines)
	}

	mm.logger.Debug("Goroutine limit check passed", "current", numGoroutines, "max", maxGoroutines)
	return nil
}

// ForceGarbageCollection forces garbage collection if memory usage is high
func (mm *MemoryManager) ForceGarbageCollection() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	stats := mm.getCurrentMemoryStats()

	if stats.MemoryUtilization >= mm.config.GCThreshold {
		mm.logger.Info("Forcing garbage collection due to high memory usage",
			"utilization", stats.MemoryUtilization,
			"threshold", mm.config.GCThreshold,
		)

		// Force garbage collection
		runtime.GC()
		debug.FreeOSMemory()

		atomic.AddInt64(&mm.stats.ForcedGCCollections, 1)
		mm.stats.LastGC = time.Now()

		// Update stats after GC
		mm.updateMemoryStats()

		mm.logger.Info("Garbage collection completed",
			"new_utilization", mm.stats.MemoryUtilization,
			"new_usage", mm.stats.CurrentMemoryUsage,
		)
	}
}

// GetMemoryStats returns current memory statistics
func (mm *MemoryManager) GetMemoryStats() *MemoryStats {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Update stats before returning
	mm.updateMemoryStats()

	// Return a copy to prevent race conditions
	stats := *mm.stats
	return &stats
}

// startMemoryMonitoring starts the memory monitoring goroutine
func (mm *MemoryManager) startMemoryMonitoring() {
	mm.monitoringTicker = time.NewTicker(mm.config.MonitoringInterval)
	defer mm.monitoringTicker.Stop()

	mm.logger.Info("Starting memory monitoring",
		"interval", mm.config.MonitoringInterval,
	)

	for {
		select {
		case <-mm.monitoringTicker.C:
			mm.performMemoryMonitoring()
		case <-mm.shutdownChan:
			mm.logger.Info("Memory monitoring stopped")
			return
		}
	}
}

// performMemoryMonitoring performs periodic memory monitoring and cleanup
func (mm *MemoryManager) performMemoryMonitoring() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Update memory statistics
	mm.updateMemoryStats()

	// Check for memory pressure and force GC if needed
	mm.ForceGarbageCollection()

	// Check for goroutine leaks if enabled
	if mm.config.GoroutineLeakDetection {
		mm.checkGoroutineLeaks()
	}

	// Log memory statistics periodically
	mm.logger.Debug("Memory monitoring completed",
		"memory_usage", mm.stats.CurrentMemoryUsage,
		"memory_utilization", mm.stats.MemoryUtilization,
		"goroutines", mm.stats.GoroutineCount,
		"gc_collections", mm.stats.GCCollections,
	)
}

// updateMemoryStats updates the current memory statistics
func (mm *MemoryManager) updateMemoryStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Update memory statistics
	mm.stats.CurrentMemoryUsage = int64(m.Alloc)
	mm.stats.MemoryUtilization = float64(m.Alloc) / float64(mm.config.MaxMemoryUsage)
	mm.stats.GoroutineCount = runtime.NumGoroutine()
	mm.stats.GCCollections = int64(m.NumGC)
	mm.stats.LastUpdate = time.Now()

	// Update peak values
	if mm.stats.CurrentMemoryUsage > mm.stats.PeakMemoryUsage {
		mm.stats.PeakMemoryUsage = mm.stats.CurrentMemoryUsage
	}
	if mm.stats.GoroutineCount > mm.stats.PeakGoroutineCount {
		mm.stats.PeakGoroutineCount = mm.stats.GoroutineCount
	}
}

// getCurrentMemoryStats gets current memory statistics without locking
func (mm *MemoryManager) getCurrentMemoryStats() *MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &MemoryStats{
		CurrentMemoryUsage: int64(m.Alloc),
		MemoryUtilization:  float64(m.Alloc) / float64(mm.config.MaxMemoryUsage),
		GoroutineCount:     runtime.NumGoroutine(),
		GCCollections:      int64(m.NumGC),
		LastUpdate:         time.Now(),
	}
}

// checkGoroutineLeaks checks for potential goroutine leaks
func (mm *MemoryManager) checkGoroutineLeaks() {
	currentGoroutines := runtime.NumGoroutine()

	// If goroutine count is significantly higher than expected, log a warning
	expectedGoroutines := mm.config.MaxGoroutines / 2 // Expect to use about half of max
	if currentGoroutines > expectedGoroutines {
		mm.logger.Warn("Potential goroutine leak detected",
			"current_goroutines", currentGoroutines,
			"expected_goroutines", expectedGoroutines,
			"max_goroutines", mm.config.MaxGoroutines,
		)
	}
}

// Close shuts down the memory manager
func (mm *MemoryManager) Close() {
	close(mm.shutdownChan)

	if mm.monitoringTicker != nil {
		mm.monitoringTicker.Stop()
	}

	mm.logger.Info("Memory manager shut down")
}

// Memory Circuit Breaker Methods

// AllowRequest checks if requests should be allowed through the circuit breaker
func (mcb *MemoryCircuitBreaker) AllowRequest() bool {
	mcb.mu.RLock()
	defer mcb.mu.RUnlock()

	now := time.Now()

	switch mcb.state {
	case MemoryCircuitBreakerClosed:
		return true
	case MemoryCircuitBreakerOpen:
		if now.Sub(mcb.lastTriggered) >= mcb.timeout {
			mcb.state = MemoryCircuitBreakerHalfOpen
			mcb.logger.Info("Memory circuit breaker transitioning to half-open")
			return true
		}
		return false
	case MemoryCircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// RecordTrigger records a memory threshold trigger
func (mcb *MemoryCircuitBreaker) RecordTrigger() {
	mcb.mu.Lock()
	defer mcb.mu.Unlock()

	mcb.triggerCount++
	mcb.lastTriggered = time.Now()

	if mcb.triggerCount >= mcb.maxTriggers {
		mcb.state = MemoryCircuitBreakerOpen
		mcb.logger.Error("Memory circuit breaker opened due to repeated triggers",
			"trigger_count", mcb.triggerCount,
			"max_triggers", mcb.maxTriggers,
		)
	}
}

// RecordSuccess records a successful memory recovery
func (mcb *MemoryCircuitBreaker) RecordSuccess() {
	mcb.mu.Lock()
	defer mcb.mu.Unlock()

	if mcb.state == MemoryCircuitBreakerHalfOpen {
		mcb.state = MemoryCircuitBreakerClosed
		mcb.triggerCount = 0
		mcb.logger.Info("Memory circuit breaker closed after successful recovery")
	}
}

// GetState returns the current circuit breaker state
func (mcb *MemoryCircuitBreaker) GetState() MemoryCircuitBreakerState {
	mcb.mu.RLock()
	defer mcb.mu.RUnlock()
	return mcb.state
}
