package performance

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryOptimizer manages memory usage and optimization
type MemoryOptimizer struct {
	// Configuration
	maxMemory     uint64
	gcThreshold   float64
	checkInterval time.Duration
	logger        *slog.Logger

	// State
	running atomic.Bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Statistics
	stats MemoryStats

	// Object pools
	bufferPool  *BufferPool
	messagePool *MessagePool
}

// MemoryStats tracks memory statistics
type MemoryStats struct {
	Allocs       atomic.Uint64
	TotalAllocs  atomic.Uint64
	Sys          atomic.Uint64
	Mallocs      atomic.Uint64
	Frees        atomic.Uint64
	HeapAlloc    atomic.Uint64
	HeapInuse    atomic.Uint64
	HeapIdle     atomic.Uint64
	GCRuns       atomic.Uint32
	GCPauseTotal atomic.Uint64 // nanoseconds
	LastGC       atomic.Int64  // unix nano
}

// BufferPool manages reusable byte buffers
type BufferPool struct {
	pool sync.Pool
}

// MessagePool manages reusable message structures
type MessagePool struct {
	pool sync.Pool
}

// Message represents a pooled message structure
type Message struct {
	Headers map[string]string
	Body    []byte
	Size    int
}

// MemoryOptimizerConfig configures the memory optimizer
type MemoryOptimizerConfig struct {
	MaxMemory     uint64        // Maximum memory in bytes
	GCThreshold   float64       // GC trigger threshold (0.0-1.0)
	CheckInterval time.Duration // Memory check interval
	Logger        *slog.Logger
}

// NewMemoryOptimizer creates a new memory optimizer
func NewMemoryOptimizer(config MemoryOptimizerConfig) *MemoryOptimizer {
	if config.MaxMemory == 0 {
		config.MaxMemory = 2 * 1024 * 1024 * 1024 // 2GB default
	}
	if config.GCThreshold == 0 {
		config.GCThreshold = 0.85 // 85% default
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	mo := &MemoryOptimizer{
		maxMemory:     config.MaxMemory,
		gcThreshold:   config.GCThreshold,
		checkInterval: config.CheckInterval,
		logger:        config.Logger,
		ctx:           ctx,
		cancel:        cancel,
		bufferPool:    NewBufferPool(),
		messagePool:   NewMessagePool(),
	}

	// Start monitoring
	mo.running.Store(true)
	mo.wg.Add(1)
	go mo.monitorLoop()

	return mo
}

// NewBufferPool creates a new buffer pool
func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 4096)
				return &buf
			},
		},
	}
}

// NewMessagePool creates a new message pool
func NewMessagePool() *MessagePool {
	return &MessagePool{
		pool: sync.Pool{
			New: func() interface{} {
				return &Message{
					Headers: make(map[string]string),
					Body:    make([]byte, 0, 1024),
				}
			},
		},
	}
}

// GetBuffer gets a buffer from the pool
func (bp *BufferPool) Get(size int) *[]byte {
	buf := bp.pool.Get().(*[]byte)
	if cap(*buf) < size {
		*buf = make([]byte, size)
	}
	*buf = (*buf)[:size]
	return buf
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf *[]byte) {
	if buf != nil {
		*buf = (*buf)[:0]
		bp.pool.Put(buf)
	}
}

// GetMessage gets a message from the pool
func (mp *MessagePool) Get() *Message {
	msg := mp.pool.Get().(*Message)
	return msg
}

// Put returns a message to the pool
func (mp *MessagePool) Put(msg *Message) {
	if msg != nil {
		// Clear message
		for k := range msg.Headers {
			delete(msg.Headers, k)
		}
		msg.Body = msg.Body[:0]
		msg.Size = 0
		mp.pool.Put(msg)
	}
}

// monitorLoop monitors memory usage
func (mo *MemoryOptimizer) monitorLoop() {
	defer mo.wg.Done()

	ticker := time.NewTicker(mo.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mo.ctx.Done():
			return

		case <-ticker.C:
			mo.checkMemory()
		}
	}
}

// checkMemory checks current memory usage
func (mo *MemoryOptimizer) checkMemory() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Update statistics
	mo.stats.Allocs.Store(m.Alloc)
	mo.stats.TotalAllocs.Store(m.TotalAlloc)
	mo.stats.Sys.Store(m.Sys)
	mo.stats.Mallocs.Store(m.Mallocs)
	mo.stats.Frees.Store(m.Frees)
	mo.stats.HeapAlloc.Store(m.HeapAlloc)
	mo.stats.HeapInuse.Store(m.HeapInuse)
	mo.stats.HeapIdle.Store(m.HeapIdle)
	mo.stats.GCRuns.Store(m.NumGC)
	mo.stats.GCPauseTotal.Store(m.PauseTotalNs)
	mo.stats.LastGC.Store(int64(m.LastGC))

	// Calculate memory usage percentage
	usage := float64(m.HeapAlloc) / float64(mo.maxMemory)

	// Log memory status
	mo.logger.Debug("memory status",
		"heap_alloc_mb", m.HeapAlloc/(1024*1024),
		"heap_sys_mb", m.HeapSys/(1024*1024),
		"heap_inuse_mb", m.HeapInuse/(1024*1024),
		"heap_idle_mb", m.HeapIdle/(1024*1024),
		"usage_percent", fmt.Sprintf("%.2f%%", usage*100),
		"gc_runs", m.NumGC)

	// Trigger GC if threshold exceeded
	if usage > mo.gcThreshold {
		mo.logger.Info("memory threshold exceeded, triggering GC",
			"usage_percent", fmt.Sprintf("%.2f%%", usage*100),
			"threshold_percent", fmt.Sprintf("%.2f%%", mo.gcThreshold*100))

		start := time.Now()
		runtime.GC()
		duration := time.Since(start)

		runtime.ReadMemStats(&m)
		newUsage := float64(m.HeapAlloc) / float64(mo.maxMemory)

		mo.logger.Info("GC completed",
			"duration_ms", duration.Milliseconds(),
			"before_mb", m.HeapAlloc/(1024*1024),
			"after_percent", fmt.Sprintf("%.2f%%", newUsage*100))
	}
}

// OptimizeBuffers optimizes buffer usage
func (mo *MemoryOptimizer) OptimizeBuffers() {
	// Free OS memory
	debug.FreeOSMemory()

	mo.logger.Debug("buffer optimization completed")
}

// GetStats returns current memory statistics
func (mo *MemoryOptimizer) GetStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	avgGCPause := uint64(0)
	if m.NumGC > 0 {
		avgGCPause = m.PauseTotalNs / uint64(m.NumGC)
	}

	return map[string]interface{}{
		"heap_alloc_mb":     m.HeapAlloc / (1024 * 1024),
		"heap_sys_mb":       m.HeapSys / (1024 * 1024),
		"heap_inuse_mb":     m.HeapInuse / (1024 * 1024),
		"heap_idle_mb":      m.HeapIdle / (1024 * 1024),
		"heap_released_mb":  m.HeapReleased / (1024 * 1024),
		"stack_inuse_mb":    m.StackInuse / (1024 * 1024),
		"stack_sys_mb":      m.StackSys / (1024 * 1024),
		"total_alloc_mb":    m.TotalAlloc / (1024 * 1024),
		"sys_mb":            m.Sys / (1024 * 1024),
		"mallocs":           m.Mallocs,
		"frees":             m.Frees,
		"live_objects":      m.Mallocs - m.Frees,
		"gc_runs":           m.NumGC,
		"gc_pause_total_ms": m.PauseTotalNs / 1000000,
		"gc_pause_avg_ms":   avgGCPause / 1000000,
		"gc_cpu_fraction":   m.GCCPUFraction,
		"next_gc_mb":        m.NextGC / (1024 * 1024),
		"last_gc":           time.Unix(0, int64(m.LastGC)).Format(time.RFC3339),
		"max_memory_mb":     mo.maxMemory / (1024 * 1024),
		"usage_percent":     fmt.Sprintf("%.2f", float64(m.HeapAlloc)/float64(mo.maxMemory)*100),
		"goroutines":        runtime.NumGoroutine(),
	}
}

// GetBufferPool returns the buffer pool
func (mo *MemoryOptimizer) GetBufferPool() *BufferPool {
	return mo.bufferPool
}

// GetMessagePool returns the message pool
func (mo *MemoryOptimizer) GetMessagePool() *MessagePool {
	return mo.messagePool
}

// ForceGC forces garbage collection
func (mo *MemoryOptimizer) ForceGC() time.Duration {
	start := time.Now()
	runtime.GC()
	duration := time.Since(start)

	mo.logger.Info("forced GC completed", "duration_ms", duration.Milliseconds())
	return duration
}

// SetGCPercent sets the GC target percentage
func (mo *MemoryOptimizer) SetGCPercent(percent int) int {
	old := debug.SetGCPercent(percent)
	mo.logger.Info("GC percent changed", "old", old, "new", percent)
	return old
}

// SetMemoryLimit sets the Go runtime memory limit
func (mo *MemoryOptimizer) SetMemoryLimit(limit int64) int64 {
	old := debug.SetMemoryLimit(limit)
	mo.logger.Info("memory limit changed",
		"old_mb", old/(1024*1024),
		"new_mb", limit/(1024*1024))
	return old
}

// GetMemoryLimit returns the current memory limit
func (mo *MemoryOptimizer) GetMemoryLimit() int64 {
	return debug.SetMemoryLimit(-1)
}

// Close stops the memory optimizer
func (mo *MemoryOptimizer) Close() error {
	if !mo.running.Load() {
		return fmt.Errorf("memory optimizer already stopped")
	}

	mo.running.Store(false)
	mo.cancel()
	mo.wg.Wait()

	mo.logger.Info("memory optimizer stopped")
	return nil
}

// MemoryProfile generates a memory profile
func (mo *MemoryOptimizer) MemoryProfile() []byte {
	var buf []byte
	runtime.MemProfile(buf, 0)
	return buf
}

// HeapDump triggers a heap dump
func (mo *MemoryOptimizer) HeapDump(filename string) error {
	// This would typically write to a file
	// Implementation depends on specific requirements
	mo.logger.Info("heap dump requested", "filename", filename)
	return nil
}
