package smtp

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceLimits defines resource limits for the SMTP server
type ResourceLimits struct {
	MaxConnections            int           `toml:"max_connections" json:"max_connections"`                         // Maximum concurrent connections
	MaxConnectionsPerIP       int           `toml:"max_connections_per_ip" json:"max_connections_per_ip"`           // Maximum connections per IP
	MaxGoroutines             int           `toml:"max_goroutines" json:"max_goroutines"`                           // Maximum goroutines
	ConnectionTimeout         time.Duration `toml:"connection_timeout" json:"connection_timeout"`                   // Connection timeout
	SessionTimeout            time.Duration `toml:"session_timeout" json:"session_timeout"`                         // Session timeout
	IdleTimeout               time.Duration `toml:"idle_timeout" json:"idle_timeout"`                               // Idle connection timeout
	RateLimitWindow           time.Duration `toml:"rate_limit_window" json:"rate_limit_window"`                     // Rate limiting window
	MaxRequestsPerWindow      int           `toml:"max_requests_per_window" json:"max_requests_per_window"`         // Max requests per window
	MaxMemoryUsage            int64         `toml:"max_memory_usage" json:"max_memory_usage"`                       // Maximum memory usage in bytes
	GoroutinePoolSize         int           `toml:"goroutine_pool_size" json:"goroutine_pool_size"`                 // Worker goroutine pool size
	CircuitBreakerEnabled     bool          `toml:"circuit_breaker_enabled" json:"circuit_breaker_enabled"`         // Enable circuit breakers
	ResourceMonitoringEnabled bool          `toml:"resource_monitoring_enabled" json:"resource_monitoring_enabled"` // Enable resource monitoring
}

// DefaultResourceLimits returns sensible default resource limits
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxConnections:            1000,
		MaxConnectionsPerIP:       50,
		MaxGoroutines:             2000,
		ConnectionTimeout:         30 * time.Second,
		SessionTimeout:            5 * time.Minute,
		IdleTimeout:               2 * time.Minute,
		RateLimitWindow:           time.Minute,
		MaxRequestsPerWindow:      100,
		MaxMemoryUsage:            2 * 1024 * 1024 * 1024, // 2GB - more production appropriate
		GoroutinePoolSize:         100,
		CircuitBreakerEnabled:     true,
		ResourceMonitoringEnabled: true,
	}
}

// ConnectionInfo tracks information about active connections
type ConnectionInfo struct {
	RemoteAddr    string
	ConnectedAt   time.Time
	LastActivity  time.Time
	RequestCount  int32
	BytesSent     int64
	BytesReceived int64
	SessionID     string
}

// IPConnectionTracker tracks connections per IP address
type IPConnectionTracker struct {
	connections map[string]int32
	mutex       sync.RWMutex
	maxPerIP    int32
}

// NewIPConnectionTracker creates a new IP connection tracker
func NewIPConnectionTracker(maxPerIP int) *IPConnectionTracker {
	return &IPConnectionTracker{
		connections: make(map[string]int32),
		maxPerIP:    int32(maxPerIP),
	}
}

// CanConnect checks if an IP can establish a new connection
func (tracker *IPConnectionTracker) CanConnect(ip string) bool {
	tracker.mutex.RLock()
	count := tracker.connections[ip]
	tracker.mutex.RUnlock()

	return count < tracker.maxPerIP
}

// AddConnection adds a connection for an IP
func (tracker *IPConnectionTracker) AddConnection(ip string) bool {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if tracker.connections[ip] >= tracker.maxPerIP {
		return false
	}

	tracker.connections[ip]++
	return true
}

// RemoveConnection removes a connection for an IP
func (tracker *IPConnectionTracker) RemoveConnection(ip string) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if tracker.connections[ip] > 0 {
		tracker.connections[ip]--
		if tracker.connections[ip] == 0 {
			delete(tracker.connections, ip)
		}
	}
}

// GetConnectionCount returns the connection count for an IP
func (tracker *IPConnectionTracker) GetConnectionCount(ip string) int {
	tracker.mutex.RLock()
	defer tracker.mutex.RUnlock()
	return int(tracker.connections[ip])
}

// GetTotalConnections returns total connections across all IPs
func (tracker *IPConnectionTracker) GetTotalConnections() int {
	tracker.mutex.RLock()
	defer tracker.mutex.RUnlock()

	total := int32(0)
	for _, count := range tracker.connections {
		total += count
	}
	return int(total)
}

// ResourceRateLimiter implements token bucket rate limiting
type ResourceRateLimiter struct {
	tokens         int32
	maxTokens      int32
	refillRate     int32 // tokens per second
	lastRefill     int64 // unix timestamp
	mutex          sync.Mutex
	windowStart    time.Time
	windowCount    int32
	windowLimit    int32
	windowDuration time.Duration
}

// NewResourceRateLimiter creates a new rate limiter
func NewResourceRateLimiter(maxTokens, refillRate int, windowLimit int, windowDuration time.Duration) *ResourceRateLimiter {
	now := time.Now()
	return &ResourceRateLimiter{
		tokens:         int32(maxTokens),
		maxTokens:      int32(maxTokens),
		refillRate:     int32(refillRate),
		lastRefill:     now.Unix(),
		windowStart:    now,
		windowLimit:    int32(windowLimit),
		windowDuration: windowDuration,
	}
}

// Allow checks if a request is allowed under rate limiting
func (rl *ResourceRateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Check window-based rate limiting
	if now.Sub(rl.windowStart) >= rl.windowDuration {
		rl.windowStart = now
		rl.windowCount = 0
	}

	if rl.windowCount >= rl.windowLimit {
		return false
	}

	// Refill tokens based on time elapsed
	elapsed := now.Unix() - rl.lastRefill
	if elapsed > 0 {
		tokensToAdd := int32(elapsed) * rl.refillRate
		rl.tokens = minInt32(rl.maxTokens, rl.tokens+tokensToAdd)
		rl.lastRefill = now.Unix()
	}

	// Check if we have tokens available
	if rl.tokens > 0 {
		rl.tokens--
		rl.windowCount++
		return true
	}

	return false
}

// GetTokens returns current token count
func (rl *ResourceRateLimiter) GetTokens() int {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	return int(rl.tokens)
}

// GoroutinePool manages a pool of worker goroutines
type GoroutinePool struct {
	workers    chan struct{}
	tasks      chan func()
	wg         sync.WaitGroup
	closed     int32
	maxWorkers int
	logger     *slog.Logger
}

// NewGoroutinePool creates a new goroutine pool
func NewGoroutinePool(maxWorkers int, logger *slog.Logger) *GoroutinePool {
	pool := &GoroutinePool{
		workers:    make(chan struct{}, maxWorkers),
		tasks:      make(chan func(), maxWorkers*2), // Buffer for pending tasks
		maxWorkers: maxWorkers,
		logger:     logger,
	}

	// Pre-allocate worker tokens
	for i := 0; i < maxWorkers; i++ {
		pool.workers <- struct{}{}
	}

	// Start worker goroutines
	for i := 0; i < maxWorkers; i++ {
		pool.wg.Add(1)
		go pool.worker()
	}

	pool.logger.Info("Goroutine pool initialized",
		"max_workers", maxWorkers,
		"buffer_size", maxWorkers*2,
	)

	return pool
}

// worker is the main worker goroutine function
func (pool *GoroutinePool) worker() {
	defer pool.wg.Done()

	for task := range pool.tasks {
		if atomic.LoadInt32(&pool.closed) == 1 {
			return
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					pool.logger.Error("Worker panic recovered",
						"panic", r,
					)
				}
			}()

			task()
		}()
	}
}

// Submit submits a task to the pool
func (pool *GoroutinePool) Submit(task func()) bool {
	if atomic.LoadInt32(&pool.closed) == 1 {
		return false
	}

	select {
	case <-pool.workers:
		// Worker available, submit task
		select {
		case pool.tasks <- func() {
			defer func() {
				pool.workers <- struct{}{} // Return worker token
			}()
			task()
		}:
			return true
		default:
			// Task queue full, return worker token
			pool.workers <- struct{}{}
			return false
		}
	default:
		// No workers available
		return false
	}
}

// Close closes the goroutine pool
func (pool *GoroutinePool) Close() {
	if atomic.CompareAndSwapInt32(&pool.closed, 0, 1) {
		close(pool.tasks)
		pool.wg.Wait()
		pool.logger.Info("Goroutine pool closed")
	}
}

// GetStats returns pool statistics
func (pool *GoroutinePool) GetStats() map[string]interface{} {
	availableWorkers := len(pool.workers)
	pendingTasks := len(pool.tasks)

	return map[string]interface{}{
		"max_workers":       pool.maxWorkers,
		"available_workers": availableWorkers,
		"active_workers":    pool.maxWorkers - availableWorkers,
		"pending_tasks":     pendingTasks,
		"utilization":       float64(pool.maxWorkers-availableWorkers) / float64(pool.maxWorkers),
	}
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for external services
type CircuitBreaker struct {
	name            string
	maxFailures     int32
	timeout         time.Duration
	failureCount    int32
	lastFailureTime time.Time
	state           CircuitBreakerState
	mutex           sync.RWMutex
	logger          *slog.Logger
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, maxFailures int, timeout time.Duration, logger *slog.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		name:        name,
		maxFailures: int32(maxFailures),
		timeout:     timeout,
		state:       CircuitBreakerClosed,
		logger:      logger,
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.AllowRequest() {
		return fmt.Errorf("circuit breaker %s is open", cb.name)
	}

	err := fn()

	if err != nil {
		cb.RecordFailure()
		return err
	}

	cb.RecordSuccess()
	return nil
}

// AllowRequest checks if a request should be allowed
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		if now.Sub(cb.lastFailureTime) >= cb.timeout {
			cb.state = CircuitBreakerHalfOpen
			cb.logger.Info("Circuit breaker transitioning to half-open",
				"name", cb.name,
			)
			return true
		}
		return false
	case CircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if cb.state == CircuitBreakerHalfOpen {
		cb.state = CircuitBreakerClosed
		cb.failureCount = 0
		cb.logger.Info("Circuit breaker closed after successful request",
			"name", cb.name,
		)
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount++
	cb.lastFailureTime = time.Now()

	if cb.failureCount >= cb.maxFailures {
		cb.state = CircuitBreakerOpen
		cb.logger.Warn("Circuit breaker opened due to failures",
			"name", cb.name,
			"failure_count", cb.failureCount,
		)
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	return map[string]interface{}{
		"name":          cb.name,
		"state":         cb.state,
		"failure_count": cb.failureCount,
		"max_failures":  cb.maxFailures,
		"timeout":       cb.timeout,
	}
}

// ResourceManager manages all server resources and limits
type ResourceManager struct {
	limits               *ResourceLimits
	connections          map[string]*ConnectionInfo
	connectionsMutex     sync.RWMutex
	ipTracker            *IPConnectionTracker
	globalRateLimiter    *ResourceRateLimiter
	ipRateLimiters       map[string]*ResourceRateLimiter
	rateLimitersMutex    sync.RWMutex
	goroutinePool        *GoroutinePool
	circuitBreakers      map[string]*CircuitBreaker
	circuitBreakersMutex sync.RWMutex
	memoryManager        *MemoryManager
	activeConnections    int32
	totalRequests        int64
	rejectedRequests     int64
	logger               *slog.Logger
	shutdownChan         chan struct{}
	monitoringEnabled    bool
}

// NewResourceManager creates a new resource manager
func NewResourceManager(limits *ResourceLimits, logger *slog.Logger) *ResourceManager {
	if limits == nil {
		limits = DefaultResourceLimits()
	}

	rm := &ResourceManager{
		limits:            limits,
		connections:       make(map[string]*ConnectionInfo),
		ipTracker:         NewIPConnectionTracker(limits.MaxConnectionsPerIP),
		globalRateLimiter: NewResourceRateLimiter(limits.MaxRequestsPerWindow, limits.MaxRequestsPerWindow/60, limits.MaxRequestsPerWindow, limits.RateLimitWindow),
		ipRateLimiters:    make(map[string]*ResourceRateLimiter),
		circuitBreakers:   make(map[string]*CircuitBreaker),
		logger:            logger,
		shutdownChan:      make(chan struct{}),
		monitoringEnabled: limits.ResourceMonitoringEnabled,
	}

	// Initialize memory manager with resource limits
	memoryConfig := &MemoryConfig{
		MaxMemoryUsage:             limits.MaxMemoryUsage,
		MemoryWarningThreshold:     0.75, // 75% warning
		MemoryCriticalThreshold:    0.90, // 90% critical
		GCThreshold:                0.80, // 80% force GC
		MonitoringInterval:         5 * time.Second,
		PerConnectionMemoryLimit:   limits.MaxMemoryUsage / int64(limits.MaxConnections), // Distribute memory across connections
		MaxGoroutines:              limits.MaxGoroutines,
		GoroutineLeakDetection:     true,
		MemoryExhaustionProtection: true,
	}
	rm.memoryManager = NewMemoryManager(memoryConfig, logger)

	// Initialize goroutine pool
	rm.goroutinePool = NewGoroutinePool(limits.GoroutinePoolSize, logger)

	// Start monitoring if enabled
	if rm.monitoringEnabled {
		go rm.startResourceMonitoring()
	}

	logger.Info("Resource manager initialized",
		"max_connections", limits.MaxConnections,
		"max_connections_per_ip", limits.MaxConnectionsPerIP,
		"goroutine_pool_size", limits.GoroutinePoolSize,
		"max_memory_usage", limits.MaxMemoryUsage,
		"monitoring_enabled", rm.monitoringEnabled,
	)

	return rm
}

// CanAcceptConnection checks if a new connection can be accepted
func (rm *ResourceManager) CanAcceptConnection(remoteAddr string) bool {
	fmt.Printf("DEBUG: CanAcceptConnection called for %s\n", remoteAddr)

	// Check memory limits first (most critical)
	if rm.memoryManager != nil {
		fmt.Printf("DEBUG: Checking memory limits\n")
		if err := rm.memoryManager.CheckMemoryLimit(); err != nil {
			fmt.Printf("DEBUG: Memory limit check failed: %v\n", err)
			atomic.AddInt64(&rm.rejectedRequests, 1)
			rm.logger.Warn("Connection rejected: memory limit exceeded",
				"remote_addr", remoteAddr,
				"error", err,
			)
			return false
		}
		fmt.Printf("DEBUG: Memory limit check passed\n")

		// Check goroutine limits
		if err := rm.memoryManager.CheckGoroutineLimit(); err != nil {
			fmt.Printf("DEBUG: Goroutine limit check failed: %v\n", err)
			atomic.AddInt64(&rm.rejectedRequests, 1)
			rm.logger.Warn("Connection rejected: goroutine limit exceeded",
				"remote_addr", remoteAddr,
				"error", err,
			)
			return false
		}
		fmt.Printf("DEBUG: Goroutine limit check passed\n")
	} else {
		fmt.Printf("DEBUG: Memory manager is nil, skipping memory checks\n")
	}

	// Check global connection limit
	fmt.Printf("DEBUG: Checking global connection limit: %d/%d\n", atomic.LoadInt32(&rm.activeConnections), rm.limits.MaxConnections)
	if atomic.LoadInt32(&rm.activeConnections) >= int32(rm.limits.MaxConnections) {
		fmt.Printf("DEBUG: Global connection limit reached\n")
		atomic.AddInt64(&rm.rejectedRequests, 1)
		rm.logger.Warn("Connection rejected: global limit reached",
			"active_connections", rm.activeConnections,
			"max_connections", rm.limits.MaxConnections,
			"remote_addr", remoteAddr,
		)
		return false
	}
	fmt.Printf("DEBUG: Global connection limit check passed\n")

	// Extract IP from address
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	// Check per-IP connection limit
	fmt.Printf("DEBUG: Checking per-IP connection limit for %s\n", host)
	if !rm.ipTracker.CanConnect(host) {
		fmt.Printf("DEBUG: Per-IP connection limit reached for %s\n", host)
		atomic.AddInt64(&rm.rejectedRequests, 1)
		rm.logger.Warn("Connection rejected: IP limit reached",
			"ip", host,
			"ip_connections", rm.ipTracker.GetConnectionCount(host),
			"max_per_ip", rm.limits.MaxConnectionsPerIP,
		)
		return false
	}
	fmt.Printf("DEBUG: Per-IP connection limit check passed\n")

	// Check global rate limiting
	fmt.Printf("DEBUG: Checking global rate limiting\n")
	if !rm.globalRateLimiter.Allow() {
		fmt.Printf("DEBUG: Global rate limit exceeded\n")
		atomic.AddInt64(&rm.rejectedRequests, 1)
		rm.logger.Warn("Connection rejected: global rate limit exceeded",
			"remote_addr", remoteAddr,
		)
		return false
	}
	fmt.Printf("DEBUG: Global rate limit check passed\n")

	// Check per-IP rate limiting
	fmt.Printf("DEBUG: Checking per-IP rate limiting\n")
	ipRateLimiter := rm.getOrCreateIPRateLimiter(host)
	if !ipRateLimiter.Allow() {
		fmt.Printf("DEBUG: Per-IP rate limit exceeded\n")
		atomic.AddInt64(&rm.rejectedRequests, 1)
		rm.logger.Warn("Connection rejected: IP rate limit exceeded",
			"ip", host,
		)
		return false
	}
	fmt.Printf("DEBUG: Per-IP rate limit check passed\n")

	fmt.Printf("DEBUG: All connection checks passed, accepting connection\n")
	return true
}

// AcceptConnection registers a new connection with atomic operations
func (rm *ResourceManager) AcceptConnection(conn net.Conn) string {
	remoteAddr := conn.RemoteAddr().String()
	sessionID := fmt.Sprintf("session-%d-%s", time.Now().UnixNano(), remoteAddr)

	// Extract IP from address
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	// Check memory limits for new connection
	if rm.memoryManager != nil {
		fmt.Printf("DEBUG: Checking connection memory limit for session %s\n", sessionID)
		// Estimate memory usage for new connection (connection info + buffers)
		estimatedMemory := int64(1024 * 1024) // 1MB estimate per connection
		if err := rm.memoryManager.CheckConnectionMemoryLimit(sessionID, estimatedMemory); err != nil {
			fmt.Printf("DEBUG: Connection memory limit check failed: %v\n", err)
			rm.logger.Warn("Connection rejected due to memory limit",
				"remote_addr", remoteAddr,
				"session_id", sessionID,
				"error", err,
			)
			return ""
		}
		fmt.Printf("DEBUG: Connection memory limit check passed\n")
	}

	// Atomic operation: Add IP connection tracking first
	if !rm.ipTracker.AddConnection(host) {
		// IP limit exceeded, reject connection
		rm.logger.Warn("Connection rejected due to IP limit",
			"remote_addr", remoteAddr,
			"host", host,
		)
		return ""
	}

	// Create connection info
	connInfo := &ConnectionInfo{
		RemoteAddr:   remoteAddr,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		SessionID:    sessionID,
	}

	// Atomic operation: Register connection and update counters
	rm.connectionsMutex.Lock()
	rm.connections[sessionID] = connInfo
	rm.connectionsMutex.Unlock()

	atomic.AddInt32(&rm.activeConnections, 1)
	atomic.AddInt64(&rm.totalRequests, 1)

	// Set connection timeouts
	if err := conn.SetDeadline(time.Now().Add(rm.limits.ConnectionTimeout)); err != nil {
		rm.logger.Error("Failed to set connection deadline",
			"session_id", sessionID,
			"remote_addr", remoteAddr,
			"error", err,
		)
		// Cleanup on error
		rm.ReleaseConnection(sessionID)
		return ""
	}

	rm.logger.Info("Connection accepted",
		"session_id", sessionID,
		"remote_addr", remoteAddr,
		"active_connections", atomic.LoadInt32(&rm.activeConnections),
	)

	return sessionID
}

// ReleaseConnection releases a connection and its resources with atomic cleanup
func (rm *ResourceManager) ReleaseConnection(sessionID string) {
	if sessionID == "" {
		return // Nothing to release
	}

	rm.connectionsMutex.Lock()
	connInfo, exists := rm.connections[sessionID]
	if exists {
		delete(rm.connections, sessionID)
	}
	rm.connectionsMutex.Unlock()

	if exists {
		// Extract IP from address
		host, _, err := net.SplitHostPort(connInfo.RemoteAddr)
		if err != nil {
			host = connInfo.RemoteAddr
		}

		// Atomic operation: Remove IP connection tracking
		rm.ipTracker.RemoveConnection(host)

		// Atomic operation: Decrement connection counter
		atomic.AddInt32(&rm.activeConnections, -1)

		duration := time.Since(connInfo.ConnectedAt)

		rm.logger.Info("Connection released",
			"session_id", sessionID,
			"remote_addr", connInfo.RemoteAddr,
			"duration", duration,
			"requests", connInfo.RequestCount,
			"bytes_sent", connInfo.BytesSent,
			"bytes_received", connInfo.BytesReceived,
			"active_connections", atomic.LoadInt32(&rm.activeConnections),
		)
	} else {
		rm.logger.Warn("Attempted to release non-existent connection",
			"session_id", sessionID,
		)
	}
}

// UpdateConnectionActivity updates the last activity time for a connection
func (rm *ResourceManager) UpdateConnectionActivity(sessionID string) {
	rm.connectionsMutex.RLock()
	connInfo, exists := rm.connections[sessionID]
	rm.connectionsMutex.RUnlock()

	if exists {
		connInfo.LastActivity = time.Now()
		atomic.AddInt32(&connInfo.RequestCount, 1)
	}
}

// SubmitTask submits a task to the goroutine pool
func (rm *ResourceManager) SubmitTask(task func()) bool {
	return rm.goroutinePool.Submit(task)
}

// GetCircuitBreaker gets or creates a circuit breaker for a service
func (rm *ResourceManager) GetCircuitBreaker(serviceName string) *CircuitBreaker {
	rm.circuitBreakersMutex.RLock()
	cb, exists := rm.circuitBreakers[serviceName]
	rm.circuitBreakersMutex.RUnlock()

	if !exists {
		rm.circuitBreakersMutex.Lock()
		// Double-check pattern
		if cb, exists = rm.circuitBreakers[serviceName]; !exists {
			cb = NewCircuitBreaker(serviceName, 5, 30*time.Second, rm.logger)
			rm.circuitBreakers[serviceName] = cb
		}
		rm.circuitBreakersMutex.Unlock()
	}

	return cb
}

// getOrCreateIPRateLimiter gets or creates a rate limiter for an IP
func (rm *ResourceManager) getOrCreateIPRateLimiter(ip string) *ResourceRateLimiter {
	rm.rateLimitersMutex.RLock()
	limiter, exists := rm.ipRateLimiters[ip]
	rm.rateLimitersMutex.RUnlock()

	if !exists {
		rm.rateLimitersMutex.Lock()
		// Double-check pattern
		if limiter, exists = rm.ipRateLimiters[ip]; !exists {
			limiter = NewResourceRateLimiter(
				rm.limits.MaxRequestsPerWindow/2,   // Per-IP limit is 1/2 of global (more permissive)
				rm.limits.MaxRequestsPerWindow/60,  // Refill rate (faster refill)
				rm.limits.MaxRequestsPerWindow/2,
				rm.limits.RateLimitWindow,
			)
			rm.ipRateLimiters[ip] = limiter
		}
		rm.rateLimitersMutex.Unlock()
	}

	return limiter
}

// startResourceMonitoring starts the resource monitoring goroutine
func (rm *ResourceManager) startResourceMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.logResourceStats()
			rm.cleanupIdleConnections()
			rm.cleanupOldRateLimiters()
		case <-rm.shutdownChan:
			return
		}
	}
}

// logResourceStats logs current resource statistics
func (rm *ResourceManager) logResourceStats() {
	activeConnections := atomic.LoadInt32(&rm.activeConnections)
	totalRequests := atomic.LoadInt64(&rm.totalRequests)
	rejectedRequests := atomic.LoadInt64(&rm.rejectedRequests)

	poolStats := rm.goroutinePool.GetStats()

	rm.logger.Info("Resource statistics",
		"active_connections", activeConnections,
		"total_requests", totalRequests,
		"rejected_requests", rejectedRequests,
		"rejection_rate", float64(rejectedRequests)/float64(totalRequests)*100,
		"pool_utilization", poolStats["utilization"],
		"available_workers", poolStats["available_workers"],
		"pending_tasks", poolStats["pending_tasks"],
	)
}

// cleanupIdleConnections closes idle connections
func (rm *ResourceManager) cleanupIdleConnections() {
	rm.connectionsMutex.RLock()
	var idleConnections []string
	cutoff := time.Now().Add(-rm.limits.IdleTimeout)

	for sessionID, connInfo := range rm.connections {
		if connInfo.LastActivity.Before(cutoff) {
			idleConnections = append(idleConnections, sessionID)
		}
	}
	rm.connectionsMutex.RUnlock()

	if len(idleConnections) > 0 {
		rm.logger.Info("Cleaning up idle connections",
			"count", len(idleConnections),
		)

		for _, sessionID := range idleConnections {
			rm.ReleaseConnection(sessionID)
		}
	}
}

// cleanupOldRateLimiters removes unused rate limiters
func (rm *ResourceManager) cleanupOldRateLimiters() {
	rm.rateLimitersMutex.Lock()
	defer rm.rateLimitersMutex.Unlock()

	// Simple cleanup: remove rate limiters for IPs with no active connections
	for ip := range rm.ipRateLimiters {
		if rm.ipTracker.GetConnectionCount(ip) == 0 {
			delete(rm.ipRateLimiters, ip)
		}
	}
}

// GetSessionTimeout returns the configured session timeout
func (rm *ResourceManager) GetSessionTimeout() time.Duration {
	return rm.limits.SessionTimeout
}

// GetConnectionTimeout returns the configured connection timeout
func (rm *ResourceManager) GetConnectionTimeout() time.Duration {
	return rm.limits.ConnectionTimeout
}

// GetMemoryManager returns the memory manager instance
func (rm *ResourceManager) GetMemoryManager() *MemoryManager {
	return rm.memoryManager
}

// SetMemoryManager sets the memory manager for the resource manager
func (rm *ResourceManager) SetMemoryManager(memoryManager *MemoryManager) {
	rm.memoryManager = memoryManager
}

// GetStats returns comprehensive resource manager statistics
func (rm *ResourceManager) GetStats() map[string]interface{} {
	activeConnections := atomic.LoadInt32(&rm.activeConnections)
	totalRequests := atomic.LoadInt64(&rm.totalRequests)
	rejectedRequests := atomic.LoadInt64(&rm.rejectedRequests)

	poolStats := rm.goroutinePool.GetStats()

	// Get circuit breaker stats
	rm.circuitBreakersMutex.RLock()
	circuitBreakerStats := make(map[string]interface{})
	for name, cb := range rm.circuitBreakers {
		circuitBreakerStats[name] = cb.GetStats()
	}
	rm.circuitBreakersMutex.RUnlock()

	// Get memory statistics
	var memoryStats map[string]interface{}
	if rm.memoryManager != nil {
		memStats := rm.memoryManager.GetMemoryStats()
		memoryStats = map[string]interface{}{
			"current_usage":   memStats.CurrentMemoryUsage,
			"peak_usage":      memStats.PeakMemoryUsage,
			"utilization":     memStats.MemoryUtilization,
			"goroutine_count": memStats.GoroutineCount,
			"peak_goroutines": memStats.PeakGoroutineCount,
			"gc_collections":  memStats.GCCollections,
			"forced_gc":       memStats.ForcedGCCollections,
			"memory_warnings": memStats.MemoryWarnings,
			"critical_alerts": memStats.MemoryCriticalAlerts,
			"last_gc":         memStats.LastGC,
			"last_update":     memStats.LastUpdate,
		}
	}

	return map[string]interface{}{
		"active_connections":     activeConnections,
		"max_connections":        rm.limits.MaxConnections,
		"total_requests":         totalRequests,
		"rejected_requests":      rejectedRequests,
		"rejection_rate":         float64(rejectedRequests) / float64(maxInt64(1, totalRequests)) * 100,
		"connection_utilization": float64(activeConnections) / float64(rm.limits.MaxConnections) * 100,
		"goroutine_pool":         poolStats,
		"circuit_breakers":       circuitBreakerStats,
		"memory_manager":         memoryStats,
		"rate_limiters": map[string]interface{}{
			"global_tokens": rm.globalRateLimiter.GetTokens(),
			"ip_limiters":   len(rm.ipRateLimiters),
		},
	}
}

// Close shuts down the resource manager
func (rm *ResourceManager) Close() {
	close(rm.shutdownChan)
	rm.goroutinePool.Close()

	// Close memory manager
	if rm.memoryManager != nil {
		rm.memoryManager.Close()
	}

	rm.logger.Info("Resource manager shut down")
}

// Helper functions
func minInt32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
