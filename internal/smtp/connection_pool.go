package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionPool manages reusable SMTP connections with advanced pooling
type ConnectionPool struct {
	// Pool configuration
	minIdle       int
	maxIdle       int
	maxActive     int
	maxLifetime   time.Duration
	idleTimeout   time.Duration
	waitTimeout   time.Duration
	testOnBorrow  bool
	testOnReturn  bool
	testWhileIdle bool

	// Pool state
	idleConns   chan *PooledConnection
	activeConns int32
	totalConns  int32
	mu          sync.RWMutex
	closed      bool
	logger      *slog.Logger

	// Statistics
	stats PoolStatistics

	// Factory function
	factory ConnectionFactory

	// Maintenance
	maintCtx    context.Context
	maintCancel context.CancelFunc
	maintWg     sync.WaitGroup
}

// PooledConnection wraps a connection with pool metadata
type PooledConnection struct {
	conn        interface{}
	createdAt   time.Time
	lastUsedAt  time.Time
	usageCount  int64
	pool        *ConnectionPool
	healthy     bool
	maxLifetime time.Duration
}

// ConnectionFactory creates new connections
type ConnectionFactory func(ctx context.Context) (interface{}, error)

// ConnectionValidator validates connections
type ConnectionValidator func(interface{}) bool

// PoolStatistics tracks connection pool metrics
type PoolStatistics struct {
	Created         atomic.Int64
	Reused          atomic.Int64
	Destroyed       atomic.Int64
	WaitCount       atomic.Int64
	WaitDuration    atomic.Int64 // nanoseconds
	AcquireSuccess  atomic.Int64
	AcquireFailed   atomic.Int64
	IdleTimeouts    atomic.Int64
	LifetimeExpired atomic.Int64
	HealthCheckFail atomic.Int64
}

// PoolConfig defines connection pool configuration
type PoolConfig struct {
	MinIdle       int
	MaxIdle       int
	MaxActive     int
	MaxLifetime   time.Duration
	IdleTimeout   time.Duration
	WaitTimeout   time.Duration
	TestOnBorrow  bool
	TestOnReturn  bool
	TestWhileIdle bool
	Factory       ConnectionFactory
	Validator     ConnectionValidator
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config PoolConfig, logger *slog.Logger) (*ConnectionPool, error) {
	if config.MinIdle < 0 {
		return nil, fmt.Errorf("minIdle must be >= 0")
	}
	if config.MaxIdle < config.MinIdle {
		return nil, fmt.Errorf("maxIdle must be >= minIdle")
	}
	if config.MaxActive < config.MaxIdle {
		return nil, fmt.Errorf("maxActive must be >= maxIdle")
	}
	if config.Factory == nil {
		return nil, fmt.Errorf("factory function is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &ConnectionPool{
		minIdle:       config.MinIdle,
		maxIdle:       config.MaxIdle,
		maxActive:     config.MaxActive,
		maxLifetime:   config.MaxLifetime,
		idleTimeout:   config.IdleTimeout,
		waitTimeout:   config.WaitTimeout,
		testOnBorrow:  config.TestOnBorrow,
		testOnReturn:  config.TestOnReturn,
		testWhileIdle: config.TestWhileIdle,
		idleConns:     make(chan *PooledConnection, config.MaxIdle),
		factory:       config.Factory,
		logger:        logger,
		maintCtx:      ctx,
		maintCancel:   cancel,
	}

	// Pre-populate with minIdle connections
	if err := pool.warmUp(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to warm up pool: %w", err)
	}

	// Start maintenance goroutine
	pool.maintWg.Add(1)
	go pool.maintenanceLoop()

	return pool, nil
}

// warmUp pre-creates minIdle connections
func (p *ConnectionPool) warmUp(ctx context.Context) error {
	for i := 0; i < p.minIdle; i++ {
		conn, err := p.createConnection(ctx)
		if err != nil {
			p.logger.Warn("failed to create connection during warmup",
				"error", err,
				"created", i,
				"target", p.minIdle)
			return err
		}

		select {
		case p.idleConns <- conn:
		default:
			p.destroyConnection(conn)
			return fmt.Errorf("failed to add connection to pool")
		}
	}

	p.logger.Info("connection pool warmed up",
		"idle_connections", p.minIdle)
	return nil
}

// Acquire gets a connection from the pool
func (p *ConnectionPool) Acquire(ctx context.Context) (*PooledConnection, error) {
	start := time.Now()

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, fmt.Errorf("connection pool is closed")
	}
	p.mu.RUnlock()

	// Try to get idle connection first
	select {
	case conn := <-p.idleConns:
		// Validate connection if needed
		if p.testOnBorrow && !p.validateConnection(conn) {
			p.destroyConnection(conn)
			p.stats.HealthCheckFail.Add(1)
			return p.Acquire(ctx) // Retry
		}

		// Check if connection expired
		if p.maxLifetime > 0 && time.Since(conn.createdAt) > p.maxLifetime {
			p.destroyConnection(conn)
			p.stats.LifetimeExpired.Add(1)
			return p.Acquire(ctx) // Retry
		}

		conn.lastUsedAt = time.Now()
		conn.usageCount++
		atomic.AddInt32(&p.activeConns, 1)
		p.stats.Reused.Add(1)
		p.stats.AcquireSuccess.Add(1)

		return conn, nil

	default:
		// No idle connections available
	}

	// Try to create new connection if under limit
	if atomic.LoadInt32(&p.totalConns) < int32(p.maxActive) {
		conn, err := p.createConnection(ctx)
		if err == nil {
			atomic.AddInt32(&p.activeConns, 1)
			p.stats.AcquireSuccess.Add(1)
			return conn, nil
		}

		p.logger.Warn("failed to create new connection", "error", err)
		p.stats.AcquireFailed.Add(1)
	}

	// Wait for connection to become available
	p.stats.WaitCount.Add(1)
	waitCtx := ctx
	if p.waitTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, p.waitTimeout)
		defer cancel()
	}

	select {
	case conn := <-p.idleConns:
		duration := time.Since(start)
		p.stats.WaitDuration.Add(duration.Nanoseconds())

		// Validate after waiting
		if p.testOnBorrow && !p.validateConnection(conn) {
			p.destroyConnection(conn)
			p.stats.HealthCheckFail.Add(1)
			return p.Acquire(ctx) // Retry
		}

		conn.lastUsedAt = time.Now()
		conn.usageCount++
		atomic.AddInt32(&p.activeConns, 1)
		p.stats.Reused.Add(1)
		p.stats.AcquireSuccess.Add(1)

		return conn, nil

	case <-waitCtx.Done():
		duration := time.Since(start)
		p.stats.WaitDuration.Add(duration.Nanoseconds())
		p.stats.AcquireFailed.Add(1)

		if waitCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout waiting for connection after %v", duration)
		}
		return nil, waitCtx.Err()
	}
}

// Release returns a connection to the pool
func (p *ConnectionPool) Release(conn *PooledConnection) error {
	if conn == nil {
		return fmt.Errorf("cannot release nil connection")
	}

	atomic.AddInt32(&p.activeConns, -1)

	p.mu.RLock()
	closed := p.closed
	p.mu.RUnlock()

	if closed {
		p.destroyConnection(conn)
		return nil
	}

	// Validate connection before returning to pool
	if p.testOnReturn {
		if !p.validateConnection(conn) {
			p.destroyConnection(conn)
			p.stats.HealthCheckFail.Add(1)
			return nil
		}
	}

	// Check if connection expired
	if p.maxLifetime > 0 && time.Since(conn.createdAt) > p.maxLifetime {
		p.destroyConnection(conn)
		p.stats.LifetimeExpired.Add(1)
		return nil
	}

	conn.lastUsedAt = time.Now()

	// Try to return to pool
	select {
	case p.idleConns <- conn:
		return nil
	default:
		// Pool is full, destroy connection
		p.destroyConnection(conn)
		return nil
	}
}

// createConnection creates a new pooled connection
func (p *ConnectionPool) createConnection(ctx context.Context) (*PooledConnection, error) {
	conn, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}

	pooledConn := &PooledConnection{
		conn:        conn,
		createdAt:   time.Now(),
		lastUsedAt:  time.Now(),
		usageCount:  0,
		pool:        p,
		healthy:     true,
		maxLifetime: p.maxLifetime,
	}

	atomic.AddInt32(&p.totalConns, 1)
	p.stats.Created.Add(1)

	p.logger.Debug("created new connection",
		"total_connections", atomic.LoadInt32(&p.totalConns),
		"active_connections", atomic.LoadInt32(&p.activeConns))

	return pooledConn, nil
}

// destroyConnection destroys a pooled connection
func (p *ConnectionPool) destroyConnection(conn *PooledConnection) {
	if conn == nil {
		return
	}

	conn.healthy = false

	// Close the underlying connection if it has a Close method
	if closer, ok := conn.conn.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			p.logger.Warn("error closing connection", "error", err)
		}
	}

	atomic.AddInt32(&p.totalConns, -1)
	p.stats.Destroyed.Add(1)

	p.logger.Debug("destroyed connection",
		"total_connections", atomic.LoadInt32(&p.totalConns),
		"usage_count", conn.usageCount,
		"age", time.Since(conn.createdAt))
}

// validateConnection validates a connection
func (p *ConnectionPool) validateConnection(conn *PooledConnection) bool {
	if conn == nil || !conn.healthy {
		return false
	}

	// Check idle timeout
	if p.idleTimeout > 0 && time.Since(conn.lastUsedAt) > p.idleTimeout {
		p.stats.IdleTimeouts.Add(1)
		return false
	}

	// Check max lifetime
	if p.maxLifetime > 0 && time.Since(conn.createdAt) > p.maxLifetime {
		return false
	}

	return true
}

// maintenanceLoop performs periodic maintenance
func (p *ConnectionPool) maintenanceLoop() {
	defer p.maintWg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.maintCtx.Done():
			return

		case <-ticker.C:
			p.performMaintenance()
		}
	}
}

// performMaintenance performs pool maintenance
func (p *ConnectionPool) performMaintenance() {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()

	// Test idle connections
	if p.testWhileIdle {
		idleCount := len(p.idleConns)
		for i := 0; i < idleCount; i++ {
			select {
			case conn := <-p.idleConns:
				if p.validateConnection(conn) {
					// Return valid connection
					select {
					case p.idleConns <- conn:
					default:
						p.destroyConnection(conn)
					}
				} else {
					// Destroy invalid connection
					p.destroyConnection(conn)
					p.stats.HealthCheckFail.Add(1)
				}
			default:
				return
			}
		}
	}

	// Maintain minimum idle connections
	currentIdle := len(p.idleConns)
	currentTotal := int(atomic.LoadInt32(&p.totalConns))

	if currentIdle < p.minIdle && currentTotal < p.maxActive {
		needed := p.minIdle - currentIdle
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for i := 0; i < needed; i++ {
			if currentTotal+i >= p.maxActive {
				break
			}

			conn, err := p.createConnection(ctx)
			if err != nil {
				p.logger.Warn("failed to create connection during maintenance", "error", err)
				break
			}

			select {
			case p.idleConns <- conn:
			default:
				p.destroyConnection(conn)
				return
			}
		}
	}

	// Log statistics
	stats := p.GetStatistics()
	p.logger.Debug("connection pool maintenance",
		"idle", currentIdle,
		"active", atomic.LoadInt32(&p.activeConns),
		"total", currentTotal,
		"created", stats.Created.Load(),
		"reused", stats.Reused.Load(),
		"destroyed", stats.Destroyed.Load())
}

// GetStatistics returns pool statistics
func (p *ConnectionPool) GetStatistics() PoolStatistics {
	return PoolStatistics{
		Created:         atomic.Int64{},
		Reused:          atomic.Int64{},
		Destroyed:       atomic.Int64{},
		WaitCount:       atomic.Int64{},
		WaitDuration:    atomic.Int64{},
		AcquireSuccess:  atomic.Int64{},
		AcquireFailed:   atomic.Int64{},
		IdleTimeouts:    atomic.Int64{},
		LifetimeExpired: atomic.Int64{},
		HealthCheckFail: atomic.Int64{},
	}
}

// GetPoolInfo returns current pool information
func (p *ConnectionPool) GetPoolInfo() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := p.GetStatistics()
	avgWaitTime := time.Duration(0)
	if stats.WaitCount.Load() > 0 {
		avgWaitTime = time.Duration(stats.WaitDuration.Load() / stats.WaitCount.Load())
	}

	return map[string]interface{}{
		"idle_connections":   len(p.idleConns),
		"active_connections": atomic.LoadInt32(&p.activeConns),
		"total_connections":  atomic.LoadInt32(&p.totalConns),
		"min_idle":           p.minIdle,
		"max_idle":           p.maxIdle,
		"max_active":         p.maxActive,
		"closed":             p.closed,
		"statistics": map[string]interface{}{
			"created":           stats.Created.Load(),
			"reused":            stats.Reused.Load(),
			"destroyed":         stats.Destroyed.Load(),
			"wait_count":        stats.WaitCount.Load(),
			"avg_wait_time":     avgWaitTime.String(),
			"acquire_success":   stats.AcquireSuccess.Load(),
			"acquire_failed":    stats.AcquireFailed.Load(),
			"idle_timeouts":     stats.IdleTimeouts.Load(),
			"lifetime_expired":  stats.LifetimeExpired.Load(),
			"health_check_fail": stats.HealthCheckFail.Load(),
		},
	}
}

// Close closes the connection pool
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return fmt.Errorf("pool already closed")
	}
	p.closed = true
	p.mu.Unlock()

	// Stop maintenance
	p.maintCancel()
	p.maintWg.Wait()

	// Drain and close all idle connections
	close(p.idleConns)
	for conn := range p.idleConns {
		p.destroyConnection(conn)
	}

	p.logger.Info("connection pool closed",
		"total_created", p.stats.Created.Load(),
		"total_destroyed", p.stats.Destroyed.Load())

	return nil
}

// Conn returns the underlying connection
func (c *PooledConnection) Conn() interface{} {
	return c.conn
}

// Close returns the connection to the pool
func (c *PooledConnection) Close() error {
	return c.pool.Release(c)
}

// IsHealthy returns whether the connection is healthy
func (c *PooledConnection) IsHealthy() bool {
	return c.healthy
}

// Age returns the age of the connection
func (c *PooledConnection) Age() time.Duration {
	return time.Since(c.createdAt)
}

// IdleTime returns how long the connection has been idle
func (c *PooledConnection) IdleTime() time.Duration {
	return time.Since(c.lastUsedAt)
}

// UsageCount returns how many times the connection has been used
func (c *PooledConnection) UsageCount() int64 {
	return c.usageCount
}
