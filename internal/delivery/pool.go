package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ConnectionPool manages a pool of SMTP connections for efficient delivery
type ConnectionPool struct {
	config  *Config
	logger  *slog.Logger
	pools   map[string]*HostPool // Key: host:port
	mu      sync.RWMutex
	metrics *PoolMetrics
}

// HostPool manages connections to a specific host
type HostPool struct {
	host        string
	port        int
	connections []*PooledConnection
	mu          sync.Mutex
	maxConns    int
	activeConns int
	totalConns  int64
	errors      int64
	lastError   error
	lastUsed    time.Time
}

// PooledConnection wraps a network connection with metadata
type PooledConnection struct {
	conn       net.Conn
	host       string
	port       int
	createdAt  time.Time
	lastUsed   time.Time
	usageCount int64
	healthy    bool
	inUse      bool
}

// PoolMetrics tracks connection pool statistics
type PoolMetrics struct {
	mu                 sync.RWMutex
	TotalConnections   int64         `json:"total_connections"`
	ActiveConnections  int64         `json:"active_connections"`
	IdleConnections    int64         `json:"idle_connections"`
	PooledConnections  int64         `json:"pooled_connections"`
	CreatedConnections int64         `json:"created_connections"`
	ReusedConnections  int64         `json:"reused_connections"`
	ClosedConnections  int64         `json:"closed_connections"`
	FailedConnections  int64         `json:"failed_connections"`
	ConnectionHits     int64         `json:"connection_hits"`
	ConnectionMisses   int64         `json:"connection_misses"`
	AverageConnectTime time.Duration `json:"average_connect_time"`
	AverageLifetime    time.Duration `json:"average_lifetime"`
	PoolUtilization    float64       `json:"pool_utilization"`
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config *Config) *ConnectionPool {
	return &ConnectionPool{
		config:  config,
		logger:  slog.Default().With("component", "connection-pool"),
		pools:   make(map[string]*HostPool),
		metrics: &PoolMetrics{},
	}
}

// GetConnection retrieves a connection from the pool or creates a new one
func (cp *ConnectionPool) GetConnection(ctx context.Context, host string, port int) (net.Conn, error) {
	key := fmt.Sprintf("%s:%d", host, port)

	cp.mu.RLock()
	pool, exists := cp.pools[key]
	cp.mu.RUnlock()

	if !exists {
		cp.mu.Lock()
		// Double-check after acquiring write lock
		if pool, exists = cp.pools[key]; !exists {
			pool = &HostPool{
				host:        host,
				port:        port,
				connections: make([]*PooledConnection, 0),
				maxConns:    cp.config.MaxConnectionsPerHost,
			}
			cp.pools[key] = pool
		}
		cp.mu.Unlock()
	}

	// Try to get an existing connection
	if conn := cp.getPooledConnection(pool); conn != nil {
		cp.metrics.mu.Lock()
		cp.metrics.ConnectionHits++
		cp.metrics.ReusedConnections++
		cp.metrics.mu.Unlock()

		cp.logger.Debug("Reusing pooled connection",
			"host", host,
			"port", port,
			"usage_count", conn.usageCount)

		return conn.conn, nil
	}

	// Create new connection
	cp.metrics.mu.Lock()
	cp.metrics.ConnectionMisses++
	cp.metrics.mu.Unlock()

	return cp.createConnection(ctx, pool)
}

// getPooledConnection attempts to get a healthy connection from the pool
func (cp *ConnectionPool) getPooledConnection(pool *HostPool) *PooledConnection {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	now := time.Now()

	// Find a healthy, unused connection
	for i, conn := range pool.connections {
		if !conn.inUse && conn.healthy {
			// Check if connection is too old
			if now.Sub(conn.lastUsed) > cp.config.IdleTimeout {
				cp.logger.Debug("Connection expired, removing from pool",
					"host", conn.host,
					"port", conn.port,
					"age", now.Sub(conn.lastUsed))

				// Close expired connection
				conn.conn.Close()

				// Remove from pool
				pool.connections = append(pool.connections[:i], pool.connections[i+1:]...)

				cp.metrics.mu.Lock()
				cp.metrics.ClosedConnections++
				cp.metrics.IdleConnections--
				cp.metrics.mu.Unlock()

				continue
			}

			// Mark as in use
			conn.inUse = true
			conn.lastUsed = now
			conn.usageCount++
			pool.lastUsed = now

			cp.metrics.mu.Lock()
			cp.metrics.ActiveConnections++
			cp.metrics.IdleConnections--
			cp.metrics.mu.Unlock()

			return conn
		}
	}

	return nil
}

// createConnection creates a new connection to the host
func (cp *ConnectionPool) createConnection(ctx context.Context, pool *HostPool) (net.Conn, error) {
	pool.mu.Lock()
	// Check if we've reached the maximum connections for this host
	if pool.activeConns >= pool.maxConns {
		pool.mu.Unlock()
		return nil, fmt.Errorf("maximum connections (%d) reached for %s:%d",
			pool.maxConns, pool.host, pool.port)
	}
	pool.activeConns++
	pool.mu.Unlock()

	startTime := time.Now()

	cp.logger.Debug("Creating new connection",
		"host", pool.host,
		"port", pool.port,
		"active", pool.activeConns)

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: cp.config.ConnectionTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", pool.host, pool.port))
	if err != nil {
		pool.mu.Lock()
		pool.activeConns--
		pool.errors++
		pool.lastError = err
		pool.mu.Unlock()

		cp.metrics.mu.Lock()
		cp.metrics.FailedConnections++
		cp.metrics.mu.Unlock()

		return nil, fmt.Errorf("failed to connect to %s:%d: %w", pool.host, pool.port, err)
	}

	connectTime := time.Since(startTime)

	// Update metrics
	cp.metrics.mu.Lock()
	cp.metrics.CreatedConnections++
	cp.metrics.TotalConnections++
	cp.metrics.ActiveConnections++

	// Update average connect time
	if cp.metrics.CreatedConnections == 1 {
		cp.metrics.AverageConnectTime = connectTime
	} else {
		cp.metrics.AverageConnectTime = (cp.metrics.AverageConnectTime + connectTime) / 2
	}
	cp.metrics.mu.Unlock()

	pool.mu.Lock()
	pool.totalConns++
	pool.lastUsed = time.Now()
	pool.mu.Unlock()

	cp.logger.Info("Created new connection",
		"host", pool.host,
		"port", pool.port,
		"connect_time", connectTime,
		"total_connections", pool.totalConns)

	return conn, nil
}

// ReturnConnection returns a connection to the pool
func (cp *ConnectionPool) ReturnConnection(host string, port int, conn net.Conn) {
	key := fmt.Sprintf("%s:%d", host, port)

	cp.mu.RLock()
	pool, exists := cp.pools[key]
	cp.mu.RUnlock()

	if !exists {
		// Pool doesn't exist, just close the connection
		conn.Close()
		cp.metrics.mu.Lock()
		cp.metrics.ClosedConnections++
		cp.metrics.ActiveConnections--
		cp.metrics.mu.Unlock()
		return
	}

	// Check if this is a pooled connection
	pooledConn := cp.findPooledConnection(pool, conn)
	if pooledConn == nil {
		// Not a pooled connection, create a new pooled connection
		pooledConn = &PooledConnection{
			conn:       conn,
			host:       host,
			port:       port,
			createdAt:  time.Now(),
			lastUsed:   time.Now(),
			usageCount: 1,
			healthy:    true,
			inUse:      false,
		}
	} else {
		// Mark as not in use
		pooledConn.inUse = false
	}

	// Check connection health
	if !cp.isConnectionHealthy(pooledConn) {
		cp.logger.Debug("Connection unhealthy, closing",
			"host", host,
			"port", port)

		conn.Close()
		cp.removePooledConnection(pool, pooledConn)

		cp.metrics.mu.Lock()
		cp.metrics.ClosedConnections++
		cp.metrics.ActiveConnections--
		cp.metrics.mu.Unlock()

		pool.mu.Lock()
		pool.activeConns--
		pool.mu.Unlock()

		return
	}

	// Return to pool
	pool.mu.Lock()

	// Check if pool is full
	if len(pool.connections) >= pool.maxConns {
		// Pool is full, close this connection
		conn.Close()
		pool.activeConns--

		cp.metrics.mu.Lock()
		cp.metrics.ClosedConnections++
		cp.metrics.ActiveConnections--
		cp.metrics.mu.Unlock()

		pool.mu.Unlock()
		return
	}

	// Add to pool if not already there
	found := false
	for _, existing := range pool.connections {
		if existing == pooledConn {
			found = true
			break
		}
	}

	if !found {
		pool.connections = append(pool.connections, pooledConn)
	}

	pool.activeConns--
	pool.mu.Unlock()

	cp.metrics.mu.Lock()
	cp.metrics.ActiveConnections--
	cp.metrics.IdleConnections++
	cp.metrics.mu.Unlock()

	cp.logger.Debug("Returned connection to pool",
		"host", host,
		"port", port,
		"pool_size", len(pool.connections))
}

// findPooledConnection finds a pooled connection by its network connection
func (cp *ConnectionPool) findPooledConnection(pool *HostPool, conn net.Conn) *PooledConnection {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, pooledConn := range pool.connections {
		if pooledConn.conn == conn {
			return pooledConn
		}
	}

	return nil
}

// removePooledConnection removes a connection from the pool
func (cp *ConnectionPool) removePooledConnection(pool *HostPool, target *PooledConnection) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for i, conn := range pool.connections {
		if conn == target {
			pool.connections = append(pool.connections[:i], pool.connections[i+1:]...)
			break
		}
	}
}

// isConnectionHealthy checks if a connection is still healthy
func (cp *ConnectionPool) isConnectionHealthy(conn *PooledConnection) bool {
	// Set a very short read deadline to check if the connection is still alive
	if err := conn.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		cp.logger.Warn("Failed to set read deadline for health check", slog.String("error", err.Error()))
		return false
	}

	// Try to read one byte (this should timeout immediately on a healthy connection)
	_, err := conn.conn.Read(make([]byte, 1))

	// Reset the read deadline
	if resetErr := conn.conn.SetReadDeadline(time.Time{}); resetErr != nil {
		cp.logger.Warn("Failed to reset read deadline after health check", slog.String("error", resetErr.Error()))
	}

	// If we get a timeout, connection is likely healthy (no data to read)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		conn.healthy = true
		return true
	}

	// Any other error means connection is not healthy
	if err != nil {
		conn.healthy = false
		return false
	}

	// If we actually read data, that's unexpected for a returned connection
	conn.healthy = false
	return false
}

// cleanup runs periodic cleanup of expired connections
func (cp *ConnectionPool) cleanup(ctx context.Context) {
	ticker := time.NewTicker(cp.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cp.performCleanup()
		}
	}
}

// performCleanup removes expired and unhealthy connections
func (cp *ConnectionPool) performCleanup() {
	now := time.Now()
	cleaned := 0

	cp.mu.RLock()
	pools := make([]*HostPool, 0, len(cp.pools))
	for _, pool := range cp.pools {
		pools = append(pools, pool)
	}
	cp.mu.RUnlock()

	for _, pool := range pools {
		pool.mu.Lock()

		// Remove expired connections
		newConnections := make([]*PooledConnection, 0, len(pool.connections))
		for _, conn := range pool.connections {
			if !conn.inUse && (now.Sub(conn.lastUsed) > cp.config.IdleTimeout || !conn.healthy) {
				conn.conn.Close()
				cleaned++

				cp.metrics.mu.Lock()
				cp.metrics.ClosedConnections++
				cp.metrics.IdleConnections--
				cp.metrics.mu.Unlock()
			} else {
				newConnections = append(newConnections, conn)
			}
		}

		pool.connections = newConnections
		pool.mu.Unlock()
	}

	if cleaned > 0 {
		cp.logger.Debug("Cleaned up expired connections", "count", cleaned)
	}
}

// Close closes all connections in the pool
func (cp *ConnectionPool) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	closed := 0
	for _, pool := range cp.pools {
		pool.mu.Lock()
		for _, conn := range pool.connections {
			conn.conn.Close()
			closed++
		}
		pool.connections = nil
		pool.mu.Unlock()
	}

	cp.pools = make(map[string]*HostPool)

	cp.metrics.mu.Lock()
	cp.metrics.ClosedConnections += int64(closed)
	cp.metrics.IdleConnections = 0
	cp.metrics.ActiveConnections = 0
	cp.metrics.mu.Unlock()

	cp.logger.Info("Closed all pooled connections", "count", closed)
}

// GetStats returns current pool statistics
func (cp *ConnectionPool) GetStats() map[string]interface{} {
	cp.metrics.mu.RLock()
	defer cp.metrics.mu.RUnlock()

	// Calculate pool utilization
	var totalCapacity int64
	var totalUsed int64

	cp.mu.RLock()
	for _, pool := range cp.pools {
		totalCapacity += int64(pool.maxConns)
		totalUsed += int64(pool.activeConns + len(pool.connections))
	}
	cp.mu.RUnlock()

	utilization := 0.0
	if totalCapacity > 0 {
		utilization = float64(totalUsed) / float64(totalCapacity) * 100
	}

	return map[string]interface{}{
		"total_connections":    cp.metrics.TotalConnections,
		"active_connections":   cp.metrics.ActiveConnections,
		"idle_connections":     cp.metrics.IdleConnections,
		"pooled_connections":   cp.metrics.PooledConnections,
		"created_connections":  cp.metrics.CreatedConnections,
		"reused_connections":   cp.metrics.ReusedConnections,
		"closed_connections":   cp.metrics.ClosedConnections,
		"failed_connections":   cp.metrics.FailedConnections,
		"connection_hits":      cp.metrics.ConnectionHits,
		"connection_misses":    cp.metrics.ConnectionMisses,
		"average_connect_time": cp.metrics.AverageConnectTime,
		"average_lifetime":     cp.metrics.AverageLifetime,
		"pool_utilization":     utilization,
		"total_pools":          len(cp.pools),
	}
}
