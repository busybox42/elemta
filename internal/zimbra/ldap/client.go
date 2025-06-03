package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/zimbra"
	"github.com/go-ldap/ldap/v3"
)

// Client handles LDAP connections to Zimbra
type Client struct {
	config *zimbra.LDAPConfig
	logger *slog.Logger

	// Connection pool
	pool     chan *ldap.Conn
	poolSize int

	// Health checking
	healthCheck time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup

	// Metrics
	connectionCount int64
	queryCount      int64
	errorCount      int64
	lastConnectTime time.Time
	lastQueryTime   time.Time
	mutex           sync.RWMutex
}

// NewClient creates a new LDAP client for Zimbra
func NewClient(config *zimbra.LDAPConfig, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	client := &Client{
		config:      config,
		logger:      logger,
		pool:        make(chan *ldap.Conn, config.MaxConnections),
		poolSize:    config.MaxConnections,
		healthCheck: time.Minute,
		stopCh:      make(chan struct{}),
	}

	return client
}

// Connect initializes the LDAP connection pool
func (c *Client) Connect(ctx context.Context) error {
	c.logger.Info("Initializing LDAP connection pool",
		slog.Int("pool_size", c.poolSize),
		slog.Any("servers", c.config.Servers),
	)

	// Pre-populate the connection pool
	for i := 0; i < c.poolSize; i++ {
		conn, err := c.createConnection(ctx)
		if err != nil {
			c.logger.Error("Failed to create initial LDAP connection",
				slog.Int("connection_number", i),
				slog.String("error", err.Error()),
			)
			// Don't fail completely - try with fewer connections
			break
		}

		select {
		case c.pool <- conn:
		default:
			conn.Close()
		}
	}

	// Start health checker
	c.wg.Add(1)
	go c.healthChecker()

	c.logger.Info("LDAP connection pool initialized",
		slog.Int("active_connections", len(c.pool)),
	)

	return nil
}

// Close shuts down the LDAP client
func (c *Client) Close() error {
	c.logger.Info("Shutting down LDAP client")

	// Stop health checker
	close(c.stopCh)
	c.wg.Wait()

	// Close all pooled connections
	close(c.pool)
	for conn := range c.pool {
		conn.Close()
	}

	c.logger.Info("LDAP client shutdown complete")
	return nil
}

// GetConnection retrieves a connection from the pool
func (c *Client) GetConnection(ctx context.Context) (*ldap.Conn, error) {
	select {
	case conn := <-c.pool:
		// Test connection health
		if c.isConnectionHealthy(conn) {
			c.mutex.Lock()
			c.connectionCount++
			c.lastConnectTime = time.Now()
			c.mutex.Unlock()
			return conn, nil
		}

		// Connection is unhealthy, close it and create new one
		conn.Close()
		return c.createConnection(ctx)

	case <-ctx.Done():
		return nil, ctx.Err()

	case <-time.After(c.config.ConnectTimeout):
		// Pool is empty, create new connection
		return c.createConnection(ctx)
	}
}

// ReturnConnection returns a connection to the pool
func (c *Client) ReturnConnection(conn *ldap.Conn) {
	if conn == nil {
		return
	}

	// Check if connection is still healthy
	if !c.isConnectionHealthy(conn) {
		conn.Close()
		return
	}

	select {
	case c.pool <- conn:
		// Successfully returned to pool
	default:
		// Pool is full, close the connection
		conn.Close()
	}
}

// createConnection creates a new LDAP connection
func (c *Client) createConnection(ctx context.Context) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	// Try each server in order
	for _, server := range c.config.Servers {
		address := fmt.Sprintf("%s:%d", server, c.config.Port)

		if c.config.TLS {
			tlsConfig := c.config.TLSConfig
			if tlsConfig == nil {
				tlsConfig = &tls.Config{
					ServerName: server,
				}
			}
			conn, err = ldap.DialTLS("tcp", address, tlsConfig)
		} else {
			conn, err = ldap.Dial("tcp", address)
		}

		if err != nil {
			c.logger.Warn("Failed to connect to LDAP server",
				slog.String("server", server),
				slog.String("error", err.Error()),
			)
			continue
		}

		// Enable StartTLS if configured
		if !c.config.TLS && c.config.StartTLS {
			tlsConfig := c.config.TLSConfig
			if tlsConfig == nil {
				tlsConfig = &tls.Config{
					ServerName: server,
				}
			}

			err = conn.StartTLS(tlsConfig)
			if err != nil {
				conn.Close()
				c.logger.Warn("Failed to start TLS on LDAP connection",
					slog.String("server", server),
					slog.String("error", err.Error()),
				)
				continue
			}
		}

		// Authenticate if bind credentials provided
		if c.config.BindDN != "" {
			err = conn.Bind(c.config.BindDN, c.config.BindPass)
			if err != nil {
				conn.Close()
				c.logger.Warn("Failed to bind to LDAP server",
					slog.String("server", server),
					slog.String("bind_dn", c.config.BindDN),
					slog.String("error", err.Error()),
				)
				continue
			}
		}

		c.logger.Debug("Successfully connected to LDAP server",
			slog.String("server", server),
		)

		return conn, nil
	}

	c.mutex.Lock()
	c.errorCount++
	c.mutex.Unlock()

	return nil, fmt.Errorf("failed to connect to any LDAP server: %v", c.config.Servers)
}

// isConnectionHealthy checks if an LDAP connection is still usable
func (c *Client) isConnectionHealthy(conn *ldap.Conn) bool {
	if conn == nil {
		return false
	}

	// Simple health check - try to search for the base DN
	req := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := conn.Search(req)
		done <- err
	}()

	select {
	case err := <-done:
		return err == nil
	case <-ctx.Done():
		return false
	}
}

// healthChecker periodically checks connection health
func (c *Client) healthChecker() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.healthCheck)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkPoolHealth()
		case <-c.stopCh:
			return
		}
	}
}

// checkPoolHealth removes unhealthy connections from the pool
func (c *Client) checkPoolHealth() {
	var healthyConns []*ldap.Conn

	// Drain the pool
	for {
		select {
		case conn := <-c.pool:
			if c.isConnectionHealthy(conn) {
				healthyConns = append(healthyConns, conn)
			} else {
				conn.Close()
			}
		default:
			goto refill
		}
	}

refill:
	// Return healthy connections to pool
	for _, conn := range healthyConns {
		select {
		case c.pool <- conn:
		default:
			conn.Close()
		}
	}

	c.logger.Debug("LDAP pool health check complete",
		slog.Int("healthy_connections", len(healthyConns)),
	)
}

// GetStats returns client statistics
func (c *Client) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return map[string]interface{}{
		"pool_size":          c.poolSize,
		"active_connections": len(c.pool),
		"total_connections":  c.connectionCount,
		"total_queries":      c.queryCount,
		"total_errors":       c.errorCount,
		"last_connect_time":  c.lastConnectTime,
		"last_query_time":    c.lastQueryTime,
	}
}
