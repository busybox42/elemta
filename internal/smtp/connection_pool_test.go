package smtp

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConnection represents a mock connection for testing
type mockConnection struct {
	id       int
	closed   bool
	failNext bool
	mu       sync.Mutex
}

func (m *mockConnection) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConnection) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// TestConnectionPoolCreate tests pool creation
func TestConnectionPoolCreate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("valid configuration", func(t *testing.T) {
		connID := 0
		config := PoolConfig{
			MinIdle:     2,
			MaxIdle:     5,
			MaxActive:   10,
			MaxLifetime: 5 * time.Minute,
			IdleTimeout: 1 * time.Minute,
			WaitTimeout: 5 * time.Second,
			Factory: func(ctx context.Context) (interface{}, error) {
				connID++
				return &mockConnection{id: connID}, nil
			},
		}

		pool, err := NewConnectionPool(config, logger)
		require.NoError(t, err)
		require.NotNil(t, pool)

		defer pool.Close()

		// Verify pool warmed up with minIdle connections
		assert.Equal(t, 2, len(pool.idleConns))
	})

	t.Run("invalid minIdle", func(t *testing.T) {
		config := PoolConfig{
			MinIdle:   -1,
			MaxIdle:   5,
			MaxActive: 10,
			Factory: func(ctx context.Context) (interface{}, error) {
				return &mockConnection{}, nil
			},
		}

		pool, err := NewConnectionPool(config, logger)
		assert.Error(t, err)
		assert.Nil(t, pool)
	})

	t.Run("invalid maxIdle < minIdle", func(t *testing.T) {
		config := PoolConfig{
			MinIdle:   5,
			MaxIdle:   2,
			MaxActive: 10,
			Factory: func(ctx context.Context) (interface{}, error) {
				return &mockConnection{}, nil
			},
		}

		pool, err := NewConnectionPool(config, logger)
		assert.Error(t, err)
		assert.Nil(t, pool)
	})

	t.Run("invalid maxActive < maxIdle", func(t *testing.T) {
		config := PoolConfig{
			MinIdle:   2,
			MaxIdle:   10,
			MaxActive: 5,
			Factory: func(ctx context.Context) (interface{}, error) {
				return &mockConnection{}, nil
			},
		}

		pool, err := NewConnectionPool(config, logger)
		assert.Error(t, err)
		assert.Nil(t, pool)
	})

	t.Run("missing factory", func(t *testing.T) {
		config := PoolConfig{
			MinIdle:   2,
			MaxIdle:   5,
			MaxActive: 10,
			Factory:   nil,
		}

		pool, err := NewConnectionPool(config, logger)
		assert.Error(t, err)
		assert.Nil(t, pool)
	})
}

// TestConnectionPoolAcquireRelease tests basic acquire/release operations
func TestConnectionPoolAcquireRelease(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	connID := 0
	config := PoolConfig{
		MinIdle:     2,
		MaxIdle:     5,
		MaxActive:   10,
		MaxLifetime: 5 * time.Minute,
		IdleTimeout: 1 * time.Minute,
		WaitTimeout: 2 * time.Second,
		Factory: func(ctx context.Context) (interface{}, error) {
			connID++
			return &mockConnection{id: connID}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	t.Run("acquire and release", func(t *testing.T) {
		ctx := context.Background()

		// Acquire connection
		conn, err := pool.Acquire(ctx)
		require.NoError(t, err)
		require.NotNil(t, conn)

		initialActive := atomic.LoadInt32(&pool.activeConns)
		assert.Greater(t, initialActive, int32(0))

		// Release connection
		err = pool.Release(conn)
		require.NoError(t, err)

		finalActive := atomic.LoadInt32(&pool.activeConns)
		assert.Equal(t, initialActive-1, finalActive)
	})

	t.Run("release nil connection", func(t *testing.T) {
		err := pool.Release(nil)
		assert.Error(t, err)
	})

	t.Run("acquire from closed pool", func(t *testing.T) {
		tempConfig := PoolConfig{
			MinIdle:     1,
			MaxIdle:     2,
			MaxActive:   5,
			MaxLifetime: 5 * time.Minute,
			Factory: func(ctx context.Context) (interface{}, error) {
				return &mockConnection{}, nil
			},
		}

		tempPool, err := NewConnectionPool(tempConfig, logger)
		require.NoError(t, err)

		tempPool.Close()

		ctx := context.Background()
		conn, err := tempPool.Acquire(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
	})
}

// TestConnectionPoolReuseConnections tests connection reuse
func TestConnectionPoolReuseConnections(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	connID := 0
	config := PoolConfig{
		MinIdle:     0,
		MaxIdle:     5,
		MaxActive:   10,
		MaxLifetime: 5 * time.Minute,
		IdleTimeout: 1 * time.Minute,
		Factory: func(ctx context.Context) (interface{}, error) {
			connID++
			return &mockConnection{id: connID}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Acquire and release connection
	conn1, err := pool.Acquire(ctx)
	require.NoError(t, err)
	mockConn1 := conn1.conn.(*mockConnection)
	firstID := mockConn1.id

	err = pool.Release(conn1)
	require.NoError(t, err)

	// Acquire again - should get same connection
	conn2, err := pool.Acquire(ctx)
	require.NoError(t, err)
	mockConn2 := conn2.conn.(*mockConnection)

	assert.Equal(t, firstID, mockConn2.id, "Should reuse connection")
	assert.Greater(t, conn2.usageCount, int64(0), "Usage count should increase")

	pool.Release(conn2)
}

// TestConnectionPoolMaxPoolSize tests max pool size enforcement
func TestConnectionPoolMaxPoolSize(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:     0,
		MaxIdle:     2,
		MaxActive:   3,
		MaxLifetime: 5 * time.Minute,
		WaitTimeout: 100 * time.Millisecond,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Acquire max connections
	conns := make([]*PooledConnection, 3)
	for i := 0; i < 3; i++ {
		conn, err := pool.Acquire(ctx)
		require.NoError(t, err)
		conns[i] = conn
	}

	// Try to acquire one more - should timeout
	_, err = pool.Acquire(ctx)
	assert.Error(t, err, "Should fail when pool is exhausted")

	// Release one connection
	pool.Release(conns[0])

	// Now should succeed
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	pool.Release(conn)

	// Cleanup
	for i := 1; i < 3; i++ {
		pool.Release(conns[i])
	}
}

// TestConnectionPoolIdleTimeout tests idle connection timeout
func TestConnectionPoolIdleTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:      1,
		MaxIdle:      2,
		MaxActive:    5,
		MaxLifetime:  5 * time.Minute,
		IdleTimeout:  100 * time.Millisecond,
		TestOnBorrow: true,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Acquire and release connection
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	pool.Release(conn)

	// Wait for idle timeout
	time.Sleep(200 * time.Millisecond)

	// Acquire again - connection should be expired
	conn2, err := pool.Acquire(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, conn, conn2, "Should get new connection after idle timeout")
	pool.Release(conn2)
}

// TestConnectionPoolConnectionTimeout tests connection acquisition timeout
func TestConnectionPoolConnectionTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:     0,
		MaxIdle:     1,
		MaxActive:   1,
		WaitTimeout: 100 * time.Millisecond,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Acquire the only connection
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)

	// Try to acquire another - should timeout
	start := time.Now()
	_, err = pool.Acquire(ctx)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Greater(t, elapsed, 100*time.Millisecond, "Should wait for timeout")

	pool.Release(conn)
}

// TestConnectionPoolConcurrentAcquire tests concurrent connection acquisition
func TestConnectionPoolConcurrentAcquire(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	connID := atomic.Int32{}
	config := PoolConfig{
		MinIdle:     2,
		MaxIdle:     10,
		MaxActive:   20,
		MaxLifetime: 5 * time.Minute,
		WaitTimeout: 2 * time.Second,
		Factory: func(ctx context.Context) (interface{}, error) {
			id := connID.Add(1)
			return &mockConnection{id: int(id)}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	iterations := 50
	successCount := atomic.Int32{}

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Logf("Acquire failed for goroutine %d: %v", id, err)
				return
			}

			successCount.Add(1)

			// Simulate work
			time.Sleep(10 * time.Millisecond)

			err = pool.Release(conn)
			if err != nil {
				t.Logf("Release failed for goroutine %d: %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all or most succeeded
	assert.Greater(t, successCount.Load(), int32(iterations-5), "Most acquisitions should succeed")

	// Verify pool state
	stats := pool.GetStatistics()
	assert.Greater(t, stats.Created.Load(), int64(0))
	assert.Greater(t, stats.AcquireSuccess.Load(), int64(0))
}

// TestConnectionPoolHealthCheck tests connection health checking
func TestConnectionPoolHealthCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:      1,
		MaxIdle:      2,
		MaxActive:    5,
		TestOnBorrow: true,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
		Validator: func(conn interface{}) bool {
			mc := conn.(*mockConnection)
			return !mc.IsClosed()
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Acquire connection and mark as closed
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)

	mockConn := conn.conn.(*mockConnection)
	mockConn.Close()

	// Release connection (health check on return if enabled)
	pool.Release(conn)

	// Next acquire should create new connection if health check failed
	conn2, err := pool.Acquire(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, conn, conn2)

	pool.Release(conn2)
}

// TestConnectionPoolStats tests pool statistics
func TestConnectionPoolStats(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:     2,
		MaxIdle:     5,
		MaxActive:   10,
		MaxLifetime: 5 * time.Minute,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Perform some operations
	conn1, _ := pool.Acquire(ctx)
	conn2, _ := pool.Acquire(ctx)
	pool.Release(conn1)
	pool.Release(conn2)

	// Get statistics
	stats := pool.GetStatistics()
	assert.Greater(t, stats.Created.Load(), int64(0))
	assert.Greater(t, stats.AcquireSuccess.Load(), int64(0))

	// Get pool info
	info := pool.GetPoolInfo()
	assert.NotNil(t, info)
	assert.Equal(t, 2, info["min_idle"])
	assert.Equal(t, 5, info["max_idle"])
	assert.Equal(t, 10, info["max_active"])
}

// TestConnectionPoolClose tests pool closure
func TestConnectionPoolClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:     2,
		MaxIdle:     5,
		MaxActive:   10,
		MaxLifetime: 5 * time.Minute,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)

	// Acquire some connections
	ctx := context.Background()
	conn1, _ := pool.Acquire(ctx)
	conn2, _ := pool.Acquire(ctx)
	pool.Release(conn1)
	// Keep conn2 active

	// Close pool
	err = pool.Close()
	require.NoError(t, err)

	// Verify pool is closed
	assert.True(t, pool.closed)

	// Try to close again
	err = pool.Close()
	assert.Error(t, err, "Should fail to close already closed pool")

	// Release remaining connection (should be destroyed)
	pool.Release(conn2)
}

// TestConnectionPoolGoroutineCleanup tests goroutine cleanup
func TestConnectionPoolGoroutineCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	config := PoolConfig{
		MinIdle:     2,
		MaxIdle:     5,
		MaxActive:   10,
		MaxLifetime: 5 * time.Minute,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)

	// Use pool
	ctx := context.Background()
	conn, _ := pool.Acquire(ctx)
	pool.Release(conn)

	// Close pool
	pool.Close()

	// Wait for cleanup
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineLeak := finalGoroutines - initialGoroutines

	// Allow small tolerance for background goroutines
	assert.LessOrEqual(t, goroutineLeak, 5, "Should not leak significant goroutines")
}

// TestConnectionPoolMaxLifetime tests connection max lifetime
func TestConnectionPoolMaxLifetime(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:     1,
		MaxIdle:     2,
		MaxActive:   5,
		MaxLifetime: 200 * time.Millisecond,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Acquire connection
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	createdAt := conn.createdAt

	// Release it
	pool.Release(conn)

	// Wait for lifetime to expire
	time.Sleep(300 * time.Millisecond)

	// Acquire again - should get new connection
	conn2, err := pool.Acquire(ctx)
	require.NoError(t, err)
	assert.True(t, conn2.createdAt.After(createdAt), "Should create new connection after lifetime expired")

	pool.Release(conn2)
}

// TestPooledConnectionMethods tests PooledConnection helper methods
func TestPooledConnectionMethods(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:     1,
		MaxIdle:     2,
		MaxActive:   5,
		MaxLifetime: 5 * time.Minute,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)

	// Test Conn()
	assert.NotNil(t, conn.Conn())

	// Test IsHealthy()
	assert.True(t, conn.IsHealthy())

	// Test Age()
	age := conn.Age()
	assert.Greater(t, age, time.Duration(0))

	// Test IdleTime()
	time.Sleep(10 * time.Millisecond)
	idleTime := conn.IdleTime()
	assert.Greater(t, idleTime, time.Duration(0))

	// Test UsageCount()
	assert.Greater(t, conn.UsageCount(), int64(0))

	// Test Close() (returns to pool)
	err = conn.Close()
	assert.NoError(t, err)
}

// TestConnectionPoolFactoryError tests handling of factory errors
func TestConnectionPoolFactoryError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	factoryErr := errors.New("factory error")
	config := PoolConfig{
		MinIdle:     0,
		MaxIdle:     2,
		MaxActive:   5,
		MaxLifetime: 5 * time.Minute,
		WaitTimeout: 100 * time.Millisecond,
		Factory: func(ctx context.Context) (interface{}, error) {
			return nil, factoryErr
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err) // MinIdle is 0, so no warmup
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	assert.Error(t, err)
	assert.Nil(t, conn)
}

// TestConnectionPoolMaintenance tests pool maintenance operations
func TestConnectionPoolMaintenance(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := PoolConfig{
		MinIdle:       2,
		MaxIdle:       5,
		MaxActive:     10,
		MaxLifetime:   5 * time.Minute,
		TestWhileIdle: true,
		Factory: func(ctx context.Context) (interface{}, error) {
			return &mockConnection{}, nil
		},
		Validator: func(conn interface{}) bool {
			mc := conn.(*mockConnection)
			return !mc.IsClosed()
		},
	}

	pool, err := NewConnectionPool(config, logger)
	require.NoError(t, err)
	defer pool.Close()

	// Wait for at least one maintenance cycle
	time.Sleep(100 * time.Millisecond)

	// Manually trigger maintenance
	pool.performMaintenance()

	// Verify pool has minimum idle connections
	assert.GreaterOrEqual(t, len(pool.idleConns), config.MinIdle)
}
