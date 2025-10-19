package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.caches)
	assert.Empty(t, manager.caches)
}

func TestManagerRegister(t *testing.T) {
	manager := NewManager()

	t.Run("Register new cache", func(t *testing.T) {
		cache := NewMemory(Config{Name: "test-cache"})
		err := manager.Register(cache)
		assert.NoError(t, err)

		retrieved, exists := manager.Get("test-cache")
		assert.True(t, exists)
		assert.Equal(t, cache, retrieved)
	})

	t.Run("Register duplicate cache fails", func(t *testing.T) {
		cache1 := NewMemory(Config{Name: "duplicate"})
		cache2 := NewMemory(Config{Name: "duplicate"})

		err := manager.Register(cache1)
		require.NoError(t, err)

		err = manager.Register(cache2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})

	t.Run("Register multiple caches", func(t *testing.T) {
		mgr := NewManager()
		for i := 0; i < 5; i++ {
			cache := NewMemory(Config{Name: "cache-" + string(rune(48+i))})
			err := mgr.Register(cache)
			assert.NoError(t, err)
		}

		caches := mgr.List()
		assert.Len(t, caches, 5)
	})
}

func TestManagerGet(t *testing.T) {
	manager := NewManager()

	cache := NewMemory(Config{Name: "exists"})
	manager.Register(cache)

	t.Run("Get existing cache", func(t *testing.T) {
		retrieved, exists := manager.Get("exists")
		assert.True(t, exists)
		assert.NotNil(t, retrieved)
		assert.Equal(t, "exists", retrieved.Name())
	})

	t.Run("Get non-existent cache", func(t *testing.T) {
		retrieved, exists := manager.Get("does-not-exist")
		assert.False(t, exists)
		assert.Nil(t, retrieved)
	})
}

func TestManagerList(t *testing.T) {
	manager := NewManager()

	// Register multiple caches
	for i := 0; i < 3; i++ {
		cache := NewMemory(Config{Name: "list-cache-" + string(rune(48+i))})
		manager.Register(cache)
	}

	list := manager.List()
	assert.Len(t, list, 3)
	assert.Contains(t, list, "list-cache-0")
	assert.Contains(t, list, "list-cache-1")
	assert.Contains(t, list, "list-cache-2")
}

func TestManagerRemove(t *testing.T) {
	manager := NewManager()

	t.Run("Remove existing cache", func(t *testing.T) {
		cache := NewMemory(Config{Name: "remove-me"})
		cache.Connect()
		manager.Register(cache)

		err := manager.Remove("remove-me")
		assert.NoError(t, err)

		_, exists := manager.Get("remove-me")
		assert.False(t, exists)
	})

	t.Run("Remove non-existent cache", func(t *testing.T) {
		err := manager.Remove("does-not-exist")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("Remove disconnected cache", func(t *testing.T) {
		cache := NewMemory(Config{Name: "disconnected"})
		// Don't connect
		manager.Register(cache)

		err := manager.Remove("disconnected")
		assert.NoError(t, err)
	})
}

func TestManagerCloseAll(t *testing.T) {
	t.Run("Close all connected caches", func(t *testing.T) {
		manager := NewManager()

		for i := 0; i < 3; i++ {
			cache := NewMemory(Config{Name: "close-" + string(rune(48+i))})
			cache.Connect()
			manager.Register(cache)
		}

		err := manager.CloseAll()
		assert.NoError(t, err)

		// Verify all caches are closed
		for name := range manager.List() {
			cache, _ := manager.Get(name)
			assert.False(t, cache.IsConnected())
		}
	})

	t.Run("Close all with mixed connected/disconnected", func(t *testing.T) {
		manager := NewManager()

		cache1 := NewMemory(Config{Name: "connected"})
		cache1.Connect()
		manager.Register(cache1)

		cache2 := NewMemory(Config{Name: "disconnected"})
		manager.Register(cache2)

		err := manager.CloseAll()
		assert.NoError(t, err)
	})

	t.Run("Close empty manager", func(t *testing.T) {
		manager := NewManager()
		err := manager.CloseAll()
		assert.NoError(t, err)
	})
}

func TestCacheFactory(t *testing.T) {
	t.Run("Create memory cache", func(t *testing.T) {
		config := Config{
			Type: "memory",
			Name: "test",
		}

		cache, err := Factory(config)
		require.NoError(t, err)
		assert.NotNil(t, cache)
		assert.Equal(t, "memory", cache.Type())
	})

	t.Run("Create redis cache", func(t *testing.T) {
		config := Config{
			Type: "redis",
			Name: "test-redis",
			Host: "localhost",
			Port: 6379,
		}

		cache, err := Factory(config)
		require.NoError(t, err)
		assert.NotNil(t, cache)
		assert.Equal(t, "redis", cache.Type())
	})

	t.Run("Create memcached cache", func(t *testing.T) {
		config := Config{
			Type: "memcached",
			Name: "test-memcached",
			Host: "localhost",
			Port: 11211,
		}

		cache, err := Factory(config)
		require.NoError(t, err)
		assert.NotNil(t, cache)
		assert.Equal(t, "memcached", cache.Type())
	})

	t.Run("Unsupported cache type", func(t *testing.T) {
		config := Config{
			Type: "unsupported",
			Name: "test",
		}

		cache, err := Factory(config)
		assert.Error(t, err)
		assert.Nil(t, cache)
		assert.Contains(t, err.Error(), "unsupported cache type")
	})
}

func TestMemoryCacheBasicOperations(t *testing.T) {
	cache := NewMemory(Config{Name: "test"})
	ctx := context.Background()

	t.Run("Connect cache", func(t *testing.T) {
		err := cache.Connect()
		assert.NoError(t, err)
		assert.True(t, cache.IsConnected())
	})

	t.Run("Set and Get", func(t *testing.T) {
		err := cache.Set(ctx, "key1", "value1", 0)
		assert.NoError(t, err)

		value, err := cache.Get(ctx, "key1")
		assert.NoError(t, err)
		assert.Equal(t, "value1", value)
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		_, err := cache.Get(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("Exists check", func(t *testing.T) {
		cache.Set(ctx, "exists-key", "value", 0)
		
		exists, err := cache.Exists(ctx, "exists-key")
		assert.NoError(t, err)
		assert.True(t, exists)

		exists, err = cache.Exists(ctx, "no-key")
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Delete key", func(t *testing.T) {
		cache.Set(ctx, "delete-me", "value", 0)

		err := cache.Delete(ctx, "delete-me")
		assert.NoError(t, err)

		_, err = cache.Get(ctx, "delete-me")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("Delete non-existent key", func(t *testing.T) {
		err := cache.Delete(ctx, "never-existed")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("Close cache", func(t *testing.T) {
		err := cache.Close()
		assert.NoError(t, err)
		assert.False(t, cache.IsConnected())
	})
}

func TestMemoryCacheExpiration(t *testing.T) {
	cache := NewMemory(Config{Name: "expiration-test"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()

	t.Run("Set with expiration", func(t *testing.T) {
		err := cache.Set(ctx, "expires", "value", 100*time.Millisecond)
		assert.NoError(t, err)

		// Should exist immediately
		value, err := cache.Get(ctx, "expires")
		assert.NoError(t, err)
		assert.Equal(t, "value", value)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired
		_, err = cache.Get(ctx, "expires")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("SetNX with expiration", func(t *testing.T) {
		ok, err := cache.SetNX(ctx, "setnx-key", "first", 200*time.Millisecond)
		assert.NoError(t, err)
		assert.True(t, ok, "First SetNX should succeed")

		ok, err = cache.SetNX(ctx, "setnx-key", "second", 200*time.Millisecond)
		assert.NoError(t, err)
		assert.False(t, ok, "Second SetNX should fail")

		// Wait for expiration
		time.Sleep(250 * time.Millisecond)

		// Should be able to SetNX again
		ok, err = cache.SetNX(ctx, "setnx-key", "third", 0)
		assert.NoError(t, err)
		assert.True(t, ok, "SetNX after expiration should succeed")
	})

	t.Run("Expire existing key", func(t *testing.T) {
		cache.Set(ctx, "expire-me", "value", 0) // No expiration

		// Set expiration
		err := cache.Expire(ctx, "expire-me", 100*time.Millisecond)
		assert.NoError(t, err)

		// Should exist immediately
		exists, err := cache.Exists(ctx, "expire-me")
		assert.NoError(t, err)
		assert.True(t, exists)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired
		exists, err = cache.Exists(ctx, "expire-me")
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Expire non-existent key", func(t *testing.T) {
		err := cache.Expire(ctx, "not-here", time.Second)
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestMemoryCacheNumericOperations(t *testing.T) {
	cache := NewMemory(Config{Name: "numeric-test"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()

	t.Run("Increment new key", func(t *testing.T) {
		value, err := cache.Increment(ctx, "counter", 1)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), value)
	})

	t.Run("Increment existing key", func(t *testing.T) {
		cache.Set(ctx, "counter2", int64(10), 0)

		value, err := cache.Increment(ctx, "counter2", 5)
		assert.NoError(t, err)
		assert.Equal(t, int64(15), value)
	})

	t.Run("Increment with different numeric types", func(t *testing.T) {
		// Test int
		cache.Set(ctx, "int-key", int(100), 0)
		val, err := cache.Increment(ctx, "int-key", 50)
		assert.NoError(t, err)
		assert.Equal(t, int64(150), val)

		// Test float64
		cache.Set(ctx, "float-key", float64(200), 0)
		val, err = cache.Increment(ctx, "float-key", 50)
		assert.NoError(t, err)
		assert.Equal(t, int64(250), val)

		// Test string number
		cache.Set(ctx, "string-key", "300", 0)
		val, err = cache.Increment(ctx, "string-key", 50)
		assert.NoError(t, err)
		assert.Equal(t, int64(350), val)
	})

	t.Run("Increment non-numeric value fails", func(t *testing.T) {
		cache.Set(ctx, "non-numeric", "not-a-number", 0)

		_, err := cache.Increment(ctx, "non-numeric", 1)
		assert.Error(t, err)
	})

	t.Run("Decrement", func(t *testing.T) {
		cache.Set(ctx, "dec-counter", int64(100), 0)

		value, err := cache.Decrement(ctx, "dec-counter", 30)
		assert.NoError(t, err)
		assert.Equal(t, int64(70), value)
	})

	t.Run("Decrement new key", func(t *testing.T) {
		value, err := cache.Decrement(ctx, "new-dec", 10)
		assert.NoError(t, err)
		assert.Equal(t, int64(-10), value)
	})
}

func TestMemoryCacheFlushAll(t *testing.T) {
	cache := NewMemory(Config{Name: "flush-test"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()

	// Add multiple items
	cache.Set(ctx, "key1", "value1", 0)
	cache.Set(ctx, "key2", "value2", 0)
	cache.Set(ctx, "key3", "value3", 0)

	// Verify they exist
	_, err := cache.Get(ctx, "key1")
	assert.NoError(t, err)

	// Flush all
	err = cache.FlushAll(ctx)
	assert.NoError(t, err)

	// Verify all are gone
	_, err = cache.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = cache.Get(ctx, "key2")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMemoryCacheDisconnected(t *testing.T) {
	cache := NewMemory(Config{Name: "disconnected"})
	ctx := context.Background()

	t.Run("Operations fail when disconnected", func(t *testing.T) {
		_, err := cache.Get(ctx, "key")
		assert.ErrorIs(t, err, ErrNotConnected)

		err = cache.Set(ctx, "key", "value", 0)
		assert.ErrorIs(t, err, ErrNotConnected)

		_, err = cache.SetNX(ctx, "key", "value", 0)
		assert.ErrorIs(t, err, ErrNotConnected)

		err = cache.Delete(ctx, "key")
		assert.ErrorIs(t, err, ErrNotConnected)

		_, err = cache.Exists(ctx, "key")
		assert.ErrorIs(t, err, ErrNotConnected)

		_, err = cache.Increment(ctx, "key", 1)
		assert.ErrorIs(t, err, ErrNotConnected)

		err = cache.FlushAll(ctx)
		assert.ErrorIs(t, err, ErrNotConnected)
	})
}

func TestMemoryCacheConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency tests in short mode")
	}

	cache := NewMemory(Config{Name: "concurrent"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()

	t.Run("Concurrent Set operations", func(t *testing.T) {
		var wg sync.WaitGroup
		numGoroutines := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				key := "key-" + string(rune(idx))
				cache.Set(ctx, key, idx, 0)
			}(i)
		}

		wg.Wait()
		t.Log("✓ Concurrent Set operations completed")
	})

	t.Run("Concurrent Get operations", func(t *testing.T) {
		cache.Set(ctx, "shared-key", "shared-value", 0)

		var wg sync.WaitGroup
		numReads := 1000

		for i := 0; i < numReads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.Get(ctx, "shared-key")
			}()
		}

		wg.Wait()
		t.Log("✓ Concurrent Get operations completed")
	})

	t.Run("Concurrent Increment", func(t *testing.T) {
		cache.Set(ctx, "counter", int64(0), 0)

		var wg sync.WaitGroup
		numIncrements := 1000

		for i := 0; i < numIncrements; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.Increment(ctx, "counter", 1)
			}()
		}

		wg.Wait()

		// Final value should be numIncrements
		val, err := cache.Get(ctx, "counter")
		require.NoError(t, err)
		assert.Equal(t, int64(numIncrements), val)
		t.Log("✓ Concurrent Increment operations completed correctly")
	})

	t.Run("Mixed concurrent operations", func(t *testing.T) {
		var wg sync.WaitGroup

		// Writers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				cache.Set(ctx, "mixed-"+string(rune(idx)), idx, 100*time.Millisecond)
			}(i)
		}

		// Readers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				cache.Get(ctx, "mixed-"+string(rune(idx)))
			}(i)
		}

		// Deleters
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				cache.Delete(ctx, "mixed-"+string(rune(idx)))
			}(i)
		}

		wg.Wait()
		t.Log("✓ Mixed concurrent operations completed")
	})
}

func TestMemoryCacheEdgeCases(t *testing.T) {
	cache := NewMemory(Config{Name: "edge-cases"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()

	t.Run("Empty key", func(t *testing.T) {
		err := cache.Set(ctx, "", "value", 0)
		assert.NoError(t, err)

		val, err := cache.Get(ctx, "")
		assert.NoError(t, err)
		assert.Equal(t, "value", val)
	})

	t.Run("Nil value", func(t *testing.T) {
		err := cache.Set(ctx, "nil-key", nil, 0)
		assert.NoError(t, err)

		val, err := cache.Get(ctx, "nil-key")
		assert.NoError(t, err)
		assert.Nil(t, val)
	})

	t.Run("Complex values", func(t *testing.T) {
		type ComplexStruct struct {
			Name  string
			Count int
			Tags  []string
		}

		complex := ComplexStruct{
			Name:  "test",
			Count: 42,
			Tags:  []string{"tag1", "tag2"},
		}

		err := cache.Set(ctx, "complex", complex, 0)
		assert.NoError(t, err)

		val, err := cache.Get(ctx, "complex")
		assert.NoError(t, err)
		assert.Equal(t, complex, val)
	})

	t.Run("Very long keys", func(t *testing.T) {
		longKey := string(make([]byte, 1000))
		for i := range longKey {
			longKey = longKey[:i] + "a"
		}

		err := cache.Set(ctx, longKey, "value", 0)
		assert.NoError(t, err)

		val, err := cache.Get(ctx, longKey)
		assert.NoError(t, err)
		assert.Equal(t, "value", val)
	})

	t.Run("Large values", func(t *testing.T) {
		largeValue := make([]byte, 1024*1024) // 1MB
		err := cache.Set(ctx, "large", largeValue, 0)
		assert.NoError(t, err)

		val, err := cache.Get(ctx, "large")
		assert.NoError(t, err)
		assert.Equal(t, largeValue, val)
	})

	t.Run("Double connect is idempotent", func(t *testing.T) {
		cache := NewMemory(Config{Name: "double-connect"})
		err := cache.Connect()
		assert.NoError(t, err)

		err = cache.Connect()
		assert.NoError(t, err) // Should not error
		assert.True(t, cache.IsConnected())
		
		cache.Close()
	})

	t.Run("Double close is idempotent", func(t *testing.T) {
		cache := NewMemory(Config{Name: "double-close"})
		cache.Connect()

		err := cache.Close()
		assert.NoError(t, err)

		err = cache.Close()
		assert.NoError(t, err) // Should not error
	})
}

func TestCacheErrors(t *testing.T) {
	t.Run("Error constants", func(t *testing.T) {
		assert.Equal(t, "key not found in cache", ErrNotFound.Error())
		assert.Equal(t, "key already exists in cache", ErrAlreadyExists.Error())
		assert.Equal(t, "not connected to cache", ErrNotConnected.Error())
	})
}

func BenchmarkMemoryCacheSet(b *testing.B) {
	cache := NewMemory(Config{Name: "bench"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(ctx, "bench-key", i, 0)
	}
}

func BenchmarkMemoryCacheGet(b *testing.B) {
	cache := NewMemory(Config{Name: "bench"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()
	cache.Set(ctx, "bench-key", "value", 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(ctx, "bench-key")
	}
}

func BenchmarkMemoryCacheIncrement(b *testing.B) {
	cache := NewMemory(Config{Name: "bench"})
	cache.Connect()
	defer cache.Close()

	ctx := context.Background()
	cache.Set(ctx, "counter", int64(0), 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Increment(ctx, "counter", 1)
	}
}

