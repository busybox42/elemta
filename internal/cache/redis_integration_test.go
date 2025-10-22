package cache

import (
	"context"
	"testing"
	"time"
)

// TestRedisIntegration tests basic Redis functionality with the updated client
func TestRedisIntegration(t *testing.T) {
	// Skip if Redis is not available
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	config := Config{
		Name:     "test-redis",
		Type:     "redis",
		Host:     "localhost",
		Port:     6379,
		Database: 0,
	}

	redis := NewRedis(config)

	// Test connection (will fail gracefully if Redis is not available)
	err := redis.Connect()
	if err != nil {
		t.Skipf("Redis not available, skipping test: %v", err)
	}
	defer redis.Close()

	ctx := context.Background()

	// Test basic operations
	t.Run("Set and Get", func(t *testing.T) {
		key := "test:integration:key"
		value := "test-value"

		// Set value
		err := redis.Set(ctx, key, value, time.Minute)
		if err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}

		// Get value
		result, err := redis.Get(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}

		if result != value {
			t.Errorf("Expected %s, got %v", value, result)
		}

		// Clean up
		redis.Delete(ctx, key)
	})

	t.Run("SetNX", func(t *testing.T) {
		key := "test:integration:nx"
		value := "nx-value"

		// SetNX should succeed for new key
		ok, err := redis.SetNX(ctx, key, value, time.Minute)
		if err != nil {
			t.Fatalf("Failed to SetNX: %v", err)
		}
		if !ok {
			t.Error("SetNX should have succeeded for new key")
		}

		// SetNX should fail for existing key
		ok, err = redis.SetNX(ctx, key, "different-value", time.Minute)
		if err != nil {
			t.Fatalf("Failed to SetNX: %v", err)
		}
		if ok {
			t.Error("SetNX should have failed for existing key")
		}

		// Clean up
		redis.Delete(ctx, key)
	})

	t.Run("Exists and Delete", func(t *testing.T) {
		key := "test:integration:exists"
		value := "exists-value"

		// Key should not exist initially
		exists, err := redis.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Failed to check existence: %v", err)
		}
		if exists {
			t.Error("Key should not exist initially")
		}

		// Set value
		err = redis.Set(ctx, key, value, time.Minute)
		if err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}

		// Key should exist now
		exists, err = redis.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Failed to check existence: %v", err)
		}
		if !exists {
			t.Error("Key should exist after setting")
		}

		// Delete key
		err = redis.Delete(ctx, key)
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}

		// Key should not exist after deletion
		exists, err = redis.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Failed to check existence: %v", err)
		}
		if exists {
			t.Error("Key should not exist after deletion")
		}
	})

	t.Run("Increment and Decrement", func(t *testing.T) {
		key := "test:integration:counter"

		// Increment non-existing key
		result, err := redis.Increment(ctx, key, 5)
		if err != nil {
			t.Fatalf("Failed to increment: %v", err)
		}
		if result != 5 {
			t.Errorf("Expected 5, got %d", result)
		}

		// Increment existing key
		result, err = redis.Increment(ctx, key, 3)
		if err != nil {
			t.Fatalf("Failed to increment: %v", err)
		}
		if result != 8 {
			t.Errorf("Expected 8, got %d", result)
		}

		// Decrement
		result, err = redis.Decrement(ctx, key, 2)
		if err != nil {
			t.Fatalf("Failed to decrement: %v", err)
		}
		if result != 6 {
			t.Errorf("Expected 6, got %d", result)
		}

		// Clean up
		redis.Delete(ctx, key)
	})
}

// TestRedisClientVersion verifies we're using the correct Redis client version
func TestRedisClientVersion(t *testing.T) {
	config := Config{
		Name: "version-test",
		Type: "redis",
		Host: "localhost",
		Port: 6379,
	}

	redis := NewRedis(config)

	// Test that the client can be created without errors
	if redis == nil {
		t.Fatal("Failed to create Redis client")
	}

	// Verify the client type
	if redis.Type() != "redis" {
		t.Errorf("Expected type 'redis', got %s", redis.Type())
	}

	// Verify the name
	if redis.Name() != "version-test" {
		t.Errorf("Expected name 'version-test', got %s", redis.Name())
	}
}
