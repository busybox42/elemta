package context_test

import (
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/context"
	"github.com/stretchr/testify/assert"
)

func TestNewContext(t *testing.T) {
	ctx := context.NewContext()
	assert.NotNil(t, ctx)
	assert.Equal(t, 0, ctx.Count())
}

func TestSetAndGet(t *testing.T) {
	ctx := context.NewContext()

	// Test string values
	ctx.Set("string", "value")
	value, ok := ctx.Get("string")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Test int values
	ctx.Set("int", 42)
	value, ok = ctx.Get("int")
	assert.True(t, ok)
	assert.Equal(t, 42, value)

	// Test float values
	ctx.Set("float", 3.14)
	value, ok = ctx.Get("float")
	assert.True(t, ok)
	assert.Equal(t, 3.14, value)

	// Test bool values
	ctx.Set("bool", true)
	value, ok = ctx.Get("bool")
	assert.True(t, ok)
	assert.Equal(t, true, value)

	// Test non-existent key
	value, ok = ctx.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, value)
}

func TestGetTyped(t *testing.T) {
	ctx := context.NewContext()

	// Test GetString
	ctx.Set("string", "value")
	value, ok := ctx.GetString("string")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Test GetInt
	ctx.Set("int", 42)
	intValue, ok := ctx.GetInt("int")
	assert.True(t, ok)
	assert.Equal(t, 42, intValue)

	// Test GetFloat
	ctx.Set("float", 3.14)
	floatValue, ok := ctx.GetFloat("float")
	assert.True(t, ok)
	assert.Equal(t, 3.14, floatValue)

	// Test GetBool
	ctx.Set("bool", true)
	boolValue, ok := ctx.GetBool("bool")
	assert.True(t, ok)
	assert.Equal(t, true, boolValue)

	// Test type mismatch
	ctx.Set("string", "value")
	_, ok = ctx.GetInt("string")
	assert.False(t, ok)
	_, ok = ctx.GetFloat("string")
	assert.False(t, ok)
	_, ok = ctx.GetBool("string")
	assert.False(t, ok)
}

func TestSetWithExpiration(t *testing.T) {
	ctx := context.NewContext()

	// Set a value with a short expiration
	ctx.SetWithExpiration("key", "value", 50*time.Millisecond)

	// Value should be available immediately
	value, ok := ctx.Get("key")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Wait for the value to expire
	time.Sleep(100 * time.Millisecond)

	// Value should no longer be available
	value, ok = ctx.Get("key")
	assert.False(t, ok)
	assert.Nil(t, value)
}

func TestDelete(t *testing.T) {
	ctx := context.NewContext()

	// Set a value
	ctx.Set("key", "value")

	// Value should be available
	value, ok := ctx.Get("key")
	assert.True(t, ok)
	assert.Equal(t, "value", value)

	// Delete the value
	ctx.Delete("key")

	// Value should no longer be available
	value, ok = ctx.Get("key")
	assert.False(t, ok)
	assert.Nil(t, value)

	// Deleting a non-existent key should not cause an error
	ctx.Delete("nonexistent")
}

func TestClear(t *testing.T) {
	ctx := context.NewContext()

	// Set multiple values
	ctx.Set("key1", "value1")
	ctx.Set("key2", "value2")
	ctx.Set("key3", "value3")

	// All values should be available
	assert.Equal(t, 3, ctx.Count())

	// Clear the context
	ctx.Clear()

	// No values should be available
	assert.Equal(t, 0, ctx.Count())
	_, ok := ctx.Get("key1")
	assert.False(t, ok)
}

func TestKeys(t *testing.T) {
	ctx := context.NewContext()

	// Set multiple values
	ctx.Set("key1", "value1")
	ctx.Set("key2", "value2")
	ctx.Set("key3", "value3")

	// Get all keys
	keys := ctx.Keys()
	assert.Equal(t, 3, len(keys))
	assert.Contains(t, keys, "key1")
	assert.Contains(t, keys, "key2")
	assert.Contains(t, keys, "key3")
}

func TestDump(t *testing.T) {
	ctx := context.NewContext()

	// Set a value
	ctx.Set("key", "value")

	// Dump the context
	dump := ctx.Dump()
	assert.Contains(t, dump, "Context dump:")
	assert.Contains(t, dump, "key = value")
	assert.Contains(t, dump, "expires never")
}

func TestCount(t *testing.T) {
	ctx := context.NewContext()

	// Initially, count should be 0
	assert.Equal(t, 0, ctx.Count())

	// Set multiple values
	ctx.Set("key1", "value1")
	ctx.Set("key2", "value2")
	ctx.Set("key3", "value3")

	// Count should be 3
	assert.Equal(t, 3, ctx.Count())

	// Delete a value
	ctx.Delete("key1")

	// Count should be 2
	assert.Equal(t, 2, ctx.Count())

	// Clear the context
	ctx.Clear()

	// Count should be 0
	assert.Equal(t, 0, ctx.Count())
}

func TestCleanup(t *testing.T) {
	ctx := context.NewContext()

	// Set values with different expirations
	ctx.SetWithExpiration("key1", "value1", 50*time.Millisecond)
	ctx.SetWithExpiration("key2", "value2", 150*time.Millisecond)
	ctx.Set("key3", "value3") // No expiration

	// Wait for key1 to expire
	time.Sleep(100 * time.Millisecond)

	// Run cleanup
	count := ctx.Cleanup()
	assert.Equal(t, 1, count) // Only key1 should be cleaned up

	// key1 should be gone, key2 and key3 should still be there
	_, ok := ctx.Get("key1")
	assert.False(t, ok)
	_, ok = ctx.Get("key2")
	assert.True(t, ok)
	_, ok = ctx.Get("key3")
	assert.True(t, ok)

	// Wait for key2 to expire
	time.Sleep(100 * time.Millisecond)

	// Run cleanup again
	count = ctx.Cleanup()
	assert.Equal(t, 1, count) // Only key2 should be cleaned up

	// key1 and key2 should be gone, key3 should still be there
	_, ok = ctx.Get("key1")
	assert.False(t, ok)
	_, ok = ctx.Get("key2")
	assert.False(t, ok)
	_, ok = ctx.Get("key3")
	assert.True(t, ok)
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.NewContext()
	done := make(chan bool)

	// Start multiple goroutines to set and get values
	for i := 0; i < 10; i++ {
		go func(id int) {
			key := "key" + string(rune('0'+id))
			value := "value" + string(rune('0'+id))
			ctx.Set(key, value)
			time.Sleep(10 * time.Millisecond)
			val, ok := ctx.Get(key)
			assert.True(t, ok)
			assert.Equal(t, value, val)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// All values should be in the context
	assert.Equal(t, 10, ctx.Count())
}
