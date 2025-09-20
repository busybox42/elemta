package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis implements the Cache interface for Redis
type Redis struct {
	config    Config
	client    *redis.Client
	connected bool
}

// NewRedis creates a new Redis cache
func NewRedis(config Config) *Redis {
	if config.Port == 0 {
		config.Port = 6379 // Default Redis port
	}

	return &Redis{
		config:    config,
		connected: false,
	}
}

// Connect establishes a connection to Redis
func (r *Redis) Connect() error {
	if r.connected {
		return nil
	}

	r.client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", r.config.Host, r.config.Port),
		Password: r.config.Password,
		DB:       r.config.Database,
	})

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	r.connected = true
	return nil
}

// Close closes the connection to Redis
func (r *Redis) Close() error {
	if !r.connected {
		return nil
	}

	err := r.client.Close()
	if err != nil {
		return err
	}

	r.connected = false
	return nil
}

// IsConnected returns true if connected to Redis
func (r *Redis) IsConnected() bool {
	return r.connected
}

// Name returns the name of this cache instance
func (r *Redis) Name() string {
	return r.config.Name
}

// Type returns the type of this cache
func (r *Redis) Type() string {
	return "redis"
}

// Get retrieves a value from Redis
func (r *Redis) Get(ctx context.Context, key string) (interface{}, error) {
	if !r.connected {
		return nil, ErrNotConnected
	}

	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return val, nil
}

// Set stores a value in Redis
func (r *Redis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if !r.connected {
		return ErrNotConnected
	}

	return r.client.Set(ctx, key, value, expiration).Err()
}

// SetNX sets a value in Redis only if the key does not exist
func (r *Redis) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	if !r.connected {
		return false, ErrNotConnected
	}

	return r.client.SetNX(ctx, key, value, expiration).Result()
}

// Delete removes a value from Redis
func (r *Redis) Delete(ctx context.Context, key string) error {
	if !r.connected {
		return ErrNotConnected
	}

	result, err := r.client.Del(ctx, key).Result()
	if err != nil {
		return err
	}

	if result == 0 {
		return ErrNotFound
	}

	return nil
}

// Exists checks if a key exists in Redis
func (r *Redis) Exists(ctx context.Context, key string) (bool, error) {
	if !r.connected {
		return false, ErrNotConnected
	}

	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return result > 0, nil
}

// Increment increments a numeric value in Redis
func (r *Redis) Increment(ctx context.Context, key string, amount int64) (int64, error) {
	if !r.connected {
		return 0, ErrNotConnected
	}

	return r.client.IncrBy(ctx, key, amount).Result()
}

// Decrement decrements a numeric value in Redis
func (r *Redis) Decrement(ctx context.Context, key string, amount int64) (int64, error) {
	if !r.connected {
		return 0, ErrNotConnected
	}

	return r.client.DecrBy(ctx, key, amount).Result()
}

// Expire sets an expiration time on a key
func (r *Redis) Expire(ctx context.Context, key string, expiration time.Duration) error {
	if !r.connected {
		return ErrNotConnected
	}

	success, err := r.client.Expire(ctx, key, expiration).Result()
	if err != nil {
		return err
	}

	if !success {
		return ErrNotFound
	}

	return nil
}

// FlushAll removes all keys from Redis
func (r *Redis) FlushAll(ctx context.Context) error {
	if !r.connected {
		return ErrNotConnected
	}

	return r.client.FlushAll(ctx).Err()
}
