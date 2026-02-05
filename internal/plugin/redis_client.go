package plugin

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"log/slog"

	"github.com/valkey-io/valkey-go"
)

// RedisClient wraps Valkey operations for rate limiting
type RedisClient struct {
	client    valkey.Client
	keyPrefix string
	logger    *slog.Logger
	enabled   bool
}

// NewRedisClient creates a new Valkey client for rate limiting
func NewRedisClient(redisURL, keyPrefix string, logger *slog.Logger) (*RedisClient, error) {
	if redisURL == "" {
		return &RedisClient{
			enabled: false,
			logger:  logger,
		}, nil
	}

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{redisURL},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Valkey client: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		return nil, fmt.Errorf("failed to connect to Valkey: %w", err)
	}

	return &RedisClient{
		client:    client,
		keyPrefix: keyPrefix,
		logger:    logger,
		enabled:   true,
	}, nil
}

// Close closes the Valkey connection
func (rc *RedisClient) Close() error {
	if !rc.enabled || rc.client == nil {
		return nil
	}
	rc.client.Close()
	return nil
}

// GetTokenBucket retrieves token bucket state from Valkey
func (rc *RedisClient) GetTokenBucket(ctx context.Context, key string) (*TokenBucketState, error) {
	if !rc.enabled {
		return nil, fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized //nolint:staticcheck // Product name should be capitalized
	}

	fullKey := rc.keyPrefix + ":" + key

	// Get current state
	tokensCmd := rc.client.Do(ctx, rc.client.B().Get().Key(fullKey+":tokens").Build())
	lastRefillCmd := rc.client.Do(ctx, rc.client.B().Get().Key(fullKey+":last_refill").Build())

	// Parse tokens
	tokens := 0.0
	if tokensStr, err := tokensCmd.ToString(); err == nil {
		if t, err := strconv.ParseFloat(tokensStr, 64); err == nil {
			tokens = t
		}
	}

	// Parse last refill time
	lastRefill := time.Now()
	if lastRefillStr, err := lastRefillCmd.ToString(); err == nil {
		if t, err := strconv.ParseInt(lastRefillStr, 10, 64); err == nil {
			lastRefill = time.Unix(t, 0)
		}
	}

	return &TokenBucketState{
		Tokens:     tokens,
		LastRefill: lastRefill,
	}, nil
}

// SetTokenBucket stores token bucket state in Valkey
func (rc *RedisClient) SetTokenBucket(ctx context.Context, key string, state *TokenBucketState, ttl time.Duration) error {
	if !rc.enabled {
		return fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized //nolint:staticcheck // Product name should be capitalized
	}

	fullKey := rc.keyPrefix + ":" + key

	// Set tokens
	err := rc.client.Do(ctx, rc.client.B().Setex().Key(fullKey+":tokens").Seconds(int64(ttl.Seconds())).Value(fmt.Sprintf("%.6f", state.Tokens)).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to set tokens: %w", err)
	}

	// Set last refill time
	err = rc.client.Do(ctx, rc.client.B().Setex().Key(fullKey+":last_refill").Seconds(int64(ttl.Seconds())).Value(fmt.Sprintf("%d", state.LastRefill.Unix())).Build()).Error()
	if err != nil {
		return fmt.Errorf("failed to set last refill time: %w", err)
	}

	return nil
}

// IncrementCounter increments a counter in Valkey
func (rc *RedisClient) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if !rc.enabled {
		return 0, fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	fullKey := rc.keyPrefix + ":" + key

	// Increment counter
	incrCmd := rc.client.Do(ctx, rc.client.B().Incr().Key(fullKey).Build())
	if err := incrCmd.Error(); err != nil {
		return 0, fmt.Errorf("failed to increment counter: %w", err)
	}

	// Set expiration
	err := rc.client.Do(ctx, rc.client.B().Expire().Key(fullKey).Seconds(int64(ttl.Seconds())).Build()).Error()
	if err != nil {
		return 0, fmt.Errorf("failed to set expiration: %w", err)
	}

	return incrCmd.AsInt64()
}

// GetCounter retrieves a counter value from Valkey
func (rc *RedisClient) GetCounter(ctx context.Context, key string) (int64, error) {
	if !rc.enabled {
		return 0, fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	fullKey := rc.keyPrefix + ":" + key

	val, err := rc.client.Do(ctx, rc.client.B().Get().Key(fullKey).Build()).ToString()
	if err != nil {
		return 0, nil // Key doesn't exist
	}

	return strconv.ParseInt(val, 10, 64)
}

// SetWhitelistItem adds an item to the whitelist in Valkey
func (rc *RedisClient) SetWhitelistItem(ctx context.Context, item string) error {
	if !rc.enabled {
		return fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	key := rc.keyPrefix + ":whitelist:" + item
	return rc.client.Do(ctx, rc.client.B().Set().Key(key).Value("1").Build()).Error()
}

// SetBlacklistItem adds an item to the blacklist in Valkey
func (rc *RedisClient) SetBlacklistItem(ctx context.Context, item string) error {
	if !rc.enabled {
		return fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	key := rc.keyPrefix + ":blacklist:" + item
	return rc.client.Do(ctx, rc.client.B().Set().Key(key).Value("1").Build()).Error()
}

// RemoveWhitelistItem removes an item from the whitelist in Valkey
func (rc *RedisClient) RemoveWhitelistItem(ctx context.Context, item string) error {
	if !rc.enabled {
		return fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	key := rc.keyPrefix + ":whitelist:" + item
	return rc.client.Do(ctx, rc.client.B().Del().Key(key).Build()).Error()
}

// RemoveBlacklistItem removes an item from the blacklist in Valkey
func (rc *RedisClient) RemoveBlacklistItem(ctx context.Context, item string) error {
	if !rc.enabled {
		return fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	key := rc.keyPrefix + ":blacklist:" + item
	return rc.client.Do(ctx, rc.client.B().Del().Key(key).Build()).Error()
}

// IsWhitelisted checks if an item is whitelisted in Valkey
func (rc *RedisClient) IsWhitelisted(ctx context.Context, item string) (bool, error) {
	if !rc.enabled {
		return false, fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	key := rc.keyPrefix + ":whitelist:" + item
	_, err := rc.client.Do(ctx, rc.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return false, nil // Key doesn't exist
	}
	return true, nil
}

// IsBlacklisted checks if an item is blacklisted in Valkey
func (rc *RedisClient) IsBlacklisted(ctx context.Context, item string) (bool, error) {
	if !rc.enabled {
		return false, fmt.Errorf("Valkey client not enabled") //nolint:staticcheck // Product name should be capitalized
	}

	key := rc.keyPrefix + ":blacklist:" + item
	_, err := rc.client.Do(ctx, rc.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return false, nil // Key doesn't exist
	}
	return true, nil
}

// TokenBucketState represents the state of a token bucket in Valkey
type TokenBucketState struct {
	Tokens     float64
	LastRefill time.Time
}
