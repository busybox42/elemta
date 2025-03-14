# Caching System

Elemta includes a flexible caching system that supports multiple backends. This document explains how to configure and use the caching system.

## Supported Cache Backends

Elemta currently supports the following cache backends:

- **In-Memory**: A simple in-memory cache, ideal for development and small deployments
- **Redis**: A distributed cache using Redis, ideal for production and clustered deployments

## Configuration

The cache is configured using the `cache.Config` struct:

```go
import "github.com/yourusername/elemta/internal/cache"

// Create a cache manager with in-memory cache
inMemoryManager := cache.NewManager(&cache.Config{
    Type: "memory",
})

// Create a cache manager with Redis cache
redisManager := cache.NewManager(&cache.Config{
    Type:     "redis",
    Address:  "localhost:6379",
    Password: "",
    DB:       0,
})
```

### Configuration Options

#### Common Options

- `Type`: The type of cache to use. Valid values are `"memory"` and `"redis"`.

#### Redis-Specific Options

- `Address`: The address of the Redis server (e.g., `"localhost:6379"`)
- `Password`: The password for the Redis server (if required)
- `DB`: The Redis database number to use
- `MaxRetries`: Maximum number of retries for Redis operations
- `PoolSize`: Size of the connection pool
- `MinIdleConns`: Minimum number of idle connections in the pool

## Usage

Once you have created a cache manager, you can get a cache instance and use it:

```go
// Get a cache instance
c := manager.GetCache()

// Set a value with TTL in seconds
c.Set("key", "value", 60)

// Get a value
value, found := c.Get("key")
if found {
    fmt.Println("Value:", value)
} else {
    fmt.Println("Key not found")
}

// Delete a value
c.Delete("key")

// Check if a key exists
exists := c.Has("key")

// Clear the entire cache
c.Clear()
```

## Advanced Usage

### Working with Structured Data

You can cache any serializable data:

```go
type User struct {
    ID    int
    Name  string
    Email string
}

// Cache a user
user := User{ID: 1, Name: "John Doe", Email: "john@example.com"}
c.Set("user:1", user, 300)

// Retrieve the user
var retrievedUser User
value, found := c.Get("user:1")
if found {
    retrievedUser = value.(User)
    fmt.Println("User:", retrievedUser.Name)
}
```

### Cache Prefixing

You can use key prefixes to organize your cache:

```go
// Using prefixes for different types of data
c.Set("user:1", userData, 300)
c.Set("post:1", postData, 600)
c.Set("comment:1", commentData, 150)

// Getting all user keys (requires Redis)
// Note: This is a Redis-specific operation and not available in the generic Cache interface
```

### Cache Expiration Strategies

Different expiration strategies can be used depending on your needs:

- **Short TTL (1-5 minutes)**: For frequently changing data
- **Medium TTL (10-30 minutes)**: For semi-static data
- **Long TTL (1+ hours)**: For rarely changing data
- **No expiration (0)**: For static data (use with caution)

Example:

```go
// Frequently changing data
c.Set("active_users", activeUsers, 60) // 1 minute

// Semi-static data
c.Set("category_list", categories, 1800) // 30 minutes

// Rarely changing data
c.Set("site_configuration", config, 86400) // 24 hours

// Static data (no expiration)
c.Set("country_codes", countryCodes, 0)
```

## Best Practices

- **Use meaningful key names**: Include the data type and identifier in the key
- **Set appropriate TTLs**: Balance between performance and data freshness
- **Handle cache misses gracefully**: Always have a fallback for when data is not in the cache
- **Don't cache everything**: Focus on caching data that is expensive to compute or retrieve
- **Monitor cache usage**: Keep an eye on memory usage and hit/miss ratios

## Troubleshooting

### Redis Connection Issues

If you're having trouble connecting to Redis:

1. Check that the Redis server is running
2. Verify that the connection details (address, password) are correct
3. Ensure that the Redis server is accessible from your application
4. Check for network issues or firewall rules

### Memory Usage

If you're experiencing high memory usage with the in-memory cache:

1. Set appropriate TTLs for cached items
2. Limit the amount of data stored in the cache
3. Consider switching to Redis for better memory management

### Cache Consistency

If cached data becomes inconsistent with the source data:

1. Reduce TTLs for frequently changing data
2. Implement cache invalidation when data changes
3. Use versioned cache keys for critical data 