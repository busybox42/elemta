package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DNSCache provides caching for DNS lookups with TTL support
type DNSCache struct {
	config  *Config
	logger  *slog.Logger
	cache   map[string]*CacheEntry
	mu      sync.RWMutex
	metrics *DNSMetrics
}

// CacheEntry represents a cached DNS entry
type CacheEntry struct {
	Key       string      `json:"key"`
	Type      string      `json:"type"`
	Value     interface{} `json:"value"`
	TTL       int         `json:"ttl"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Hits      int64       `json:"hits"`
	LastHit   time.Time   `json:"last_hit"`
}

// DNSMetrics tracks DNS cache statistics
type DNSMetrics struct {
	mu             sync.RWMutex
	Queries        int64         `json:"queries"`
	CacheHits      int64         `json:"cache_hits"`
	CacheMisses    int64         `json:"cache_misses"`
	Errors         int64         `json:"errors"`
	Evictions      int64         `json:"evictions"`
	Refreshes      int64         `json:"refreshes"`
	AverageLatency time.Duration `json:"average_latency"`
	HitRatio       float64       `json:"hit_ratio"`
	CacheSize      int           `json:"cache_size"`
	MaxCacheSize   int           `json:"max_cache_size"`
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(config *Config) *DNSCache {
	return &DNSCache{
		config:  config,
		logger:  slog.Default().With("component", "dns-cache"),
		cache:   make(map[string]*CacheEntry),
		metrics: &DNSMetrics{MaxCacheSize: config.DNSCacheSize},
	}
}

// LookupMX performs MX record lookup with caching
func (dc *DNSCache) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	key := fmt.Sprintf("mx:%s", domain)

	// Check cache first
	if entry := dc.getFromCache(key); entry != nil {
		if mxRecords, ok := entry.Value.([]*net.MX); ok {
			dc.updateMetrics(true, 0)
			dc.logger.Debug("DNS cache hit", "domain", domain, "type", "MX")
			return mxRecords, nil
		}
	}

	// Cache miss, perform lookup
	startTime := time.Now()
	mxRecords, err := dc.performMXLookup(ctx, domain)
	latency := time.Since(startTime)

	if err != nil {
		dc.updateMetrics(false, latency)
		dc.metrics.mu.Lock()
		dc.metrics.Errors++
		dc.metrics.mu.Unlock()
		return nil, err
	}

	// Cache the result
	dc.putInCache(key, "MX", mxRecords, int(dc.config.DNSCacheTTL.Seconds()))
	dc.updateMetrics(false, latency)

	dc.logger.Debug("DNS lookup completed",
		"domain", domain,
		"type", "MX",
		"records", len(mxRecords),
		"latency", latency)

	return mxRecords, nil
}

// LookupA performs A record lookup with caching
func (dc *DNSCache) LookupA(ctx context.Context, hostname string) ([]net.IP, error) {
	key := fmt.Sprintf("a:%s", hostname)

	// Check cache first
	if entry := dc.getFromCache(key); entry != nil {
		if ips, ok := entry.Value.([]net.IP); ok {
			dc.updateMetrics(true, 0)
			dc.logger.Debug("DNS cache hit", "hostname", hostname, "type", "A")
			return ips, nil
		}
	}

	// Cache miss, perform lookup
	startTime := time.Now()
	ips, err := dc.performALookup(ctx, hostname)
	latency := time.Since(startTime)

	if err != nil {
		dc.updateMetrics(false, latency)
		dc.metrics.mu.Lock()
		dc.metrics.Errors++
		dc.metrics.mu.Unlock()
		return nil, err
	}

	// Cache the result
	dc.putInCache(key, "A", ips, int(dc.config.DNSCacheTTL.Seconds()))
	dc.updateMetrics(false, latency)

	dc.logger.Debug("DNS lookup completed",
		"hostname", hostname,
		"type", "A",
		"records", len(ips),
		"latency", latency)

	return ips, nil
}

// LookupTXT performs TXT record lookup with caching
func (dc *DNSCache) LookupTXT(ctx context.Context, name string) ([]string, error) {
	key := fmt.Sprintf("txt:%s", name)

	// Check cache first
	if entry := dc.getFromCache(key); entry != nil {
		if records, ok := entry.Value.([]string); ok {
			dc.updateMetrics(true, 0)
			dc.logger.Debug("DNS cache hit", "name", name, "type", "TXT")
			return records, nil
		}
	}

	// Cache miss, perform lookup
	startTime := time.Now()
	records, err := dc.performTXTLookup(ctx, name)
	latency := time.Since(startTime)

	if err != nil {
		dc.updateMetrics(false, latency)
		dc.metrics.mu.Lock()
		dc.metrics.Errors++
		dc.metrics.mu.Unlock()
		return nil, err
	}

	// Cache the result
	dc.putInCache(key, "TXT", records, int(dc.config.DNSCacheTTL.Seconds()))
	dc.updateMetrics(false, latency)

	dc.logger.Debug("DNS lookup completed",
		"name", name,
		"type", "TXT",
		"records", len(records),
		"latency", latency)

	return records, nil
}

// performMXLookup performs the actual MX lookup with retries
func (dc *DNSCache) performMXLookup(ctx context.Context, domain string) ([]*net.MX, error) {
	var mxRecords []*net.MX
	var err error

	for attempt := 0; attempt < dc.config.DNSRetries; attempt++ {
		// Use context with timeout for each attempt
		lookupCtx, cancel := context.WithTimeout(ctx, dc.config.DNSTimeout)

		mxRecords, err = net.DefaultResolver.LookupMX(lookupCtx, domain)
		cancel()

		if err == nil {
			break
		}

		dc.logger.Debug("MX lookup attempt failed",
			"domain", domain,
			"attempt", attempt+1,
			"error", err)

		// Wait before retry (with context cancellation check)
		if attempt < dc.config.DNSRetries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				// Continue to next attempt
			}
		}
	}

	return mxRecords, err
}

// performALookup performs the actual A record lookup with retries
func (dc *DNSCache) performALookup(ctx context.Context, hostname string) ([]net.IP, error) {
	var ipAddrs []net.IPAddr
	var err error

	for attempt := 0; attempt < dc.config.DNSRetries; attempt++ {
		// Use context with timeout for each attempt
		lookupCtx, cancel := context.WithTimeout(ctx, dc.config.DNSTimeout)

		ipAddrs, err = net.DefaultResolver.LookupIPAddr(lookupCtx, hostname)
		cancel()

		if err == nil {
			// Convert IPAddr to IP
			result := make([]net.IP, len(ipAddrs))
			for i, ipAddr := range ipAddrs {
				result[i] = ipAddr.IP
			}
			return result, nil
		}

		dc.logger.Debug("A lookup attempt failed",
			"hostname", hostname,
			"attempt", attempt+1,
			"error", err)

		// Wait before retry (with context cancellation check)
		if attempt < dc.config.DNSRetries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				// Continue to next attempt
			}
		}
	}

	return nil, err
}

// performTXTLookup performs the actual TXT record lookup with retries
func (dc *DNSCache) performTXTLookup(ctx context.Context, name string) ([]string, error) {
	var records []string
	var err error

	for attempt := 0; attempt < dc.config.DNSRetries; attempt++ {
		// Use context with timeout for each attempt
		lookupCtx, cancel := context.WithTimeout(ctx, dc.config.DNSTimeout)

		records, err = net.DefaultResolver.LookupTXT(lookupCtx, name)
		cancel()

		if err == nil {
			break
		}

		dc.logger.Debug("TXT lookup attempt failed",
			"name", name,
			"attempt", attempt+1,
			"error", err)

		// Wait before retry (with context cancellation check)
		if attempt < dc.config.DNSRetries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				// Continue to next attempt
			}
		}
	}

	return records, err
}

// getFromCache retrieves an entry from the cache
func (dc *DNSCache) getFromCache(key string) *CacheEntry {
	dc.mu.RLock()
	entry, exists := dc.cache[key]
	dc.mu.RUnlock()

	if !exists {
		return nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		dc.mu.Lock()
		delete(dc.cache, key)
		dc.mu.Unlock()

		dc.metrics.mu.Lock()
		dc.metrics.Evictions++
		dc.metrics.mu.Unlock()

		dc.logger.Debug("DNS cache entry expired", "key", key)
		return nil
	}

	// Update hit statistics
	dc.mu.Lock()
	entry.Hits++
	entry.LastHit = time.Now()
	dc.mu.Unlock()

	return entry
}

// putInCache stores an entry in the cache
func (dc *DNSCache) putInCache(key, recordType string, value interface{}, ttl int) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Check if cache is full
	if len(dc.cache) >= dc.config.DNSCacheSize {
		dc.evictLRU()
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:       key,
		Type:      recordType,
		Value:     value,
		TTL:       ttl,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
		Hits:      0,
		LastHit:   now,
	}

	dc.cache[key] = entry

	dc.metrics.mu.Lock()
	dc.metrics.CacheSize = len(dc.cache)
	dc.metrics.mu.Unlock()

	dc.logger.Debug("DNS cache entry stored",
		"key", key,
		"type", recordType,
		"ttl", ttl)
}

// evictLRU removes the least recently used entry from the cache
func (dc *DNSCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range dc.cache {
		if oldestKey == "" || entry.LastHit.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastHit
		}
	}

	if oldestKey != "" {
		delete(dc.cache, oldestKey)

		dc.metrics.mu.Lock()
		dc.metrics.Evictions++
		dc.metrics.mu.Unlock()

		dc.logger.Debug("DNS cache entry evicted (LRU)", "key", oldestKey)
	}
}

// updateMetrics updates DNS lookup metrics
func (dc *DNSCache) updateMetrics(hit bool, latency time.Duration) {
	dc.metrics.mu.Lock()
	defer dc.metrics.mu.Unlock()

	dc.metrics.Queries++

	if hit {
		dc.metrics.CacheHits++
	} else {
		dc.metrics.CacheMisses++

		// Update average latency for cache misses only
		if dc.metrics.CacheMisses == 1 {
			dc.metrics.AverageLatency = latency
		} else {
			dc.metrics.AverageLatency = (dc.metrics.AverageLatency + latency) / 2
		}
	}

	// Update hit ratio
	if dc.metrics.Queries > 0 {
		dc.metrics.HitRatio = float64(dc.metrics.CacheHits) / float64(dc.metrics.Queries) * 100
	}
}

// cleanup runs periodic cleanup of expired entries
func (dc *DNSCache) cleanup(ctx context.Context) {
	// Run cleanup every minute
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dc.performCleanup()
		}
	}
}

// performCleanup removes expired entries from the cache
func (dc *DNSCache) performCleanup() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	now := time.Now()
	expired := 0

	for key, entry := range dc.cache {
		if now.After(entry.ExpiresAt) {
			delete(dc.cache, key)
			expired++
		}
	}

	if expired > 0 {
		dc.metrics.mu.Lock()
		dc.metrics.Evictions += int64(expired)
		dc.metrics.CacheSize = len(dc.cache)
		dc.metrics.mu.Unlock()

		dc.logger.Debug("DNS cache cleanup completed", "expired_entries", expired)
	}
}

// Clear removes all entries from the cache
func (dc *DNSCache) Clear() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	cleared := len(dc.cache)
	dc.cache = make(map[string]*CacheEntry)

	dc.metrics.mu.Lock()
	dc.metrics.CacheSize = 0
	dc.metrics.Evictions += int64(cleared)
	dc.metrics.mu.Unlock()

	dc.logger.Info("DNS cache cleared", "entries_removed", cleared)
}

// GetStats returns current DNS cache statistics
func (dc *DNSCache) GetStats() map[string]interface{} {
	dc.metrics.mu.RLock()
	defer dc.metrics.mu.RUnlock()

	return map[string]interface{}{
		"queries":           dc.metrics.Queries,
		"cache_hits":        dc.metrics.CacheHits,
		"cache_misses":      dc.metrics.CacheMisses,
		"errors":            dc.metrics.Errors,
		"evictions":         dc.metrics.Evictions,
		"refreshes":         dc.metrics.Refreshes,
		"average_latency":   dc.metrics.AverageLatency,
		"hit_ratio":         dc.metrics.HitRatio,
		"cache_size":        dc.metrics.CacheSize,
		"max_cache_size":    dc.metrics.MaxCacheSize,
		"cache_utilization": float64(dc.metrics.CacheSize) / float64(dc.metrics.MaxCacheSize) * 100,
	}
}

// GetCacheContents returns a summary of cache contents for debugging
func (dc *DNSCache) GetCacheContents() map[string]interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	contents := make(map[string]interface{})
	typeCount := make(map[string]int)

	for key, entry := range dc.cache {
		typeCount[entry.Type]++
		contents[key] = map[string]interface{}{
			"type":       entry.Type,
			"created_at": entry.CreatedAt,
			"expires_at": entry.ExpiresAt,
			"hits":       entry.Hits,
			"last_hit":   entry.LastHit,
			"ttl":        entry.TTL,
		}
	}

	return map[string]interface{}{
		"total_entries": len(dc.cache),
		"by_type":       typeCount,
		"entries":       contents,
	}
}

// PrewarmCache preloads the cache with common DNS entries
func (dc *DNSCache) PrewarmCache(ctx context.Context, domains []string) {
	dc.logger.Info("Prewarming DNS cache", "domains", len(domains))

	for _, domain := range domains {
		// Prewarm MX records
		go func(d string) {
			if _, err := dc.LookupMX(ctx, d); err != nil {
				dc.logger.Debug("Failed to prewarm MX record", "domain", d, "error", err)
			}
		}(domain)

		// Prewarm A records for the domain
		go func(d string) {
			if _, err := dc.LookupA(ctx, d); err != nil {
				dc.logger.Debug("Failed to prewarm A record", "domain", d, "error", err)
			}
		}(domain)

		// Small delay to avoid overwhelming DNS servers
		time.Sleep(10 * time.Millisecond)
	}
}
