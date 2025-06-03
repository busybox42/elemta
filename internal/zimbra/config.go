package zimbra

import (
	"crypto/tls"
	"time"
)

// Config holds all Zimbra integration configuration
type Config struct {
	// LDAP configuration
	LDAP LDAPConfig `toml:"ldap" json:"ldap"`

	// SOAP API configuration
	SOAP SOAPConfig `toml:"soap" json:"soap"`

	// Delivery configuration
	Delivery DeliveryConfig `toml:"delivery" json:"delivery"`

	// General settings
	Enabled bool `toml:"enabled" json:"enabled"`

	// Cache settings
	Cache CacheConfig `toml:"cache" json:"cache"`
}

// LDAPConfig configures LDAP integration with Zimbra
type LDAPConfig struct {
	// Connection settings
	Servers  []string `toml:"servers" json:"servers"`
	Port     int      `toml:"port" json:"port"`
	BaseDN   string   `toml:"base_dn" json:"base_dn"`
	BindDN   string   `toml:"bind_dn" json:"bind_dn"`
	BindPass string   `toml:"bind_password" json:"bind_password"`

	// TLS settings
	TLS       bool        `toml:"tls" json:"tls"`
	StartTLS  bool        `toml:"start_tls" json:"start_tls"`
	TLSConfig *tls.Config `toml:"-" json:"-"`

	// Connection pooling
	MaxConnections int           `toml:"max_connections" json:"max_connections"`
	MaxIdleTime    time.Duration `toml:"max_idle_time" json:"max_idle_time"`

	// Timeouts
	ConnectTimeout time.Duration `toml:"connect_timeout" json:"connect_timeout"`
	SearchTimeout  time.Duration `toml:"search_timeout" json:"search_timeout"`

	// Search settings
	UserSearchBase   string `toml:"user_search_base" json:"user_search_base"`
	UserSearchFilter string `toml:"user_search_filter" json:"user_search_filter"`
	GroupSearchBase  string `toml:"group_search_base" json:"group_search_base"`
	AliasSearchBase  string `toml:"alias_search_base" json:"alias_search_base"`

	// Local domains handled by this Zimbra instance
	LocalDomains []string `toml:"local_domains" json:"local_domains"`
}

// SOAPConfig configures SOAP API integration
type SOAPConfig struct {
	// Connection settings
	URL      string `toml:"url" json:"url"`
	AdminURL string `toml:"admin_url" json:"admin_url"`

	// Authentication
	AdminUser     string `toml:"admin_user" json:"admin_user"`
	AdminPassword string `toml:"admin_password" json:"admin_password"`

	// HTTP settings
	Timeout    time.Duration `toml:"timeout" json:"timeout"`
	MaxRetries int           `toml:"max_retries" json:"max_retries"`
	RetryDelay time.Duration `toml:"retry_delay" json:"retry_delay"`

	// TLS settings
	TLS           bool        `toml:"tls" json:"tls"`
	TLSConfig     *tls.Config `toml:"-" json:"-"`
	SkipTLSVerify bool        `toml:"skip_tls_verify" json:"skip_tls_verify"`

	// Token management
	TokenLifetime time.Duration `toml:"token_lifetime" json:"token_lifetime"`

	// Circuit breaker settings
	CircuitBreakerThreshold int           `toml:"circuit_breaker_threshold" json:"circuit_breaker_threshold"`
	CircuitBreakerTimeout   time.Duration `toml:"circuit_breaker_timeout" json:"circuit_breaker_timeout"`
}

// DeliveryConfig configures message delivery to Zimbra
type DeliveryConfig struct {
	// LMTP settings
	LMTPServers []string      `toml:"lmtp_servers" json:"lmtp_servers"`
	LMTPPort    int           `toml:"lmtp_port" json:"lmtp_port"`
	LMTPTimeout time.Duration `toml:"lmtp_timeout" json:"lmtp_timeout"`

	// Connection pooling
	MaxConnections  int           `toml:"max_connections" json:"max_connections"`
	MaxIdleTime     time.Duration `toml:"max_idle_time" json:"max_idle_time"`
	HealthCheckTime time.Duration `toml:"health_check_time" json:"health_check_time"`

	// Delivery settings
	RetryAttempts int           `toml:"retry_attempts" json:"retry_attempts"`
	RetryDelay    time.Duration `toml:"retry_delay" json:"retry_delay"`

	// Local domains (delivered via LMTP)
	LocalDomains []string `toml:"local_domains" json:"local_domains"`
}

// CacheConfig configures caching for LDAP and SOAP responses
type CacheConfig struct {
	// User cache settings
	UserCacheTTL  time.Duration `toml:"user_cache_ttl" json:"user_cache_ttl"`
	UserCacheSize int           `toml:"user_cache_size" json:"user_cache_size"`

	// Alias cache settings
	AliasCacheTTL  time.Duration `toml:"alias_cache_ttl" json:"alias_cache_ttl"`
	AliasCacheSize int           `toml:"alias_cache_size" json:"alias_cache_size"`

	// Group cache settings
	GroupCacheTTL  time.Duration `toml:"group_cache_ttl" json:"group_cache_ttl"`
	GroupCacheSize int           `toml:"group_cache_size" json:"group_cache_size"`

	// Policy cache settings
	PolicyCacheTTL  time.Duration `toml:"policy_cache_ttl" json:"policy_cache_ttl"`
	PolicyCacheSize int           `toml:"policy_cache_size" json:"policy_cache_size"`
}

// DefaultConfig returns a default Zimbra configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		LDAP: LDAPConfig{
			Servers:          []string{"localhost"},
			Port:             389,
			BaseDN:           "dc=zimbra,dc=local",
			MaxConnections:   10,
			MaxIdleTime:      5 * time.Minute,
			ConnectTimeout:   10 * time.Second,
			SearchTimeout:    30 * time.Second,
			UserSearchBase:   "ou=people",
			UserSearchFilter: "(mail=%s)",
			GroupSearchBase:  "ou=groups",
			AliasSearchBase:  "ou=aliases",
			LocalDomains:     []string{"zimbra-test.local"},
		},
		SOAP: SOAPConfig{
			URL:                     "https://zimbra-test.local:7071/service/admin/soap",
			AdminURL:                "https://zimbra-test.local:7071/service/admin/soap",
			Timeout:                 30 * time.Second,
			MaxRetries:              3,
			RetryDelay:              time.Second,
			TokenLifetime:           24 * time.Hour,
			CircuitBreakerThreshold: 5,
			CircuitBreakerTimeout:   30 * time.Second,
		},
		Delivery: DeliveryConfig{
			LMTPServers:     []string{"zimbra-test.local"},
			LMTPPort:        7025,
			LMTPTimeout:     60 * time.Second,
			MaxConnections:  10,
			MaxIdleTime:     5 * time.Minute,
			HealthCheckTime: time.Minute,
			RetryAttempts:   3,
			RetryDelay:      30 * time.Second,
			LocalDomains:    []string{"zimbra-test.local"},
		},
		Cache: CacheConfig{
			UserCacheTTL:    5 * time.Minute,
			UserCacheSize:   1000,
			AliasCacheTTL:   10 * time.Minute,
			AliasCacheSize:  500,
			GroupCacheTTL:   10 * time.Minute,
			GroupCacheSize:  200,
			PolicyCacheTTL:  15 * time.Minute,
			PolicyCacheSize: 100,
		},
	}
}
