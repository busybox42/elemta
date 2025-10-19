package zimbra

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config, "Should return non-nil config")
	assert.False(t, config.Enabled, "Should be disabled by default")

	t.Run("LDAP defaults", func(t *testing.T) {
		assert.Equal(t, []string{"localhost"}, config.LDAP.Servers)
		assert.Equal(t, 389, config.LDAP.Port)
		assert.Equal(t, "dc=zimbra,dc=local", config.LDAP.BaseDN)
		assert.Equal(t, 10, config.LDAP.MaxConnections)
		assert.Equal(t, 5*time.Minute, config.LDAP.MaxIdleTime)
		assert.Equal(t, 10*time.Second, config.LDAP.ConnectTimeout)
		assert.Equal(t, 30*time.Second, config.LDAP.SearchTimeout)
		assert.Equal(t, "ou=people", config.LDAP.UserSearchBase)
		assert.Equal(t, "(mail=%s)", config.LDAP.UserSearchFilter)
		assert.Equal(t, "ou=groups", config.LDAP.GroupSearchBase)
		assert.Equal(t, "ou=aliases", config.LDAP.AliasSearchBase)
		assert.Equal(t, []string{"zimbra-test.local"}, config.LDAP.LocalDomains)
	})

	t.Run("SOAP defaults", func(t *testing.T) {
		assert.Equal(t, "https://zimbra-test.local:7071/service/admin/soap", config.SOAP.URL)
		assert.Equal(t, "https://zimbra-test.local:7071/service/admin/soap", config.SOAP.AdminURL)
		assert.Equal(t, 30*time.Second, config.SOAP.Timeout)
		assert.Equal(t, 3, config.SOAP.MaxRetries)
		assert.Equal(t, time.Second, config.SOAP.RetryDelay)
		assert.Equal(t, 24*time.Hour, config.SOAP.TokenLifetime)
		assert.Equal(t, 5, config.SOAP.CircuitBreakerThreshold)
		assert.Equal(t, 30*time.Second, config.SOAP.CircuitBreakerTimeout)
	})

	t.Run("Delivery defaults", func(t *testing.T) {
		assert.Equal(t, []string{"zimbra-test.local"}, config.Delivery.LMTPServers)
		assert.Equal(t, 7025, config.Delivery.LMTPPort)
		assert.Equal(t, 60*time.Second, config.Delivery.LMTPTimeout)
		assert.Equal(t, 10, config.Delivery.MaxConnections)
		assert.Equal(t, 5*time.Minute, config.Delivery.MaxIdleTime)
		assert.Equal(t, time.Minute, config.Delivery.HealthCheckTime)
		assert.Equal(t, 3, config.Delivery.RetryAttempts)
		assert.Equal(t, 30*time.Second, config.Delivery.RetryDelay)
		assert.Equal(t, []string{"zimbra-test.local"}, config.Delivery.LocalDomains)
	})

	t.Run("Cache defaults", func(t *testing.T) {
		assert.Equal(t, 5*time.Minute, config.Cache.UserCacheTTL)
		assert.Equal(t, 1000, config.Cache.UserCacheSize)
		assert.Equal(t, 10*time.Minute, config.Cache.AliasCacheTTL)
		assert.Equal(t, 500, config.Cache.AliasCacheSize)
		assert.Equal(t, 10*time.Minute, config.Cache.GroupCacheTTL)
		assert.Equal(t, 200, config.Cache.GroupCacheSize)
		assert.Equal(t, 15*time.Minute, config.Cache.PolicyCacheTTL)
		assert.Equal(t, 100, config.Cache.PolicyCacheSize)
	})
}

func TestLDAPConfig(t *testing.T) {
	t.Run("Create custom LDAP config", func(t *testing.T) {
		config := &LDAPConfig{
			Servers:          []string{"ldap1.example.com", "ldap2.example.com"},
			Port:             636, // LDAPS
			BaseDN:           "dc=example,dc=com",
			BindDN:           "cn=admin,dc=example,dc=com",
			BindPass:         "secret",
			TLS:              true,
			StartTLS:         false,
			MaxConnections:   20,
			MaxIdleTime:      10 * time.Minute,
			ConnectTimeout:   15 * time.Second,
			SearchTimeout:    45 * time.Second,
			UserSearchBase:   "ou=users",
			UserSearchFilter: "(uid=%s)",
			GroupSearchBase:  "ou=groups",
			AliasSearchBase:  "ou=email",
			LocalDomains:     []string{"example.com", "mail.example.com"},
		}

		assert.Len(t, config.Servers, 2)
		assert.Equal(t, 636, config.Port)
		assert.True(t, config.TLS)
		assert.False(t, config.StartTLS)
		assert.Equal(t, 20, config.MaxConnections)
		assert.Len(t, config.LocalDomains, 2)
	})

	t.Run("LDAP config with StartTLS", func(t *testing.T) {
		config := &LDAPConfig{
			Port:     389,
			StartTLS: true,
			TLS:      false,
		}

		assert.Equal(t, 389, config.Port)
		assert.True(t, config.StartTLS)
		assert.False(t, config.TLS)
	})

	t.Run("LDAP config with multiple local domains", func(t *testing.T) {
		domains := []string{
			"domain1.com",
			"domain2.com",
			"domain3.com",
			"subdomain.domain1.com",
		}

		config := &LDAPConfig{
			LocalDomains: domains,
		}

		assert.Equal(t, domains, config.LocalDomains)
		assert.Len(t, config.LocalDomains, 4)
	})
}

func TestSOAPConfig(t *testing.T) {
	t.Run("Create custom SOAP config", func(t *testing.T) {
		config := &SOAPConfig{
			URL:                     "https://zimbra.example.com:7071/service/soap",
			AdminURL:                "https://zimbra.example.com:7071/service/admin/soap",
			AdminUser:               "admin",
			AdminPassword:           "secure_password",
			Timeout:                 60 * time.Second,
			MaxRetries:              5,
			RetryDelay:              2 * time.Second,
			TLS:                     true,
			SkipTLSVerify:           false,
			TokenLifetime:           12 * time.Hour,
			CircuitBreakerThreshold: 10,
			CircuitBreakerTimeout:   60 * time.Second,
		}

		assert.Contains(t, config.URL, "zimbra.example.com")
		assert.Equal(t, "admin", config.AdminUser)
		assert.Equal(t, 60*time.Second, config.Timeout)
		assert.Equal(t, 5, config.MaxRetries)
		assert.True(t, config.TLS)
		assert.False(t, config.SkipTLSVerify)
	})

	t.Run("SOAP config with TLS verification disabled", func(t *testing.T) {
		config := &SOAPConfig{
			URL:           "https://self-signed.example.com:7071/service/soap",
			TLS:           true,
			SkipTLSVerify: true, // For self-signed certs
		}

		assert.True(t, config.TLS)
		assert.True(t, config.SkipTLSVerify)
	})

	t.Run("SOAP config with circuit breaker", func(t *testing.T) {
		config := &SOAPConfig{
			CircuitBreakerThreshold: 3,
			CircuitBreakerTimeout:   15 * time.Second,
		}

		assert.Equal(t, 3, config.CircuitBreakerThreshold)
		assert.Equal(t, 15*time.Second, config.CircuitBreakerTimeout)
	})
}

func TestDeliveryConfig(t *testing.T) {
	t.Run("Create custom delivery config", func(t *testing.T) {
		config := &DeliveryConfig{
			LMTPServers:     []string{"lmtp1.example.com", "lmtp2.example.com"},
			LMTPPort:        24,
			LMTPTimeout:     120 * time.Second,
			MaxConnections:  25,
			MaxIdleTime:     10 * time.Minute,
			HealthCheckTime: 2 * time.Minute,
			RetryAttempts:   5,
			RetryDelay:      60 * time.Second,
			LocalDomains:    []string{"example.com", "mail.example.com"},
		}

		assert.Len(t, config.LMTPServers, 2)
		assert.Equal(t, 24, config.LMTPPort)
		assert.Equal(t, 120*time.Second, config.LMTPTimeout)
		assert.Equal(t, 25, config.MaxConnections)
		assert.Len(t, config.LocalDomains, 2)
	})

	t.Run("Delivery config with connection pooling", func(t *testing.T) {
		config := &DeliveryConfig{
			MaxConnections:  50,
			MaxIdleTime:     15 * time.Minute,
			HealthCheckTime: 30 * time.Second,
		}

		assert.Equal(t, 50, config.MaxConnections)
		assert.Equal(t, 15*time.Minute, config.MaxIdleTime)
		assert.Equal(t, 30*time.Second, config.HealthCheckTime)
	})

	t.Run("Delivery config with retry settings", func(t *testing.T) {
		config := &DeliveryConfig{
			RetryAttempts: 10,
			RetryDelay:    5 * time.Minute,
		}

		assert.Equal(t, 10, config.RetryAttempts)
		assert.Equal(t, 5*time.Minute, config.RetryDelay)
	})
}

func TestCacheConfig(t *testing.T) {
	t.Run("Create custom cache config", func(t *testing.T) {
		config := &CacheConfig{
			UserCacheTTL:    15 * time.Minute,
			UserCacheSize:   5000,
			AliasCacheTTL:   30 * time.Minute,
			AliasCacheSize:  2000,
			GroupCacheTTL:   30 * time.Minute,
			GroupCacheSize:  1000,
			PolicyCacheTTL:  60 * time.Minute,
			PolicyCacheSize: 500,
		}

		assert.Equal(t, 15*time.Minute, config.UserCacheTTL)
		assert.Equal(t, 5000, config.UserCacheSize)
		assert.Equal(t, 30*time.Minute, config.AliasCacheTTL)
		assert.Equal(t, 2000, config.AliasCacheSize)
	})

	t.Run("Cache config with large sizes", func(t *testing.T) {
		config := &CacheConfig{
			UserCacheSize:   100000,
			AliasCacheSize:  50000,
			GroupCacheSize:  10000,
			PolicyCacheSize: 5000,
		}

		assert.Equal(t, 100000, config.UserCacheSize)
		assert.Equal(t, 50000, config.AliasCacheSize)
		assert.Equal(t, 10000, config.GroupCacheSize)
		assert.Equal(t, 5000, config.PolicyCacheSize)
	})

	t.Run("Cache config with long TTLs", func(t *testing.T) {
		config := &CacheConfig{
			UserCacheTTL:   24 * time.Hour,
			AliasCacheTTL:  48 * time.Hour,
			GroupCacheTTL:  72 * time.Hour,
			PolicyCacheTTL: 168 * time.Hour, // 1 week
		}

		assert.Equal(t, 24*time.Hour, config.UserCacheTTL)
		assert.Equal(t, 168*time.Hour, config.PolicyCacheTTL)
	})
}

func TestCompleteZimbraConfig(t *testing.T) {
	t.Run("Create complete Zimbra configuration", func(t *testing.T) {
		config := &Config{
			Enabled: true,
			LDAP: LDAPConfig{
				Servers:        []string{"ldap.zimbra.com"},
				Port:           389,
				BaseDN:         "dc=zimbra,dc=com",
				LocalDomains:   []string{"zimbra.com"},
				MaxConnections: 15,
			},
			SOAP: SOAPConfig{
				URL:        "https://zimbra.com:7071/service/admin/soap",
				AdminUser:  "admin",
				MaxRetries: 3,
			},
			Delivery: DeliveryConfig{
				LMTPServers:  []string{"lmtp.zimbra.com"},
				LMTPPort:     7025,
				LocalDomains: []string{"zimbra.com"},
			},
			Cache: CacheConfig{
				UserCacheSize: 2000,
				UserCacheTTL:  10 * time.Minute,
			},
		}

		assert.True(t, config.Enabled)
		assert.NotNil(t, config.LDAP)
		assert.NotNil(t, config.SOAP)
		assert.NotNil(t, config.Delivery)
		assert.NotNil(t, config.Cache)
	})

	t.Run("Disabled Zimbra configuration", func(t *testing.T) {
		config := &Config{
			Enabled: false,
		}

		assert.False(t, config.Enabled)
		// Other fields can be zero-values when disabled
	})
}

func TestLDAPConfigTimeouts(t *testing.T) {
	t.Run("Short timeouts", func(t *testing.T) {
		config := &LDAPConfig{
			ConnectTimeout: 1 * time.Second,
			SearchTimeout:  5 * time.Second,
			MaxIdleTime:    30 * time.Second,
		}

		assert.Equal(t, 1*time.Second, config.ConnectTimeout)
		assert.Equal(t, 5*time.Second, config.SearchTimeout)
		assert.Equal(t, 30*time.Second, config.MaxIdleTime)
	})

	t.Run("Long timeouts for slow networks", func(t *testing.T) {
		config := &LDAPConfig{
			ConnectTimeout: 30 * time.Second,
			SearchTimeout:  2 * time.Minute,
			MaxIdleTime:    30 * time.Minute,
		}

		assert.Equal(t, 30*time.Second, config.ConnectTimeout)
		assert.Equal(t, 2*time.Minute, config.SearchTimeout)
		assert.Equal(t, 30*time.Minute, config.MaxIdleTime)
	})
}

func TestSOAPConfigRetry(t *testing.T) {
	t.Run("Aggressive retry config", func(t *testing.T) {
		config := &SOAPConfig{
			MaxRetries: 10,
			RetryDelay: 500 * time.Millisecond,
		}

		assert.Equal(t, 10, config.MaxRetries)
		assert.Equal(t, 500*time.Millisecond, config.RetryDelay)
	})

	t.Run("Conservative retry config", func(t *testing.T) {
		config := &SOAPConfig{
			MaxRetries: 1,
			RetryDelay: 5 * time.Second,
		}

		assert.Equal(t, 1, config.MaxRetries)
		assert.Equal(t, 5*time.Second, config.RetryDelay)
	})

	t.Run("No retry config", func(t *testing.T) {
		config := &SOAPConfig{
			MaxRetries: 0,
			RetryDelay: 0,
		}

		assert.Equal(t, 0, config.MaxRetries)
		assert.Equal(t, time.Duration(0), config.RetryDelay)
	})
}

func TestDeliveryConfigConnectionPooling(t *testing.T) {
	t.Run("Small pool for low-volume", func(t *testing.T) {
		config := &DeliveryConfig{
			MaxConnections:  5,
			MaxIdleTime:     1 * time.Minute,
			HealthCheckTime: 30 * time.Second,
		}

		assert.Equal(t, 5, config.MaxConnections)
		assert.Equal(t, 1*time.Minute, config.MaxIdleTime)
	})

	t.Run("Large pool for high-volume", func(t *testing.T) {
		config := &DeliveryConfig{
			MaxConnections:  100,
			MaxIdleTime:     30 * time.Minute,
			HealthCheckTime: 5 * time.Minute,
		}

		assert.Equal(t, 100, config.MaxConnections)
		assert.Equal(t, 30*time.Minute, config.MaxIdleTime)
		assert.Equal(t, 5*time.Minute, config.HealthCheckTime)
	})
}

func TestConfigEdgeCases(t *testing.T) {
	t.Run("Config with empty strings", func(t *testing.T) {
		config := &Config{
			Enabled: true,
			LDAP: LDAPConfig{
				BaseDN:   "",
				BindDN:   "",
				BindPass: "",
			},
		}

		assert.True(t, config.Enabled)
		assert.Empty(t, config.LDAP.BaseDN)
		assert.Empty(t, config.LDAP.BindDN)
	})

	t.Run("Config with zero timeouts", func(t *testing.T) {
		config := &Config{
			LDAP: LDAPConfig{
				ConnectTimeout: 0,
				SearchTimeout:  0,
			},
			SOAP: SOAPConfig{
				Timeout: 0,
			},
			Delivery: DeliveryConfig{
				LMTPTimeout: 0,
			},
		}

		assert.Equal(t, time.Duration(0), config.LDAP.ConnectTimeout)
		assert.Equal(t, time.Duration(0), config.SOAP.Timeout)
		assert.Equal(t, time.Duration(0), config.Delivery.LMTPTimeout)
	})

	t.Run("Config with nil TLSConfig", func(t *testing.T) {
		config := &LDAPConfig{
			TLS:       true,
			TLSConfig: nil, // Will be populated at runtime
		}

		assert.True(t, config.TLS)
		assert.Nil(t, config.TLSConfig)
	})

	t.Run("Config with empty server lists", func(t *testing.T) {
		config := &Config{
			LDAP: LDAPConfig{
				Servers: []string{},
			},
			Delivery: DeliveryConfig{
				LMTPServers: []string{},
			},
		}

		assert.Empty(t, config.LDAP.Servers)
		assert.Empty(t, config.Delivery.LMTPServers)
	})
}

func TestSearchFilters(t *testing.T) {
	t.Run("Standard email search filter", func(t *testing.T) {
		config := &LDAPConfig{
			UserSearchFilter: "(mail=%s)",
		}

		assert.Equal(t, "(mail=%s)", config.UserSearchFilter)
	})

	t.Run("UID-based search filter", func(t *testing.T) {
		config := &LDAPConfig{
			UserSearchFilter: "(uid=%s)",
		}

		assert.Equal(t, "(uid=%s)", config.UserSearchFilter)
	})

	t.Run("Complex OR filter", func(t *testing.T) {
		config := &LDAPConfig{
			UserSearchFilter: "(|(mail=%s)(uid=%s)(zimbraMailAlias=%s))",
		}

		assert.Contains(t, config.UserSearchFilter, "mail=%s")
		assert.Contains(t, config.UserSearchFilter, "uid=%s")
		assert.Contains(t, config.UserSearchFilter, "zimbraMailAlias=%s")
	})
}

func BenchmarkDefaultConfig(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultConfig()
	}
}

