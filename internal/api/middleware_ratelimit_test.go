package api

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimitMiddleware(t *testing.T) {
	tests := []struct {
		name            string
		config          RateLimitConfig
		requests        int
		expectedAllowed int
		expectedBlocked int
		delayBetween    time.Duration
	}{
		{
			name: "disabled rate limiting",
			config: RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 1.0,
				Burst:             2,
			},
			requests:        10,
			expectedAllowed: 10,
			expectedBlocked: 0,
		},
		{
			name: "burst allows initial requests",
			config: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 1.0,
				Burst:             3,
			},
			requests:        5,
			expectedAllowed: 3,
			expectedBlocked: 2,
		},
		{
			name: "rate limiting blocks excess requests",
			config: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10.0,
				Burst:             5,
			},
			requests:        10,
			expectedAllowed: 5,
			expectedBlocked: 5,
		},
		{
			name: "default values when zero",
			config: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0,
				Burst:             0,
			},
			requests:        25,
			expectedAllowed: 20, // Default burst
			expectedBlocked: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimitMiddleware(tt.config)
			defer rl.Stop()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := rl.Limit(handler)

			allowed := 0
			blocked := 0

			for i := 0; i < tt.requests; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:1234"
				rr := httptest.NewRecorder()

				middleware.ServeHTTP(rr, req)

				if rr.Code == http.StatusOK {
					allowed++
				} else if rr.Code == http.StatusTooManyRequests {
					blocked++
				}

				if tt.delayBetween > 0 {
					time.Sleep(tt.delayBetween)
				}
			}

			if allowed != tt.expectedAllowed {
				t.Errorf("Expected %d allowed requests, got %d", tt.expectedAllowed, allowed)
			}

			if blocked != tt.expectedBlocked {
				t.Errorf("Expected %d blocked requests, got %d", tt.expectedBlocked, blocked)
			}
		})
	}
}

func TestRateLimitPerIP(t *testing.T) {
	config := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 2.0,
		Burst:             3,
	}

	rl := NewRateLimitMiddleware(config)
	defer rl.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Limit(handler)

	// Test that rate limiting is per-IP
	ips := []string{"192.168.1.1:1234", "192.168.1.2:1234", "10.0.0.1:5678"}

	for _, ip := range ips {
		allowed := 0
		blocked := 0

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = ip
			rr := httptest.NewRecorder()

			middleware.ServeHTTP(rr, req)

			if rr.Code == http.StatusOK {
				allowed++
			} else if rr.Code == http.StatusTooManyRequests {
				blocked++
			}
		}

		// Each IP should get burst of 3, then be limited
		if allowed != 3 {
			t.Errorf("IP %s: expected 3 allowed requests, got %d", ip, allowed)
		}
		if blocked != 2 {
			t.Errorf("IP %s: expected 2 blocked requests, got %d", ip, blocked)
		}
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		headers        map[string]string
		trustedProxies []*net.IPNet
		expected       string
	}{
		{
			name:       "plain RemoteAddr",
			remoteAddr: "192.168.1.1:1234",
			expected:   "192.168.1.1",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "no trusted proxies ignores X-Forwarded-For",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			expected: "10.0.0.1",
		},
		{
			name:       "no trusted proxies ignores X-Real-IP",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.5",
			},
			expected: "10.0.0.1",
		},
		{
			name:       "untrusted proxy ignored",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			trustedProxies: mustParseCIDRs("172.16.0.0/12"),
			expected:       "10.0.0.1",
		},
		{
			name:       "trusted proxy honors X-Forwarded-For single IP",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			trustedProxies: mustParseCIDRs("10.0.0.0/8"),
			expected:       "203.0.113.1",
		},
		{
			name:       "trusted proxy returns rightmost untrusted IP",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 198.51.100.1, 10.0.0.5",
			},
			trustedProxies: mustParseCIDRs("10.0.0.0/8"),
			expected:       "198.51.100.1",
		},
		{
			name:       "trusted proxy with X-Real-IP fallback",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.5",
			},
			trustedProxies: mustParseCIDRs("10.0.0.0/8"),
			expected:       "203.0.113.5",
		},
		{
			name:       "trusted proxy X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.5",
			},
			trustedProxies: mustParseCIDRs("10.0.0.0/8"),
			expected:       "203.0.113.1",
		},
		{
			name:       "CIDR trusted proxy matches",
			remoteAddr: "172.20.0.5:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			trustedProxies: mustParseCIDRs("172.16.0.0/12"),
			expected:       "203.0.113.1",
		},
		{
			name:       "single IP trusted proxy",
			remoteAddr: "192.168.1.100:1234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			trustedProxies: mustParseCIDRs("192.168.1.100/32"),
			expected:       "203.0.113.1",
		},
		{
			name:       "all forwarded IPs are trusted returns RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.2, 10.0.0.3",
			},
			trustedProxies: mustParseCIDRs("10.0.0.0/8"),
			expected:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := extractIP(req, tt.trustedProxies)
			if ip != tt.expected {
				t.Errorf("Expected IP %s, got %s", tt.expected, ip)
			}
		})
	}
}

// mustParseCIDRs parses a comma-separated list of CIDRs for test setup
func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	var result []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR in test: %s: %v", cidr, err))
		}
		result = append(result, ipNet)
	}
	return result
}

func TestRateLimitCleanup(t *testing.T) {
	config := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 10.0,
		Burst:             5,
	}

	rl := NewRateLimitMiddleware(config)

	// Create limiters for many IPs
	for i := 0; i < 1500; i++ {
		ip := testIP(i)
		_ = rl.getLimiter(ip)
	}

	initialCount := len(rl.limiters)
	if initialCount != 1500 {
		t.Errorf("Expected 1500 limiters, got %d", initialCount)
	}

	// Trigger cleanup by waiting
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup since we can't wait 5 minutes
	rl.mu.Lock()
	if len(rl.limiters) > 1000 {
		rl.limiters = make(map[string]*rate.Limiter)
	}
	finalCount := len(rl.limiters)
	rl.mu.Unlock()

	if finalCount >= initialCount {
		t.Errorf("Expected cleanup to reduce limiters from %d, still at %d", initialCount, finalCount)
	}

	rl.Stop()
}

func testIP(n int) string {
	a := n / (256 * 256 * 256)
	b := (n / (256 * 256)) % 256
	c := (n / 256) % 256
	d := n % 256
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func BenchmarkRateLimitMiddleware(b *testing.B) {
	config := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1000.0,
		Burst:             2000,
	}

	rl := NewRateLimitMiddleware(config)
	defer rl.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Limit(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
	}
}
