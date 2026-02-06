package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	tests := []struct {
		name                 string
		config               CORSConfig
		origin               string
		method               string
		expectedStatus       int
		expectedAllowOrigin  string
		expectedAllowCreds   string
		expectedAllowMethods string
	}{
		{
			name: "disabled CORS - no headers set",
			config: CORSConfig{
				Enabled: false,
			},
			origin:              "http://example.com",
			method:              "GET",
			expectedStatus:      http.StatusOK,
			expectedAllowOrigin: "",
		},
		{
			name: "allowed origin",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:8025"},
			},
			origin:               "http://localhost:8025",
			method:               "GET",
			expectedStatus:       http.StatusOK,
			expectedAllowOrigin:  "http://localhost:8025",
			expectedAllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
		},
		{
			name: "wildcard origin",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"*"},
			},
			origin:               "http://example.com",
			method:               "GET",
			expectedStatus:       http.StatusOK,
			expectedAllowOrigin:  "*",
			expectedAllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
		},
		{
			name: "disallowed origin - preflight request",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:8025"},
			},
			origin:              "http://evil.com",
			method:              "OPTIONS",
			expectedStatus:      http.StatusForbidden,
			expectedAllowOrigin: "",
		},
		{
			name: "disallowed origin - normal request",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:8025"},
			},
			origin:              "http://evil.com",
			method:              "GET",
			expectedStatus:      http.StatusOK,
			expectedAllowOrigin: "",
		},
		{
			name: "multiple allowed origins",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:8025", "http://localhost:3000"},
			},
			origin:              "http://localhost:3000",
			method:              "GET",
			expectedStatus:      http.StatusOK,
			expectedAllowOrigin: "http://localhost:3000",
		},
		{
			name: "credentials allowed",
			config: CORSConfig{
				Enabled:          true,
				AllowedOrigins:   []string{"http://localhost:8025"},
				AllowCredentials: true,
			},
			origin:              "http://localhost:8025",
			method:              "GET",
			expectedStatus:      http.StatusOK,
			expectedAllowOrigin: "http://localhost:8025",
			expectedAllowCreds:  "true",
		},
		{
			name: "custom methods and headers",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:8025"},
				AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"Content-Type"},
			},
			origin:               "http://localhost:8025",
			method:               "OPTIONS",
			expectedStatus:       http.StatusOK,
			expectedAllowOrigin:  "http://localhost:8025",
			expectedAllowMethods: "GET, POST",
		},
		{
			name: "no origin header - should still work",
			config: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:8025"},
			},
			origin:              "",
			method:              "GET",
			expectedStatus:      http.StatusOK,
			expectedAllowOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCORSMiddleware(tt.config)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := cm.Handler(handler)

			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rr := httptest.NewRecorder()

			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			if allowOrigin != tt.expectedAllowOrigin {
				t.Errorf("Expected Allow-Origin '%s', got '%s'", tt.expectedAllowOrigin, allowOrigin)
			}

			if tt.expectedAllowCreds != "" {
				allowCreds := rr.Header().Get("Access-Control-Allow-Credentials")
				if allowCreds != tt.expectedAllowCreds {
					t.Errorf("Expected Allow-Credentials '%s', got '%s'", tt.expectedAllowCreds, allowCreds)
				}
			}

			if tt.expectedAllowMethods != "" {
				allowMethods := rr.Header().Get("Access-Control-Allow-Methods")
				if allowMethods != tt.expectedAllowMethods {
					t.Errorf("Expected Allow-Methods '%s', got '%s'", tt.expectedAllowMethods, allowMethods)
				}
			}
		})
	}
}

func TestCORSDefaults(t *testing.T) {
	config := CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"http://localhost:8025"},
	}

	cm := NewCORSMiddleware(config)

	if len(cm.config.AllowedMethods) == 0 {
		t.Error("Expected default methods to be set")
	}

	if len(cm.config.AllowedHeaders) == 0 {
		t.Error("Expected default headers to be set")
	}

	if cm.config.MaxAge == 0 {
		t.Error("Expected default MaxAge to be set")
	}
}

func TestCORSPreflightRequest(t *testing.T) {
	config := CORSConfig{
		Enabled:        true,
		AllowedOrigins: []string{"http://localhost:8025"},
	}

	cm := NewCORSMiddleware(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for preflight request")
	})

	middleware := cm.Handler(handler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:8025")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for preflight, got %d", rr.Code)
	}

	allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "http://localhost:8025" {
		t.Errorf("Expected Allow-Origin 'http://localhost:8025', got '%s'", allowOrigin)
	}
}

func TestCORSSecurity(t *testing.T) {
	// Test that wildcard with credentials is allowed (should be warned about in production)
	config := CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}

	cm := NewCORSMiddleware(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := cm.Handler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://evil.com")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	// Note: In production, wildcard + credentials should be rejected,
	// but we allow configuration flexibility here
	allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		t.Error("Expected CORS headers to be set even with wildcard")
	}
}
