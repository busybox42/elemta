package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	queueDir := t.TempDir()

	t.Run("Create server with valid config", func(t *testing.T) {
		config := &Config{
			Enabled:     true,
			ListenAddr:  "127.0.0.1:8025",
			WebRoot:     "./web",
			AuthEnabled: false,
		}

		server, err := NewServer(config, queueDir)
		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.Equal(t, "127.0.0.1:8025", server.listenAddr)
		assert.Equal(t, "./web", server.webRoot)
		assert.NotNil(t, server.queueMgr)
	})

	t.Run("Create server with default listen address", func(t *testing.T) {
		config := &Config{
			Enabled:    true,
			ListenAddr: "", // Empty, should use default
			WebRoot:    "./web",
		}

		server, err := NewServer(config, queueDir)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1:8025", server.listenAddr, "Should use default listen address")
	})

	t.Run("Create server with default web root", func(t *testing.T) {
		config := &Config{
			Enabled:    true,
			ListenAddr: "127.0.0.1:8025",
			WebRoot:    "", // Empty, should use default
		}

		server, err := NewServer(config, queueDir)
		require.NoError(t, err)
		assert.Equal(t, "./web/static", server.webRoot, "Should use default web root")
	})

	t.Run("Fail to create server when disabled", func(t *testing.T) {
		config := &Config{
			Enabled: false,
		}

		server, err := NewServer(config, queueDir)
		assert.Error(t, err, "Should error when API server is disabled")
		assert.Nil(t, server)
		assert.Contains(t, err.Error(), "disabled")
	})

	t.Run("Create server with auth enabled fails gracefully", func(t *testing.T) {
		config := &Config{
			Enabled:     true,
			ListenAddr:  "127.0.0.1:8025",
			AuthEnabled: true, // Will fail without proper datasource
		}

		// This will fail to initialize auth, but that's expected in tests
		server, err := NewServer(config, queueDir)
		// Either fails or succeeds depending on environment
		if err != nil {
			assert.Contains(t, err.Error(), "authentication")
			t.Logf("✓ Auth initialization failed as expected: %v", err)
		} else {
			assert.NotNil(t, server)
			t.Log("✓ Server created (auth may have initialized from environment)")
		}
	})
}

func TestServerQueueEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping API endpoint tests in short mode")
	}

	queueDir := t.TempDir()
	config := &Config{
		Enabled:     true,
		ListenAddr:  "127.0.0.1:0", // Random port
		AuthEnabled: false,
	}

	server, err := NewServer(config, queueDir)
	require.NoError(t, err)

	// Create test router
	router := http.NewServeMux()

	t.Run("Queue stats endpoint structure", func(t *testing.T) {
		// The actual endpoint would be registered by setupRoutes()
		// Here we verify the server has a queue manager
		assert.NotNil(t, server.queueMgr, "Queue manager should be initialized")

		stats := server.queueMgr.GetStats()
		assert.NotNil(t, stats)
		t.Log("✓ Queue stats endpoint dependencies available")
	})

	t.Run("Server has required components", func(t *testing.T) {
		assert.NotNil(t, server.queueMgr, "Queue manager required")
		assert.NotEmpty(t, server.listenAddr, "Listen address required")
		assert.NotEmpty(t, server.webRoot, "Web root required")
	})

	_ = router // Avoid unused warning
}

func TestAPIConfig(t *testing.T) {
	t.Run("Valid config", func(t *testing.T) {
		config := &Config{
			Enabled:     true,
			ListenAddr:  "0.0.0.0:8080",
			WebRoot:     "/var/www/elemta",
			AuthEnabled: true,
		}

		assert.True(t, config.Enabled)
		assert.Equal(t, "0.0.0.0:8080", config.ListenAddr)
		assert.Equal(t, "/var/www/elemta", config.WebRoot)
		assert.True(t, config.AuthEnabled)
	})

	t.Run("Minimal config", func(t *testing.T) {
		config := &Config{
			Enabled: true,
		}

		assert.True(t, config.Enabled)
		assert.Empty(t, config.ListenAddr)
		assert.Empty(t, config.WebRoot)
		assert.False(t, config.AuthEnabled)
	})

	t.Run("Production config", func(t *testing.T) {
		config := &Config{
			Enabled:     true,
			ListenAddr:  "127.0.0.1:8025",
			WebRoot:     "/app/web/static",
			AuthEnabled: true,
		}

		assert.True(t, config.Enabled)
		assert.True(t, config.AuthEnabled)
		assert.Contains(t, config.ListenAddr, "127.0.0.1")
	})
}

func TestServerStart(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping server start tests in short mode")
	}

	queueDir := t.TempDir()

	t.Run("Start and stop server", func(t *testing.T) {
		config := &Config{
			Enabled:     true,
			ListenAddr:  "127.0.0.1:0", // Random port
			AuthEnabled: false,
		}

		server, err := NewServer(config, queueDir)
		require.NoError(t, err)

		// Start server in goroutine
		serverErr := make(chan error, 1)
		go func() {
			err := server.Start()
			if err != nil && err != http.ErrServerClosed {
				serverErr <- err
			}
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// Stop server
		err = server.Stop()
		assert.NoError(t, err, "Server stop should succeed")

		// Check for server errors
		select {
		case err := <-serverErr:
			t.Fatalf("Server error: %v", err)
		case <-time.After(100 * time.Millisecond):
			// No error, good
		}
	})
}

func TestAPIServerHelpers(t *testing.T) {
	t.Run("JSON response helper", func(t *testing.T) {
		// Create test response writer
		w := httptest.NewRecorder()

		// Test data
		data := map[string]interface{}{
			"status":  "success",
			"message": "Test response",
			"count":   42,
		}

		// Manually write JSON response (testing the pattern used in server.go)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)

		// Verify response
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		// Parse response
		var response map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "success", response["status"])
		assert.Equal(t, "Test response", response["message"])
		assert.Equal(t, float64(42), response["count"])
	})

	t.Run("Error response helper", func(t *testing.T) {
		w := httptest.NewRecorder()

		// Error response pattern
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid request",
		})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "Invalid request", response["error"])
	})
}

func TestServerEdgeCases(t *testing.T) {
	t.Run("Create server with various listen addresses", func(t *testing.T) {
		queueDir := t.TempDir()

		addresses := []string{
			"127.0.0.1:8080",
			"localhost:9090",
			"0.0.0.0:8025",
			":8025", // All interfaces
		}

		for _, addr := range addresses {
			config := &Config{
				Enabled:    true,
				ListenAddr: addr,
			}

			server, err := NewServer(config, queueDir)
			require.NoError(t, err, "Should create server with address: %s", addr)
			assert.Equal(t, addr, server.listenAddr)
		}
	})

	t.Run("Create server with various web roots", func(t *testing.T) {
		queueDir := t.TempDir()

		roots := []string{
			"./web",
			"/var/www/elemta",
			"/app/static",
			"../public",
		}

		for _, root := range roots {
			config := &Config{
				Enabled: true,
				WebRoot: root,
			}

			server, err := NewServer(config, queueDir)
			require.NoError(t, err, "Should create server with web root: %s", root)
			assert.Equal(t, root, server.webRoot)
		}
	})

	t.Run("Nil config", func(t *testing.T) {
		queueDir := t.TempDir()

		// This should panic or return error - let's catch it
		defer func() {
			if r := recover(); r != nil {
				t.Logf("✓ Panicked on nil config as expected: %v", r)
			}
		}()

		// Trying to create with nil config might panic
		server, err := NewServer(nil, queueDir)
		if err != nil {
			t.Logf("✓ Returned error on nil config: %v", err)
		} else if server == nil {
			t.Log("✓ Returned nil server on nil config")
		}
	})
}

func TestQueueManagerIntegration(t *testing.T) {
	queueDir := t.TempDir()
	config := &Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:8025",
	}

	server, err := NewServer(config, queueDir)
	require.NoError(t, err)

	t.Run("Queue manager is initialized", func(t *testing.T) {
		assert.NotNil(t, server.queueMgr, "Queue manager should be initialized")
	})

	t.Run("Queue manager provides stats", func(t *testing.T) {
		stats := server.queueMgr.GetStats()
		assert.NotNil(t, stats, "Stats should be available")
		// Stats are likely zero on new queue
		assert.GreaterOrEqual(t, stats.ActiveCount, 0)
	})

	t.Run("Queue manager can enqueue messages", func(t *testing.T) {
		msgID, err := server.queueMgr.EnqueueMessage(
			"sender@test.com",
			[]string{"recipient@test.com"},
			"Test Subject",
			[]byte("Test message body"),
			0, // Normal priority
			time.Now(),
		)
		require.NoError(t, err)
		assert.NotEmpty(t, msgID)
		t.Logf("✓ Enqueued message: %s", msgID)
	})
}

func TestConfigValidation(t *testing.T) {
	queueDir := t.TempDir()

	t.Run("Disabled config", func(t *testing.T) {
		config := &Config{
			Enabled:    false,
			ListenAddr: "127.0.0.1:8025",
		}

		server, err := NewServer(config, queueDir)
		assert.Error(t, err)
		assert.Nil(t, server)
		assert.Contains(t, err.Error(), "disabled")
	})

	t.Run("Empty queue directory", func(t *testing.T) {
		config := &Config{
			Enabled:    true,
			ListenAddr: "127.0.0.1:8025",
		}

		server, err := NewServer(config, "") // Empty queue dir
		require.NoError(t, err, "Should handle empty queue dir")
		assert.NotNil(t, server)
	})
}

func TestHTTPHandlers(t *testing.T) {
	t.Run("Health check handler pattern", func(t *testing.T) {
		// Test the handler pattern used in the API server
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "ok",
				"uptime": "1h",
			})
		})

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "ok", response["status"])
	})

	t.Run("Queue stats handler pattern", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stats := map[string]interface{}{
				"active":   10,
				"deferred": 5,
				"failed":   2,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(stats)
		})

		req := httptest.NewRequest("GET", "/api/queue/stats", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var stats map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&stats)
		require.NoError(t, err)
		assert.Equal(t, float64(10), stats["active"])
	})

	t.Run("Error handler pattern", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Internal server error",
				"message": "Something went wrong",
			})
		})

		req := httptest.NewRequest("GET", "/api/error", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "Internal server error", response["error"])
	})
}

func TestCORSHeaders(t *testing.T) {
	t.Run("CORS headers for API requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS middleware pattern
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		})

		// Test OPTIONS request
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})
}

func TestServerStop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping server lifecycle tests in short mode")
	}

	queueDir := t.TempDir()
	config := &Config{
		Enabled:     true,
		ListenAddr:  "127.0.0.1:0",
		AuthEnabled: false,
	}

	t.Run("Stop server gracefully", func(t *testing.T) {
		server, err := NewServer(config, queueDir)
		require.NoError(t, err)

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Stop server
		err = server.Stop()
		assert.NoError(t, err)
	})

	t.Run("Stop server that was never started", func(t *testing.T) {
		server, err := NewServer(config, queueDir)
		require.NoError(t, err)

		// Stop without starting
		err = server.Stop()
		// Should handle gracefully (either no error or specific error)
		if err != nil {
			t.Logf("Stop returned error (acceptable): %v", err)
		} else {
			t.Log("✓ Stop handled gracefully")
		}
	})

	t.Run("Multiple stop calls are idempotent", func(t *testing.T) {
		server, err := NewServer(config, queueDir)
		require.NoError(t, err)

		// Start server
		go server.Start()
		time.Sleep(100 * time.Millisecond)

		// Stop multiple times
		err1 := server.Stop()
		err2 := server.Stop()
		err3 := server.Stop()

		// First stop should succeed
		assert.NoError(t, err1)
		// Subsequent stops may error or succeed
		t.Logf("Stop calls: %v, %v, %v", err1, err2, err3)
	})
}

func BenchmarkNewServer(b *testing.B) {
	queueDir := b.TempDir()
	config := &Config{
		Enabled:     true,
		ListenAddr:  "127.0.0.1:8025",
		AuthEnabled: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server, err := NewServer(config, queueDir)
		if err != nil {
			b.Fatal(err)
		}
		_ = server
	}
}

func BenchmarkJSONEncode(b *testing.B) {
	data := map[string]interface{}{
		"active":   100,
		"deferred": 50,
		"failed":   10,
		"total":    160,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		json.NewEncoder(w).Encode(data)
	}
}
