package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/gorilla/mux"
)

// TestMuxIntegration verifies that gorilla/mux still works correctly
func TestMuxIntegration(t *testing.T) {
	// Create a test router
	r := mux.NewRouter()

	// Add a test route with path variables
	r.HandleFunc("/test/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		response := map[string]string{
			"id":      id,
			"message": "test successful",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Test the route
	req := httptest.NewRequest("GET", "/test/123", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	err := json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["id"] != "123" {
		t.Errorf("Expected id '123', got '%s'", response["id"])
	}

	if response["message"] != "test successful" {
		t.Errorf("Expected message 'test successful', got '%s'", response["message"])
	}
}

// TestServerCreation verifies that the API server can be created
func TestServerCreation(t *testing.T) {
	config := &Config{
		Enabled:    true,
		ListenAddr: ":8080",
	}

	queueDir := t.TempDir()

	server, err := NewServer(config, (*MainConfig)(nil), queueDir, 0, "") // Tests use immediate deletion
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if server == nil {
		t.Fatal("Server should not be nil")
	}

	// Verify server configuration
	if server.listenAddr != ":8080" {
		t.Errorf("Expected listen address ':8080', got '%s'", server.listenAddr)
	}
}

// TestQueueTypeValidation tests queue type parsing
func TestQueueTypeValidation(t *testing.T) {
	tests := []struct {
		input    string
		expected queue.QueueType
		hasError bool
	}{
		{"active", queue.Active, false},
		{"deferred", queue.Deferred, false},
		{"hold", queue.Hold, false},
		{"failed", queue.Failed, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		result, err := parseQueueType(test.input)

		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input '%s', but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input '%s': %v", test.input, err)
			}
			if result != test.expected {
				t.Errorf("For input '%s', expected %s, got %s", test.input, test.expected, result)
			}
		}
	}
}
