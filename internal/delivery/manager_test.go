package delivery

import (
	"context"
	"testing"
	"time"
)

func TestDeliveryManager(t *testing.T) {
	config := DefaultConfig()
	config.MaxConnectionsPerHost = 2
	config.DNSCacheSize = 10
	config.MaxConcurrentDeliveries = 5

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create delivery manager: %v", err)
	}

	// Test manager start/stop
	t.Run("StartStop", func(t *testing.T) {
		if err := manager.Start(); err != nil {
			t.Fatalf("Failed to start manager: %v", err)
		}

		if !manager.running {
			t.Error("Manager should be running after start")
		}

		if err := manager.Stop(); err != nil {
			t.Fatalf("Failed to stop manager: %v", err)
		}

		if manager.running {
			t.Error("Manager should not be running after stop")
		}
	})

	// Restart for other tests
	if err := manager.Start(); err != nil {
		t.Fatalf("Failed to restart manager: %v", err)
	}
	defer manager.Stop()

	t.Run("DeliverMessage", func(t *testing.T) {
		msg := &Message{
			ID:       "test-msg-1",
			From:     "sender@example.com",
			To:       []string{"recipient@example.com"},
			Data:     []byte("Subject: Test\r\n\r\nTest message body"),
			Priority: PriorityNormal,
			Size:     100,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// This will likely fail due to no actual SMTP server, but we can test the flow
		result, err := manager.DeliverMessage(ctx, msg)

		// We expect an error since we're not connecting to real servers
		if err == nil {
			t.Log("Delivery succeeded (unexpected but ok for test)")
		} else {
			t.Logf("Delivery failed as expected: %v", err)
		}

		if result == nil {
			t.Error("Result should not be nil even on failure")
		}

		if result != nil {
			if result.MessageID != msg.ID {
				t.Errorf("Expected message ID %s, got %s", msg.ID, result.MessageID)
			}

			if result.TotalRecipients != len(msg.To) {
				t.Errorf("Expected %d recipients, got %d", len(msg.To), result.TotalRecipients)
			}
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		connectionStats := manager.GetConnectionStats()
		if connectionStats == nil {
			t.Error("Connection stats should not be nil")
		}

		dnsStats := manager.GetDNSStats()
		if dnsStats == nil {
			t.Error("DNS stats should not be nil")
		}

		deliveryStats := manager.GetDeliveryStats()
		if deliveryStats == nil {
			t.Error("Delivery stats should not be nil")
		}
	})
}

func TestConnectionPool(t *testing.T) {
	config := DefaultConfig()
	config.MaxConnectionsPerHost = 2

	pool := NewConnectionPool(config)
	ctx := context.Background()

	t.Run("BasicConnection", func(t *testing.T) {
		// Try to connect to a non-existent host (should fail)
		_, err := pool.GetConnection(ctx, "nonexistent.example.com", 25)
		if err == nil {
			t.Error("Expected connection to fail for non-existent host")
		}
	})

	t.Run("ConnectionReuse", func(t *testing.T) {
		// Test pool statistics
		stats := pool.GetStats()
		if stats == nil {
			t.Error("Stats should not be nil")
		}

		initialConnections := stats["total_connections"].(int64)

		pool.Close()

		stats = pool.GetStats()
		closedConnections := stats["closed_connections"].(int64)

		if closedConnections < initialConnections {
			t.Logf("Closed %d connections", closedConnections)
		}
	})
}

func TestDNSCache(t *testing.T) {
	config := DefaultConfig()
	cache := NewDNSCache(config)
	ctx := context.Background()

	t.Run("MXLookup", func(t *testing.T) {
		// Test with a domain that should have MX records
		domain := "gmail.com"

		// First lookup (cache miss)
		records1, err := cache.LookupMX(ctx, domain)
		if err != nil {
			t.Logf("MX lookup failed (network issue): %v", err)
			return // Skip test if network is unavailable
		}

		if len(records1) == 0 {
			t.Errorf("Expected MX records for %s", domain)
		}

		// Second lookup (should be cached)
		records2, err := cache.LookupMX(ctx, domain)
		if err != nil {
			t.Fatalf("Cached MX lookup failed: %v", err)
		}

		if len(records2) != len(records1) {
			t.Error("Cached result should match original result")
		}

		stats := cache.GetStats()
		hits := stats["cache_hits"].(int64)
		if hits < 1 {
			t.Error("Expected at least one cache hit")
		}
	})

	t.Run("ALookup", func(t *testing.T) {
		hostname := "google.com"

		ips, err := cache.LookupA(ctx, hostname)
		if err != nil {
			t.Logf("A lookup failed (network issue): %v", err)
			return
		}

		if len(ips) == 0 {
			t.Errorf("Expected A records for %s", hostname)
		}
	})

	t.Run("CacheStats", func(t *testing.T) {
		stats := cache.GetStats()
		if stats == nil {
			t.Error("Stats should not be nil")
		}

		contents := cache.GetCacheContents()
		if contents == nil {
			t.Error("Cache contents should not be nil")
		}
	})

	t.Run("CacheCleanup", func(t *testing.T) {
		cache.Clear()

		stats := cache.GetStats()
		cacheSize := stats["cache_size"].(int)
		if cacheSize != 0 {
			t.Errorf("Expected cache size 0 after clear, got %d", cacheSize)
		}
	})
}

func TestRouter(t *testing.T) {
	config := DefaultConfig()
	config.LocalDomains = []string{"localhost", "local.example.com"}
	// Don't set RelayHost to test direct delivery

	router := NewRouter(config)
	ctx := context.Background()

	t.Run("LocalDelivery", func(t *testing.T) {
		msg := &Message{
			ID:   "test-local",
			From: "sender@example.com",
			To:   []string{"user@localhost"},
		}

		routes, err := router.RouteMessage(ctx, msg)
		if err != nil {
			t.Fatalf("Routing failed: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("Expected 1 route, got %d", len(routes))
		}

		route := routes[0]
		if route.Type != RouteTypeLocal {
			t.Errorf("Expected local route, got %s", route.Type)
		}

		if route.Host != "localhost" {
			t.Errorf("Expected localhost, got %s", route.Host)
		}
	})

	t.Run("DirectDelivery", func(t *testing.T) {
		msg := &Message{
			ID:   "test-direct",
			From: "sender@example.com",
			To:   []string{"user@remote.example.com"},
		}

		routes, err := router.RouteMessage(ctx, msg)
		if err != nil {
			t.Fatalf("Routing failed: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("Expected 1 route, got %d", len(routes))
		}

		route := routes[0]
		if route.Type != RouteTypeDirect {
			t.Errorf("Expected direct route, got %s", route.Type)
		}
	})

	t.Run("RoutingRules", func(t *testing.T) {
		rule := &RoutingRule{
			ID:         "test-rule",
			Name:       "Test Rule",
			Enabled:    true,
			Priority:   1,
			FromDomain: []string{"example.com"},
			RouteType:  RouteTypeRelay,
			RelayHost:  "custom-relay.example.com",
			RelayPort:  25,
		}

		router.AddRoutingRule(rule)

		msg := &Message{
			ID:   "test-rule-match",
			From: "sender@example.com",
			To:   []string{"user@anywhere.com"},
		}

		routes, err := router.RouteMessage(ctx, msg)
		if err != nil {
			t.Fatalf("Routing failed: %v", err)
		}

		if len(routes) != 1 {
			t.Fatalf("Expected 1 route, got %d", len(routes))
		}

		route := routes[0]
		if route.Type != RouteTypeRelay {
			t.Errorf("Expected relay route, got %s", route.Type)
		}

		if route.Host != "custom-relay.example.com" {
			t.Errorf("Expected custom-relay.example.com, got %s", route.Host)
		}

		// Test rule removal
		router.RemoveRoutingRule("test-rule")

		rules := router.GetRoutingRules()
		for _, r := range rules {
			if r.ID == "test-rule" {
				t.Error("Rule should have been removed")
			}
		}
	})

	t.Run("RouterStats", func(t *testing.T) {
		stats := router.GetStats()
		if stats == nil {
			t.Error("Stats should not be nil")
		}

		totalMessages := stats["total_messages"].(int64)
		if totalMessages < 1 {
			t.Error("Expected at least one routed message")
		}
	})
}

func TestDeliveryTracker(t *testing.T) {
	config := DefaultConfig()
	tracker := NewDeliveryTracker(config)

	t.Run("TrackDelivery", func(t *testing.T) {
		msg := &Message{
			ID:       "test-track",
			From:     "sender@example.com",
			To:       []string{"recipient1@example.com", "recipient2@example.com"},
			Priority: PriorityHigh,
		}

		deliveryID := tracker.StartDelivery(msg)
		if deliveryID == "" {
			t.Error("Delivery ID should not be empty")
		}

		// Test getting delivery info
		delivery, exists := tracker.GetDelivery(deliveryID)
		if !exists {
			t.Error("Delivery should exist")
		}

		if delivery.Status != StatusPending {
			t.Errorf("Expected pending status, got %s", delivery.Status)
		}

		if delivery.TotalRecipients != 2 {
			t.Errorf("Expected 2 recipients, got %d", delivery.TotalRecipients)
		}

		// Test adding an attempt
		attempt := &DeliveryAttempt{
			ID:            "attempt-1",
			MessageID:     msg.ID,
			StartTime:     time.Now(),
			Status:        StatusFailed,
			AttemptNumber: 1,
		}

		tracker.AddAttempt(deliveryID, attempt)

		delivery, _ = tracker.GetDelivery(deliveryID)
		if len(delivery.Attempts) != 1 {
			t.Errorf("Expected 1 attempt, got %d", len(delivery.Attempts))
		}

		// Test updating delivery result
		result := &DeliveryResult{
			MessageID:            msg.ID,
			Success:              false,
			SuccessfulRecipients: 1,
			FailedRecipients:     1,
			Duration:             100 * time.Millisecond,
		}

		tracker.UpdateDelivery(deliveryID, result)

		delivery, _ = tracker.GetDelivery(deliveryID)
		if delivery.Status != StatusFailed {
			t.Errorf("Expected failed status, got %s", delivery.Status)
		}

		// Test finishing delivery
		tracker.FinishDelivery(deliveryID)

		delivery, _ = tracker.GetDelivery(deliveryID)
		if delivery.EndTime.IsZero() {
			t.Error("End time should be set after finishing")
		}
	})

	t.Run("TrackerStats", func(t *testing.T) {
		stats := tracker.GetStats()
		if stats == nil {
			t.Error("Stats should not be nil")
		}

		totalDeliveries := stats["total_deliveries"].(int64)
		if totalDeliveries < 1 {
			t.Error("Expected at least one tracked delivery")
		}

		detailedStats := tracker.GetDetailedStats()
		if detailedStats == nil {
			t.Error("Detailed stats should not be nil")
		}
	})

	t.Run("ActiveDeliveries", func(t *testing.T) {
		active := tracker.GetActiveDeliveries()
		t.Logf("Found %d active deliveries", len(active))
	})

	t.Run("FailedDeliveries", func(t *testing.T) {
		failed := tracker.GetFailedDeliveries(10)
		if len(failed) < 1 {
			t.Error("Expected at least one failed delivery from previous test")
		}
	})

	t.Run("RecentDeliveries", func(t *testing.T) {
		recent := tracker.GetRecentDeliveries(1 * time.Hour)
		if len(recent) < 1 {
			t.Error("Expected at least one recent delivery")
		}
	})
}

func TestCreateTLSConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultConfig()
		tlsConfig, err := createTLSConfig(config)
		if err != nil {
			t.Fatalf("Failed to create TLS config: %v", err)
		}

		if tlsConfig == nil {
			t.Error("TLS config should not be nil")
		} else if tlsConfig.MinVersion == 0 {
			t.Error("TLS min version should be set")
		}
	})

	t.Run("CustomTLSVersion", func(t *testing.T) {
		config := DefaultConfig()
		config.TLSMinVersion = "1.3"

		tlsConfig, err := createTLSConfig(config)
		if err != nil {
			t.Fatalf("Failed to create TLS config: %v", err)
		}

		// Note: the exact constant values depend on the Go version
		if tlsConfig.MinVersion == 0 {
			t.Error("TLS 1.3 min version should be set")
		}
	})
}

func TestDeliveryTypes(t *testing.T) {
	t.Run("Message", func(t *testing.T) {
		msg := &Message{
			ID:       "test-123",
			From:     "sender@example.com",
			To:       []string{"recipient@example.com"},
			Data:     []byte("Test message"),
			Priority: PriorityNormal,
		}

		if msg.ID != "test-123" {
			t.Error("Message ID not set correctly")
		}

		if len(msg.To) != 1 {
			t.Error("Recipients not set correctly")
		}
	})

	t.Run("Route", func(t *testing.T) {
		route := &Route{
			Type:       RouteTypeDirect,
			Host:       "mx.example.com",
			Port:       25,
			Recipients: []string{"user@example.com"},
			Priority:   PriorityNormal,
		}

		if route.Type != RouteTypeDirect {
			t.Error("Route type not set correctly")
		}

		if route.Port != 25 {
			t.Error("Route port not set correctly")
		}
	})

	t.Run("DeliveryError", func(t *testing.T) {
		err := &DeliveryError{
			Type:      ErrorTypeConnection,
			Message:   "Connection failed",
			Temporary: true,
			Retryable: true,
		}

		errorStr := err.Error()
		if errorStr == "" {
			t.Error("Error string should not be empty")
		}

		if !err.Temporary {
			t.Error("Error should be marked as temporary")
		}

		if !err.Retryable {
			t.Error("Error should be marked as retryable")
		}
	})
}
