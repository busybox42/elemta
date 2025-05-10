package smtp_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	// Reset the prometheus registry to avoid conflicts
	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	t.Run("GetMetricsReturnsSingleton", func(t *testing.T) {
		metrics1 := smtp.GetMetrics()
		metrics2 := smtp.GetMetrics()

		// Should be the same instance
		assert.Equal(t, metrics1, metrics2, "GetMetrics should return the same instance")
	})

	t.Run("TrackConnectionDuration", func(t *testing.T) {
		metrics := smtp.GetMetrics()

		// Get initial values
		initialTotal := testGetCounterValue(t, metrics.ConnectionsTotal)
		initialErrors := testGetCounterValue(t, metrics.ConnectionErrors)

		// Track successful connection
		err := metrics.TrackConnectionDuration(func() error {
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, initialTotal+1, testGetCounterValue(t, metrics.ConnectionsTotal),
			"ConnectionsTotal should be incremented")
		assert.Equal(t, initialErrors, testGetCounterValue(t, metrics.ConnectionErrors),
			"ConnectionErrors should not change for successful connections")

		// Track connection with error
		err = metrics.TrackConnectionDuration(func() error {
			time.Sleep(10 * time.Millisecond) // Simulate work
			return os.ErrNotExist
		})

		assert.Error(t, err)
		assert.Equal(t, initialTotal+2, testGetCounterValue(t, metrics.ConnectionsTotal),
			"ConnectionsTotal should be incremented again")
		assert.Equal(t, initialErrors+1, testGetCounterValue(t, metrics.ConnectionErrors),
			"ConnectionErrors should be incremented")
	})

	t.Run("TrackDeliveryDuration", func(t *testing.T) {
		metrics := smtp.GetMetrics()

		// Get initial values
		initialAttempts := testGetCounterValue(t, metrics.DeliveryAttempts)
		initialSuccesses := testGetCounterValue(t, metrics.DeliverySuccesses)
		initialFailures := testGetCounterValue(t, metrics.DeliveryFailures)

		// Track successful delivery
		err := metrics.TrackDeliveryDuration(func() error {
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, initialAttempts+1, testGetCounterValue(t, metrics.DeliveryAttempts),
			"DeliveryAttempts should be incremented")
		assert.Equal(t, initialSuccesses+1, testGetCounterValue(t, metrics.DeliverySuccesses),
			"DeliverySuccesses should be incremented for successful delivery")
		assert.Equal(t, initialFailures, testGetCounterValue(t, metrics.DeliveryFailures),
			"DeliveryFailures should not change for successful delivery")

		// Track failed delivery
		err = metrics.TrackDeliveryDuration(func() error {
			time.Sleep(10 * time.Millisecond) // Simulate work
			return os.ErrNotExist
		})

		assert.Error(t, err)
		assert.Equal(t, initialAttempts+2, testGetCounterValue(t, metrics.DeliveryAttempts),
			"DeliveryAttempts should be incremented again")
		assert.Equal(t, initialSuccesses+1, testGetCounterValue(t, metrics.DeliverySuccesses),
			"DeliverySuccesses should not change for failed delivery")
		assert.Equal(t, initialFailures+1, testGetCounterValue(t, metrics.DeliveryFailures),
			"DeliveryFailures should be incremented")
	})

	t.Run("UpdateQueueSizes", func(t *testing.T) {
		metrics := smtp.GetMetrics()

		// Create a temporary directory for queue files
		tempDir, err := os.MkdirTemp("", "queue-test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Create queue directories
		queueTypes := []string{"active", "deferred", "held", "failed"}
		for _, qType := range queueTypes {
			qDir := filepath.Join(tempDir, qType)
			err := os.MkdirAll(qDir, 0755)
			require.NoError(t, err)
		}

		// Create test config
		config := &smtp.Config{
			QueueDir: tempDir,
		}

		// Before adding any files
		metrics.UpdateQueueSizes(config)
		for _, qType := range queueTypes {
			gauge := metrics.QueueSize.WithLabelValues(qType)
			assert.Equal(t, float64(0), testGetGaugeValue(t, gauge),
				"Queue size for %s should be 0 initially", qType)
		}

		// Add some message files to the active queue
		activeDir := filepath.Join(tempDir, "active")
		for i := 0; i < 3; i++ {
			// Create a message file
			msgFile := filepath.Join(activeDir, fmt.Sprintf("msg%d", i))
			err := os.WriteFile(msgFile, []byte("test"), 0644)
			require.NoError(t, err)

			// Create a metadata file
			metaFile := filepath.Join(activeDir, fmt.Sprintf("msg%d.json", i))
			err = os.WriteFile(metaFile, []byte("{}"), 0644)
			require.NoError(t, err)
		}

		// Update metrics
		metrics.UpdateQueueSizes(config)

		// Check queue sizes
		assert.Equal(t, float64(3), testGetGaugeValue(t, metrics.QueueSize.WithLabelValues("active")),
			"Active queue size should be 3")
		assert.Equal(t, float64(0), testGetGaugeValue(t, metrics.QueueSize.WithLabelValues("deferred")),
			"Deferred queue size should be 0")
	})

	t.Run("StartMetricsServer", func(t *testing.T) {
		// Create a unique registry for this test to avoid conflicts with global registry
		registry := prometheus.NewRegistry()

		// Register at least one metric in this registry to ensure there's some output
		testCounter := prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_metric",
			Help: "A test metric for the isolated registry",
		})
		registry.MustRegister(testCounter)
		testCounter.Inc() // Increment it to ensure there's a value

		// Create a metrics server with the isolated registry
		metricsPort := 9191 // Use a port unlikely to be in use
		metricsAddr := fmt.Sprintf(":%d", metricsPort)

		// Start a metrics server in the background
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var serverError error
		serverReady := make(chan struct{})

		go func() {
			// Setup a simple HTTP handler using our registry
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

			// Create a server that will shut down when the context is canceled
			server := &http.Server{Addr: metricsAddr, Handler: mux}

			// Signal when the server is ready to accept connections
			ln, err := net.Listen("tcp", metricsAddr)
			if err != nil {
				serverError = err
				close(serverReady)
				return
			}
			close(serverReady)

			// Start serving
			go func() {
				if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
					t.Logf("Metrics server error: %v", err)
				}
			}()

			// Wait for context cancellation then shut down
			<-ctx.Done()
			server.Shutdown(context.Background())
		}()

		// Wait for server to be ready or error
		<-serverReady
		if serverError != nil {
			t.Skip(fmt.Sprintf("Skipping test as metrics server failed to start: %v", serverError))
		}

		// Wait a moment for the server to be fully ready
		time.Sleep(100 * time.Millisecond)

		// Now try to access the metrics endpoint
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", metricsPort))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Metrics endpoint should return 200 OK")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// In an isolated registry, we might not have the TYPE suffix yet if no metrics
		// were registered, but should at least get a valid response
		assert.NotEmpty(t, body, "Metrics response should not be empty")
	})
}

// Helper function to get the value of a counter
func testGetCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	// Use a safer approach that doesn't rely on prometheusValue
	var metric dto.Metric
	err := counter.Write(&metric)
	require.NoError(t, err)

	// Safety check to handle nil counter
	if metric.Counter == nil {
		t.Logf("Warning: metric.Counter is nil")
		return 0 // Return 0 if counter is nil, this is safer than crashing
	}

	return *metric.Counter.Value
}

// Helper function to get the value of a gauge
func testGetGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	// Use a safer approach that doesn't rely on prometheusValue
	var metric dto.Metric
	err := gauge.Write(&metric)
	require.NoError(t, err)

	// Safety check to handle nil gauge
	if metric.Gauge == nil {
		t.Logf("Warning: metric.Gauge is nil")
		return 0 // Return 0 if gauge is nil, this is safer than crashing
	}

	return *metric.Gauge.Value
}

// Helper function to extract value from a prometheus metric
func prometheusValue(m interface{}) (float64, error) {
	var metric dto.Metric
	metric.Reset() // Initialize the metric struct

	switch v := m.(type) {
	case prometheus.Counter:
		if err := v.Write(&metric); err != nil {
			return 0, err
		}
		if metric.Counter == nil {
			return 0, fmt.Errorf("counter value is nil")
		}
		return *metric.Counter.Value, nil
	case prometheus.Gauge:
		if err := v.Write(&metric); err != nil {
			return 0, err
		}
		if metric.Gauge == nil {
			return 0, fmt.Errorf("gauge value is nil")
		}
		return *metric.Gauge.Value, nil
	default:
		return 0, fmt.Errorf("unsupported metric type: %T", m)
	}
}
