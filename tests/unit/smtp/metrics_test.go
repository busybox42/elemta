package smtp_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elemta/internal/smtp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
		tempDir, err := ioutil.TempDir("", "queue-test")
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
			err := ioutil.WriteFile(msgFile, []byte("test"), 0644)
			require.NoError(t, err)

			// Create a metadata file
			metaFile := filepath.Join(activeDir, fmt.Sprintf("msg%d.json", i))
			err = ioutil.WriteFile(metaFile, []byte("{}"), 0644)
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
		// Use a test HTTP server
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			promhttp.Handler().ServeHTTP(w, r)
		}))
		defer ts.Close()

		// Make a request to verify the metrics endpoint works
		resp, err := http.Get(ts.URL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Metrics endpoint should return 200 OK")

		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)

		// Just check that metrics output contains expected text
		assert.Contains(t, string(body), "elemta_connections_total")
	})
}

// Helper function to get the value of a counter
func testGetCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	value, err := prometheusValue(counter)
	require.NoError(t, err)
	return value
}

// Helper function to get the value of a gauge
func testGetGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	value, err := prometheusValue(gauge)
	require.NoError(t, err)
	return value
}

// Helper function to extract value from a prometheus metric
func prometheusValue(m interface{}) (float64, error) {
	var metric dto.Metric

	switch v := m.(type) {
	case prometheus.Counter:
		if err := v.Write(&metric); err != nil {
			return 0, err
		}
		return *metric.Counter.Value, nil
	case prometheus.Gauge:
		if err := v.Write(&metric); err != nil {
			return 0, err
		}
		return *metric.Gauge.Value, nil
	default:
		return 0, fmt.Errorf("unsupported metric type: %T", m)
	}
}
