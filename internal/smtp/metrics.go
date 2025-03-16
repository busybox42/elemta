package smtp

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Singleton metrics instance
	metricsInstance *Metrics
	metricsOnce     sync.Once
)

// Metrics holds all Prometheus metrics for the SMTP server
type Metrics struct {
	// Connection metrics
	ConnectionsTotal   prometheus.Counter
	ConnectionsActive  prometheus.Gauge
	ConnectionDuration prometheus.Histogram
	ConnectionErrors   prometheus.Counter

	// Message metrics
	MessagesReceived  prometheus.Counter
	MessagesDelivered prometheus.Counter
	MessagesFailed    prometheus.Counter
	MessageSize       prometheus.Histogram

	// Queue metrics
	QueueSize           prometheus.GaugeVec
	QueueProcessingTime prometheus.Histogram

	// Delivery metrics
	DeliveryAttempts  prometheus.Counter
	DeliverySuccesses prometheus.Counter
	DeliveryFailures  prometheus.Counter
	DeliveryDuration  prometheus.Histogram

	// TLS metrics
	TLSConnections       prometheus.Counter
	TLSHandshakeFailures prometheus.Counter

	// Authentication metrics
	AuthAttempts  prometheus.Counter
	AuthSuccesses prometheus.Counter
	AuthFailures  prometheus.Counter
}

// GetMetrics returns the singleton metrics instance
func GetMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsInstance = newMetrics()
	})
	return metricsInstance
}

// newMetrics creates and registers all metrics
func newMetrics() *Metrics {
	m := &Metrics{
		// Connection metrics
		ConnectionsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_connections_total",
			Help: "Total number of SMTP connections",
		}),
		ConnectionsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "elemta_connections_active",
			Help: "Number of active SMTP connections",
		}),
		ConnectionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "elemta_connection_duration_seconds",
			Help:    "Duration of SMTP connections",
			Buckets: prometheus.DefBuckets,
		}),
		ConnectionErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_connection_errors_total",
			Help: "Total number of SMTP connection errors",
		}),

		// Message metrics
		MessagesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_messages_received_total",
			Help: "Total number of messages received",
		}),
		MessagesDelivered: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_messages_delivered_total",
			Help: "Total number of messages delivered",
		}),
		MessagesFailed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_messages_failed_total",
			Help: "Total number of messages that failed delivery",
		}),
		MessageSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "elemta_message_size_bytes",
			Help:    "Size of messages in bytes",
			Buckets: []float64{1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024},
		}),

		// Queue metrics
		QueueSize: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "elemta_queue_size",
			Help: "Number of messages in queue",
		}, []string{"queue_type"}),
		QueueProcessingTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "elemta_queue_processing_time_seconds",
			Help:    "Time taken to process queue",
			Buckets: prometheus.DefBuckets,
		}),

		// Delivery metrics
		DeliveryAttempts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_delivery_attempts_total",
			Help: "Total number of delivery attempts",
		}),
		DeliverySuccesses: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_delivery_successes_total",
			Help: "Total number of successful deliveries",
		}),
		DeliveryFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_delivery_failures_total",
			Help: "Total number of failed deliveries",
		}),
		DeliveryDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "elemta_delivery_duration_seconds",
			Help:    "Duration of delivery attempts",
			Buckets: prometheus.DefBuckets,
		}),

		// TLS metrics
		TLSConnections: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_tls_connections_total",
			Help: "Total number of TLS connections",
		}),
		TLSHandshakeFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_tls_handshake_failures_total",
			Help: "Total number of TLS handshake failures",
		}),

		// Authentication metrics
		AuthAttempts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_auth_attempts_total",
			Help: "Total number of authentication attempts",
		}),
		AuthSuccesses: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_auth_successes_total",
			Help: "Total number of successful authentications",
		}),
		AuthFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elemta_auth_failures_total",
			Help: "Total number of failed authentications",
		}),
	}

	// Initialize queue size metrics for different queue types
	for _, queueType := range []string{"active", "deferred", "held", "failed"} {
		m.QueueSize.WithLabelValues(queueType).Set(0)
	}

	return m
}

// StartMetricsServer starts the Prometheus metrics HTTP server
func StartMetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't crash
			// We'll use fmt.Printf here since we might not have a logger available
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()

	return server
}

// UpdateQueueSizes updates the queue size metrics
func (m *Metrics) UpdateQueueSizes(config *Config) {
	// Update queue sizes for different queue types
	for _, queueType := range []string{"active", "deferred", "held", "failed"} {
		queueDir := filepath.Join(config.QueueDir, queueType)
		files, err := os.ReadDir(queueDir)
		if err != nil {
			continue
		}

		// Count only message files, not metadata files
		count := 0
		for _, file := range files {
			if filepath.Ext(file.Name()) != ".json" {
				count++
			}
		}

		m.QueueSize.WithLabelValues(queueType).Set(float64(count))
	}
}

// TrackDeliveryDuration tracks the duration of a delivery attempt
func (m *Metrics) TrackDeliveryDuration(f func() error) error {
	startTime := time.Now()
	m.DeliveryAttempts.Inc()

	err := f()

	duration := time.Since(startTime).Seconds()
	m.DeliveryDuration.Observe(duration)

	if err != nil {
		m.DeliveryFailures.Inc()
	} else {
		m.DeliverySuccesses.Inc()
	}

	return err
}

// TrackConnectionDuration tracks the duration of an SMTP connection
func (m *Metrics) TrackConnectionDuration(f func() error) error {
	startTime := time.Now()
	m.ConnectionsTotal.Inc()
	m.ConnectionsActive.Inc()

	defer func() {
		duration := time.Since(startTime).Seconds()
		m.ConnectionDuration.Observe(duration)
		m.ConnectionsActive.Dec()
	}()

	err := f()
	if err != nil {
		m.ConnectionErrors.Inc()
	}

	return err
}

// TrackQueueProcessingTime tracks the time taken to process the queue
func (m *Metrics) TrackQueueProcessingTime(f func() error) error {
	startTime := time.Now()

	err := f()

	duration := time.Since(startTime).Seconds()
	m.QueueProcessingTime.Observe(duration)

	return err
}
