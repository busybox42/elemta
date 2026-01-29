package queue

import (
	"context"
	"time"
)

// QueueManager defines the interface for queue management operations
type QueueManager interface {
	// Basic queue operations
	EnqueueMessage(from string, to []string, subject string, data []byte, priority Priority, receivedAt time.Time) (string, error)
	GetMessage(id string) (Message, error)
	DeleteMessage(id string) error
	ListMessages(queueType QueueType) ([]Message, error)
	GetAllMessages() ([]Message, error)

	// Queue management
	MoveMessage(id string, targetQueue QueueType, reason string) error
	FlushQueue(queueType QueueType) error
	FlushAllQueues() error

	// Message content operations
	GetMessageContent(id string) ([]byte, error)

	// Tracking and annotations
	AddAttempt(id string, result string, errorMsg string) error
	SetAnnotation(id string, key, value string) error

	// Statistics and monitoring
	GetStats() QueueStats
	UpdateStats() error
	GetFailedQueueRetentionHours() int

	// Cleanup
	CleanupExpiredMessages(retentionHours int) (int, error)

	// Lifecycle
	Stop()
}

// DeliveryManager defines the interface for message delivery operations
type DeliveryManager interface {
	// Delivery operations
	ProcessQueue(ctx context.Context, queueType QueueType) error
	DeliverMessage(ctx context.Context, msg Message) error

	// Delivery configuration
	SetMaxConcurrent(count int)
	SetRetrySchedule(schedule []int)
	GetFailedQueueRetentionHours() int

	// Delivery hooks and events
	AddDeliveryHook(hook DeliveryHook)

	// Rate limiting
	AcquireRateLimit(domain string) bool
	ReleaseRateLimit(domain string)

	// Lifecycle
	Start() error
	Stop() error
}

// DeliveryHook is called on delivery events
type DeliveryHook func(event string, messageID string, details map[string]interface{})

// ProcessorManager defines the interface for queue processing coordination
type ProcessorManager interface {
	// Processor lifecycle
	Start() error
	Stop() error

	// Processing control
	SetEnabled(enabled bool)
	SetInterval(interval time.Duration)
	SetMaxWorkers(count int)

	// Queue processing coordination
	ProcessAllQueues(ctx context.Context) error
	ProcessActiveQueue(ctx context.Context) error
	ProcessDeferredQueue(ctx context.Context) error

	// Cleanup coordination
	RunCleanup() error
}

// StorageBackend defines the interface for queue storage implementations
type StorageBackend interface {
	// Basic storage operations
	Store(msg Message) error
	Retrieve(id string) (Message, error)
	Update(msg Message) error
	Delete(id string) error

	// Listing and querying
	List(queueType QueueType) ([]Message, error)
	Count(queueType QueueType) (int, error)

	// Bulk operations
	DeleteAll(queueType QueueType) error
	Move(id string, fromQueue, toQueue QueueType) error

	// Content operations
	StoreContent(id string, data []byte) error
	RetrieveContent(id string) ([]byte, error)
	DeleteContent(id string) error

	// Cleanup
	Cleanup(retentionHours int) (int, error)
}

// DeliveryBackend defines the interface for delivery implementations
type DeliveryBackend interface {
	// Delivery operations
	DeliverMessage(ctx context.Context, msg Message, data []byte) error

	// Connection management
	SupportsConnection(protocol string) bool
	GetMaxConcurrent() int

	// Delivery information
	GetName() string
	GetProtocol() string
}

// MonitoringBackend defines the interface for queue monitoring
type MonitoringBackend interface {
	// Metrics collection
	RecordMessageEnqueued(queueType QueueType, priority Priority)
	RecordMessageDelivered(messageID string, duration time.Duration)
	RecordMessageFailed(messageID string, reason string)
	RecordMessageDeferred(messageID string, retryCount int)

	// Statistics reporting
	GetDeliveryStats() DeliveryStats
	GetQueueDepth(queueType QueueType) int
	GetProcessingRate() float64

	// Health checks
	IsHealthy() bool
	GetLastError() error
}

// DeliveryStats contains delivery performance statistics
type DeliveryStats struct {
	TotalProcessed   int64         `json:"total_processed"`
	TotalDelivered   int64         `json:"total_delivered"`
	TotalFailed      int64         `json:"total_failed"`
	TotalDeferred    int64         `json:"total_deferred"`
	AverageLatency   time.Duration `json:"average_latency"`
	DeliveryRate     float64       `json:"delivery_rate_per_minute"`
	FailureRate      float64       `json:"failure_rate_percentage"`
	LastProcessed    time.Time     `json:"last_processed"`
	ProcessingErrors []string      `json:"processing_errors,omitempty"`
}

// QueueConfiguration contains all queue-related configuration
type QueueConfiguration struct {
	// Storage configuration
	QueueDir    string `toml:"queue_dir" json:"queue_dir"`
	StorageType string `toml:"storage_type" json:"storage_type"` // "file", "database", etc.

	// Processing configuration
	Enabled         bool `toml:"enabled" json:"enabled"`
	MaxWorkers      int  `toml:"max_workers" json:"max_workers"`
	ProcessInterval int  `toml:"process_interval" json:"process_interval"` // seconds

	// Delivery configuration
	MaxConcurrent   int   `toml:"max_concurrent" json:"max_concurrent"`
	RetrySchedule   []int `toml:"retry_schedule" json:"retry_schedule"` // seconds
	MaxRetries      int   `toml:"max_retries" json:"max_retries"`
	DeliveryTimeout int   `toml:"delivery_timeout" json:"delivery_timeout"` // seconds

	// Retention configuration
	RetentionHours            int `toml:"retention_hours" json:"retention_hours"`
	FailedQueueRetentionHours int `toml:"failed_queue_retention_hours" json:"failed_queue_retention_hours"` // 0 = immediate deletion
	CleanupInterval           int `toml:"cleanup_interval" json:"cleanup_interval"`                         // hours

	// Rate limiting configuration
	RateLimitEnabled   bool `toml:"rate_limit_enabled" json:"rate_limit_enabled"`
	RateLimitPerDomain int  `toml:"rate_limit_per_domain" json:"rate_limit_per_domain"`
	RateLimitWindow    int  `toml:"rate_limit_window" json:"rate_limit_window"` // seconds

	// Monitoring configuration
	MonitoringEnabled bool   `toml:"monitoring_enabled" json:"monitoring_enabled"`
	MetricsEndpoint   string `toml:"metrics_endpoint" json:"metrics_endpoint"`

	// Debug configuration
	Debug          bool `toml:"debug" json:"debug"`
	VerboseLogging bool `toml:"verbose_logging" json:"verbose_logging"`
}

// UnifiedQueueSystem coordinates all queue operations
type UnifiedQueueSystem struct {
	QueueManager      QueueManager
	DeliveryManager   DeliveryManager
	ProcessorManager  ProcessorManager
	StorageBackend    StorageBackend
	DeliveryBackend   DeliveryBackend
	MonitoringBackend MonitoringBackend
	Config            QueueConfiguration
}

// NewUnifiedQueueSystem creates a new unified queue system
func NewUnifiedQueueSystem(config QueueConfiguration) *UnifiedQueueSystem {
	// Create storage backend
	var storage StorageBackend
	switch config.StorageType {
	case "database":
		// TODO: Implement database storage backend
		storage = NewFileStorageBackend(config.QueueDir)
	default:
		storage = NewFileStorageBackend(config.QueueDir)
	}

	// Create queue manager using storage backend
	queueManager := NewManagerWithStorage(storage, 0) // Test uses immediate deletion

	// Create delivery manager
	deliveryManager := NewDeliveryManager(queueManager, config)

	// Create processor manager
	processorManager := NewProcessorManager(queueManager, deliveryManager, config)

	// Create monitoring backend
	var monitoring MonitoringBackend
	if config.MonitoringEnabled {
		monitoring = NewMonitoringBackend()
	}

	return &UnifiedQueueSystem{
		QueueManager:      queueManager,
		DeliveryManager:   deliveryManager,
		ProcessorManager:  processorManager,
		StorageBackend:    storage,
		MonitoringBackend: monitoring,
		Config:            config,
	}
}

// Start initializes and starts all components of the queue system
func (uqs *UnifiedQueueSystem) Start() error {
	if err := uqs.ProcessorManager.Start(); err != nil {
		return err
	}

	if err := uqs.DeliveryManager.Start(); err != nil {
		_ = uqs.ProcessorManager.Stop() // Best effort cleanup
		return err
	}

	return nil
}

// Stop gracefully shuts down all components of the queue system
func (uqs *UnifiedQueueSystem) Stop() error {
	_ = uqs.ProcessorManager.Stop() // Best effort
	_ = uqs.DeliveryManager.Stop()  // Best effort
	uqs.QueueManager.Stop()         // No error return
	return nil
}

// GetSystemStats returns comprehensive statistics for the entire queue system
func (uqs *UnifiedQueueSystem) GetSystemStats() SystemStats {
	queueStats := uqs.QueueManager.GetStats()

	var deliveryStats DeliveryStats
	if uqs.MonitoringBackend != nil {
		deliveryStats = uqs.MonitoringBackend.GetDeliveryStats()
	}

	return SystemStats{
		QueueStats:    queueStats,
		DeliveryStats: deliveryStats,
		SystemHealth:  uqs.MonitoringBackend != nil && uqs.MonitoringBackend.IsHealthy(),
		LastUpdated:   time.Now(),
	}
}

// SystemStats contains comprehensive queue system statistics
type SystemStats struct {
	QueueStats    QueueStats    `json:"queue_stats"`
	DeliveryStats DeliveryStats `json:"delivery_stats"`
	SystemHealth  bool          `json:"system_health"`
	LastUpdated   time.Time     `json:"last_updated"`
}
