package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	deliverymetrics "github.com/busybox42/elemta/internal/metrics"
	"github.com/busybox42/elemta/internal/plugin"
	"github.com/busybox42/elemta/internal/queue"
	"github.com/google/uuid"
	"github.com/sony/gobreaker"
	"golang.org/x/sync/errgroup"
)

// Server represents an SMTP server
type Server struct {
	config          *Config
	listener        net.Listener
	running         bool
	pluginManager   *plugin.Manager
	builtinPlugins  *plugin.BuiltinPlugins // Built-in plugins for spam/antivirus scanning
	authenticator   Authenticator
	metricsManager  *MetricsManager    // Extracted metrics management
	queueManager    queue.QueueManager // Unified queue system
	queueProcessor  *queue.Processor   // Queue processor for message delivery
	tlsManager      TLSHandler
	resourceManager *ResourceManager // Resource management and rate limiting
	slogger         *slog.Logger     // Structured logger for resource management

	// Concurrency management
	workerPool   *WorkerPool        // Standardized worker pool for connection handling
	rootCtx      context.Context    // Server root context for lifecycle management
	rootCancel   context.CancelFunc // Server root context cancellation
	ctx          context.Context    // Server context for graceful shutdown (worker context)
	cancel       context.CancelFunc
	errGroup     *errgroup.Group // Coordinated goroutine management
	shutdownOnce sync.Once       // Ensure shutdown is called only once
}

// NewServer creates a new SMTP server
func NewServer(config *Config) (*Server, error) {
	// Validate configuration
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.Hostname == "" {
		// Try to get hostname from OS
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("hostname not provided in config and could not be determined: %w", err)
		}
		config.Hostname = hostname
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":2525" // Default SMTP port (non-privileged)
	}

	// Set up logger
	// Set up logger
	// logger := log.New(os.Stdout, "SMTP: ", log.LstdFlags) - Removed in favor of slogger

	// Set up structured logger for resource management
	slogger := slog.Default().With(
		"component", "smtp-server",
		"hostname", config.Hostname,
	)

	slogger.Info("Initializing SMTP server",
		"event_type", "system",
		"hostname", config.Hostname)

	// Initialize plugin manager if enabled
	var pluginManager *plugin.Manager
	var builtinPlugins *plugin.BuiltinPlugins
	if config.Plugins != nil && config.Plugins.Enabled {
		pluginManager = plugin.NewManager(config.Plugins.PluginPath)
		slogger.Info("Plugin system enabled", "path", config.Plugins.PluginPath)

		// Load plugins
		if err := pluginManager.LoadPlugins(); err != nil {
			slogger.Warn("Failed to load plugins", "error", err)
		}

		// Load specific plugins if specified
		if len(config.Plugins.Plugins) > 0 {
			slogger.Info("Attempting to load specified plugins", "count", len(config.Plugins.Plugins))
			for _, pluginName := range config.Plugins.Plugins {
				if err := pluginManager.LoadPlugin(pluginName); err != nil {
					slogger.Warn("Failed to load plugin", "plugin", pluginName, "error", err)
				} else {
					slogger.Info("Successfully loaded plugin", "plugin", pluginName)
				}
			}
		}
	}

	// Initialize builtin plugins for basic spam/antivirus scanning
	builtinPlugins = plugin.NewBuiltinPlugins()
	// Only initialize plugins if explicitly enabled
	if config.Plugins != nil && config.Plugins.Enabled {
		if len(config.Plugins.Plugins) > 0 {
			// Initialize builtin plugins with configuration
			pluginConfig := make(map[string]map[string]interface{})
			// Add default configurations for builtin plugins
			pluginConfig["clamav"] = map[string]interface{}{
				"host":    "elemta-clamav",
				"port":    3310,
				"timeout": 30,
			}
			pluginConfig["rspamd"] = map[string]interface{}{
				"host":      "elemta-rspamd",
				"port":      11334,
				"timeout":   30,
				"threshold": 5.0,
			}

			if err := builtinPlugins.InitBuiltinPlugins(config.Plugins.Plugins, pluginConfig); err != nil {
				slogger.Warn("Failed to initialize builtin plugins", "error", err)
			} else {
				slogger.Info("Builtin plugins initialized successfully")
			}
		} else {
			// Initialize with basic builtin scanning if plugins enabled but none specified
			basicPlugins := []string{"rspamd"}
			if os.Getenv("ELEMTA_DISABLE_CLAMAV") != "true" {
				basicPlugins = append(basicPlugins, "clamav")
			}

			pluginConfig := make(map[string]map[string]interface{})
			if os.Getenv("ELEMTA_DISABLE_CLAMAV") != "true" {
				pluginConfig["clamav"] = map[string]interface{}{
					"host":    "elemta-clamav",
					"port":    3310,
					"timeout": 30,
				}
			}
			pluginConfig["rspamd"] = map[string]interface{}{
				"host":      "elemta-rspamd",
				"port":      11334,
				"timeout":   30,
				"threshold": 5.0,
			}

			if err := builtinPlugins.InitBuiltinPlugins(basicPlugins, pluginConfig); err != nil {
				slogger.Warn("Failed to initialize basic builtin plugins", "error", err)
			} else {
				slogger.Info("Basic builtin plugins initialized successfully")
			}
		}
	} else {
		slogger.Info("Plugins disabled or not configured")
	}

	// Initialize authenticator if enabled
	var authenticator Authenticator
	var err error
	if config.Auth != nil && config.Auth.Enabled {
		slogger.Info("Authentication enabled, initializing authenticator")
		authenticator, err = NewAuthenticator(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize authenticator: %w", err)
		}

		if config.Auth.Required {
			slogger.Info("Authentication will be required for all mail transactions")
		} else {
			slogger.Info("Authentication available but not required")
		}
	} else {
		// Create a dummy authenticator that always returns true
		slogger.Info("Authentication disabled, using dummy authenticator")
		authenticator = &SMTPAuthenticator{
			config: &AuthConfig{
				Enabled:  false,
				Required: false,
			},
		}
	}

	// Initialize metrics
	metrics := GetMetrics()
	slogger.Info("Metrics system initialized")

	// Initialize metrics manager
	metricsManager := NewMetricsManager(config, slogger, metrics)

	// Debug: print AuthConfig and TLSConfig
	if config.Auth != nil {
		slogger.Info("Auth config loaded",
			"enabled", config.Auth.Enabled,
			"required", config.Auth.Required,
			"datasource", config.Auth.DataSourceType)
	}

	if config.TLS != nil {
		slogger.Info("TLS config loaded",
			"enabled", config.TLS.Enabled,
			"starttls", config.TLS.EnableStartTLS)
	}

	// Initialize unified queue system
	slogger.Info("Initializing unified queue system", "directory", config.QueueDir)
	queueManager := queue.NewManager(config.QueueDir, config.FailedQueueRetentionHours)
	slogger.Info("Unified queue system initialized")

	// Initialize queue processor if enabled
	var queueProcessor *queue.Processor
	if config.QueueProcessorEnabled {
		slogger.Info("Queue processor enabled, initializing")

		// Create LMTP delivery handler
		deliveryHost := "elemta-dovecot"
		deliveryPort := 2424
		if config.Delivery != nil {
			if config.Delivery.Host != "" {
				deliveryHost = config.Delivery.Host
			}
			if config.Delivery.Port != 0 {
				deliveryPort = config.Delivery.Port
			}
		}

		// Determine per-domain concurrency limit for LMTP deliveries
		maxPerDomain := config.MaxConnectionsPerDomain
		if maxPerDomain <= 0 {
			maxPerDomain = 10
		}

		slogger.Info("Creating LMTP delivery handler", "host", deliveryHost, "port", deliveryPort, "max_per_domain", maxPerDomain)
		lmtpHandler := queue.NewLMTPDeliveryHandler(deliveryHost, deliveryPort, maxPerDomain, config.FailedQueueRetentionHours)

		// Create processor configuration
		processorConfig := queue.ProcessorConfig{
			Enabled:       config.QueueProcessorEnabled,
			Interval:      time.Duration(config.QueueProcessInterval) * time.Second,
			MaxConcurrent: config.QueueWorkers,
			MaxRetries:    config.MaxRetries,
			RetrySchedule: config.RetrySchedule,
			CleanupAge:    24 * time.Hour,
		}

		slogger.Info("Creating queue processor",
			"enabled", processorConfig.Enabled,
			"interval", processorConfig.Interval,
			"workers", processorConfig.MaxConcurrent)

		queueProcessor = queue.NewProcessor(queueManager, processorConfig, lmtpHandler)
		slogger.Info("Queue processor initialized successfully")

		// Set up Valkey metrics recorder if available
		valkeyAddr := os.Getenv("VALKEY_ADDR")
		if valkeyAddr == "" {
			valkeyAddr = "elemta-valkey:6379"
		}
		metricsStore, err := deliverymetrics.NewValkeyStore(valkeyAddr)
		if err != nil {
			slogger.Warn("Failed to connect to Valkey for metrics", "error", err)
		} else {
			queueProcessor.SetMetricsRecorder(metricsStore)
			slogger.Info("Connected to Valkey for metrics", "address", valkeyAddr)
		}
	} else {
		slogger.Info("Queue processor disabled")
	}

	// Initialize resource manager with limits from config
	var resourceLimits *ResourceLimits
	var resourceManager *ResourceManager

	if config.Resources != nil {
		// Use memory configuration if available, otherwise use defaults
		var memoryConfig *MemoryConfig
		if config.Memory != nil {
			memoryConfig = config.Memory
			slogger.Info("Using memory configuration",
				"total_mb", memoryConfig.MaxMemoryUsage/(1024*1024),
				"per_conn_mb", memoryConfig.PerConnectionMemoryLimit/(1024*1024))
		} else {
			memoryConfig = DefaultMemoryConfig()
			slogger.Info("Using default memory configuration",
				"total_mb", memoryConfig.MaxMemoryUsage/(1024*1024),
				"per_conn_mb", memoryConfig.PerConnectionMemoryLimit/(1024*1024))
		}

		// Handle missing fields with sensible defaults
		maxConnPerIP := config.Resources.MaxConnectionsPerIP
		if maxConnPerIP == 0 {
			maxConnPerIP = config.Resources.MaxConcurrent // Fallback to MaxConcurrent if not set
			if maxConnPerIP == 0 {
				maxConnPerIP = 50 // Final fallback default
			}
		}

		goroutinePoolSize := config.Resources.GoroutinePoolSize
		if goroutinePoolSize == 0 {
			goroutinePoolSize = 100 // Default pool size
		}

		rateLimitWindow := time.Duration(config.Resources.RateLimitWindow) * time.Second
		if rateLimitWindow == 0 {
			rateLimitWindow = time.Minute // Default 1 minute window
		}

		maxRequestsPerWindow := config.Resources.MaxRequestsPerWindow
		if maxRequestsPerWindow == 0 {
			maxRequestsPerWindow = config.Resources.MaxConnections * 10 // Default: 10 requests per connection
		}

		resourceLimits = &ResourceLimits{
			MaxConnections:            config.Resources.MaxConnections,
			MaxConnectionsPerIP:       maxConnPerIP,
			MaxGoroutines:             config.Resources.MaxConnections * 2, // Allow 2 goroutines per connection
			ConnectionTimeout:         time.Duration(config.Resources.ConnectionTimeout) * time.Second,
			SessionTimeout:            time.Duration(config.Resources.SessionTimeout) * time.Second,
			IdleTimeout:               time.Duration(config.Resources.IdleTimeout) * time.Second,
			RateLimitWindow:           rateLimitWindow,
			MaxRequestsPerWindow:      maxRequestsPerWindow,
			MaxMemoryUsage:            memoryConfig.MaxMemoryUsage, // Use configured memory limit
			GoroutinePoolSize:         goroutinePoolSize,
			CircuitBreakerEnabled:     true,
			ResourceMonitoringEnabled: true,
			ValkeyURL:                 config.Resources.ValkeyURL,       // Valkey for distributed rate limiting
			ValkeyKeyPrefix:           config.Resources.ValkeyKeyPrefix, // Valkey key prefix
		}

		// Initialize resource manager with memory configuration
		resourceManager = NewResourceManager(resourceLimits, slogger)

		// Initialize memory manager with configuration
		memoryManager := NewMemoryManager(memoryConfig, slogger)
		resourceManager.SetMemoryManager(memoryManager)

		slogger.Info("Resource manager initialized with memory protection enabled")
	} else {
		resourceLimits = DefaultResourceLimits()
		resourceManager = NewResourceManager(resourceLimits, slogger)
		// Initialize default memory manager
		memoryManager := NewMemoryManager(DefaultMemoryConfig(), slogger)
		resourceManager.SetMemoryManager(memoryManager)
		slogger.Info("Resource manager initialized with default memory protection")
	}

	// Initialize concurrency management with hierarchical context
	rootCtx, rootCancel := context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(rootCtx)
	errGroup, gctx := errgroup.WithContext(ctx)

	// Initialize worker pool for connection handling
	workerPoolConfig := &WorkerPoolConfig{
		Size:               20,  // Configurable worker pool size
		JobBufferSize:      100, // Buffer for incoming connections
		ResultBufferSize:   100,
		CircuitBreakerName: "smtp-connections",
		MaxRequests:        1000,
		Interval:           time.Minute,
		Timeout:            30 * time.Second,
		MaxGoroutines:      int32(resourceLimits.MaxGoroutines),
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			slogger.Info("SMTP connection circuit breaker state changed",
				"name", name,
				"from", from.String(),
				"to", to.String(),
			)
		},
	}

	workerPool := NewWorkerPool(workerPoolConfig, slogger)

	server := &Server{
		config:          config,
		running:         false,
		pluginManager:   pluginManager,
		builtinPlugins:  builtinPlugins,
		authenticator:   authenticator,
		metricsManager:  metricsManager,
		queueManager:    queueManager,
		queueProcessor:  queueProcessor,
		resourceManager: resourceManager,
		slogger:         slogger,

		// Concurrency management with hierarchical context
		workerPool: workerPool,
		rootCtx:    rootCtx,    // Server lifecycle context
		rootCancel: rootCancel, // Server lifecycle cancellation
		ctx:        gctx,       // Worker context (derived from root)
		cancel:     cancel,     // Worker context cancellation
		errGroup:   errGroup,
	}

	// Initialize TLS manager if TLS is enabled
	if config.TLS != nil && config.TLS.Enabled {
		slogger.Info("TLS enabled, initializing TLS manager")
		tlsManager, err := NewTLSManager(config)
		if err != nil {
			// TLS is explicitly enabled; failing to initialize it is a hard error
			return nil, fmt.Errorf("failed to initialize TLS manager: %w", err)
		}
		server.tlsManager = tlsManager
		server.tlsManager = tlsManager
		slogger.Info("TLS manager initialized successfully")

		// Log certificate information
		if config.TLS.CertFile != "" {
			slogger.Info("Using TLS certificate", "file", config.TLS.CertFile)
		}
		if config.TLS.LetsEncrypt != nil && config.TLS.LetsEncrypt.Enabled {
			slogger.Info("Let's Encrypt enabled", "domain", config.TLS.LetsEncrypt.Domain)
		}
	} else {
		slogger.Info("TLS disabled")
	}

	// Initialize scanner manager
	scannerManager := NewScannerManager(config, server)
	if err := scannerManager.Initialize(context.Background()); err != nil {
		slogger.Warn("Error initializing scanner manager",
			"error", err,
			"component", "scanner-manager",
		)
		// Continue even if scanner initialization fails
		// This prevents the server from crashing if scanners are misconfigured
	}

	return server, nil
}

// Addr returns the server's listen address
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	if s.running {
		return fmt.Errorf("server already running")
	}

	s.slogger.Info("Starting SMTP server",
		"event_type", "system",
		"listen_addr", s.config.ListenAddr)

	// Create all required queue directories
	if err := s.setupQueueDirectories(); err != nil {
		return fmt.Errorf("queue directory setup failed: %w", err)
	}

	// Create listener
	s.slogger.Info("Creating TCP listener", "address", s.config.ListenAddr)
	var err error
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.running = true
	s.slogger.Info("SMTP server running",
		"event_type", "system",
		"listen_addr", s.config.ListenAddr)

	// Start the new queue system if available
	if s.queueManager != nil {

		// The new queue system doesn't need explicit startup
		s.slogger.Info("Starting unified queue system")
		// The new queue system doesn't need explicit startup
		s.slogger.Info("Unified queue system started successfully")
	}

	// Start queue processor if available
	if s.queueProcessor != nil {
		s.slogger.Info("Starting queue processor")
		if err := s.queueProcessor.Start(); err != nil {
			s.slogger.Warn("Failed to start queue processor", "error", err)
		} else {
			s.slogger.Info("Queue processor started successfully")
		}
	}

	// Start metrics server if enabled
	if err := s.metricsManager.Start(); err != nil {
		s.slogger.Error("Failed to start metrics server", "error", err)
		return err
	}

	// Start periodic queue size updates
	go s.updateQueueMetricsWithRetry()

	// Start worker pool for connection handling
	s.slogger.Info("Starting worker pool", "workers", s.workerPool.size)
	if err := s.workerPool.Start(); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}

	// Handle connections with coordinated goroutine management
	s.errGroup.Go(s.acceptConnections)

	return nil
}

// setupQueueDirectories ensures all needed queue directories exist with secure permissions
func (s *Server) setupQueueDirectories() error {
	if s.config.QueueDir == "" {
		return fmt.Errorf("queue directory not configured")
	}

	// Ensure main queue directory exists with secure permissions (0700)
	if err := os.MkdirAll(s.config.QueueDir, 0700); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Create subdirectories for different queue types with secure permissions
	queueTypes := []string{"active", "deferred", "held", "failed", "data", "tmp", "quarantine"}

	for _, qType := range queueTypes {
		qDir := filepath.Join(s.config.QueueDir, qType)
		if err := os.MkdirAll(qDir, 0700); err != nil {
			return fmt.Errorf("failed to create %s queue directory: %w", qType, err)
		}
		s.slogger.Info("Created secure queue directory", "path", qDir, "mode", "0700")
	}

	return nil
}

// updateQueueMetricsWithRetry periodically updates queue size metrics with retry on failure
func (s *Server) updateQueueMetricsWithRetry() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for s.running {
		// Update metrics and log any errors we encounter
		func() {
			// Use defer to catch any panics that might occur
			defer func() {
				if r := recover(); r != nil {
					s.slogger.Error("Panic in queue metrics update", "panic", r)
				}
			}()

			// Update queue metrics
			s.metricsManager.UpdateQueueSizes()
			s.slogger.Debug("Queue metrics updated successfully")
		}()

		<-ticker.C
	}
}

// acceptConnections accepts and handles incoming connections with standardized worker pool
func (s *Server) acceptConnections() error {
	s.slogger.Info("Starting connection acceptance loop")
	s.slogger.Debug("acceptConnections goroutine started")

	for {
		select {
		case <-s.ctx.Done():
			s.slogger.Info("Context cancelled, stopping connection acceptance")
			return s.ctx.Err()
		default:
		}

		// Set a short timeout on accept to allow periodic context checking
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				s.slogger.Error("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Check if it's a timeout error (expected)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			if s.running {
				s.slogger.Error("Failed to accept connection", "error", err)
			}
			continue
		}

		s.slogger.Debug("Connection accepted", "remote_addr", conn.RemoteAddr().String())

		// Reset deadline after successful accept
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Time{}) // Best effort
		}

		// Check if connection can be accepted based on resource limits
		clientAddr := conn.RemoteAddr().String()
		s.slogger.Debug("Checking if connection can be accepted", "client_addr", clientAddr)
		if !s.resourceManager.CanAcceptConnection(clientAddr) {
			s.slogger.Warn("Connection rejected due to resource limits", "client_ip", clientAddr)
			_ = conn.Close() // Ignore error when rejecting connection
			continue
		}
		s.slogger.Debug("Connection accepted by resource manager")

		// Create connection job for worker pool
		jobID := uuid.New().String()
		connectionJob := &ConnectionJob{
			id:        jobID,
			conn:      conn,
			handler:   s.handleConnectionWithContext,
			priority:  1, // Normal priority
			createdAt: time.Now(),
		}

		// Submit job to worker pool with timeout
		s.slogger.Debug("Submitting connection job to worker pool", "job_id", jobID)
		if err := s.workerPool.SubmitWithTimeout(connectionJob, 5*time.Second); err != nil {
			s.slogger.Warn("Failed to submit connection to worker pool, handling directly",
				"remote_addr", clientAddr,
				"job_id", jobID,
				"error", err,
				"worker_pool_stats", s.workerPool.GetStats(),
			)

			// Fallback: handle connection directly in a tracked goroutine
			s.errGroup.Go(func() error {
				defer func() {
					if r := recover(); r != nil {
						s.slogger.Error("panic in fallback connection handler",
							"remote_addr", clientAddr,
							"job_id", jobID,
							"panic", r,
						)
					}
				}()
				s.handleAndCloseSession(s.ctx, conn)
				return nil
			})
		} else {
			s.slogger.Debug("Connection submitted to worker pool",
				"remote_addr", clientAddr,
				"job_id", jobID,
			)
		}
	}
}

// handleConnectionWithContext processes a connection with proper context handling
// handleConnectionWithContext handles a connection with context support
func (s *Server) handleConnectionWithContext(ctx context.Context, conn interface{}) error {
	s.slogger.Debug("handleConnectionWithContext called")
	netConn, ok := conn.(net.Conn)
	if !ok {
		s.slogger.Debug("Invalid connection type")
		return fmt.Errorf("invalid connection type")
	}
	s.slogger.Debug("Connection type is valid, proceeding with session handling")

	// Ensure connection is closed when done
	defer func() {
		s.slogger.Debug("Closing connection")
		_ = netConn.Close() // Ignore error in defer cleanup
	}()

	// Handle the session with context - pass ctx to the session handler
	s.slogger.Debug("Calling handleAndCloseSession")
	s.handleAndCloseSession(ctx, netConn)
	s.slogger.Debug("handleAndCloseSession completed")
	return nil
}

// handleAndCloseSession processes a connection and ensures it's properly closed with guaranteed cleanup
func (s *Server) handleAndCloseSession(ctx context.Context, conn net.Conn) {
	clientIP := conn.RemoteAddr().String()
	s.slogger.Debug("handleAndCloseSession called", "client_ip", clientIP)
	var sessionID string
	var cleanupDone bool

	// Initialize logger if it's nil
	// Initialize logger if it's nil
	// if s.logger == nil { ... } - Removed

	// Guaranteed cleanup function that runs even on panic
	cleanup := func() {
		if cleanupDone {
			return
		}
		cleanupDone = true

		// Release connection from resource manager
		if sessionID != "" {
			s.resourceManager.ReleaseConnection(sessionID)
		}

		// Close the connection
		if err := conn.Close(); err != nil {
			s.slogger.Error("Failed to close connection during cleanup", "error", err, "client_ip", clientIP, "session_id", sessionID)
		}
	}

	// Ensure cleanup happens even on panic
	defer func() {
		if r := recover(); r != nil {
			s.slogger.Error("Panic in session handling", "panic", r, "client_ip", clientIP, "session_id", sessionID)
			cleanup()
			panic(r) // Re-panic to maintain panic behavior
		}
		cleanup()
	}()

	// Register connection with resource manager
	s.slogger.Debug("Registering connection with resource manager")
	sessionID = s.resourceManager.AcceptConnection(conn)
	s.slogger.Debug("Connection registered", "session_id", sessionID)
	s.slogger.Info("New connection", "client_ip", clientIP, "session_id", sessionID)

	// Set connection timeout
	s.slogger.Debug("Setting connection deadline")
	if err := conn.SetDeadline(time.Now().Add(s.resourceManager.GetConnectionTimeout())); err != nil {
		s.slogger.Debug("Failed to set connection deadline", "error", err)
		s.slogger.Error("Failed to set connection deadline", "error", err, "client_ip", clientIP, "session_id", sessionID)
	} else {
		s.slogger.Debug("Connection deadline set successfully")
	}

	// Create a new session with the current configuration and authentication
	// Use context.Background() to avoid inheriting the short-lived worker pool job context
	s.slogger.Debug("Creating new SMTP session", "client_ip", clientIP)
	session := NewSession(context.Background(), conn, s.config, s.authenticator)
	s.slogger.Debug("SMTP session created successfully")

	// Set the TLS manager from the server
	session.SetTLSManager(s.tlsManager)

	// Set the builtin plugins from the server
	session.SetBuiltinPlugins(s.builtinPlugins)

	// Set queue manager for message processing
	if s.queueManager != nil {
		session.SetQueueManager(s.queueManager)
	}

	// Set additional components
	session.SetResourceManager(s.resourceManager)
	// Note: Builtin plugins would be set through plugin manager if needed

	// Handle the SMTP session directly (circuit breaker disabled for now due to premature failures)
	s.slogger.Debug("Starting session.Handle()", "client_ip", clientIP)
	err := session.Handle()
	s.slogger.Debug("session.Handle() completed", "client_ip", clientIP)

	if err != nil {
		if err != io.EOF && err != context.DeadlineExceeded {
			s.slogger.Error("Session error", "error", err, "client_ip", clientIP, "session_id", sessionID)
		}
	}
}

// Close closes the server and all associated resources with graceful shutdown
func (s *Server) Close() error {
	var shutdownErr error

	s.shutdownOnce.Do(func() {
		s.slogger.Info("Initiating graceful server shutdown")
		s.running = false

		// Cancel root context first to propagate cancellation to all sessions
		if s.rootCancel != nil {
			s.slogger.Debug("Cancelling server root context to propagate shutdown signal")
			s.rootCancel()
		}

		// Close listener first to stop accepting new connections
		if s.listener != nil {
			if err := s.listener.Close(); err != nil {
				s.slogger.Error("Error closing listener", "error", err)
				shutdownErr = err
			}
		}

		// Stop worker pool gracefully
		if s.workerPool != nil {
			s.slogger.Info("Stopping worker pool")
			if err := s.workerPool.Stop(); err != nil {
				s.slogger.Error("Error stopping worker pool", "error", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			} else {
				s.slogger.Info("Worker pool stopped successfully")
			}
		}

		// Wait for all managed goroutines to complete with configured timeout
		shutdownTimeout := s.config.Timeouts.ShutdownTimeout
		if shutdownTimeout == 0 {
			shutdownTimeout = 30 * time.Second // fallback default
		}

		s.slogger.Info("Waiting for goroutines to complete", "timeout", shutdownTimeout)
		done := make(chan error, 1)
		go func() {
			done <- s.errGroup.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				s.slogger.Error("Error during goroutine shutdown", "error", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			} else {
				s.slogger.Info("All goroutines stopped successfully")
			}
		case <-time.After(shutdownTimeout):
			s.slogger.Warn("Goroutine shutdown timeout after 30 seconds")
			if shutdownErr == nil {
				shutdownErr = fmt.Errorf("shutdown timeout")
			}
		}

		// Close resource manager
		if s.resourceManager != nil {
			s.resourceManager.Close()
		}

		// Close metrics server if it was started
		if s.metricsManager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.metricsManager.Shutdown(ctx); err != nil {
				s.slogger.Error("Error shutting down metrics server", "error", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Close plugin manager
		if s.pluginManager != nil {
			if err := s.pluginManager.Close(); err != nil {
				s.slogger.Error("Error closing plugin manager", "error", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Close authenticator
		if s.authenticator != nil {
			if auth, ok := s.authenticator.(*SMTPAuthenticator); ok {
				if err := auth.Close(); err != nil {
					s.slogger.Error("Error closing authenticator", "error", err)
					if shutdownErr == nil {
						shutdownErr = err
					}
				}
			}
		}

		// Stop TLS manager if it was initialized
		if s.tlsManager != nil {
			if err := s.tlsManager.Stop(); err != nil {
				s.slogger.Error("Error stopping TLS manager", "error", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Stop queue processor
		if s.queueProcessor != nil {
			s.slogger.Info("Stopping queue processor")
			if err := s.queueProcessor.Stop(); err != nil {
				s.slogger.Error("Error stopping queue processor", "error", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			} else {
				s.slogger.Info("Queue processor stopped successfully")
			}
		}

		// Stop queue manager
		if s.queueManager != nil {
			s.slogger.Info("Stopping queue manager")
			s.queueManager.Stop()
		}

		s.slogger.Info("Graceful server shutdown completed")
	})

	return shutdownErr
}

// Wait waits for all server goroutines to complete
func (s *Server) Wait() error {
	return s.errGroup.Wait()
}

// ... existing code ...
