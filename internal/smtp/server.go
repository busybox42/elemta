package smtp

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/busybox42/elemta/internal/api"
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
	metrics         *Metrics
	metricsServer   *http.Server
	apiServer       *api.Server
	queueManager    queue.QueueManager // Unified queue system
	queueProcessor  *queue.Processor   // Queue processor for message delivery
	tlsManager      TLSHandler
	logger          *log.Logger
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
	logger := log.New(os.Stdout, "SMTP: ", log.LstdFlags)
	logger.Printf("Initializing SMTP server with hostname: %s", config.Hostname)

	// Set up structured logger for resource management
	slogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "smtp-server",
		"hostname", config.Hostname,
	)

	// Initialize plugin manager if enabled
	var pluginManager *plugin.Manager
	var builtinPlugins *plugin.BuiltinPlugins
	if config.Plugins != nil && config.Plugins.Enabled {
		pluginManager = plugin.NewManager(config.Plugins.PluginPath)
		logger.Printf("Plugin system enabled, using path: %s", config.Plugins.PluginPath)

		// Load plugins
		if err := pluginManager.LoadPlugins(); err != nil {
			logger.Printf("Warning: failed to load plugins: %v", err)
		}

		// Load specific plugins if specified
		if len(config.Plugins.Plugins) > 0 {
			logger.Printf("Attempting to load %d specified plugins", len(config.Plugins.Plugins))
			for _, pluginName := range config.Plugins.Plugins {
				if err := pluginManager.LoadPlugin(pluginName); err != nil {
					logger.Printf("Warning: failed to load plugin %s: %v", pluginName, err)
				} else {
					logger.Printf("Successfully loaded plugin: %s", pluginName)
				}
			}
		}
	}

	// Initialize builtin plugins for basic spam/antivirus scanning
	builtinPlugins = plugin.NewBuiltinPlugins()
	if config.Plugins != nil && len(config.Plugins.Plugins) > 0 {
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
			logger.Printf("Warning: failed to initialize builtin plugins: %v", err)
		} else {
			logger.Printf("Builtin plugins initialized successfully")
		}
	} else {
		// Initialize with basic builtin scanning even if no plugins specified
		basicPlugins := []string{"clamav", "rspamd"}
		pluginConfig := make(map[string]map[string]interface{})
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

		if err := builtinPlugins.InitBuiltinPlugins(basicPlugins, pluginConfig); err != nil {
			logger.Printf("Warning: failed to initialize basic builtin plugins: %v", err)
		} else {
			logger.Printf("Basic builtin plugins initialized successfully")
		}
	}

	// Initialize authenticator if enabled
	var authenticator Authenticator
	var err error
	if config.Auth != nil && config.Auth.Enabled {
		logger.Printf("Authentication enabled, initializing authenticator")
		authenticator, err = NewAuthenticator(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize authenticator: %w", err)
		}

		if config.Auth.Required {
			logger.Printf("Authentication will be required for all mail transactions")
		} else {
			logger.Printf("Authentication available but not required")
		}
	} else {
		// Create a dummy authenticator that always returns true
		logger.Printf("Authentication disabled, using dummy authenticator")
		authenticator = &SMTPAuthenticator{
			config: &AuthConfig{
				Enabled:  false,
				Required: false,
			},
		}
	}

	// Initialize metrics
	metrics := GetMetrics()
	logger.Printf("Metrics system initialized")

	// Debug: print AuthConfig and TLSConfig
	if config.Auth != nil {
		logger.Printf("Auth config loaded: enabled=%v, required=%v, datasource=%s",
			config.Auth.Enabled,
			config.Auth.Required,
			config.Auth.DataSourceType)
	}

	if config.TLS != nil {
		logger.Printf("TLS config loaded: enabled=%v, starttls=%v",
			config.TLS.Enabled,
			config.TLS.EnableStartTLS)
	}

	// Initialize unified queue system
	logger.Printf("Initializing unified queue system with directory: %s", config.QueueDir)
	queueManager := queue.NewManager(config.QueueDir)
	logger.Printf("Unified queue system initialized")

	// Initialize queue processor if enabled
	var queueProcessor *queue.Processor
	if config.QueueProcessorEnabled {
		logger.Printf("Queue processor enabled, initializing...")

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

		logger.Printf("Creating LMTP delivery handler: %s:%d (max_per_domain=%d)", deliveryHost, deliveryPort, maxPerDomain)
		lmtpHandler := queue.NewLMTPDeliveryHandler(deliveryHost, deliveryPort, maxPerDomain)

		// Create processor configuration
		processorConfig := queue.ProcessorConfig{
			Enabled:       config.QueueProcessorEnabled,
			Interval:      time.Duration(config.QueueProcessInterval) * time.Second,
			MaxConcurrent: config.QueueWorkers,
			MaxRetries:    config.MaxRetries,
			RetrySchedule: config.RetrySchedule,
			CleanupAge:    24 * time.Hour,
		}

		logger.Printf("Creating queue processor with config: enabled=%v, interval=%v, workers=%d",
			processorConfig.Enabled, processorConfig.Interval, processorConfig.MaxConcurrent)

		queueProcessor = queue.NewProcessor(queueManager, processorConfig, lmtpHandler)
		logger.Printf("Queue processor initialized successfully")
	} else {
		logger.Printf("Queue processor disabled")
	}

	// Initialize resource manager with limits from config
	var resourceLimits *ResourceLimits
	var resourceManager *ResourceManager

	if config.Resources != nil {
		// Use memory configuration if available, otherwise use defaults
		var memoryConfig *MemoryConfig
		if config.Memory != nil {
			memoryConfig = config.Memory
			logger.Printf("Using memory configuration: %dMB total, %dMB per connection",
				memoryConfig.MaxMemoryUsage/(1024*1024),
				memoryConfig.PerConnectionMemoryLimit/(1024*1024))
		} else {
			memoryConfig = DefaultMemoryConfig()
			logger.Printf("Using default memory configuration: %dMB total, %dMB per connection",
				memoryConfig.MaxMemoryUsage/(1024*1024),
				memoryConfig.PerConnectionMemoryLimit/(1024*1024))
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

		logger.Printf("Resource manager initialized with memory protection enabled")
	} else {
		resourceLimits = DefaultResourceLimits()
		resourceManager = NewResourceManager(resourceLimits, slogger)
		// Initialize default memory manager
		memoryManager := NewMemoryManager(DefaultMemoryConfig(), slogger)
		resourceManager.SetMemoryManager(memoryManager)
		logger.Printf("Resource manager initialized with default memory protection")
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
		metrics:         metrics,
		queueManager:    queueManager,
		queueProcessor:  queueProcessor,
		logger:          logger,
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
		logger.Printf("TLS enabled, initializing TLS manager")
		tlsManager, err := NewTLSManager(config)
		if err != nil {
			// TLS is explicitly enabled; failing to initialize it is a hard error
			return nil, fmt.Errorf("failed to initialize TLS manager: %w", err)
		}
		server.tlsManager = tlsManager
		logger.Printf("TLS manager initialized successfully")

		// Log certificate information
		if config.TLS.CertFile != "" {
			logger.Printf("Using TLS certificate: %s", config.TLS.CertFile)
		}
		if config.TLS.LetsEncrypt != nil && config.TLS.LetsEncrypt.Enabled {
			logger.Printf("Let's Encrypt enabled for domain: %s", config.TLS.LetsEncrypt.Domain)
		}
	} else {
		logger.Printf("TLS disabled")
	}

	// Initialize scanner manager
	scannerManager := NewScannerManager(config, server)
	if err := scannerManager.Initialize(context.Background()); err != nil {
		log.Printf("Warning: Error initializing scanner manager: %v", err)
		// Continue even if scanner initialization fails
		// This prevents the server from crashing if scanners are misconfigured
	}

	return server, nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	if s.running {
		return fmt.Errorf("server already running")
	}

	s.logger.Printf("Starting SMTP server on %s", s.config.ListenAddr)

	// Create all required queue directories
	if err := s.setupQueueDirectories(); err != nil {
		return fmt.Errorf("queue directory setup failed: %w", err)
	}

	// Create listener
	s.logger.Printf("Creating TCP listener on %s", s.config.ListenAddr)
	var err error
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.running = true
	s.logger.Printf("SMTP server running on %s", s.config.ListenAddr)

	// Start the new queue system if available
	if s.queueManager != nil {
		s.logger.Printf("Starting unified queue system")
		// The new queue system doesn't need explicit startup
		s.logger.Printf("Unified queue system started successfully")
	}

	// Start queue processor if available
	if s.queueProcessor != nil {
		s.logger.Printf("Starting queue processor")
		if err := s.queueProcessor.Start(); err != nil {
			s.logger.Printf("Warning: failed to start queue processor: %v", err)
		} else {
			s.logger.Printf("Queue processor started successfully")
		}
	}

	// Start metrics server if enabled
	if s.config.Metrics != nil && s.config.Metrics.Enabled {
		s.logger.Printf("Starting metrics server on %s", s.config.Metrics.ListenAddr)
		s.metricsServer = StartMetricsServer(s.config.Metrics.ListenAddr)

		// Start periodic queue size updates
		go s.updateQueueMetricsWithRetry()
	}

	// Start API server if enabled
	if s.config.API != nil && s.config.API.Enabled {
		s.logger.Printf("Starting API server on %s", s.config.API.ListenAddr)
		apiServer, err := api.NewServer(&api.Config{
			Enabled:    s.config.API.Enabled,
			ListenAddr: s.config.API.ListenAddr,
		}, s.config.QueueDir)

		if err != nil {
			s.logger.Printf("Warning: failed to create API server: %v", err)
		} else {
			s.apiServer = apiServer
			if err := s.apiServer.Start(); err != nil {
				s.logger.Printf("Warning: failed to start API server: %v", err)
			} else {
				s.logger.Printf("API server started successfully")
			}
		}
	}

	// Start worker pool for connection handling
	s.logger.Printf("Starting worker pool with %d workers", s.workerPool.size)
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
		s.logger.Printf("Created secure queue directory: %s (0700)", qDir)
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
					s.logger.Printf("Panic in queue metrics update: %v", r)
				}
			}()

			s.metrics.UpdateQueueSizes(s.config)
			s.logger.Printf("Queue metrics updated successfully")
		}()

		<-ticker.C
	}
}

// acceptConnections accepts and handles incoming connections with standardized worker pool
func (s *Server) acceptConnections() error {
	s.logger.Printf("Starting connection acceptance loop")
	s.slogger.Debug("acceptConnections goroutine started")

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Printf("Context cancelled, stopping connection acceptance")
			return s.ctx.Err()
		default:
		}

		// Set a short timeout on accept to allow periodic context checking
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				s.logger.Printf("Failed to set accept deadline: %v", err)
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Check if it's a timeout error (expected)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			if s.running {
				s.logger.Printf("Failed to accept connection: %v", err)
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
			s.logger.Printf("Connection rejected due to resource limits: %s", clientAddr)
			conn.Close()
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
		netConn.Close()
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
	if s.logger == nil {
		s.logger = log.New(os.Stdout, "SMTP: ", log.LstdFlags)
	}

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
			s.logger.Printf("failed to close connection during cleanup: %v, client: %s, session: %s", err, clientIP, sessionID)
		}
	}

	// Ensure cleanup happens even on panic
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("panic in session handling: %v, client: %s, session: %s", r, clientIP, sessionID)
			cleanup()
			panic(r) // Re-panic to maintain panic behavior
		}
		cleanup()
	}()

	// Register connection with resource manager
	s.slogger.Debug("Registering connection with resource manager")
	sessionID = s.resourceManager.AcceptConnection(conn)
	s.slogger.Debug("Connection registered", "session_id", sessionID)
	s.logger.Printf("new connection: %s (session: %s)", clientIP, sessionID)

	// Set connection timeout
	s.slogger.Debug("Setting connection deadline")
	if err := conn.SetDeadline(time.Now().Add(s.resourceManager.GetConnectionTimeout())); err != nil {
		s.slogger.Debug("Failed to set connection deadline", "error", err)
		s.logger.Printf("failed to set connection deadline: %v, client: %s, session: %s", err, clientIP, sessionID)
	} else {
		s.slogger.Debug("Connection deadline set successfully")
	}

	// Create a new session with the current configuration and authentication
	// Pass the server's worker context for proper cancellation propagation
	s.slogger.Debug("Creating new SMTP session", "client_ip", clientIP)
	session := NewSession(ctx, conn, s.config, s.authenticator)
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
			s.logger.Printf("session error: %v, client: %s, session: %s", err, clientIP, sessionID)
		}
	}
}

// Close closes the server and all associated resources with graceful shutdown
func (s *Server) Close() error {
	var shutdownErr error

	s.shutdownOnce.Do(func() {
		s.logger.Printf("Initiating graceful server shutdown")
		s.running = false

		// Cancel root context first to propagate cancellation to all sessions
		if s.rootCancel != nil {
			s.logger.Printf("Cancelling server root context to propagate shutdown signal")
			s.rootCancel()
		}

		// Close listener first to stop accepting new connections
		if s.listener != nil {
			if err := s.listener.Close(); err != nil {
				s.logger.Printf("Error closing listener: %v", err)
				shutdownErr = err
			}
		}

		// Stop worker pool gracefully
		if s.workerPool != nil {
			s.logger.Printf("Stopping worker pool...")
			if err := s.workerPool.Stop(); err != nil {
				s.logger.Printf("Error stopping worker pool: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			} else {
				s.logger.Printf("Worker pool stopped successfully")
			}
		}

		// Wait for all managed goroutines to complete with configured timeout
		shutdownTimeout := s.config.Timeouts.ShutdownTimeout
		if shutdownTimeout == 0 {
			shutdownTimeout = 30 * time.Second // fallback default
		}

		s.logger.Printf("Waiting for goroutines to complete (timeout: %v)", shutdownTimeout)
		done := make(chan error, 1)
		go func() {
			done <- s.errGroup.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				s.logger.Printf("Error during goroutine shutdown: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			} else {
				s.logger.Printf("All goroutines stopped successfully")
			}
		case <-time.After(shutdownTimeout):
			s.logger.Printf("Warning: Goroutine shutdown timeout after 30 seconds")
			if shutdownErr == nil {
				shutdownErr = fmt.Errorf("shutdown timeout")
			}
		}

		// Close resource manager
		if s.resourceManager != nil {
			s.resourceManager.Close()
		}

		// Close metrics server if it was started
		if s.metricsServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.metricsServer.Shutdown(ctx); err != nil {
				s.logger.Printf("Error shutting down metrics server: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Close plugin manager
		if s.pluginManager != nil {
			if err := s.pluginManager.Close(); err != nil {
				s.logger.Printf("Error closing plugin manager: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Close authenticator
		if s.authenticator != nil {
			if auth, ok := s.authenticator.(*SMTPAuthenticator); ok {
				if err := auth.Close(); err != nil {
					s.logger.Printf("Error closing authenticator: %v", err)
					if shutdownErr == nil {
						shutdownErr = err
					}
				}
			}
		}

		// Stop TLS manager if it was initialized
		if s.tlsManager != nil {
			if err := s.tlsManager.Stop(); err != nil {
				s.logger.Printf("Error stopping TLS manager: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Stop queue processor
		if s.queueProcessor != nil {
			s.logger.Printf("Stopping queue processor")
			if err := s.queueProcessor.Stop(); err != nil {
				s.logger.Printf("Error stopping queue processor: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			} else {
				s.logger.Printf("Queue processor stopped successfully")
			}
		}

		// Stop queue manager
		if s.queueManager != nil {
			s.logger.Printf("Stopping queue manager")
			s.queueManager.Stop()
		}

		// Stop API server if running
		if s.apiServer != nil {
			if err := s.apiServer.Stop(); err != nil {
				s.logger.Printf("Error stopping API server: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		s.logger.Printf("Graceful server shutdown completed")
	})

	return shutdownErr
}

// Wait waits for all server goroutines to complete
func (s *Server) Wait() error {
	return s.errGroup.Wait()
}

// ... existing code ...
