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
	"time"

	"github.com/busybox42/elemta/internal/api"
	"github.com/busybox42/elemta/internal/plugin"
)

// Server represents an SMTP server
type Server struct {
	config           *Config
	listener         net.Listener
	running          bool
	pluginManager    *plugin.Manager
	authenticator    Authenticator
	metrics          *Metrics
	metricsServer    *http.Server
	apiServer        *api.Server
	queueManager     *QueueManager
	queueIntegration *QueueProcessorIntegration // New queue system integration
	tlsManager       TLSHandler
	logger           *log.Logger
	resourceManager  *ResourceManager // Resource management and rate limiting
	slogger          *slog.Logger     // Structured logger for resource management
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

	// Initialize queue manager
	logger.Printf("Initializing queue manager with directory: %s", config.QueueDir)
	queueManager := NewQueueManager(config)

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

	// Initialize new queue system integration
	queueIntegration, err := NewQueueProcessorIntegration(config)
	if err != nil {
		logger.Printf("Warning: Failed to initialize new queue system: %v", err)
		// Continue with old system for now
	} else {
		logger.Printf("New queue system with delivery handlers initialized")
	}

	// Initialize resource manager with limits from config
	var resourceLimits *ResourceLimits
	if config.Resources != nil {
		resourceLimits = &ResourceLimits{
			MaxConnections:            config.Resources.MaxConnections,
			MaxConnectionsPerIP:       config.Resources.MaxConcurrent, // Use MaxConcurrent as per-IP limit
			MaxGoroutines:             config.Resources.MaxConnections * 2, // Allow 2 goroutines per connection
			ConnectionTimeout:         time.Duration(config.Resources.ConnectionTimeout) * time.Second,
			SessionTimeout:            config.SessionTimeout,
			IdleTimeout:               time.Duration(config.Resources.ReadTimeout) * time.Second,
			RateLimitWindow:           time.Minute,
			MaxRequestsPerWindow:      config.Resources.MaxConnections * 10, // 10 requests per connection per minute
			MaxMemoryUsage:            500 * 1024 * 1024, // 500MB default
			GoroutinePoolSize:         config.MaxWorkers,
			CircuitBreakerEnabled:     true,
			ResourceMonitoringEnabled: true,
		}
	} else {
		resourceLimits = DefaultResourceLimits()
	}
	
	resourceManager := NewResourceManager(resourceLimits, slogger)

	server := &Server{
		config:           config,
		running:          false,
		pluginManager:    pluginManager,
		authenticator:    authenticator,
		metrics:          metrics,
		queueManager:     queueManager,
		queueIntegration: queueIntegration,
		logger:           logger,
		resourceManager:  resourceManager,
		slogger:          slogger,
	}

	// Initialize TLS manager if TLS is enabled
	if config.TLS != nil && config.TLS.Enabled {
		logger.Printf("TLS enabled, initializing TLS manager")
		tlsManager, err := NewTLSManager(config)
		if err != nil {
			logger.Printf("Warning: Failed to initialize TLS manager: %v", err)
		} else {
			server.tlsManager = tlsManager
			logger.Printf("TLS manager initialized successfully")

			// Log certificate information
			if config.TLS.CertFile != "" {
				logger.Printf("Using TLS certificate: %s", config.TLS.CertFile)
			}
			if config.TLS.LetsEncrypt != nil && config.TLS.LetsEncrypt.Enabled {
				logger.Printf("Let's Encrypt enabled for domain: %s", config.TLS.LetsEncrypt.Domain)
			}
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
	if s.queueIntegration != nil {
		s.logger.Printf("Starting new queue system with delivery handlers")
		if err := s.queueIntegration.Start(); err != nil {
			s.logger.Printf("Warning: Failed to start new queue system: %v", err)
		} else {
			s.logger.Printf("New queue system started successfully")
		}
	} else {
		// Fallback to old queue manager if queue processor is enabled
		if s.config.QueueProcessorEnabled {
			s.logger.Printf("Starting old queue processor with interval %d seconds and %d workers",
				s.config.QueueProcessInterval, s.config.QueueWorkers)
			s.StartQueueProcessor()
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

	// Handle connections in a goroutine
	go s.acceptConnections()

	return nil
}

// setupQueueDirectories ensures all needed queue directories exist
func (s *Server) setupQueueDirectories() error {
	if s.config.QueueDir == "" {
		return fmt.Errorf("queue directory not configured")
	}

	// Ensure main queue directory exists
	if err := os.MkdirAll(s.config.QueueDir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Create subdirectories for different queue types
	queueTypes := []string{"active", "deferred", "held", "failed", "data", "tmp", "quarantine"}

	for _, qType := range queueTypes {
		qDir := filepath.Join(s.config.QueueDir, qType)
		if err := os.MkdirAll(qDir, 0755); err != nil {
			return fmt.Errorf("failed to create %s queue directory: %w", qType, err)
		}
		s.logger.Printf("Created queue directory: %s", qDir)
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

// acceptConnections accepts and handles incoming connections with resource management
func (s *Server) acceptConnections() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				s.logger.Printf("Failed to accept connection: %v", err)
			}
			continue
		}
		
		// Check if connection can be accepted based on resource limits
		if !s.resourceManager.CanAcceptConnection(conn.RemoteAddr().String()) {
			s.logger.Printf("Connection rejected due to resource limits: %s", conn.RemoteAddr().String())
			conn.Close()
			continue
		}
		
		// Use goroutine pool for connection handling
		if !s.resourceManager.SubmitTask(func() {
			s.handleAndCloseSession(conn)
		}) {
			// Goroutine pool is full, handle directly but log warning
			s.slogger.Warn("Goroutine pool full, handling connection directly",
				"remote_addr", conn.RemoteAddr().String(),
			)
			go s.handleAndCloseSession(conn)
		}
	}
}

// handleAndCloseSession processes a connection and ensures it's properly closed
func (s *Server) handleAndCloseSession(conn net.Conn) {
	clientIP := conn.RemoteAddr().String()

	// Initialize logger if it's nil
	if s.logger == nil {
		s.logger = log.New(os.Stdout, "SMTP: ", log.LstdFlags)
	}

	// Register connection with resource manager
	sessionID := s.resourceManager.AcceptConnection(conn)
	defer s.resourceManager.ReleaseConnection(sessionID)

	s.logger.Printf("new connection: %s (session: %s)", clientIP, sessionID)

	// Create a new session with the current configuration and authentication
	session := NewSession(conn, s.config, s.authenticator)

	// Set the queue manager and TLS manager from the server
	session.queueManager = s.queueManager
	session.tlsManager = s.tlsManager

	// Set the queue integration if available
	if s.queueIntegration != nil {
		session.queueIntegration = s.queueIntegration
	}

	// Set session ID for tracking
	session.sessionID = sessionID
	session.resourceManager = s.resourceManager

	// Handle the SMTP session with circuit breaker protection for external services
	smtpCircuitBreaker := s.resourceManager.GetCircuitBreaker("smtp-session")
	err := smtpCircuitBreaker.Execute(func() error {
		return session.Handle()
	})

	if err != nil {
		if err != io.EOF {
			s.logger.Printf("session error: %v, client: %s, session: %s", err, clientIP, sessionID)
		}
	}

	// Close the connection
	if err := conn.Close(); err != nil {
		s.logger.Printf("failed to close connection: %v, client: %s, session: %s", err, clientIP, sessionID)
	}
}

// Close closes the server and all associated resources
func (s *Server) Close() error {
	s.running = false
	
	// Close resource manager
	if s.resourceManager != nil {
		s.resourceManager.Close()
	}

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}

	// Close metrics server if it was started
	if s.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.metricsServer.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down metrics server: %v", err)
		}
	}

	// Close plugin manager
	if s.pluginManager != nil {
		if err := s.pluginManager.Close(); err != nil {
			log.Printf("Error closing plugin manager: %v", err)
		}
	}

	// Close authenticator
	if s.authenticator != nil {
		if auth, ok := s.authenticator.(*SMTPAuthenticator); ok {
			if err := auth.Close(); err != nil {
				log.Printf("Error closing authenticator: %v", err)
			}
		}
	}

	// Stop TLS manager if it was initialized
	if s.tlsManager != nil {
		if err := s.tlsManager.Stop(); err != nil {
			log.Printf("Error stopping TLS manager: %v", err)
		}
	}

	// Stop queue integration
	if s.queueIntegration != nil {
		log.Printf("Stopping queue integration")
		if err := s.queueIntegration.Stop(); err != nil {
			log.Printf("Error stopping queue integration: %v", err)
		}
	}

	// Stop queue manager
	if s.queueManager != nil {
		log.Printf("Stopping queue manager")
		s.queueManager.Stop()
	}

	// Stop API server if running
	if s.apiServer != nil {
		if err := s.apiServer.Stop(); err != nil {
			log.Printf("Error stopping API server: %v", err)
		}
	}

	return nil
}

// ... existing code ...

