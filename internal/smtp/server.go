package smtp

import (
	"context"
	"fmt"
	"io"
	"log"
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
	config        *Config
	listener      net.Listener
	running       bool
	pluginManager *plugin.Manager
	authenticator Authenticator
	metrics       *Metrics
	metricsServer *http.Server
	apiServer     *api.Server
	queueManager  *QueueManager
	tlsManager    TLSHandler
	logger        *log.Logger
}

// NewServer creates a new SMTP server
func NewServer(config *Config) (*Server, error) {
	// Initialize plugin manager if enabled
	var pluginManager *plugin.Manager
	if config.Plugins != nil && config.Plugins.Enabled {
		pluginManager = plugin.NewManager(config.Plugins.PluginPath)

		// Load plugins
		if err := pluginManager.LoadPlugins(); err != nil {
			log.Printf("Warning: failed to load plugins: %v", err)
		}

		// Load specific plugins if specified
		for _, pluginName := range config.Plugins.Plugins {
			if err := pluginManager.LoadPlugin(pluginName); err != nil {
				log.Printf("Warning: failed to load plugin %s: %v", pluginName, err)
			}
		}
	}

	// Initialize authenticator if enabled
	var authenticator Authenticator
	var err error
	if config.Auth != nil && config.Auth.Enabled {
		authenticator, err = NewAuthenticator(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize authenticator: %w", err)
		}
	} else {
		// Create a dummy authenticator that always returns true
		authenticator = &SMTPAuthenticator{
			config: &AuthConfig{
				Enabled:  false,
				Required: false,
			},
		}
	}

	// Initialize metrics
	metrics := GetMetrics()

	// Initialize queue manager
	queueManager := NewQueueManager(config)

	// Debug: print AuthConfig and TLSConfig
	if config.Auth != nil {
		fmt.Printf("[DEBUG] AuthConfig: %+v\n", *config.Auth)
	} else {
		fmt.Println("[DEBUG] AuthConfig: <nil>")
	}
	if config.TLS != nil {
		fmt.Printf("[DEBUG] TLSConfig: %+v\n", *config.TLS)
	} else {
		fmt.Println("[DEBUG] TLSConfig: <nil>")
	}

	server := &Server{
		config:        config,
		running:       false,
		pluginManager: pluginManager,
		authenticator: authenticator,
		metrics:       metrics,
		queueManager:  queueManager,
	}

	// Initialize TLS manager if TLS is enabled
	if config.TLS != nil && config.TLS.Enabled {
		tlsManager, err := NewTLSManager(config)
		if err != nil {
			log.Printf("Warning: Failed to initialize TLS manager: %v", err)
		} else {
			server.tlsManager = tlsManager
			log.Printf("TLS manager initialized successfully")
		}
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

	// Ensure queue directory exists
	if s.config.QueueDir != "" {
		if err := os.MkdirAll(s.config.QueueDir, 0755); err != nil {
			return fmt.Errorf("failed to create queue directory: %w", err)
		}

		// Create subdirectories for different queue types
		for _, dir := range []string{"active", "deferred", "held", "failed", "data"} {
			queueSubDir := filepath.Join(s.config.QueueDir, dir)
			if err := os.MkdirAll(queueSubDir, 0755); err != nil {
				return fmt.Errorf("failed to create queue subdirectory %s: %w", dir, err)
			}
		}
	}

	var err error
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.running = true
	log.Printf("Elemta MTA starting on %s", s.config.ListenAddr)

	// Start the queue manager if queue processor is enabled
	if s.queueManager != nil {
		log.Printf("Initializing queue manager, config says enabled: %v, interval: %d seconds",
			s.config.QueueProcessorEnabled, s.config.QueueProcessInterval)
		s.StartQueueProcessor()
	}

	// Start metrics server if enabled
	if s.config.Metrics != nil && s.config.Metrics.Enabled {
		s.metricsServer = StartMetricsServer(s.config.Metrics.ListenAddr)
		log.Printf("Metrics server started on %s", s.config.Metrics.ListenAddr)

		// Start periodic queue size updates
		go s.updateQueueMetrics()
	}

	// Start API server if enabled
	if s.config.API != nil && s.config.API.Enabled {
		apiServer, err := api.NewServer(&api.Config{
			Enabled:    s.config.API.Enabled,
			ListenAddr: s.config.API.ListenAddr,
		}, s.config.QueueDir)

		if err != nil {
			log.Printf("Warning: failed to create API server: %v", err)
		} else {
			s.apiServer = apiServer
			if err := s.apiServer.Start(); err != nil {
				log.Printf("Warning: failed to start API server: %v", err)
			}
		}
	}

	// Handle connections in a goroutine
	go s.acceptConnections()

	return nil
}

// updateQueueMetrics periodically updates queue size metrics
func (s *Server) updateQueueMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for s.running {
		s.metrics.UpdateQueueSizes(s.config)
		<-ticker.C
	}
}

// acceptConnections accepts and handles incoming connections
func (s *Server) acceptConnections() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("Failed to accept connection: %v", err)
			}
			continue
		}
		go s.handleAndCloseSession(conn)
	}
}

// handleAndCloseSession processes a connection and ensures it's properly closed
func (s *Server) handleAndCloseSession(conn net.Conn) {
	clientIP := conn.RemoteAddr().String()
	s.logger.Printf("new connection: %s", clientIP)

	// Create a new session with the current configuration and authentication
	session := NewSession(conn, s.config, s.authenticator)
	session.queueManager = s.queueManager
	session.tlsManager = s.tlsManager

	// Add debug logging for plugins
	if session.builtinPlugins != nil {
		s.logger.Printf("Plugins configuration: antivirusEnabled=%v, antispamEnabled=%v, antivirusOpts=%v, antispamOpts=%v",
			session.builtinPlugins.AntivirusEnabled, session.builtinPlugins.AntispamEnabled, session.builtinPlugins.AntivirusOpts, session.builtinPlugins.AntispamOpts)
	} else {
		s.logger.Println("Plugins not initialized")
	}

	// Handle the SMTP session
	err := session.Handle()
	if err != nil {
		if err != io.EOF {
			s.logger.Printf("session error: %v, client: %s", err, clientIP)
		}
	}

	// Close the connection
	if err := conn.Close(); err != nil {
		s.logger.Printf("failed to close connection: %v, client: %s", err, clientIP)
	}
}

// Close closes the server and all associated resources
func (s *Server) Close() error {
	s.running = false

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
