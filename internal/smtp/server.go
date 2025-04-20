package smtp

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
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

	// Create queue manager
	queueManager := NewQueueManager(config)

	return &Server{
		config:        config,
		pluginManager: pluginManager,
		authenticator: authenticator,
		metrics:       metrics,
		queueManager:  queueManager,
	}, nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.running = true
	log.Printf("Elemta MTA starting on %s", s.config.ListenAddr)

	// Start the queue manager
	s.queueManager.Start()
	log.Printf("Queue manager started processing queued messages")

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
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	session := NewSession(conn, s.config, s.authenticator, s.queueManager)

	// Track connection metrics
	s.metrics.TrackConnectionDuration(func() error {
		err := session.Handle()
		if err != nil {
			log.Printf("Session error: %v", err)
		}
		return err
	})
}

// Close closes the server and all associated resources
func (s *Server) Close() error {
	s.running = false

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}

	// Stop the queue manager
	if s.queueManager != nil {
		s.queueManager.Stop()
		log.Printf("Queue manager stopped")
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

	// Stop API server if running
	if s.apiServer != nil {
		if err := s.apiServer.Stop(); err != nil {
			log.Printf("Error stopping API server: %v", err)
		}
	}

	return nil
}

// ... existing code ...
