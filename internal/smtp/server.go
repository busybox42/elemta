package smtp

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/busybox42/elemta/internal/plugin"
)

// Server represents an SMTP server
type Server struct {
	config        *Config
	listener      net.Listener
	running       bool
	pluginManager *plugin.Manager
	authenticator Authenticator
}

// NewServer creates a new SMTP server
func NewServer(config *Config) (*Server, error) {
	// Initialize plugin manager if enabled
	var pluginManager *plugin.Manager
	if config.Plugins != nil && config.Plugins.Enabled {
		pluginManager = plugin.NewManager(config.Plugins.PluginPath)

		// Load plugins
		if err := pluginManager.LoadPlugins(); err != nil {
			return nil, fmt.Errorf("failed to load plugins: %w", err)
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

	server := &Server{
		config:        config,
		running:       false,
		pluginManager: pluginManager,
		authenticator: authenticator,
	}

	// Initialize scanner manager
	scannerManager := NewScannerManager(config, server)
	if err := scannerManager.Initialize(context.Background()); err != nil {
		log.Printf("Warning: Error initializing scanner manager: %v", err)
	}

	return server, nil
}

// Start starts the SMTP server
func (s *Server) Start() error {
	if s.running {
		return fmt.Errorf("server already running")
	}

	var err error
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.running = true
	log.Printf("Elemta MTA starting on %s", s.config.ListenAddr)

	// Handle connections in a goroutine
	go s.acceptConnections()

	return nil
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
	session := NewSession(conn, s.config, s.authenticator)
	if err := session.Handle(); err != nil {
		log.Printf("Session error: %v", err)
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

	return nil
}

// ... existing code ...
