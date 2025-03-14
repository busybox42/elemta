package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// TLSManager handles TLS certificates and connections
type TLSManager struct {
	config      *Config
	tlsConfig   *tls.Config
	certManager *autocert.Manager
}

// NewTLSManager creates a new TLS manager
func NewTLSManager(config *Config) (*TLSManager, error) {
	manager := &TLSManager{
		config: config,
	}

	// If TLS is not enabled, return early
	if config.TLS == nil || !config.TLS.Enabled {
		return manager, nil
	}

	// Set up TLS configuration
	var err error
	manager.tlsConfig, err = manager.setupTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to set up TLS config: %w", err)
	}

	return manager, nil
}

// setupTLSConfig sets up the TLS configuration
func (m *TLSManager) setupTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.NoClientCert,
	}

	// Check if Let's Encrypt is enabled
	if m.config.TLS.LetsEncrypt != nil && m.config.TLS.LetsEncrypt.Enabled {
		var err error
		tlsConfig, err = m.setupLetsEncrypt()
		if err != nil {
			return nil, err
		}
		return tlsConfig, nil
	}

	// Use provided certificate files
	if m.config.TLS.CertFile != "" && m.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(m.config.TLS.CertFile, m.config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		return nil, fmt.Errorf("TLS enabled but no certificate files provided")
	}

	return tlsConfig, nil
}

// setupLetsEncrypt sets up Let's Encrypt certificate manager
func (m *TLSManager) setupLetsEncrypt() (*tls.Config, error) {
	leConfig := m.config.TLS.LetsEncrypt

	// Validate configuration
	if leConfig.Domain == "" {
		return nil, fmt.Errorf("Let's Encrypt enabled but no domain provided")
	}

	// Create cache directory if it doesn't exist
	cacheDir := leConfig.CacheDir
	if cacheDir == "" {
		cacheDir = "./certs"
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certificate cache directory: %w", err)
	}

	// Create certificate manager
	m.certManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(leConfig.Domain),
		Email:      leConfig.Email,
	}

	// Configure ACME client if using staging environment
	if leConfig.Staging {
		m.certManager.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}
	}

	return m.certManager.TLSConfig(), nil
}

// GetTLSConfig returns the TLS configuration
func (m *TLSManager) GetTLSConfig() *tls.Config {
	return m.tlsConfig
}

// StartTLSListener starts a TLS listener
func (m *TLSManager) StartTLSListener(ctx context.Context) (net.Listener, error) {
	if m.config.TLS == nil || !m.config.TLS.Enabled {
		return nil, fmt.Errorf("TLS not enabled")
	}

	if m.tlsConfig == nil {
		return nil, fmt.Errorf("TLS configuration not initialized")
	}

	listenAddr := m.config.TLS.ListenAddr
	if listenAddr == "" {
		listenAddr = ":465" // Default SMTPS port
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", listenAddr, m.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS listener: %w", err)
	}

	log.Printf("Started TLS listener on %s", listenAddr)
	return listener, nil
}

// WrapConnection wraps a connection with TLS
func (m *TLSManager) WrapConnection(conn net.Conn) (net.Conn, error) {
	if m.config.TLS == nil || !m.config.TLS.Enabled {
		return nil, fmt.Errorf("TLS not enabled")
	}

	if m.tlsConfig == nil {
		return nil, fmt.Errorf("TLS configuration not initialized")
	}

	// Create server-side TLS connection
	tlsConn := tls.Server(conn, m.tlsConfig)

	// Set deadline for handshake
	deadline := time.Now().Add(10 * time.Second)
	if err := tlsConn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline for TLS handshake: %w", err)
	}

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Reset deadline
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("failed to reset deadline after TLS handshake: %w", err)
	}

	return tlsConn, nil
}

// RenewCertificates forces certificate renewal
func (m *TLSManager) RenewCertificates(ctx context.Context) error {
	if m.config.TLS == nil || !m.config.TLS.Enabled {
		return fmt.Errorf("TLS not enabled")
	}

	if m.config.TLS.LetsEncrypt == nil || !m.config.TLS.LetsEncrypt.Enabled {
		return fmt.Errorf("Let's Encrypt not enabled")
	}

	if m.certManager == nil {
		return fmt.Errorf("certificate manager not initialized")
	}

	domain := m.config.TLS.LetsEncrypt.Domain
	if domain == "" {
		return fmt.Errorf("no domain specified for certificate renewal")
	}

	// Force certificate renewal
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("Forcing renewal of certificate for %s", domain)
	_, err := m.certManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: domain,
	})
	return err
}

// GetCertificateInfo returns information about the current certificate
func (m *TLSManager) GetCertificateInfo() (map[string]interface{}, error) {
	if m.config.TLS == nil || !m.config.TLS.Enabled {
		return nil, fmt.Errorf("TLS not enabled")
	}

	info := make(map[string]interface{})
	info["enabled"] = true

	// Check if using Let's Encrypt
	if m.config.TLS.LetsEncrypt != nil && m.config.TLS.LetsEncrypt.Enabled {
		info["type"] = "letsencrypt"
		info["domain"] = m.config.TLS.LetsEncrypt.Domain
		info["email"] = m.config.TLS.LetsEncrypt.Email
		info["staging"] = m.config.TLS.LetsEncrypt.Staging

		// Check certificate cache
		cacheDir := m.config.TLS.LetsEncrypt.CacheDir
		if cacheDir == "" {
			cacheDir = "./certs"
		}

		// List certificates in cache
		certs, err := filepath.Glob(filepath.Join(cacheDir, "*.crt"))
		if err == nil {
			info["cached_certs"] = certs
		}
	} else {
		info["type"] = "manual"
		info["cert_file"] = m.config.TLS.CertFile
		info["key_file"] = m.config.TLS.KeyFile
	}

	return info, nil
}
