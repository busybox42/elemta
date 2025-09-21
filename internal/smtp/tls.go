package smtp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// TLSHandler interface defines methods for handling TLS connections
type TLSHandler interface {
	WrapConnection(conn net.Conn) (net.Conn, error)
	GetTLSConfig() *tls.Config
	StartTLSListener(ctx context.Context) (net.Listener, error)
	RenewCertificates(ctx context.Context) error
	GetCertificateInfo() (map[string]interface{}, error)
	Stop() error
}

// TLSManager handles TLS certificates and connections
type TLSManager struct {
	config            *Config
	tlsConfig         *tls.Config
	certManager       *autocert.Manager
	certInfo          *CertificateInfo
	renewMutex        sync.Mutex
	stopChan          chan struct{}
	logger            *log.Logger
	httpServer        *http.Server
	notificationsSent map[string]time.Time // Track when notifications were last sent
	// New security components
	security    *TLSSecurity
	monitor     *TLSMonitor
	certMonitor *CertificateMonitor
	slogger     *slog.Logger
}

// CertificateInfo holds information about the current certificate
type CertificateInfo struct {
	Domain    string    `json:"domain"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Issuer    string    `json:"issuer"`
	Source    string    `json:"source"` // "manual" or "letsencrypt"
	Renewed   time.Time `json:"last_renewed,omitempty"`
}

// NewTLSManager creates a new TLS manager
func NewTLSManager(config *Config) (*TLSManager, error) {
	// Create structured logger
	slogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	manager := &TLSManager{
		config:            config,
		stopChan:          make(chan struct{}),
		logger:            log.New(os.Stdout, "[TLS] ", log.LstdFlags),
		notificationsSent: make(map[string]time.Time),
		slogger:           slogger,
	}

	// If TLS is not enabled, return early
	if config.TLS == nil || !config.TLS.Enabled {
		return manager, nil
	}

	// Initialize security hardening and monitoring components
	manager.security = NewTLSSecurity(config.TLS, slogger)
	manager.monitor = NewTLSMonitor(slogger)
	
	// Initialize certificate monitor with default alerter
	alerter := NewDefaultCertificateAlerter(slogger)
	manager.certMonitor = NewCertificateMonitor(slogger, alerter)

	// Set up TLS configuration with security hardening
	var err error
	manager.tlsConfig, err = manager.setupSecureTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to set up TLS config: %w", err)
	}

	// Start certificate monitoring and renewal service if Let's Encrypt is enabled
	if config.TLS.LetsEncrypt != nil && config.TLS.LetsEncrypt.Enabled {
		go manager.startCertificateRenewalService()
	}

	// Start TLS monitoring
	manager.monitor.Enable()

	return manager, nil
}

// setupSecureTLSConfig sets up the TLS configuration with security hardening
func (m *TLSManager) setupSecureTLSConfig() (*tls.Config, error) {
	// Get security-hardened TLS configuration
	tlsConfig := m.security.GetSecureTLSConfig()

	return m.configureCertificates(tlsConfig)
}

// configureCertificates handles Let's Encrypt or manual certificate configuration
func (m *TLSManager) configureCertificates(tlsConfig *tls.Config) (*tls.Config, error) {
	// Apply custom configuration overrides if available
	if m.config.TLS.MinVersion != "" {
		minVersion, err := parseTLSVersion(m.config.TLS.MinVersion)
		if err != nil {
			m.logger.Printf("Warning: Invalid TLS min version '%s', using security default: %v",
				m.config.TLS.MinVersion, err)
		} else {
			tlsConfig.MinVersion = minVersion
		}
	}

	if m.config.TLS.MaxVersion != "" {
		maxVersion, err := parseTLSVersion(m.config.TLS.MaxVersion)
		if err != nil {
			m.logger.Printf("Warning: Invalid TLS max version '%s', using security default: %v",
				m.config.TLS.MaxVersion, err)
		} else {
			tlsConfig.MaxVersion = maxVersion
		}
	}

	if m.config.TLS.ClientAuth != "" {
		clientAuth, err := parseClientAuth(m.config.TLS.ClientAuth)
		if err != nil {
			m.logger.Printf("Warning: Invalid client auth '%s', using security default: %v",
				m.config.TLS.ClientAuth, err)
		} else {
			tlsConfig.ClientAuth = clientAuth
		}
	}

	// Check if Let's Encrypt is enabled
	if m.config.TLS.LetsEncrypt != nil && m.config.TLS.LetsEncrypt.Enabled {
		leTLSConfig, err := m.setupLetsEncrypt()
		if err != nil {
			return nil, err
		}

		// Merge Let's Encrypt config with security hardened config
		leTLSConfig.MinVersion = tlsConfig.MinVersion
		leTLSConfig.MaxVersion = tlsConfig.MaxVersion
		leTLSConfig.CipherSuites = tlsConfig.CipherSuites
		leTLSConfig.ClientAuth = tlsConfig.ClientAuth
		leTLSConfig.PreferServerCipherSuites = tlsConfig.PreferServerCipherSuites
		leTLSConfig.CurvePreferences = tlsConfig.CurvePreferences
		leTLSConfig.SessionTicketsDisabled = tlsConfig.SessionTicketsDisabled
		leTLSConfig.Renegotiation = tlsConfig.Renegotiation

		return leTLSConfig, nil
	}

	// Use provided certificate files
	if m.config.TLS.CertFile != "" && m.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(m.config.TLS.CertFile, m.config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Validate certificate with security module
		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				m.logger.Printf("Warning: Failed to parse certificate for validation: %v", err)
			} else {
				// Use Let's Encrypt domain or empty string for validation
				domain := ""
				if m.config.TLS.LetsEncrypt != nil {
					domain = m.config.TLS.LetsEncrypt.Domain
				}
				if err := m.security.ValidateCertificate(x509Cert, domain); err != nil {
					m.logger.Printf("Warning: Certificate validation failed: %v", err)
				}
			}
		}

		// Update certificate info
		if err := m.updateCertificateInfo(cert); err != nil {
			m.logger.Printf("Warning: Failed to update certificate info: %v", err)
		}
	} else {
		return nil, fmt.Errorf("TLS enabled but no certificate files provided")
	}

	return tlsConfig, nil
}

// setupTLSConfig sets up the TLS configuration (legacy method for backward compatibility)
func (m *TLSManager) setupTLSConfig() (*tls.Config, error) {
	// Start with default secure settings
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.NoClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Apply custom TLS version if specified
	if m.config.TLS.MinVersion != "" {
		minVersion, err := parseTLSVersion(m.config.TLS.MinVersion)
		if err != nil {
			m.logger.Printf("Warning: Invalid TLS min version '%s', using default: %v",
				m.config.TLS.MinVersion, err)
		} else {
			tlsConfig.MinVersion = minVersion
		}
	}

	// Apply custom TLS maximum version if specified
	if m.config.TLS.MaxVersion != "" {
		maxVersion, err := parseTLSVersion(m.config.TLS.MaxVersion)
		if err != nil {
			m.logger.Printf("Warning: Invalid TLS max version '%s', using default: %v",
				m.config.TLS.MaxVersion, err)
		} else {
			tlsConfig.MaxVersion = maxVersion
		}
	}

	// Apply custom cipher suites if specified
	if len(m.config.TLS.Ciphers) > 0 {
		cipherSuites, err := parseCipherSuites(m.config.TLS.Ciphers)
		if err != nil {
			m.logger.Printf("Warning: Some cipher suites are invalid, using default: %v", err)
		} else if len(cipherSuites) > 0 {
			tlsConfig.CipherSuites = cipherSuites
		}
	}

	// Apply custom client auth if specified
	if m.config.TLS.ClientAuth != "" {
		clientAuth, err := parseClientAuth(m.config.TLS.ClientAuth)
		if err != nil {
			m.logger.Printf("Warning: Invalid client auth '%s', using default: %v",
				m.config.TLS.ClientAuth, err)
		} else {
			tlsConfig.ClientAuth = clientAuth
		}
	}

	// Check if Let's Encrypt is enabled
	if m.config.TLS.LetsEncrypt != nil && m.config.TLS.LetsEncrypt.Enabled {
		var err error
		leTLSConfig, err := m.setupLetsEncrypt()
		if err != nil {
			return nil, err
		}

		// Merge Let's Encrypt config with our customized config
		leTLSConfig.MinVersion = tlsConfig.MinVersion
		leTLSConfig.MaxVersion = tlsConfig.MaxVersion
		leTLSConfig.CipherSuites = tlsConfig.CipherSuites
		leTLSConfig.ClientAuth = tlsConfig.ClientAuth

		return leTLSConfig, nil
	}

	// Use provided certificate files
	if m.config.TLS.CertFile != "" && m.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(m.config.TLS.CertFile, m.config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Update certificate info
		if err := m.updateCertificateInfo(cert); err != nil {
			m.logger.Printf("Warning: Failed to update certificate info: %v", err)
		}
	} else {
		return nil, fmt.Errorf("TLS enabled but no certificate files provided")
	}

	return tlsConfig, nil
}

// parseTLSVersion parses a TLS version string into a uint16 value
func parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "1.0", "tls1.0":
		return tls.VersionTLS10, nil
	case "1.1", "tls1.1":
		return tls.VersionTLS11, nil
	case "1.2", "tls1.2":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}

// parseCipherSuites parses a list of cipher suite strings into uint16 values
// with security validation to prevent weak cipher suites
func parseCipherSuites(ciphers []string) ([]uint16, error) {
	// Map of cipher suite names to values - SECURE CIPHERS ONLY
	cipherMap := map[string]uint16{
		// Secure AEAD cipher suites (TLS 1.2)
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		// Secure CBC cipher suites (for compatibility, but not recommended)
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		// Secure RSA cipher suites (for compatibility, but not recommended)
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":               tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	// Define weak cipher suites that are explicitly blocked
	weakCiphers := map[string]bool{
		"TLS_RSA_WITH_RC4_128_SHA":                      true,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 true,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              true,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                true,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           true,
		// Add more weak ciphers as they are discovered
	}

	var cipherSuites []uint16
	var invalidCiphers []string
	var weakCiphersFound []string

	for _, cipher := range ciphers {
		// Check if cipher is explicitly weak
		if weakCiphers[cipher] {
			weakCiphersFound = append(weakCiphersFound, cipher)
			continue
		}

		// Check if cipher is in our secure map
		if val, ok := cipherMap[cipher]; ok {
			cipherSuites = append(cipherSuites, val)
		} else {
			invalidCiphers = append(invalidCiphers, cipher)
		}
	}

	// Build error message
	var errors []string
	if len(weakCiphersFound) > 0 {
		errors = append(errors, fmt.Sprintf("weak cipher suites blocked for security: %v", weakCiphersFound))
	}
	if len(invalidCiphers) > 0 {
		errors = append(errors, fmt.Sprintf("invalid cipher suites: %v", invalidCiphers))
	}

	var err error
	if len(errors) > 0 {
		err = fmt.Errorf("cipher suite validation failed: %s", strings.Join(errors, "; "))
	}

	return cipherSuites, err
}

// parseClientAuth parses a client auth string into a tls.ClientAuthType
func parseClientAuth(authType string) (tls.ClientAuthType, error) {
	switch authType {
	case "no_auth", "none":
		return tls.NoClientCert, nil
	case "request":
		return tls.RequestClientCert, nil
	case "require":
		return tls.RequireAnyClientCert, nil
	case "verify":
		return tls.VerifyClientCertIfGiven, nil
	case "require_verify":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return tls.NoClientCert, fmt.Errorf("unsupported client auth type: %s", authType)
	}
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
		m.logger.Printf("Using Let's Encrypt staging environment for domain: %s", leConfig.Domain)
	} else {
		m.logger.Printf("Using Let's Encrypt production environment for domain: %s", leConfig.Domain)
	}

	// Start HTTP server for ACME HTTP-01 challenge
	// This is needed for domain ownership validation
	httpServer := &http.Server{
		Addr:    ":http",
		Handler: m.certManager.HTTPHandler(nil),
	}

	go func() {
		m.logger.Printf("Starting HTTP server for ACME challenges on port 80")
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			m.logger.Printf("HTTP server for ACME challenges error: %v", err)
		}
	}()

	// Store the HTTP server so we can shut it down later
	m.httpServer = httpServer

	// Provide more detailed information about ACME challenges
	m.logger.Printf("Let's Encrypt will attempt to validate domain ownership using HTTP-01 challenge")
	m.logger.Printf("Ensure port 80 is open and accessible from the internet for domain: %s", leConfig.Domain)
	m.logger.Printf("Let's Encrypt may also attempt TLS-ALPN-01 challenge if port 443 is accessible")

	// Get initial certificate to check if it works
	m.logger.Printf("Obtaining initial Let's Encrypt certificate for %s", leConfig.Domain)
	hello := &tls.ClientHelloInfo{
		ServerName: leConfig.Domain,
	}

	// Attempt to get the certificate but don't fail if it doesn't work yet
	cert, err := m.certManager.GetCertificate(hello)
	if err != nil {
		m.logger.Printf("Warning: Failed to obtain initial Let's Encrypt certificate: %v", err)
		m.logger.Printf("This is not fatal - certificate will be obtained when first needed")
		// Don't fail here, Let's Encrypt will attempt to get the cert when needed
	} else {
		m.logger.Printf("Successfully obtained initial Let's Encrypt certificate for %s", leConfig.Domain)

		// Create a tls.Certificate for updating info
		if len(cert.Certificate) > 0 {
			tlsCert := tls.Certificate{
				Certificate: cert.Certificate,
				PrivateKey:  cert.PrivateKey,
				Leaf:        cert.Leaf,
			}

			if err := m.updateCertificateInfo(tlsCert); err != nil {
				m.logger.Printf("Warning: Failed to update certificate info: %v", err)
			} else {
				m.logger.Printf("Certificate valid from %s to %s",
					m.certInfo.NotBefore.Format(time.RFC3339),
					m.certInfo.NotAfter.Format(time.RFC3339))
			}
		}
	}

	// Update certificate info even if we failed, it will be updated on successful renewal
	if m.certInfo == nil {
		m.certInfo = &CertificateInfo{
			Domain: leConfig.Domain,
			Source: "letsencrypt",
		}
	}

	return m.certManager.TLSConfig(), nil
}

// startCertificateRenewalService starts a service to monitor and renew certificates
func (m *TLSManager) startCertificateRenewalService() {
	m.logger.Printf("Starting certificate renewal service")

	// Check renewal settings
	renewalConfig := m.config.TLS.RenewalConfig
	if renewalConfig == nil || !renewalConfig.AutoRenew {
		m.logger.Printf("Certificate auto-renewal is disabled, skipping renewal service")
		return
	}

	// Use configured check interval or default to 24 hours
	checkInterval := renewalConfig.CheckInterval
	if checkInterval <= 0 {
		checkInterval = 24 * time.Hour
	}

	// Check certificate every configured interval
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// Do an initial check
	m.checkAndRenewCertificate()

	for {
		select {
		case <-ticker.C:
			m.checkAndRenewCertificate()
		case <-m.stopChan:
			m.logger.Printf("Certificate renewal service stopped")
			return
		}
	}
}

// checkAndRenewCertificate checks if the certificate needs renewal and renews it if necessary
func (m *TLSManager) checkAndRenewCertificate() {
	m.renewMutex.Lock()
	defer m.renewMutex.Unlock()

	if m.config.TLS == nil || !m.config.TLS.Enabled {
		return
	}

	// Check if using Let's Encrypt
	if m.config.TLS.LetsEncrypt == nil || !m.config.TLS.LetsEncrypt.Enabled || m.certManager == nil {
		return
	}

	domain := m.config.TLS.LetsEncrypt.Domain
	if domain == "" {
		m.logger.Printf("Error: No domain specified for certificate renewal")
		return
	}

	// Check if we need to renew
	needsRenewal := false

	// Get renewal settings
	renewalDays := 30 // Default to 30 days
	if m.config.TLS.RenewalConfig != nil && m.config.TLS.RenewalConfig.RenewalDays > 0 {
		renewalDays = m.config.TLS.RenewalConfig.RenewalDays
	}

	// Define notification thresholds (days before expiration)
	notificationThresholds := []int{30, 14, 7, 3, 1}

	if m.certInfo != nil && !m.certInfo.NotAfter.IsZero() {
		daysUntilExpiration := int(time.Until(m.certInfo.NotAfter).Hours() / 24)

		// If certificate is close to expiration, trigger renewal
		if daysUntilExpiration <= renewalDays {
			needsRenewal = true
			m.logger.Printf("Certificate for %s expires in %d days, renewal needed", domain, daysUntilExpiration)
		}

		// Send notifications at specified thresholds
		for _, threshold := range notificationThresholds {
			if daysUntilExpiration <= threshold {
				notificationKey := fmt.Sprintf("expiration-%d", threshold)

				// Check if we've already sent this notification recently
				lastSent, exists := m.notificationsSent[notificationKey]
				if !exists || time.Since(lastSent) > 24*time.Hour {
					m.sendExpirationNotification(domain, daysUntilExpiration, threshold)
					m.notificationsSent[notificationKey] = time.Now()
				}
			}
		}
	} else {
		// If we don't have certificate info, force renewal
		needsRenewal = true
		m.logger.Printf("No valid certificate info for %s, renewal needed", domain)
	}

	// Force renewal if configured
	if m.config.TLS.RenewalConfig != nil && m.config.TLS.RenewalConfig.ForceRenewal {
		needsRenewal = true
		m.logger.Printf("Forced renewal configured for %s", domain)

		// Reset the force renewal flag to avoid continuous renewals
		m.config.TLS.RenewalConfig.ForceRenewal = false
	}

	if !needsRenewal {
		m.logger.Printf("Certificate for %s is still valid, no renewal needed", domain)
		return
	}

	// Force certificate renewal
	m.logger.Printf("Renewing certificate for %s", domain)
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	// Get the certificate
	cert, err := m.certManager.GetCertificate(hello)
	if err != nil {
		m.logger.Printf("Error renewing certificate: %v", err)

		// Send renewal failure notification
		m.sendRenewalFailureNotification(domain, err)
		return
	}

	// Update certificate info - need to convert to tls.Certificate
	if len(cert.Certificate) > 0 {
		// Create a new tls.Certificate for updating info
		tlsCert := tls.Certificate{
			Certificate: cert.Certificate,
			PrivateKey:  cert.PrivateKey,
			Leaf:        cert.Leaf,
		}

		if err := m.updateCertificateInfo(tlsCert); err != nil {
			m.logger.Printf("Warning: Failed to update certificate info after renewal: %v", err)
		} else {
			m.certInfo.Renewed = time.Now()
			m.logger.Printf("Certificate successfully renewed, valid until %s", m.certInfo.NotAfter.Format(time.RFC3339))

			// Send renewal success notification
			daysUntilExpiration := int(time.Until(m.certInfo.NotAfter).Hours() / 24)
			m.sendRenewalSuccessNotification(domain, daysUntilExpiration)
		}
	}
}

// sendExpirationNotification sends a notification that a certificate is about to expire
func (m *TLSManager) sendExpirationNotification(domain string, daysLeft, threshold int) {
	m.logger.Printf("NOTIFICATION: Certificate for %s will expire in %d days (threshold: %d days)",
		domain, daysLeft, threshold)

	// In a production system, this would send an email, Slack notification, etc.
	// For now, we just log it with a distinctive prefix
}

// sendRenewalSuccessNotification sends a notification that a certificate was successfully renewed
func (m *TLSManager) sendRenewalSuccessNotification(domain string, validDays int) {
	m.logger.Printf("NOTIFICATION: Certificate for %s was successfully renewed. Valid for %d days",
		domain, validDays)

	// In a production system, this would send an email, Slack notification, etc.
}

// sendRenewalFailureNotification sends a notification that a certificate renewal failed
func (m *TLSManager) sendRenewalFailureNotification(domain string, err error) {
	m.logger.Printf("NOTIFICATION: Certificate renewal for %s FAILED: %v", domain, err)

	// In a production system, this would send an email, Slack notification, etc.
}

// updateCertificateInfo extracts and stores information about the certificate
func (m *TLSManager) updateCertificateInfo(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if m.certInfo == nil {
		m.certInfo = &CertificateInfo{}
	}

	m.certInfo.NotBefore = x509Cert.NotBefore
	m.certInfo.NotAfter = x509Cert.NotAfter
	m.certInfo.Domain = x509Cert.Subject.CommonName

	if len(x509Cert.Issuer.Organization) > 0 {
		m.certInfo.Issuer = x509Cert.Issuer.Organization[0]
	} else {
		m.certInfo.Issuer = x509Cert.Issuer.CommonName
	}

	if m.config.TLS.LetsEncrypt != nil && m.config.TLS.LetsEncrypt.Enabled {
		m.certInfo.Source = "letsencrypt"
	} else {
		m.certInfo.Source = "manual"
	}

	// Add certificate to monitoring if monitor is available
	if m.certMonitor != nil {
		m.certMonitor.MonitorCertificate(m.certInfo.Domain, x509Cert)
	}

	return nil
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
		listenAddr = ":2465" // Default SMTPS port (non-privileged)
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", listenAddr, m.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS listener: %w", err)
	}

	m.logger.Printf("Started TLS listener on %s", listenAddr)
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

	remoteAddr := conn.RemoteAddr().String()

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		// Record handshake failure for monitoring
		if m.monitor != nil {
			m.monitor.RecordTLSHandshakeFailure(remoteAddr, err)
		}
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Reset deadline
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("failed to reset deadline after TLS handshake: %w", err)
	}

	// Record successful TLS connection for monitoring
	if m.monitor != nil {
		connState := tlsConn.ConnectionState()
		m.monitor.RecordTLSConnection(remoteAddr, &connState)
	}

	return tlsConn, nil
}

// RenewCertificates forces certificate renewal
func (m *TLSManager) RenewCertificates(ctx context.Context) error {
	m.renewMutex.Lock()
	defer m.renewMutex.Unlock()

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
	m.logger.Printf("Forcing renewal of certificate for %s", domain)
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}

	// Get the certificate
	cert, err := m.certManager.GetCertificate(hello)
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	// Update certificate info - need to convert to tls.Certificate
	if len(cert.Certificate) > 0 {
		// Create a new tls.Certificate for updating info
		tlsCert := tls.Certificate{
			Certificate: cert.Certificate,
			PrivateKey:  cert.PrivateKey,
			Leaf:        cert.Leaf,
		}

		if err := m.updateCertificateInfo(tlsCert); err != nil {
			m.logger.Printf("Warning: Failed to update certificate info after forced renewal: %v", err)
		} else {
			m.certInfo.Renewed = time.Now()
			m.logger.Printf("Certificate successfully renewed, valid until %s", m.certInfo.NotAfter.Format(time.RFC3339))
		}
	}

	return nil
}

// GetCertificateInfo returns information about the current certificate
func (m *TLSManager) GetCertificateInfo() (map[string]interface{}, error) {
	if m.config.TLS == nil || !m.config.TLS.Enabled {
		return nil, fmt.Errorf("TLS not enabled")
	}

	info := make(map[string]interface{})
	info["enabled"] = true

	// Add certificate info if available
	if m.certInfo != nil {
		info["domain"] = m.certInfo.Domain
		info["not_before"] = m.certInfo.NotBefore
		info["not_after"] = m.certInfo.NotAfter
		info["issuer"] = m.certInfo.Issuer
		info["source"] = m.certInfo.Source

		if !m.certInfo.Renewed.IsZero() {
			info["last_renewed"] = m.certInfo.Renewed
		}

		// Calculate days until expiration
		if !m.certInfo.NotAfter.IsZero() {
			daysUntilExpiration := int(time.Until(m.certInfo.NotAfter).Hours() / 24)
			info["days_until_expiration"] = daysUntilExpiration
		}
	}

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

// SetSecurityLevel sets the TLS security level for hardening
func (m *TLSManager) SetSecurityLevel(level SecurityLevel) {
	if m.security != nil {
		m.security.SetSecurityLevel(level)
		// Regenerate TLS config with new security level
		if newConfig, err := m.setupSecureTLSConfig(); err == nil {
			m.tlsConfig = newConfig
			m.slogger.Info("TLS security level updated and configuration regenerated", "level", level)
		} else {
			m.slogger.Error("Failed to regenerate TLS config after security level change", "error", err)
		}
	}
}

// GetTLSMonitor returns the TLS monitor for external access to metrics and events
func (m *TLSManager) GetTLSMonitor() *TLSMonitor {
	return m.monitor
}

// GetTLSSecurity returns the TLS security module for external access
func (m *TLSManager) GetTLSSecurity() *TLSSecurity {
	return m.security
}

// GetCertificateMonitor returns the certificate monitor for external access
func (m *TLSManager) GetCertificateMonitor() *CertificateMonitor {
	return m.certMonitor
}

// ValidateSMTPSTS validates SMTP STS compliance for a connection
func (m *TLSManager) ValidateSMTPSTS(hostname string, tlsUsed bool) error {
	if m.security == nil {
		return fmt.Errorf("TLS security module not initialized")
	}
	return m.security.ValidateSMTPSTSCompliance(hostname, tlsUsed)
}

// GetSecurityReport generates a comprehensive TLS security report
func (m *TLSManager) GetSecurityReport(ctx context.Context, duration time.Duration) map[string]interface{} {
	report := make(map[string]interface{})

	// Add TLS manager info
	report["tls_enabled"] = m.config.TLS != nil && m.config.TLS.Enabled

	if certInfo, err := m.GetCertificateInfo(); err == nil {
		report["certificate_info"] = certInfo
	}

	// Add security configuration
	if m.security != nil && m.tlsConfig != nil {
		securityReport := m.security.GetSecurityReport(m.tlsConfig)
		report["security_config"] = securityReport
	}

	// Add monitoring data
	if m.monitor != nil {
		monitoringReport := m.monitor.GenerateSecurityReport(ctx, duration)
		report["monitoring"] = monitoringReport

		// Check for active alerts
		alerts := m.monitor.CheckAlertThresholds()
		if len(alerts) > 0 {
			report["active_alerts"] = alerts
		}
	}

	// Add certificate monitoring data
	if m.certMonitor != nil {
		certHealthReport := m.certMonitor.GetCertificateHealthReport()
		report["certificate_health"] = certHealthReport
		
		// Get all certificate statuses
		certStatuses := m.certMonitor.GetAllCertificateStatuses()
		report["certificate_count"] = len(certStatuses)
		
		// Count certificates by status
		statusCounts := make(map[string]int)
		for _, status := range certStatuses {
			statusCounts[status.Status]++
		}
		report["certificate_status_distribution"] = statusCounts
	}

	return report
}

// CheckTLSHealth performs a comprehensive TLS health check
func (m *TLSManager) CheckTLSHealth() map[string]interface{} {
	health := make(map[string]interface{})
	health["healthy"] = true
	issues := make([]string, 0)

	// Check TLS configuration
	if m.tlsConfig == nil {
		health["healthy"] = false
		issues = append(issues, "TLS configuration not initialized")
	}

	// Check certificate expiry
	if m.certInfo != nil && !m.certInfo.NotAfter.IsZero() {
		daysUntilExpiry := time.Until(m.certInfo.NotAfter).Hours() / 24
		health["days_until_expiry"] = int(daysUntilExpiry)

		if daysUntilExpiry < 30 {
			health["healthy"] = false
			issues = append(issues, fmt.Sprintf("Certificate expires in %.0f days", daysUntilExpiry))
		}
	}

	// Check monitoring status
	if m.monitor != nil {
		metrics := m.monitor.GetMetrics()
		health["total_connections"] = metrics.TotalConnections
		health["tls_connections"] = metrics.TLSConnections
		health["failed_handshakes"] = metrics.FailedHandshakes

		// Check failure rate
		if metrics.TLSConnections > 0 {
			failureRate := float64(metrics.FailedHandshakes) / float64(metrics.TLSConnections) * 100
			health["failure_rate_percent"] = failureRate

			if failureRate > 10 { // More than 10% failure rate is concerning
				health["healthy"] = false
				issues = append(issues, fmt.Sprintf("High TLS failure rate: %.1f%%", failureRate))
			}
		}
	}

	if len(issues) > 0 {
		health["issues"] = issues
	}

	return health
}

// Stop stops the TLS manager and any running services
func (m *TLSManager) Stop() error {
	m.logger.Printf("Stopping TLS manager")

	// Stop TLS monitoring
	if m.monitor != nil {
		m.monitor.Disable()
	}

	// Stop certificate renewal service
	if m.stopChan != nil {
		close(m.stopChan)
	}

	// Stop HTTP server for ACME challenges
	if m.httpServer != nil {
		m.logger.Printf("Stopping HTTP server for ACME challenges")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.httpServer.Shutdown(ctx); err != nil {
			m.logger.Printf("Error shutting down HTTP server for ACME challenges: %v", err)
		}
	}

	return nil
}
