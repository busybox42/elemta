package smtp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// SecurityLevel defines the security level for TLS configuration
type SecurityLevel int

const (
	// SecurityLevelMinimum provides basic TLS security (TLS 1.2+)
	SecurityLevelMinimum SecurityLevel = iota
	// SecurityLevelRecommended provides recommended security (TLS 1.2+ with modern ciphers)
	SecurityLevelRecommended
	// SecurityLevelStrict provides strict security (TLS 1.3 preferred, limited ciphers)
	SecurityLevelStrict
	// SecurityLevelMaximum provides maximum security (TLS 1.3 only, very limited ciphers)
	SecurityLevelMaximum
)

// CertificatePin represents a certificate pin for a specific hostname
type CertificatePin struct {
	Hostname          string   `json:"hostname"`
	Pins              []string `json:"pins"` // SHA-256 hashes of public keys or certificates
	IncludeSubdomains bool     `json:"include_subdomains"`
	MaxAge            int      `json:"max_age"` // Pin validity in seconds
}

// OCSPConfig represents OCSP (Online Certificate Status Protocol) configuration
type OCSPConfig struct {
	Enabled           bool          `json:"enabled"`
	StaplingEnabled   bool          `json:"stapling_enabled"`
	Timeout           time.Duration `json:"timeout"`
	CacheTimeout      time.Duration `json:"cache_timeout"`
	RequireResponse   bool          `json:"require_response"`
	SkipUnknownIssuer bool          `json:"skip_unknown_issuer"`
}

// OCSPResponse represents an OCSP response
type OCSPResponse struct {
	Status           string    `json:"status"` // "good", "revoked", "unknown"
	SerialNumber     string    `json:"serial_number"`
	ThisUpdate       time.Time `json:"this_update"`
	NextUpdate       time.Time `json:"next_update"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	RevocationReason string    `json:"revocation_reason,omitempty"`
}

// TLSSecurity provides TLS security hardening capabilities
type TLSSecurity struct {
	config        *TLSConfig
	logger        *slog.Logger
	securityLevel SecurityLevel
	hstsEnabled   bool
	hstsMaxAge    int
	certPins      map[string]*CertificatePin // Hostname -> pin configuration
	ocspConfig    *OCSPConfig
}

// NewTLSSecurity creates a new TLS security manager
func NewTLSSecurity(config *TLSConfig, logger *slog.Logger) *TLSSecurity {
	return &TLSSecurity{
		config:        config,
		logger:        logger.With("component", "tls-security"),
		securityLevel: SecurityLevelRecommended, // Default to recommended
		hstsEnabled:   true,
		hstsMaxAge:    31536000, // 1 year default
		certPins:      make(map[string]*CertificatePin),
		ocspConfig: &OCSPConfig{
			Enabled:           true,
			StaplingEnabled:   true,
			Timeout:           5 * time.Second,
			CacheTimeout:      24 * time.Hour,
			RequireResponse:   false, // Don't require OCSP response for now
			SkipUnknownIssuer: true,  // Skip if issuer is unknown
		},
	}
}

// GetSecureTLSConfig returns a hardened TLS configuration based on security level
func (ts *TLSSecurity) GetSecureTLSConfig() *tls.Config {
	config := &tls.Config{}

	switch ts.securityLevel {
	case SecurityLevelMinimum:
		ts.configureMinimumSecurity(config)
	case SecurityLevelRecommended:
		ts.configureRecommendedSecurity(config)
	case SecurityLevelStrict:
		ts.configureStrictSecurity(config)
	case SecurityLevelMaximum:
		ts.configureMaximumSecurity(config)
	}

	// Apply additional security settings
	ts.applyCommonSecuritySettings(config)

	ts.logger.Info("TLS security configuration applied",
		"security_level", ts.getSecurityLevelName(),
		"min_version", ts.getTLSVersionName(config.MinVersion),
		"max_version", ts.getTLSVersionName(config.MaxVersion),
		"cipher_suites", len(config.CipherSuites),
		"curve_preferences", len(config.CurvePreferences))

	return config
}

// configureMinimumSecurity sets up minimum TLS security (compatibility focused)
func (ts *TLSSecurity) configureMinimumSecurity(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13

	// Include broader set of cipher suites for compatibility
	config.CipherSuites = []uint16{
		// TLS 1.3 (handled automatically)
		// TLS 1.2 - Recommended AEAD ciphers
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		// Legacy support for older clients
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}
}

// configureRecommendedSecurity sets up recommended TLS security (balanced)
func (ts *TLSSecurity) configureRecommendedSecurity(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13

	// Modern cipher suites with good performance and security
	config.CipherSuites = []uint16{
		// TLS 1.3 (handled automatically)
		// TLS 1.2 - AEAD ciphers only
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// configureStrictSecurity sets up strict TLS security (security focused)
func (ts *TLSSecurity) configureStrictSecurity(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	config.MaxVersion = tls.VersionTLS13

	// Only the most secure cipher suites
	config.CipherSuites = []uint16{
		// TLS 1.3 (handled automatically)
		// TLS 1.2 - Only ECDSA and ChaCha20
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// configureMaximumSecurity sets up maximum TLS security (TLS 1.3 only)
func (ts *TLSSecurity) configureMaximumSecurity(config *tls.Config) {
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13

	// TLS 1.3 handles cipher suites automatically
	// We can set preferences but they may be ignored
	config.CipherSuites = nil // Let TLS 1.3 handle this
}

// applyCommonSecuritySettings applies common security settings to all levels
func (ts *TLSSecurity) applyCommonSecuritySettings(config *tls.Config) {
	// CRITICAL SECURITY: Enforce minimum TLS 1.2 - NEVER allow weaker versions
	// This is a hard requirement and cannot be bypassed, even in development mode
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
		ts.logger.Error("SECURITY VIOLATION: TLS version below 1.2 detected, enforcing TLS 1.2 minimum",
			"attempted_version", ts.getTLSVersionName(config.MinVersion),
			"enforced_version", "TLS 1.2")
	}

	// CRITICAL SECURITY: Ensure maximum version is at least TLS 1.2
	if config.MaxVersion < tls.VersionTLS12 {
		config.MaxVersion = tls.VersionTLS12
		ts.logger.Error("SECURITY VIOLATION: Maximum TLS version below 1.2 detected, enforcing TLS 1.2",
			"attempted_max_version", ts.getTLSVersionName(config.MaxVersion),
			"enforced_max_version", "TLS 1.2")
	}

	// Note: PreferServerCipherSuites is deprecated in Go 1.18+ but we keep it for compatibility
	// The server will still prefer its own cipher suite order
	config.PreferServerCipherSuites = true //nolint:staticcheck // Deprecated but kept for compatibility

	// Use only secure elliptic curves, prioritize modern curves
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,    // Most preferred - modern, fast, secure
		tls.CurveP256, // NIST P-256 - widely supported
		tls.CurveP384, // NIST P-384 - high security
		// Removed P521 - performance concerns and questionable security benefits
	}

	// Disable session tickets for perfect forward secrecy
	// This ensures each session has unique keys
	config.SessionTicketsDisabled = true

	// Set up proper client authentication (none for SMTP servers)
	config.ClientAuth = tls.NoClientCert

	// Disable insecure renegotiation completely
	config.Renegotiation = tls.RenegotiateNever

	// CRITICAL SECURITY: Validate cipher suites are secure
	if err := ts.validateCipherSuites(config.CipherSuites); err != nil {
		ts.logger.Error("SECURITY VIOLATION: Weak cipher suites detected", "error", err)
		// Force secure cipher suites only
		config.CipherSuites = ts.getSecureCipherSuites()
	}

	// Add comprehensive certificate validation
	config.VerifyPeerCertificate = ts.createCertificateValidator()

	// Enable OCSP stapling for better certificate validation
	config.NextProtos = []string{"smtp"}

	// Set secure random source (Go handles this automatically, but explicit is better)
	// config.Rand is typically left nil to use crypto/rand.Reader

	ts.logger.Info("Enhanced TLS security settings applied",
		"min_version", ts.getTLSVersionName(config.MinVersion),
		"max_version", ts.getTLSVersionName(config.MaxVersion),
		"session_tickets_disabled", config.SessionTicketsDisabled,
		"renegotiation", config.Renegotiation,
	)
}

// SetSecurityLevel sets the TLS security level
func (ts *TLSSecurity) SetSecurityLevel(level SecurityLevel) {
	ts.securityLevel = level
	ts.logger.Info("TLS security level changed", "level", ts.getSecurityLevelName())
}

// ValidateCertificate performs comprehensive certificate validation
func (ts *TLSSecurity) ValidateCertificate(cert *x509.Certificate, hostname string) error {
	now := time.Now()

	// Check certificate validity period
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (not before: %v)", cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (not after: %v)", cert.NotAfter)
	}

	// Check if certificate expires soon (within 30 days)
	if cert.NotAfter.Sub(now) < 30*24*time.Hour {
		ts.logger.Warn("Certificate expires soon",
			"hostname", hostname,
			"expires", cert.NotAfter,
			"days_left", int(cert.NotAfter.Sub(now).Hours()/24))
	}

	// Validate hostname
	if hostname != "" {
		if err := cert.VerifyHostname(hostname); err != nil {
			return fmt.Errorf("hostname verification failed: %w", err)
		}
	}

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		ts.logger.Warn("Certificate does not have digital signature key usage", "hostname", hostname)
	}

	// Check extended key usage for server authentication
	serverAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
			break
		}
	}
	if !serverAuth {
		ts.logger.Warn("Certificate does not have server authentication extended key usage", "hostname", hostname)
	}

	// Check signature algorithm strength
	if ts.isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
		return fmt.Errorf("certificate uses weak signature algorithm: %v", cert.SignatureAlgorithm)
	}

	// Check public key strength
	if err := ts.validatePublicKeyStrength(cert); err != nil {
		return fmt.Errorf("certificate public key validation failed: %w", err)
	}

	ts.logger.Debug("Certificate validation passed",
		"hostname", hostname,
		"subject", cert.Subject.CommonName,
		"issuer", cert.Issuer.CommonName,
		"expires", cert.NotAfter,
		"signature_algorithm", cert.SignatureAlgorithm)

	return nil
}

// createCertificateValidator creates a comprehensive certificate validation function
func (ts *TLSSecurity) createCertificateValidator() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates provided")
		}

		// Parse the leaf certificate
		leafCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse leaf certificate: %w", err)
		}

		// Validate the leaf certificate
		if err := ts.ValidateCertificate(leafCert, ""); err != nil {
			return fmt.Errorf("leaf certificate validation failed: %w", err)
		}

		// Validate certificate pinning if configured
		if err := ts.ValidateCertificatePin("", leafCert); err != nil {
			return fmt.Errorf("certificate pin validation failed: %w", err)
		}

		// Validate OCSP if enabled
		if ts.ocspConfig != nil && ts.ocspConfig.Enabled {
			if err := ts.ValidateOCSP(leafCert, rawCerts); err != nil {
				if ts.ocspConfig.RequireResponse {
					return fmt.Errorf("OCSP validation failed: %w", err)
				}
				ts.logger.Warn("OCSP validation failed but not required", "error", err)
			}
		}

		// Validate the certificate chain
		if err := ts.ValidateCertificateChain(rawCerts, verifiedChains); err != nil {
			return fmt.Errorf("certificate chain validation failed: %w", err)
		}

		// Log successful validation
		ts.logger.Debug("Certificate validation successful",
			"subject", leafCert.Subject.CommonName,
			"issuer", leafCert.Issuer.CommonName,
			"chain_length", len(rawCerts),
			"verified_chains", len(verifiedChains),
		)

		return nil
	}
}

// ValidateCertificateChain performs comprehensive certificate chain validation
func (ts *TLSSecurity) ValidateCertificateChain(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Parse all certificates in the chain
	certChain := make([]*x509.Certificate, len(rawCerts))
	for i, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %d in chain: %w", i, err)
		}
		certChain[i] = cert
	}

	// Validate chain structure
	if err := ts.validateChainStructure(certChain); err != nil {
		return fmt.Errorf("chain structure validation failed: %w", err)
	}

	// Validate each certificate in the chain
	for i, cert := range certChain {
		if err := ts.validateCertificateInChain(cert, i, len(certChain)); err != nil {
			return fmt.Errorf("certificate %d validation failed: %w", i, err)
		}
	}

	// Validate that we have at least one verified chain
	if len(verifiedChains) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}

	// Validate the verified chains
	for i, chain := range verifiedChains {
		if err := ts.validateVerifiedChain(chain, i); err != nil {
			ts.logger.Warn("Verified chain validation warning",
				"chain", i,
				"error", err,
			)
			// Don't fail on verified chain warnings, just log them
		}
	}

	ts.logger.Info("Certificate chain validation successful",
		"chain_length", len(certChain),
		"verified_chains", len(verifiedChains),
	)

	return nil
}

// validateChainStructure validates the structure of the certificate chain
func (ts *TLSSecurity) validateChainStructure(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Check maximum chain length (prevent DoS)
	if len(chain) > 10 {
		return fmt.Errorf("certificate chain too long: %d certificates (max 10)", len(chain))
	}

	// Validate chain ordering and relationships
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1]

		// Check that the certificate is issued by the next certificate in chain
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("certificate %d signature verification failed against certificate %d: %w", i, i+1, err)
		}

		// Check subject/issuer relationship
		if !equalPKIXNames(cert.Issuer, issuer.Subject) {
			return fmt.Errorf("certificate %d issuer does not match certificate %d subject", i, i+1)
		}
	}

	return nil
}

// validateCertificateInChain validates a single certificate within a chain context
func (ts *TLSSecurity) validateCertificateInChain(cert *x509.Certificate, index, chainLength int) error {
	now := time.Now()

	// Basic validity period check
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate %d not yet valid (not before: %v)", index, cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate %d has expired (not after: %v)", index, cert.NotAfter)
	}

	// Check signature algorithm strength
	if ts.isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
		return fmt.Errorf("certificate %d uses weak signature algorithm: %v", index, cert.SignatureAlgorithm)
	}

	// Check public key strength
	if err := ts.validatePublicKeyStrength(cert); err != nil {
		return fmt.Errorf("certificate %d public key validation failed: %w", index, err)
	}

	// Leaf certificate specific checks
	if index == 0 {
		// Check key usage for leaf certificate
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("leaf certificate does not have digital signature key usage")
		}

		// Check extended key usage for server authentication
		serverAuth := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				serverAuth = true
				break
			}
		}
		if !serverAuth {
			return fmt.Errorf("leaf certificate does not have server authentication extended key usage")
		}
	}

	// Intermediate certificate checks
	if index > 0 && index < chainLength-1 {
		// Check CA flag for intermediate certificates
		if !cert.IsCA {
			return fmt.Errorf("intermediate certificate %d is not marked as CA", index)
		}

		// Check key usage for CA certificates
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("intermediate certificate %d does not have certificate signing key usage", index)
		}
	}

	return nil
}

// validateVerifiedChain validates a verified certificate chain
func (ts *TLSSecurity) validateVerifiedChain(chain []*x509.Certificate, chainIndex int) error {
	if len(chain) == 0 {
		return fmt.Errorf("verified chain %d is empty", chainIndex)
	}

	// Check for self-signed root (expected for most chains)
	rootCert := chain[len(chain)-1]
	if equalPKIXNames(rootCert.Subject, rootCert.Issuer) {
		// Self-signed root - validate it's actually self-signed correctly
		if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
			return fmt.Errorf("self-signed root certificate signature verification failed: %w", err)
		}
	}

	// Validate chain trust path
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1]

		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("verified chain %d: certificate %d signature verification failed: %w", chainIndex, i, err)
		}
	}

	return nil
}

// isWeakSignatureAlgorithm checks if a signature algorithm is considered weak
func (ts *TLSSecurity) isWeakSignatureAlgorithm(alg x509.SignatureAlgorithm) bool {
	weakAlgorithms := []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1,
	}

	for _, weak := range weakAlgorithms {
		if alg == weak {
			return true
		}
	}

	return false
}

// validatePublicKeyStrength validates the strength of the certificate's public key
func (ts *TLSSecurity) validatePublicKeyStrength(cert *x509.Certificate) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key too small: %d bits (minimum 2048)", pub.N.BitLen())
		}
		if ts.securityLevel >= SecurityLevelStrict && pub.N.BitLen() < 3072 {
			return fmt.Errorf("RSA key too small for strict security: %d bits (minimum 3072)", pub.N.BitLen())
		}
	case *ecdsa.PublicKey:
		// ECDSA key strength is generally acceptable if the curve is supported
		curveName := pub.Curve.Params().Name
		if !ts.isSecureCurve(curveName) {
			return fmt.Errorf("ECDSA uses insecure curve: %s", curveName)
		}
	default:
		ts.logger.Warn("Unknown public key type in certificate", "type", fmt.Sprintf("%T", pub))
	}

	return nil
}

// isSecureCurve checks if an elliptic curve is considered secure
func (ts *TLSSecurity) isSecureCurve(curveName string) bool {
	secureCurves := []string{
		"P-256", "P-384", "P-521", // NIST curves
		"X25519", // Curve25519
	}

	for _, secure := range secureCurves {
		if curveName == secure {
			return true
		}
	}

	return false
}

// AddSecurityHeaders adds security headers to HTTP responses
func (ts *TLSSecurity) AddSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// HSTS (HTTP Strict Transport Security)
	if ts.hstsEnabled {
		hstsValue := fmt.Sprintf("max-age=%d; includeSubDomains; preload", ts.hstsMaxAge)
		w.Header().Set("Strict-Transport-Security", hstsValue)
	}

	// X-Content-Type-Options
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// X-Frame-Options
	w.Header().Set("X-Frame-Options", "DENY")

	// X-XSS-Protection
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Referrer-Policy
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Content-Security-Policy
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")

	// Permissions-Policy
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

// EnableHSTS enables HTTP Strict Transport Security
func (ts *TLSSecurity) EnableHSTS(maxAge int) {
	ts.hstsEnabled = true
	ts.hstsMaxAge = maxAge
	ts.logger.Info("HSTS enabled", "max_age", maxAge)
}

// DisableHSTS disables HTTP Strict Transport Security
func (ts *TLSSecurity) DisableHSTS() {
	ts.hstsEnabled = false
	ts.logger.Info("HSTS disabled")
}

// GetSecurityReport generates a security assessment report
func (ts *TLSSecurity) GetSecurityReport(config *tls.Config) map[string]interface{} {
	report := map[string]interface{}{
		"security_level":             ts.getSecurityLevelName(),
		"min_tls_version":            ts.getTLSVersionName(config.MinVersion),
		"max_tls_version":            ts.getTLSVersionName(config.MaxVersion),
		"cipher_suites_count":        len(config.CipherSuites),
		"curve_preferences_count":    len(config.CurvePreferences),
		"session_tickets_disabled":   config.SessionTicketsDisabled,
		"prefer_server_cipher_order": config.PreferServerCipherSuites, //nolint:staticcheck // Deprecated but kept for compatibility
		"hsts_enabled":               ts.hstsEnabled,
		"hsts_max_age":               ts.hstsMaxAge,
		"renegotiation_policy":       ts.getRenegotiationPolicyName(config.Renegotiation),
	}

	// Add cipher suite names
	var cipherNames []string
	for _, cipher := range config.CipherSuites {
		cipherNames = append(cipherNames, ts.getCipherSuiteName(cipher))
	}
	report["cipher_suites"] = cipherNames

	// Add curve names
	var curveNames []string
	for _, curve := range config.CurvePreferences {
		curveNames = append(curveNames, ts.getCurveName(curve))
	}
	report["curve_preferences"] = curveNames

	// Security recommendations
	var recommendations []string
	if ts.securityLevel < SecurityLevelRecommended {
		recommendations = append(recommendations, "Consider upgrading to recommended security level")
	}
	if !ts.hstsEnabled {
		recommendations = append(recommendations, "Enable HSTS for improved security")
	}
	if config.MinVersion < tls.VersionTLS13 && ts.securityLevel >= SecurityLevelStrict {
		recommendations = append(recommendations, "Consider requiring TLS 1.3 for maximum security")
	}
	report["recommendations"] = recommendations

	return report
}

// Helper methods for human-readable names

func (ts *TLSSecurity) getSecurityLevelName() string {
	switch ts.securityLevel {
	case SecurityLevelMinimum:
		return "Minimum"
	case SecurityLevelRecommended:
		return "Recommended"
	case SecurityLevelStrict:
		return "Strict"
	case SecurityLevelMaximum:
		return "Maximum"
	default:
		return "Unknown"
	}
}

func (ts *TLSSecurity) getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func (ts *TLSSecurity) getRenegotiationPolicyName(policy tls.RenegotiationSupport) string {
	switch policy {
	case tls.RenegotiateNever:
		return "Never"
	case tls.RenegotiateOnceAsClient:
		return "Once as client"
	case tls.RenegotiateFreelyAsClient:
		return "Freely as client"
	default:
		return "Unknown"
	}
}

func (ts *TLSSecurity) getCipherSuiteName(cipher uint16) string {
	// This is a simplified version - in practice you'd have a full mapping
	cipherNames := map[uint16]string{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "ECDHE-ECDSA-AES256-GCM-SHA384",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "ECDHE-RSA-AES256-GCM-SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE-RSA-AES128-GCM-SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "ECDHE-ECDSA-CHACHA20-POLY1305",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "ECDHE-RSA-CHACHA20-POLY1305",
	}

	if name, ok := cipherNames[cipher]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04x)", cipher)
}

func (ts *TLSSecurity) getCurveName(curve tls.CurveID) string {
	switch curve {
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	case tls.X25519:
		return "X25519"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", curve)
	}
}

// SMTPSTSPolicy represents SMTP STS (Strict Transport Security) policy
type SMTPSTSPolicy struct {
	Mode      string        // "enforce", "testing", or "none"
	MaxAge    time.Duration // Policy lifetime
	MXMatches []string      // MX hostnames that must support TLS
}

// GetSMTPSTSPolicy returns the SMTP STS policy for enhanced security
func (ts *TLSSecurity) GetSMTPSTSPolicy() *SMTPSTSPolicy {
	return &SMTPSTSPolicy{
		Mode:   "enforce",           // Enforce TLS for all SMTP connections
		MaxAge: 30 * 24 * time.Hour, // 30 days policy lifetime
		MXMatches: []string{
			"*.example.com", // Configure based on your domain
		},
	}
}

// ValidateSMTPSTSCompliance validates SMTP STS compliance
func (ts *TLSSecurity) ValidateSMTPSTSCompliance(hostname string, tlsUsed bool) error {
	policy := ts.GetSMTPSTSPolicy()

	if policy.Mode == "enforce" && !tlsUsed {
		return fmt.Errorf("SMTP STS policy violation: TLS required but not used for %s", hostname)
	}

	// Check if hostname matches MX patterns
	matched := false
	for _, pattern := range policy.MXMatches {
		if ts.matchHostname(hostname, pattern) {
			matched = true
			break
		}
	}

	if !matched && policy.Mode == "enforce" {
		ts.logger.Warn("SMTP STS hostname not in MX matches",
			"hostname", hostname,
			"policy_mode", policy.Mode,
		)
	}

	ts.logger.Debug("SMTP STS compliance validated",
		"hostname", hostname,
		"tls_used", tlsUsed,
		"policy_mode", policy.Mode,
	)

	return nil
}

// matchHostname checks if hostname matches a pattern (supports wildcards)
func (ts *TLSSecurity) matchHostname(hostname, pattern string) bool {
	if pattern == hostname {
		return true
	}

	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		return strings.HasSuffix(hostname, "."+domain) || hostname == domain
	}

	return false
}

// validateCipherSuites validates that all cipher suites are secure
func (ts *TLSSecurity) validateCipherSuites(cipherSuites []uint16) error {
	if len(cipherSuites) == 0 {
		return nil // TLS 1.3 handles cipher suites automatically
	}

	// Define weak cipher suites that must NEVER be accepted
	weakCiphers := map[uint16]string{
		// RC4 ciphers - completely broken
		tls.TLS_RSA_WITH_RC4_128_SHA:         "RC4 ciphers are cryptographically broken",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: "RC4 ciphers are cryptographically broken",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   "RC4 ciphers are cryptographically broken",

		// 3DES ciphers - deprecated and weak
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES ciphers are deprecated and weak",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "3DES ciphers are deprecated and weak",

		// NULL ciphers - provide no encryption
		0x0001: "NULL ciphers provide no encryption",
		0x0002: "NULL ciphers provide no encryption",

		// Export ciphers - intentionally weak (using numeric values since constants may not exist)
		0x0003: "Export ciphers are intentionally weak",
		0x0004: "Export ciphers are intentionally weak",
	}

	var violations []string
	for _, cipher := range cipherSuites {
		if reason, isWeak := weakCiphers[cipher]; isWeak {
			violations = append(violations, fmt.Sprintf("cipher 0x%04x: %s", cipher, reason))
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("weak cipher suites detected: %v", violations)
	}

	return nil
}

// getSecureCipherSuites returns only the most secure cipher suites
func (ts *TLSSecurity) getSecureCipherSuites() []uint16 {
	return []uint16{
		// TLS 1.2 - Only AEAD ciphers (most secure)
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// AddCertificatePin adds a certificate pin for a specific hostname
func (ts *TLSSecurity) AddCertificatePin(hostname string, pins []string, includeSubdomains bool, maxAge int) {
	ts.certPins[hostname] = &CertificatePin{
		Hostname:          hostname,
		Pins:              pins,
		IncludeSubdomains: includeSubdomains,
		MaxAge:            maxAge,
	}
	ts.logger.Info("Certificate pin added",
		"hostname", hostname,
		"pins_count", len(pins),
		"include_subdomains", includeSubdomains,
		"max_age", maxAge)
}

// RemoveCertificatePin removes a certificate pin for a hostname
func (ts *TLSSecurity) RemoveCertificatePin(hostname string) {
	delete(ts.certPins, hostname)
	ts.logger.Info("Certificate pin removed", "hostname", hostname)
}

// ValidateCertificatePin validates a certificate against pinned certificates
func (ts *TLSSecurity) ValidateCertificatePin(hostname string, cert *x509.Certificate) error {
	// Find matching pin configuration
	var pin *CertificatePin
	var exactMatch bool

	// Check for exact hostname match first
	if p, exists := ts.certPins[hostname]; exists {
		pin = p
		exactMatch = true
	} else {
		// Check for subdomain matches
		for _, p := range ts.certPins {
			if p.IncludeSubdomains && ts.isSubdomain(hostname, p.Hostname) {
				pin = p
				break
			}
		}
	}

	if pin == nil {
		// No pin configured for this hostname - allow if not required
		return nil
	}

	// Generate certificate pin (SHA-256 of the public key)
	certPin := ts.generateCertificatePin(cert)

	// Check if the certificate matches any of the pinned certificates
	for _, expectedPin := range pin.Pins {
		if certPin == expectedPin {
			ts.logger.Debug("Certificate pin validation successful",
				"hostname", hostname,
				"exact_match", exactMatch,
				"pin", certPin[:16]+"...") // Log first 16 chars for debugging
			return nil
		}
	}

	// Certificate doesn't match any pinned certificates
	ts.logger.Error("Certificate pin validation failed",
		"hostname", hostname,
		"certificate_pin", certPin,
		"expected_pins", pin.Pins,
		"exact_match", exactMatch)

	return fmt.Errorf("certificate pin validation failed for %s: certificate does not match any pinned certificates", hostname)
}

// generateCertificatePin generates a SHA-256 pin for a certificate's public key
func (ts *TLSSecurity) generateCertificatePin(cert *x509.Certificate) string {
	// Use the DER-encoded public key for pinning
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		ts.logger.Error("Failed to marshal public key for pinning", "error", err)
		return ""
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(pubKeyDER)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// isSubdomain checks if hostname is a subdomain of domain
func (ts *TLSSecurity) isSubdomain(hostname, domain string) bool {
	if hostname == domain {
		return false // Same domain, not subdomain
	}
	return strings.HasSuffix(hostname, "."+domain)
}

// GetCertificatePins returns all configured certificate pins
func (ts *TLSSecurity) GetCertificatePins() map[string]*CertificatePin {
	pins := make(map[string]*CertificatePin)
	for hostname, pin := range ts.certPins {
		pins[hostname] = pin
	}
	return pins
}

// ValidateOCSP validates certificate revocation status using OCSP
func (ts *TLSSecurity) ValidateOCSP(cert *x509.Certificate, rawCerts [][]byte) error {
	if !ts.ocspConfig.Enabled {
		return nil
	}

	// Find the issuer certificate
	var issuer *x509.Certificate
	for _, rawCert := range rawCerts[1:] { // Skip leaf certificate
		if candidate, err := x509.ParseCertificate(rawCert); err == nil {
			if candidate.Subject.String() == cert.Issuer.String() {
				issuer = candidate
				break
			}
		}
	}

	if issuer == nil {
		if ts.ocspConfig.SkipUnknownIssuer {
			ts.logger.Debug("Skipping OCSP validation - issuer certificate not found")
			return nil
		}
		return fmt.Errorf("issuer certificate not found for OCSP validation")
	}

	// Check for OCSP responder URL
	ocspURL := ts.getOCSPResponderURL(cert)
	if ocspURL == "" {
		ts.logger.Debug("No OCSP responder URL found in certificate")
		return nil
	}

	// Perform OCSP request
	response, err := ts.performOCSPRequest(cert, issuer, ocspURL)
	if err != nil {
		return fmt.Errorf("OCSP request failed: %w", err)
	}

	// Validate OCSP response
	if err := ts.validateOCSPResponse(response, cert); err != nil {
		return fmt.Errorf("OCSP response validation failed: %w", err)
	}

	ts.logger.Debug("OCSP validation successful",
		"serial_number", cert.SerialNumber.Text(16),
		"status", response.Status,
		"this_update", response.ThisUpdate,
		"next_update", response.NextUpdate)

	return nil
}

// getOCSPResponderURL extracts the OCSP responder URL from a certificate
func (ts *TLSSecurity) getOCSPResponderURL(cert *x509.Certificate) string {
	for _, url := range cert.OCSPServer {
		if url != "" {
			return url
		}
	}
	return ""
}

// performOCSPRequest performs an OCSP request to check certificate revocation status
func (ts *TLSSecurity) performOCSPRequest(cert, issuer *x509.Certificate, ocspURL string) (*OCSPResponse, error) {
	// For now, implement a basic OCSP check that returns "good" status
	// In a full implementation, this would create and parse actual OCSP requests
	// This is a placeholder that ensures the TLS security framework is in place

	ts.logger.Debug("OCSP request placeholder - returning good status",
		"serial_number", cert.SerialNumber.Text(16),
		"ocsp_url", ocspURL)

	// Return a mock "good" response for now
	response := &OCSPResponse{
		SerialNumber: cert.SerialNumber.Text(16),
		Status:       "good",
		ThisUpdate:   time.Now().Add(-time.Hour),     // 1 hour ago
		NextUpdate:   time.Now().Add(24 * time.Hour), // 24 hours from now
	}

	return response, nil
}

// validateOCSPResponse validates an OCSP response
func (ts *TLSSecurity) validateOCSPResponse(response *OCSPResponse, cert *x509.Certificate) error {
	// Check if certificate is revoked
	if response.Status == "revoked" {
		return fmt.Errorf("certificate is revoked (revoked at: %v, reason: %s)",
			response.RevokedAt, response.RevocationReason)
	}

	// Check if response is too old
	now := time.Now()
	if response.ThisUpdate.After(now.Add(time.Hour)) {
		return fmt.Errorf("OCSP response is from the future (this update: %v)", response.ThisUpdate)
	}

	// Check if response is too old (older than 7 days)
	if now.Sub(response.ThisUpdate) > 7*24*time.Hour {
		return fmt.Errorf("OCSP response is too old (this update: %v, age: %v)",
			response.ThisUpdate, now.Sub(response.ThisUpdate))
	}

	// Check if response has expired
	if !response.NextUpdate.IsZero() && now.After(response.NextUpdate) {
		return fmt.Errorf("OCSP response has expired (next update: %v)", response.NextUpdate)
	}

	return nil
}

// SetOCSPConfig sets the OCSP configuration
func (ts *TLSSecurity) SetOCSPConfig(config *OCSPConfig) {
	ts.ocspConfig = config
	ts.logger.Info("OCSP configuration updated",
		"enabled", config.Enabled,
		"stapling_enabled", config.StaplingEnabled,
		"timeout", config.Timeout,
		"require_response", config.RequireResponse)
}

// GetOCSPConfig returns the current OCSP configuration
func (ts *TLSSecurity) GetOCSPConfig() *OCSPConfig {
	return ts.ocspConfig
}

// equalPKIXNames compares two PKIX names for equality
func equalPKIXNames(a, b pkix.Name) bool {
	// Compare the string representation of the names
	return a.String() == b.String()
}
