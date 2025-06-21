package smtp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
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

// TLSSecurity provides TLS security hardening capabilities
type TLSSecurity struct {
	config        *TLSConfig
	logger        *slog.Logger
	securityLevel SecurityLevel
	hstsEnabled   bool
	hstsMaxAge    int
}

// NewTLSSecurity creates a new TLS security manager
func NewTLSSecurity(config *TLSConfig, logger *slog.Logger) *TLSSecurity {
	return &TLSSecurity{
		config:        config,
		logger:        logger.With("component", "tls-security"),
		securityLevel: SecurityLevelRecommended, // Default to recommended
		hstsEnabled:   true,
		hstsMaxAge:    31536000, // 1 year default
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
	// Prefer server cipher suite order
	config.PreferServerCipherSuites = true

	// Use secure elliptic curves
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,    // Most preferred
		tls.CurveP256, // NIST P-256
		tls.CurveP384, // NIST P-384
		tls.CurveP521, // NIST P-521 (optional)
	}

	// Disable session tickets for perfect forward secrecy
	// Note: This may impact performance but improves security
	config.SessionTicketsDisabled = true

	// Set up proper client authentication (none for SMTP servers)
	config.ClientAuth = tls.NoClientCert

	// Disable insecure renegotiation
	config.Renegotiation = tls.RenegotiateNever
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
		"prefer_server_cipher_order": config.PreferServerCipherSuites,
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
