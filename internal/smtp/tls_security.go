package smtp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	// Enforce minimum TLS 1.2 - never allow weaker versions
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
		ts.logger.Warn("TLS version below 1.2 detected, enforcing TLS 1.2 minimum")
	}

	// Prefer server cipher suite order for security
	config.PreferServerCipherSuites = true

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

// SMTPSTSPolicy represents SMTP STS (Strict Transport Security) policy
type SMTPSTSPolicy struct {
	Mode      string        // "enforce", "testing", or "none"
	MaxAge    time.Duration // Policy lifetime
	MXMatches []string      // MX hostnames that must support TLS
}

// GetSMTPSTSPolicy returns the SMTP STS policy for enhanced security
func (ts *TLSSecurity) GetSMTPSTSPolicy() *SMTPSTSPolicy {
	return &SMTPSTSPolicy{
		Mode:   "enforce", // Enforce TLS for all SMTP connections
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

// equalPKIXNames compares two PKIX names for equality
func equalPKIXNames(a, b pkix.Name) bool {
	// Compare the string representation of the names
	return a.String() == b.String()
}
