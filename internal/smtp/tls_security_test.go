package smtp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestNewTLSSecurity(t *testing.T) {
	config := &TLSConfig{
		Enabled: true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	security := NewTLSSecurity(config, logger)

	if security == nil {
		t.Fatal("Expected TLSSecurity instance, got nil")
	}

	if security.config != config {
		t.Error("Expected config to be set correctly")
	}

	if security.securityLevel != SecurityLevelRecommended {
		t.Error("Expected default security level to be Recommended")
	}
}

func TestSecurityLevels(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	tests := []struct {
		name  string
		level SecurityLevel
	}{
		{"Minimum", SecurityLevelMinimum},
		{"Recommended", SecurityLevelRecommended},
		{"Strict", SecurityLevelStrict},
		{"Maximum", SecurityLevelMaximum},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			security.SetSecurityLevel(tt.level)
			tlsConfig := security.GetSecureTLSConfig()

			if tlsConfig == nil {
				t.Fatal("Expected TLS config, got nil")
			}

			// Verify minimum version is at least TLS 1.2
			if tlsConfig.MinVersion < tls.VersionTLS12 {
				t.Error("Expected minimum TLS version to be at least 1.2")
			}

			// For maximum security, should enforce TLS 1.3
			if tt.level == SecurityLevelMaximum && tlsConfig.MinVersion != tls.VersionTLS13 {
				t.Error("Expected TLS 1.3 for maximum security level")
			}

			// Check that cipher suites are configured
			if tt.level != SecurityLevelMaximum && len(tlsConfig.CipherSuites) == 0 {
				t.Error("Expected cipher suites to be configured for non-maximum security levels")
			}

			// Verify secure defaults
			if !tlsConfig.PreferServerCipherSuites {
				t.Error("Expected server cipher suite preference to be enabled")
			}

			if !tlsConfig.SessionTicketsDisabled {
				t.Error("Expected session tickets to be disabled for forward secrecy")
			}

			if tlsConfig.Renegotiation != tls.RenegotiateNever {
				t.Error("Expected renegotiation to be disabled")
			}
		})
	}
}

func TestCertificateValidation(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	// Generate a test certificate
	cert := generateTestCertificateForSecurity(t, "test.example.com", time.Now().Add(30*24*time.Hour))

	// Test valid certificate
	err := security.ValidateCertificate(cert, "test.example.com")
	if err != nil {
		t.Errorf("Expected valid certificate to pass validation: %v", err)
	}

	// Test expired certificate
	expiredCert := generateTestCertificateForSecurity(t, "test.example.com", time.Now().Add(-24*time.Hour))
	err = security.ValidateCertificate(expiredCert, "test.example.com")
	if err == nil {
		t.Error("Expected expired certificate to fail validation")
	}

	// Test hostname mismatch
	err = security.ValidateCertificate(cert, "wrong.example.com")
	if err == nil {
		t.Error("Expected hostname mismatch to fail validation")
	}

	// Test certificate expiring soon (within 30 days)
	soonExpiredCert := generateTestCertificateForSecurity(t, "test.example.com", time.Now().Add(15*24*time.Hour))
	err = security.ValidateCertificate(soonExpiredCert, "test.example.com")
	// Should not error but should log warning
	if err != nil {
		t.Errorf("Certificate expiring soon should not error: %v", err)
	}
}

func TestWeakSignatureDetection(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	// Test weak signature algorithms
	weakAlgorithms := []x509.SignatureAlgorithm{
		x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
	}

	for _, alg := range weakAlgorithms {
		if !security.isWeakSignatureAlgorithm(alg) {
			t.Errorf("Expected %v to be detected as weak signature algorithm", alg)
		}
	}

	// Test strong signature algorithms
	strongAlgorithms := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}

	for _, alg := range strongAlgorithms {
		if security.isWeakSignatureAlgorithm(alg) {
			t.Errorf("Expected %v to not be detected as weak signature algorithm", alg)
		}
	}
}

func TestSecurityReport(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	tlsConfig := security.GetSecureTLSConfig()
	report := security.GetSecurityReport(tlsConfig)

	if report == nil {
		t.Fatal("Expected security report, got nil")
	}

	// Check required fields
	requiredFields := []string{
		"security_level",
		"min_tls_version",
		"max_tls_version",
		"cipher_suites",
		"curve_preferences",
		"session_tickets_disabled",
		"prefer_server_cipher_order",
		"hsts_enabled",
		"renegotiation_policy",
	}

	for _, field := range requiredFields {
		if _, exists := report[field]; !exists {
			t.Errorf("Expected field %s in security report", field)
		}
	}

	// Verify that recommendations are present
	if _, exists := report["recommendations"]; !exists {
		t.Error("Expected recommendations field in security report")
	}
}

func TestHSTSConfiguration(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	// Test HSTS enabling
	security.EnableHSTS(86400) // 24 hours
	if !security.hstsEnabled {
		t.Error("Expected HSTS to be enabled")
	}
	if security.hstsMaxAge != 86400 {
		t.Error("Expected HSTS max age to be set correctly")
	}

	// Test HSTS disabling
	security.DisableHSTS()
	if security.hstsEnabled {
		t.Error("Expected HSTS to be disabled")
	}
}

// Helper function to generate test certificates
func generateTestCertificateForSecurity(t *testing.T, commonName string, expiry time.Time) *x509.Certificate {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestCurvePreferences(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	tlsConfig := security.GetSecureTLSConfig()

	// Check that secure curves are preferred
	expectedCurves := []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	if len(tlsConfig.CurvePreferences) < len(expectedCurves) {
		t.Error("Expected at least 3 curve preferences")
	}

	// X25519 should be first (most preferred)
	if tlsConfig.CurvePreferences[0] != tls.X25519 {
		t.Error("Expected X25519 to be the most preferred curve")
	}
}

func TestSecurityLevelNames(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	tests := []struct {
		level SecurityLevel
		name  string
	}{
		{SecurityLevelMinimum, "Minimum"},
		{SecurityLevelRecommended, "Recommended"},
		{SecurityLevelStrict, "Strict"},
		{SecurityLevelMaximum, "Maximum"},
	}

	for _, tt := range tests {
		security.SetSecurityLevel(tt.level)
		name := security.getSecurityLevelName()
		if name != tt.name {
			t.Errorf("Expected security level name %s, got %s", tt.name, name)
		}
	}
}
