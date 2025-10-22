package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"testing"
)

func TestParseCipherSuitesSecurity(t *testing.T) {
	tests := []struct {
		name          string
		ciphers       []string
		expectError   bool
		expectedCount int
		errorContains string
	}{
		{
			name:          "Secure AEAD ciphers should be allowed",
			ciphers:       []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name:          "ChaCha20 ciphers should be allowed",
			ciphers:       []string{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name:          "Secure CBC ciphers should be allowed",
			ciphers:       []string{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name:          "RC4 ciphers should be blocked",
			ciphers:       []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
			expectError:   true,
			errorContains: "weak cipher suites blocked for security",
		},
		{
			name:          "3DES ciphers should be blocked",
			ciphers:       []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
			expectError:   true,
			errorContains: "weak cipher suites blocked for security",
		},
		{
			name:          "Mixed secure and weak ciphers should block weak ones",
			ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_RC4_128_SHA"},
			expectError:   true,
			errorContains: "weak cipher suites blocked for security",
		},
		{
			name:          "Invalid cipher names should be rejected",
			ciphers:       []string{"TLS_INVALID_CIPHER", "TLS_FAKE_CIPHER"},
			expectError:   true,
			errorContains: "invalid cipher suites",
		},
		{
			name:          "Empty cipher list should be allowed",
			ciphers:       []string{},
			expectError:   false,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipherSuites, err := parseCipherSuites(tt.ciphers)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %s", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
					return
				}
				if len(cipherSuites) != tt.expectedCount {
					t.Errorf("Expected %d cipher suites, got %d", tt.expectedCount, len(cipherSuites))
				}
			}
		})
	}
}

func TestTLSManagerSecurityHardening(t *testing.T) {
	// Test TLS security module directly without certificate loading
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	// Test that security hardening is applied
	tlsConfig := security.GetSecureTLSConfig()
	if tlsConfig == nil {
		t.Fatal("Expected TLS config, got nil")
	}

	// Verify minimum TLS version is 1.2
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("Expected minimum TLS version to be at least 1.2, got: %d", tlsConfig.MinVersion)
	}

	// Verify server cipher suite preference is enabled
	if !tlsConfig.PreferServerCipherSuites {
		t.Error("Expected server cipher suite preference to be enabled")
	}

	// Verify session tickets are disabled for PFS
	if !tlsConfig.SessionTicketsDisabled {
		t.Error("Expected session tickets to be disabled for perfect forward secrecy")
	}

	// Verify renegotiation is disabled
	if tlsConfig.Renegotiation != tls.RenegotiateNever {
		t.Error("Expected renegotiation to be disabled")
	}

	// Verify secure curve preferences
	expectedCurves := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	if len(tlsConfig.CurvePreferences) < len(expectedCurves) {
		t.Errorf("Expected at least %d curve preferences, got %d", len(expectedCurves), len(tlsConfig.CurvePreferences))
	}

	// Verify X25519 is the most preferred curve
	if tlsConfig.CurvePreferences[0] != tls.X25519 {
		t.Errorf("Expected X25519 to be the most preferred curve, got: %d", tlsConfig.CurvePreferences[0])
	}

	// Verify cipher suites are secure (no weak ciphers)
	for _, cipher := range tlsConfig.CipherSuites {
		if isWeakCipherSuite(cipher) {
			t.Errorf("Found weak cipher suite in configuration: %d", cipher)
		}
	}

	// Test setting to maximum security
	security.SetSecurityLevel(SecurityLevelMaximum)
	maxConfig := security.GetSecureTLSConfig()
	if maxConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected TLS 1.3 for maximum security, got: %d", maxConfig.MinVersion)
	}
}

func TestTLSSecurityLevels(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	levels := []struct {
		level           SecurityLevel
		expectedMinVer  uint16
		expectedMaxVer  uint16
		expectedCiphers int
	}{
		{SecurityLevelMinimum, tls.VersionTLS12, tls.VersionTLS13, 10},    // Includes CBC for compatibility
		{SecurityLevelRecommended, tls.VersionTLS12, tls.VersionTLS13, 6}, // AEAD only
		{SecurityLevelStrict, tls.VersionTLS12, tls.VersionTLS13, 4},      // ECDSA and ChaCha20 only
		{SecurityLevelMaximum, tls.VersionTLS13, tls.VersionTLS13, 0},     // TLS 1.3 handles ciphers
	}

	for _, level := range levels {
		t.Run(security.getSecurityLevelName(), func(t *testing.T) {
			security.SetSecurityLevel(level.level)
			tlsConfig := security.GetSecureTLSConfig()

			if tlsConfig.MinVersion != level.expectedMinVer {
				t.Errorf("Expected min version %d, got %d", level.expectedMinVer, tlsConfig.MinVersion)
			}

			if tlsConfig.MaxVersion != level.expectedMaxVer {
				t.Errorf("Expected max version %d, got %d", level.expectedMaxVer, tlsConfig.MaxVersion)
			}

			if level.expectedCiphers > 0 && len(tlsConfig.CipherSuites) != level.expectedCiphers {
				t.Errorf("Expected %d cipher suites, got %d", level.expectedCiphers, len(tlsConfig.CipherSuites))
			}

			// Verify all cipher suites are secure
			for _, cipher := range tlsConfig.CipherSuites {
				if isWeakCipherSuite(cipher) {
					t.Errorf("Found weak cipher suite: %d", cipher)
				}
			}
		})
	}
}

func TestCertificateValidationSecurity(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	// Test certificate validator creation
	validator := security.createCertificateValidator()
	if validator == nil {
		t.Fatal("Expected certificate validator, got nil")
	}

	// Test with empty certificates
	err := validator([][]byte{}, [][]*x509.Certificate{})
	if err == nil {
		t.Error("Expected error for empty certificates")
	}

	// Test with invalid certificate
	invalidCert := []byte("invalid certificate data")
	err = validator([][]byte{invalidCert}, [][]*x509.Certificate{})
	if err == nil {
		t.Error("Expected error for invalid certificate")
	}
}

func TestSMTPSTSSecurity(t *testing.T) {
	config := &TLSConfig{Enabled: true}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	security := NewTLSSecurity(config, logger)

	// Test SMTP STS policy
	policy := security.GetSMTPSTSPolicy()
	if policy == nil {
		t.Fatal("Expected SMTP STS policy, got nil")
	}

	if policy.Mode != "enforce" {
		t.Errorf("Expected enforce mode, got: %s", policy.Mode)
	}

	// Test SMTP STS compliance validation
	tests := []struct {
		name      string
		hostname  string
		tlsUsed   bool
		expectErr bool
	}{
		{"Valid TLS connection", "mail.example.com", true, false},
		{"TLS required but not used", "mail.example.com", false, true},
		{"Hostname not in MX matches", "external.com", true, false}, // Should warn but not error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := security.ValidateSMTPSTSCompliance(tt.hostname, tt.tlsUsed)
			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			contains(s[1:], substr))))
}

func isWeakCipherSuite(cipher uint16) bool {
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}

	for _, weak := range weakCiphers {
		if cipher == weak {
			return true
		}
	}
	return false
}

func createTestCertificates(t *testing.T) (string, string) {
	// Create temporary files for test certificates
	certFile, err := os.CreateTemp("", "test-*.crt")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", "test-*.key")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	keyFile.Close()

	// Use the existing test certificates from the config directory
	// Copy the test certificates to our temp files
	testCertPath := "../../config/test.crt"
	testKeyPath := "../../config/test.key"

	// Check if test certificates exist
	if _, err := os.Stat(testCertPath); err == nil {
		certData, err := os.ReadFile(testCertPath)
		if err != nil {
			t.Fatalf("Failed to read test cert: %v", err)
		}
		if err := os.WriteFile(certFile.Name(), certData, 0600); err != nil {
			t.Fatalf("Failed to write test cert: %v", err)
		}
	} else {
		// Create minimal valid certificate data for testing
		certData := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDQ5X5X5X5X5TAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxDTALBgNVBAoMBFRl
c3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBEMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxDTALBgNVBAoM
BFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATest
-----END CERTIFICATE-----`
		if err := os.WriteFile(certFile.Name(), []byte(certData), 0600); err != nil {
			t.Fatalf("Failed to write test cert: %v", err)
		}
	}

	if _, err := os.Stat(testKeyPath); err == nil {
		keyData, err := os.ReadFile(testKeyPath)
		if err != nil {
			t.Fatalf("Failed to read test key: %v", err)
		}
		if err := os.WriteFile(keyFile.Name(), keyData, 0600); err != nil {
			t.Fatalf("Failed to write test key: %v", err)
		}
	} else {
		// Create minimal valid key data for testing
		keyData := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtest
-----END PRIVATE KEY-----`
		if err := os.WriteFile(keyFile.Name(), []byte(keyData), 0600); err != nil {
			t.Fatalf("Failed to write test key: %v", err)
		}
	}

	return certFile.Name(), keyFile.Name()
}
