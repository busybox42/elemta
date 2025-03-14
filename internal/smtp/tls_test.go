package smtp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSManager(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := ioutil.TempDir("", "elemta-tls-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate self-signed test certificate
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test cases
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name: "TLS disabled",
			config: &Config{
				TLS: &TLSConfig{
					Enabled: false,
				},
			},
			wantError: false,
		},
		{
			name: "TLS enabled with valid certificate",
			config: &Config{
				TLS: &TLSConfig{
					Enabled:  true,
					CertFile: certPath,
					KeyFile:  keyPath,
				},
			},
			wantError: false,
		},
		{
			name: "TLS enabled with invalid certificate path",
			config: &Config{
				TLS: &TLSConfig{
					Enabled:  true,
					CertFile: "nonexistent.crt",
					KeyFile:  "nonexistent.key",
				},
			},
			wantError: true,
		},
		{
			name: "TLS enabled without certificate",
			config: &Config{
				TLS: &TLSConfig{
					Enabled: true,
				},
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager, err := NewTLSManager(tc.config)

			if tc.wantError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to create TLS manager: %v", err)
			}

			// If TLS is enabled, verify the TLS config was created
			if tc.config.TLS.Enabled {
				if manager.tlsConfig == nil {
					t.Errorf("TLS config is nil but TLS is enabled")
				}
			} else {
				if manager.tlsConfig != nil {
					t.Errorf("TLS config is not nil but TLS is disabled")
				}
			}
		})
	}
}

func TestTLSWrapConnection(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := ioutil.TempDir("", "elemta-tls-wrap-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate self-signed test certificate
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create TLS manager with valid config
	config := &Config{
		TLS: &TLSConfig{
			Enabled:  true,
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}

	manager, err := NewTLSManager(config)
	if err != nil {
		t.Fatalf("Failed to create TLS manager: %v", err)
	}

	// Create a mock connection
	conn := newMockConn()

	// Test WrapConnection with mock connection
	_, err = manager.WrapConnection(conn)
	// This should fail because the mock connection doesn't support TLS handshake
	if err == nil {
		t.Errorf("Expected error when wrapping mock connection, got nil")
	}
}

// Helper function to generate a self-signed certificate for testing
func generateTestCertificate(certPath, keyPath string) error {
	// Generate a new certificate
	cert, key, err := generateSelfSignedCert("localhost")
	if err != nil {
		return err
	}

	// Write certificate to file
	if err := ioutil.WriteFile(certPath, cert, 0644); err != nil {
		return err
	}

	// Write key to file
	if err := ioutil.WriteFile(keyPath, key, 0600); err != nil {
		return err
	}

	return nil
}

// generateSelfSignedCert creates a self-signed certificate for testing
func generateSelfSignedCert(host string) ([]byte, []byte, error) {
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template, err := generateCertTemplate(host)
	if err != nil {
		return nil, nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// PEM encode the private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certPEM, keyPEM, nil
}

// generateCertTemplate creates a certificate template for testing
func generateCertTemplate(host string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Elemta Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	return &template, nil
}
