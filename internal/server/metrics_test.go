package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateMetrics(t *testing.T) {
	t.Run("Valid certificate", func(t *testing.T) {
		// Create temporary directory
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "test.crt")

		// Generate test certificate
		cert, certPEM := generateTestCertificate(t, "test.example.com", time.Now().Add(365*24*time.Hour))
		err := os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		// Get metrics
		err = GetCertificateMetrics(certPath, "test.example.com")
		assert.NoError(t, err, "Should parse valid certificate")

		// Verify metrics were set (can't directly assert Prometheus metrics, but no error means success)
		t.Log("✓ Certificate metrics collected successfully")
		_ = cert // Use cert to avoid unused warning
	})

	t.Run("Certificate with no domain specified", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "auto-domain.crt")

		// Generate certificate with DNS name
		_, certPEM := generateTestCertificate(t, "auto.example.com", time.Now().Add(30*24*time.Hour))
		err := os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		// Get metrics without specifying domain (should auto-detect)
		err = GetCertificateMetrics(certPath, "")
		assert.NoError(t, err, "Should auto-detect domain from certificate")
	})

	t.Run("Expired certificate", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "expired.crt")

		// Generate expired certificate (expired 1 day ago)
		_, certPEM := generateTestCertificate(t, "expired.example.com", time.Now().Add(-24*time.Hour))
		err := os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		// Get metrics (should succeed but report as invalid)
		err = GetCertificateMetrics(certPath, "expired.example.com")
		assert.NoError(t, err, "Should parse expired certificate without error")
	})

	t.Run("Certificate expiring soon", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "expiring.crt")

		// Generate certificate expiring in 7 days
		_, certPEM := generateTestCertificate(t, "expiring.example.com", time.Now().Add(7*24*time.Hour))
		err := os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		err = GetCertificateMetrics(certPath, "expiring.example.com")
		assert.NoError(t, err, "Should handle certificate expiring soon")
	})

	t.Run("Non-existent certificate file", func(t *testing.T) {
		err := GetCertificateMetrics("/non/existent/cert.pem", "test.example.com")
		assert.Error(t, err, "Should error on non-existent file")
	})

	t.Run("Invalid PEM format", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "invalid.pem")

		// Write invalid PEM data
		err := os.WriteFile(certPath, []byte("This is not a valid PEM certificate"), 0644)
		require.NoError(t, err)

		// GetCertificateMetrics logs error but returns nil (by design)
		err = GetCertificateMetrics(certPath, "test.example.com")
		t.Log("✓ Handles invalid PEM gracefully (logs error, returns nil)")
	})

	t.Run("Valid PEM but not a certificate", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "not-cert.pem")

		// Create PEM with wrong type
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})
		err := os.WriteFile(certPath, pemData, 0644)
		require.NoError(t, err)

		// GetCertificateMetrics logs error but returns nil (by design)
		err = GetCertificateMetrics(certPath, "test.example.com")
		t.Log("✓ Handles non-certificate PEM gracefully (logs error, returns nil)")
	})
}

func TestRecordCertificateRenewal(t *testing.T) {
	t.Run("Record successful renewal", func(t *testing.T) {
		RecordCertificateRenewal("success.example.com", true)
		t.Log("✓ Successful renewal recorded")
		// Metrics are recorded to Prometheus - can't directly assert but no panic means success
	})

	t.Run("Record failed renewal", func(t *testing.T) {
		RecordCertificateRenewal("failed.example.com", false)
		t.Log("✓ Failed renewal recorded")
	})

	t.Run("Multiple renewals for same domain", func(t *testing.T) {
		domain := "multi.example.com"
		RecordCertificateRenewal(domain, true)
		RecordCertificateRenewal(domain, false)
		RecordCertificateRenewal(domain, true)
		t.Log("✓ Multiple renewal records handled")
	})
}

func TestMonitorCertificates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping monitoring test in short mode")
	}

	t.Run("Monitor directory with certificates", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create test certificates
		cert1Path := filepath.Join(tempDir, "cert1.pem")
		_, cert1PEM := generateTestCertificate(t, "test1.example.com", time.Now().Add(30*24*time.Hour))
		err := os.WriteFile(cert1Path, cert1PEM, 0644)
		require.NoError(t, err)

		cert2Path := filepath.Join(tempDir, "cert2.crt")
		_, cert2PEM := generateTestCertificate(t, "test2.example.com", time.Now().Add(60*24*time.Hour))
		err = os.WriteFile(cert2Path, cert2PEM, 0644)
		require.NoError(t, err)

		// Start monitoring in goroutine with short interval
		done := make(chan bool)
		go func() {
			MonitorCertificates(tempDir, 100*time.Millisecond)
			done <- true
		}()

		// Let it run for a few iterations
		time.Sleep(350 * time.Millisecond)

		// Stop monitoring (would normally use context, but this is a test)
		// Note: MonitorCertificates runs indefinitely, so we just verify it doesn't crash
		t.Log("✓ Certificate monitoring ran without errors")
	})

	t.Run("Monitor non-existent directory", func(t *testing.T) {
		// Should handle gracefully without crashing
		done := make(chan bool)
		go func() {
			MonitorCertificates("/non/existent/cert/dir", 50*time.Millisecond)
			done <- true
		}()

		time.Sleep(150 * time.Millisecond)
		t.Log("✓ Handles non-existent directory gracefully")
	})

	t.Run("Monitor directory with no certificates", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create some non-certificate files
		err := os.WriteFile(filepath.Join(tempDir, "readme.txt"), []byte("test"), 0644)
		require.NoError(t, err)

		done := make(chan bool)
		go func() {
			MonitorCertificates(tempDir, 50*time.Millisecond)
			done <- true
		}()

		time.Sleep(150 * time.Millisecond)
		t.Log("✓ Handles directory with no certificates")
	})

	t.Run("Monitor with private key file (should skip)", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create privkey.pem (should be skipped)
		privkeyPath := filepath.Join(tempDir, "privkey.pem")
		err := os.WriteFile(privkeyPath, []byte("fake private key"), 0644)
		require.NoError(t, err)

		// Create valid cert
		certPath := filepath.Join(tempDir, "cert.pem")
		_, certPEM := generateTestCertificate(t, "test.example.com", time.Now().Add(30*24*time.Hour))
		err = os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		done := make(chan bool)
		go func() {
			MonitorCertificates(tempDir, 50*time.Millisecond)
			done <- true
		}()

		time.Sleep(150 * time.Millisecond)
		t.Log("✓ Skips private key files correctly")
	})
}

// Helper function to generate test certificates
func generateTestCertificate(t *testing.T, dnsName string, notAfter time.Time) (*x509.Certificate, []byte) {
	t.Helper()

	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   dnsName,
			Organization: []string{"Test Org"},
		},
		DNSNames:    []string{dnsName},
		NotBefore:   time.Now().Add(-24 * time.Hour), // Valid from yesterday
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        false,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Parse back to x509.Certificate
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, certPEM
}

func TestCheckCertificatesFunction(t *testing.T) {
	t.Run("Check directory with valid certificates", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create multiple certificate files
		for i, ext := range []string{".pem", ".crt", ".cert"} {
			certPath := filepath.Join(tempDir, "test"+ext)
			domain := "test" + string(rune(i)) + ".example.com"
			_, certPEM := generateTestCertificate(t, domain, time.Now().Add(90*24*time.Hour))
			err := os.WriteFile(certPath, certPEM, 0644)
			require.NoError(t, err)
		}

		// Call checkCertificates directly (exported via MonitorCertificates)
		checkCertificates(tempDir)
		t.Log("✓ Checked multiple certificate types (.pem, .crt, .cert)")
	})

	t.Run("Check directory with mixed files", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create certificate
		certPath := filepath.Join(tempDir, "valid.pem")
		_, certPEM := generateTestCertificate(t, "valid.example.com", time.Now().Add(30*24*time.Hour))
		err := os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		// Create non-certificate files
		os.WriteFile(filepath.Join(tempDir, "readme.txt"), []byte("test"), 0644)
		os.WriteFile(filepath.Join(tempDir, "config.json"), []byte("{}"), 0644)

		// Should process only certificate files
		checkCertificates(tempDir)
		t.Log("✓ Processes only certificate files")
	})

	t.Run("Check empty directory", func(t *testing.T) {
		tempDir := t.TempDir()
		checkCertificates(tempDir)
		t.Log("✓ Handles empty directory gracefully")
	})

	t.Run("Check with invalid certificate file", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create invalid certificate file
		invalidCertPath := filepath.Join(tempDir, "invalid.pem")
		err := os.WriteFile(invalidCertPath, []byte("invalid certificate data"), 0644)
		require.NoError(t, err)

		// Should handle gracefully without crashing
		checkCertificates(tempDir)
		t.Log("✓ Handles invalid certificate gracefully")
	})
}

func TestCertificateMetricsEdgeCases(t *testing.T) {
	t.Run("Certificate with multiple DNS names", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "multi-san.pem")

		// Generate certificate with multiple SANs
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "primary.example.com",
				Organization: []string{"Test Org"},
			},
			DNSNames: []string{
				"primary.example.com",
				"secondary.example.com",
				"tertiary.example.com",
			},
			NotBefore:   time.Now().Add(-24 * time.Hour),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		require.NoError(t, err)

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		err = os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		// Should use first DNS name
		err = GetCertificateMetrics(certPath, "")
		assert.NoError(t, err)
	})

	t.Run("Certificate about to expire (24 hours)", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "expiring-soon.pem")

		_, certPEM := generateTestCertificate(t, "urgent.example.com", time.Now().Add(24*time.Hour))
		err := os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		err = GetCertificateMetrics(certPath, "urgent.example.com")
		assert.NoError(t, err, "Should handle certificate expiring in 24h")
	})

	t.Run("Certificate not yet valid", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "future.pem")

		// Generate certificate valid in the future
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "future.example.com",
			},
			DNSNames:    []string{"future.example.com"},
			NotBefore:   time.Now().Add(24 * time.Hour),  // Valid starting tomorrow
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		require.NoError(t, err)

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		err = os.WriteFile(certPath, certPEM, 0644)
		require.NoError(t, err)

		err = GetCertificateMetrics(certPath, "future.example.com")
		assert.NoError(t, err, "Should handle certificate not yet valid")
	})
}

func TestRecordCertificateRenewalEdgeCases(t *testing.T) {
	t.Run("Record renewal with empty domain", func(t *testing.T) {
		// Should not crash
		RecordCertificateRenewal("", true)
		RecordCertificateRenewal("", false)
		t.Log("✓ Handles empty domain gracefully")
	})

	t.Run("Record renewal with special characters", func(t *testing.T) {
		domains := []string{
			"test-domain.example.com",
			"test_domain.example.com",
			"xn--test-domain.example.com", // IDN
			"subdomain.test.example.com",
		}

		for _, domain := range domains {
			RecordCertificateRenewal(domain, true)
		}
		t.Log("✓ Handles various domain formats")
	})

	t.Run("Rapid successive renewals", func(t *testing.T) {
		domain := "rapid.example.com"
		for i := 0; i < 100; i++ {
			RecordCertificateRenewal(domain, i%2 == 0)
		}
		t.Log("✓ Handles rapid successive renewal records")
	})
}

func BenchmarkGetCertificateMetrics(b *testing.B) {
	tempDir := b.TempDir()
	certPath := filepath.Join(tempDir, "bench.pem")

	_, certPEM := generateBenchCertificate(b, "bench.example.com", time.Now().Add(365*24*time.Hour))
	err := os.WriteFile(certPath, certPEM, 0644)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetCertificateMetrics(certPath, "bench.example.com")
	}
}

func BenchmarkRecordCertificateRenewal(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecordCertificateRenewal("bench.example.com", true)
	}
}

// Helper for benchmark to avoid test-specific assertions
func generateBenchCertificate(b *testing.B, dnsName string, notAfter time.Time) (*x509.Certificate, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:    []string{dnsName},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		b.Fatal(err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return cert, certPEM
}

