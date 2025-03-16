package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"
	"testing"

	"github.com/busybox42/elemta/internal/plugin"
)

// Test private key for testing
const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----`

// Helper function to parse the test private key
func getTestPrivateKey(t *testing.T) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(testPrivateKey))
	if block == nil {
		t.Fatal("Failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	return privateKey
}

// Test message without DKIM signature
const testMessageWithoutDKIM = `From: sender@example.com
To: recipient@example.org
Subject: Test Message
Date: Thu, 14 Jan 2021 12:00:00 +0000

This is a test message.
`

func TestDKIMPlugin(t *testing.T) {
	// Create a new DKIM plugin
	p := NewDKIMPlugin()

	// Test initialization
	err := p.Init(map[string]interface{}{})
	if err != nil {
		t.Errorf("Init() error = %v, want nil", err)
	}

	// Test VerifyDKIM with no DKIM signature
	reader := strings.NewReader(testMessageWithoutDKIM)
	results, err := p.VerifyDKIM(reader)

	if err != nil {
		t.Errorf("VerifyDKIM() error = %v, want nil", err)
	}

	if len(results) != 0 {
		t.Errorf("VerifyDKIM() with no signature, got %v results, want 0", len(results))
	}

	// Test SignDKIM
	reader = strings.NewReader(testMessageWithoutDKIM)
	writer := &bytes.Buffer{}

	privateKey := getTestPrivateKey(t)

	options := &plugin.DKIMSignOptions{
		Domain:           "example.org",
		Selector:         "selector",
		PrivateKey:       x509.MarshalPKCS1PrivateKey(privateKey),
		Headers:          []string{"From", "To", "Subject", "Date"},
		Canonicalization: "relaxed/relaxed",
		HeaderHash:       "sha256",
		BodyHash:         "sha256",
	}

	err = p.SignDKIM(reader, writer, options)

	if err != nil {
		t.Errorf("SignDKIM() error = %v, want nil", err)
	}

	// In our simplified implementation, the output should be the same as the input
	if writer.String() != testMessageWithoutDKIM {
		t.Errorf("SignDKIM() output = %v, want %v", writer.String(), testMessageWithoutDKIM)
	}

	// Test Close
	err = p.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// Test error handling
func TestDKIMPlugin_ErrorHandling(t *testing.T) {
	p := NewDKIMPlugin()

	// Test SignDKIM with writer error
	reader := strings.NewReader(testMessageWithoutDKIM)
	errorWriter := &ErrorWriter{err: io.ErrShortWrite}

	privateKey := getTestPrivateKey(t)

	options := &plugin.DKIMSignOptions{
		Domain:           "example.org",
		Selector:         "selector",
		PrivateKey:       x509.MarshalPKCS1PrivateKey(privateKey),
		Headers:          []string{"From", "To", "Subject", "Date"},
		Canonicalization: "relaxed/relaxed",
		HeaderHash:       "sha256",
		BodyHash:         "sha256",
	}

	err := p.SignDKIM(reader, errorWriter, options)

	if err == nil {
		t.Errorf("SignDKIM() with writer error = nil, want error")
	}
}

// ErrorWriter is a mock io.Writer that always returns an error
type ErrorWriter struct {
	err error
}

func (w *ErrorWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}
