package plugin

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"
	"testing"
)

// Mock implementation of ARCPlugin for testing
type mockARCPlugin struct {
	ARCPluginBase
	verifyResult *ARCVerifyResult
	verifyError  error
	signError    error
}

func newMockARCPlugin() *mockARCPlugin {
	info := &PluginInfo{
		Name:        "mock-arc",
		Description: "Mock ARC plugin for testing",
		Version:     "1.0.0",
		Type:        PluginTypeARC,
		Author:      "Test Author",
	}
	return &mockARCPlugin{
		ARCPluginBase: *NewARCPluginBase(info),
	}
}

func (p *mockARCPlugin) VerifyARC(reader io.Reader) (*ARCVerifyResult, error) {
	return p.verifyResult, p.verifyError
}

func (p *mockARCPlugin) SignARC(reader io.Reader, writer io.Writer, options *ARCSignOptions) error {
	if p.signError != nil {
		return p.signError
	}

	// For testing, just copy the input to output
	if _, err := io.Copy(writer, reader); err != nil {
		return err
	}

	return nil
}

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

// Test message with ARC headers
const testMessageWithARC = `Authentication-Results: example.org; dkim=pass header.d=example.com
ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; d=example.org; s=selector;
 b=dOdFEyhrk/tw5wl3vMIogoxhaVsKJkrkEhnAcq2XqOLSQhPpGzhGBJzR7k1sWGokon3TmQ
 7TX9zQLO6ikRpwd/pUswiRW5DBupy58fefuclXJAhErsrebfvfiueGyhHXV7C1LyJTztywzn
 QGG4SCciU/FTlsJ0QANrnLRoadfps=
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
 d=example.org; s=selector; t=12345;
 h=from:to:subject:date;
 bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=;
 b=LcEi/UiFsP6YuN9UOE9HMGMljY8xc2OOHzz3V0rX7zTxFBPeOTu3HpUxvYYvx2HhgCvV2C
 kQQQfeOEpLFpbVdKfQHcDAT5QnVZD7UWKm5X6HhSlj3tEJ6r0WtmqTk3y0gTX5Vc1kM0rYYn
 U3ta5OjYmRJMYNkAmewBLk4h0zdQ0=
ARC-Authentication-Results: i=1; example.org; dkim=pass header.d=example.com

From: sender@example.com
To: recipient@example.org
Subject: Test Message
Date: Thu, 14 Jan 2021 12:00:00 +0000

This is a test message.
`

// Test message without ARC headers
const testMessageWithoutARC = `From: sender@example.com
To: recipient@example.org
Subject: Test Message
Date: Thu, 14 Jan 2021 12:00:00 +0000

This is a test message.
`

func TestARCPluginBase(t *testing.T) {
	info := &PluginInfo{
		Name:        "test-arc",
		Description: "Test ARC plugin",
		Version:     "1.0.0",
		Type:        PluginTypeARC,
		Author:      "Test Author",
	}

	plugin := NewARCPluginBase(info)

	// Test GetInfo
	gotInfo := plugin.GetInfo()
	if gotInfo.Name != info.Name {
		t.Errorf("GetInfo().Name = %v, want %v", gotInfo.Name, info.Name)
	}

	// Test Init
	if err := plugin.Init(nil); err != nil {
		t.Errorf("Init() error = %v, want nil", err)
	}

	// Test Close
	if err := plugin.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestMockARCPlugin_VerifyARC(t *testing.T) {
	plugin := newMockARCPlugin()

	// Test successful verification
	expectedResult := &ARCVerifyResult{
		Result:        ARCPass,
		InstanceCount: 1,
		OldestDomain:  "example.org",
		LatestDomain:  "example.org",
		Reason:        "Valid ARC chain",
	}

	plugin.verifyResult = expectedResult

	reader := strings.NewReader(testMessageWithARC)
	result, err := plugin.VerifyARC(reader)

	if err != nil {
		t.Errorf("VerifyARC() error = %v, want nil", err)
	}

	if result.Result != expectedResult.Result {
		t.Errorf("VerifyARC().Result = %v, want %v", result.Result, expectedResult.Result)
	}

	// Test error case
	expectedError := io.EOF
	plugin.verifyError = expectedError

	reader = strings.NewReader(testMessageWithARC)
	_, err = plugin.VerifyARC(reader)

	if err != expectedError {
		t.Errorf("VerifyARC() error = %v, want %v", err, expectedError)
	}
}

func TestMockARCPlugin_SignARC(t *testing.T) {
	plugin := newMockARCPlugin()

	// Test successful signing
	reader := strings.NewReader(testMessageWithoutARC)
	writer := &bytes.Buffer{}

	options := &ARCSignOptions{
		Domain:           "example.org",
		Selector:         "selector",
		PrivateKey:       x509.MarshalPKCS1PrivateKey(getTestPrivateKey(t)),
		Headers:          []string{"From", "To", "Subject", "Date"},
		Canonicalization: "relaxed/relaxed",
		HeaderHash:       "sha256",
		BodyHash:         "sha256",
		AuthResults:      "example.org; dkim=pass header.d=example.com",
		ChainValidation:  ARCNone,
	}

	err := plugin.SignARC(reader, writer, options)

	if err != nil {
		t.Errorf("SignARC() error = %v, want nil", err)
	}

	// In our mock implementation, the output should be the same as the input
	if writer.String() != testMessageWithoutARC {
		t.Errorf("SignARC() output = %v, want %v", writer.String(), testMessageWithoutARC)
	}

	// Test error case
	expectedError := io.EOF
	plugin.signError = expectedError

	reader = strings.NewReader(testMessageWithoutARC)
	writer = &bytes.Buffer{}

	err = plugin.SignARC(reader, writer, options)

	if err != expectedError {
		t.Errorf("SignARC() error = %v, want %v", err, expectedError)
	}
}
