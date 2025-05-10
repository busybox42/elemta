package smtp

import (
	"context"
	"os"
	"testing"

	"github.com/busybox42/elemta/internal/datasource"
)

// TestSMTPAuthenticator tests the SMTP authenticator
func TestSMTPAuthenticator(t *testing.T) {
	// Create a temporary SQLite database for testing
	tempFile, err := os.CreateTemp("", "elemta-auth-test.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	// Create a test config
	config := &AuthConfig{
		Enabled:        true,
		Required:       true,
		DataSourceType: "sqlite",
		DataSourceName: "sqlite",
		DataSourcePath: tempFile.Name(),
	}

	// Create an authenticator
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create a test user
	ds := auth.dataSource
	user := datasource.User{
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
		FullName: "Test User",
		IsActive: true,
	}
	if err := ds.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test authentication
	t.Run("ValidCredentials", func(t *testing.T) {
		authenticated, err := auth.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("Authentication failed with error: %v", err)
		}
		if !authenticated {
			t.Errorf("Expected authentication to succeed, but it failed")
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		authenticated, err := auth.Authenticate(context.Background(), "testuser", "wrongpass")
		if err != nil {
			t.Fatalf("Authentication failed with error: %v", err)
		}
		if authenticated {
			t.Errorf("Expected authentication to fail, but it succeeded")
		}
	})

	t.Run("NonexistentUser", func(t *testing.T) {
		authenticated, err := auth.Authenticate(context.Background(), "nonexistent", "testpass")
		if err == nil {
			if authenticated {
				t.Errorf("Expected authentication to fail, but it succeeded")
			}
		}
	})

	t.Run("IsEnabled", func(t *testing.T) {
		if !auth.IsEnabled() {
			t.Errorf("Expected IsEnabled to return true, but got false")
		}
	})

	t.Run("IsRequired", func(t *testing.T) {
		if !auth.IsRequired() {
			t.Errorf("Expected IsRequired to return true, but got false")
		}
	})

	t.Run("GetSupportedMethods", func(t *testing.T) {
		methods := auth.GetSupportedMethods()
		if len(methods) == 0 {
			t.Errorf("Expected GetSupportedMethods to return at least one method")
		}
		hasPlain := false
		hasLogin := false
		for _, method := range methods {
			if method == AuthMethodPlain {
				hasPlain = true
			}
			if method == AuthMethodLogin {
				hasLogin = true
			}
		}
		if !hasPlain {
			t.Errorf("Expected PLAIN authentication method to be supported")
		}
		if !hasLogin {
			t.Errorf("Expected LOGIN authentication method to be supported")
		}
	})
}

// TestSMTPAuthenticatorDisabled tests the SMTP authenticator when disabled
func TestSMTPAuthenticatorDisabled(t *testing.T) {
	// Create a test config with authentication disabled
	config := &AuthConfig{
		Enabled:  false,
		Required: false,
	}

	// Create an authenticator
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Test authentication when disabled
	t.Run("AuthenticationDisabled", func(t *testing.T) {
		authenticated, err := auth.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("Authentication failed with error: %v", err)
		}
		if !authenticated {
			t.Errorf("Expected authentication to succeed when disabled, but it failed")
		}
	})

	t.Run("IsEnabled", func(t *testing.T) {
		if auth.IsEnabled() {
			t.Errorf("Expected IsEnabled to return false, but got true")
		}
	})

	t.Run("IsRequired", func(t *testing.T) {
		if auth.IsRequired() {
			t.Errorf("Expected IsRequired to return false, but got true")
		}
	})
}
