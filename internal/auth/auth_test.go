package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/busybox42/elemta/internal/datasource"
	"golang.org/x/crypto/bcrypt"
)

// MockLDAP is a mock implementation of the DataSource interface for testing LDAP functionality
type MockLDAP struct {
	users map[string]datasource.User
}

func NewMockLDAP() *MockLDAP {
	return &MockLDAP{
		users: make(map[string]datasource.User),
	}
}

func (m *MockLDAP) Connect() error {
	return nil
}

func (m *MockLDAP) Close() error {
	return nil
}

func (m *MockLDAP) IsConnected() bool {
	return true
}

func (m *MockLDAP) Name() string {
	return "mock-ldap"
}

func (m *MockLDAP) Type() string {
	return "ldap"
}

func (m *MockLDAP) Authenticate(ctx context.Context, username, password string) (bool, error) {
	user, exists := m.users[username]
	if !exists {
		return false, datasource.ErrNotFound
	}

	// In a real LDAP server, this would do a bind operation
	// For our mock, we'll just compare the passwords directly
	return user.Password == password, nil
}

func (m *MockLDAP) GetUser(ctx context.Context, username string) (datasource.User, error) {
	user, exists := m.users[username]
	if !exists {
		return datasource.User{}, datasource.ErrNotFound
	}
	return user, nil
}

func (m *MockLDAP) CreateUser(ctx context.Context, user datasource.User) error {
	if _, exists := m.users[user.Username]; exists {
		return datasource.ErrAlreadyExists
	}
	m.users[user.Username] = user
	return nil
}

func (m *MockLDAP) UpdateUser(ctx context.Context, user datasource.User) error {
	if _, exists := m.users[user.Username]; !exists {
		return datasource.ErrNotFound
	}
	m.users[user.Username] = user
	return nil
}

func (m *MockLDAP) DeleteUser(ctx context.Context, username string) error {
	if _, exists := m.users[username]; !exists {
		return datasource.ErrNotFound
	}
	delete(m.users, username)
	return nil
}

func (m *MockLDAP) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]datasource.User, error) {
	// Simplified implementation for testing
	users := make([]datasource.User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *MockLDAP) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	return nil, nil
}

func TestAuth(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir, err := os.MkdirTemp("", "elemta-auth-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "auth-test.db")

	// Create a new Auth instance with SQLite datasource
	auth, err := NewWithSQLite(dbPath)
	if err != nil {
		t.Fatalf("Failed to create Auth instance: %v", err)
	}
	defer auth.Close()

	ctx := context.Background()

	// Test user creation
	t.Run("CreateUser", func(t *testing.T) {
		err := auth.CreateUser(ctx, "testuser", "password123", "test@example.com", "Test User", false)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Try to create the same user again, should fail
		err = auth.CreateUser(ctx, "testuser", "password123", "test@example.com", "Test User", false)
		if err == nil {
			t.Fatal("Expected error when creating duplicate user, got nil")
		}
		if err != ErrUserExists {
			t.Fatalf("Expected ErrUserExists, got: %v", err)
		}
	})

	// Test user existence check
	t.Run("UserExists", func(t *testing.T) {
		// Check existing user
		exists, err := auth.UserExists(ctx, "testuser")
		if err != nil {
			t.Fatalf("Failed to check if user exists: %v", err)
		}
		if !exists {
			t.Fatal("Expected user to exist, but it doesn't")
		}

		// Check non-existent user
		exists, err = auth.UserExists(ctx, "nonexistentuser")
		if err != nil {
			t.Fatalf("Failed to check if user exists: %v", err)
		}
		if exists {
			t.Fatal("Expected user not to exist, but it does")
		}
	})

	// Test user authentication
	t.Run("Authenticate", func(t *testing.T) {
		// Test with correct credentials
		authenticated, err := auth.Authenticate(ctx, "testuser", "password123")
		if err != nil {
			t.Fatalf("Authentication failed with error: %v", err)
		}
		if !authenticated {
			t.Fatal("Expected authentication to succeed, but it failed")
		}

		// Test with incorrect password
		authenticated, err = auth.Authenticate(ctx, "testuser", "wrongpassword")
		if err == nil {
			t.Fatal("Expected error with incorrect password, got nil")
		}
		if authenticated {
			t.Fatal("Expected authentication to fail, but it succeeded")
		}
		if err != ErrInvalidCredentials {
			t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
		}

		// Test with non-existent user
		authenticated, err = auth.Authenticate(ctx, "nonexistentuser", "password123")
		if err == nil {
			t.Fatal("Expected error with non-existent user, got nil")
		}
		if authenticated {
			t.Fatal("Expected authentication to fail, but it succeeded")
		}
		if err != ErrUserNotFound {
			t.Fatalf("Expected ErrUserNotFound, got: %v", err)
		}
	})

	// Test password update
	t.Run("UpdatePassword", func(t *testing.T) {
		// Update password with correct current password
		err := auth.UpdatePassword(ctx, "testuser", "password123", "newpassword123")
		if err != nil {
			t.Fatalf("Failed to update password: %v", err)
		}

		// Try to authenticate with old password, should fail
		authenticated, err := auth.Authenticate(ctx, "testuser", "password123")
		if err == nil {
			t.Fatal("Expected error with old password, got nil")
		}
		if authenticated {
			t.Fatal("Expected authentication with old password to fail, but it succeeded")
		}

		// Try to authenticate with new password, should succeed
		authenticated, err = auth.Authenticate(ctx, "testuser", "newpassword123")
		if err != nil {
			t.Fatalf("Authentication with new password failed with error: %v", err)
		}
		if !authenticated {
			t.Fatal("Expected authentication with new password to succeed, but it failed")
		}

		// Try to update password with incorrect current password
		err = auth.UpdatePassword(ctx, "testuser", "wrongpassword", "anotherpassword")
		if err == nil {
			t.Fatal("Expected error when updating with incorrect current password, got nil")
		}
		if err != ErrInvalidCredentials {
			t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
		}
	})

	// Test admin password update
	t.Run("AdminUpdatePassword", func(t *testing.T) {
		// Update password as admin
		err := auth.AdminUpdatePassword(ctx, "testuser", "adminsetpassword")
		if err != nil {
			t.Fatalf("Failed to update password as admin: %v", err)
		}

		// Try to authenticate with new password, should succeed
		authenticated, err := auth.Authenticate(ctx, "testuser", "adminsetpassword")
		if err != nil {
			t.Fatalf("Authentication with admin-set password failed with error: %v", err)
		}
		if !authenticated {
			t.Fatal("Expected authentication with admin-set password to succeed, but it failed")
		}

		// Try to update password for non-existent user
		err = auth.AdminUpdatePassword(ctx, "nonexistentuser", "newpassword")
		if err == nil {
			t.Fatal("Expected error when updating password for non-existent user, got nil")
		}
		if err != ErrUserNotFound {
			t.Fatalf("Expected ErrUserNotFound, got: %v", err)
		}
	})

	// Test get user
	t.Run("GetUser", func(t *testing.T) {
		// Get existing user
		user, err := auth.GetUser(ctx, "testuser")
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}
		if user.Username != "testuser" {
			t.Fatalf("Expected username 'testuser', got: %s", user.Username)
		}
		if user.Email != "test@example.com" {
			t.Fatalf("Expected email 'test@example.com', got: %s", user.Email)
		}
		if user.FullName != "Test User" {
			t.Fatalf("Expected full name 'Test User', got: %s", user.FullName)
		}
		if !user.IsActive {
			t.Fatal("Expected user to be active")
		}
		if user.IsAdmin {
			t.Fatal("Expected user not to be admin")
		}

		// Get non-existent user
		_, err = auth.GetUser(ctx, "nonexistentuser")
		if err == nil {
			t.Fatal("Expected error when getting non-existent user, got nil")
		}
		if err != ErrUserNotFound {
			t.Fatalf("Expected ErrUserNotFound, got: %v", err)
		}
	})

	// Test user deletion
	t.Run("DeleteUser", func(t *testing.T) {
		// Delete existing user
		err := auth.DeleteUser(ctx, "testuser")
		if err != nil {
			t.Fatalf("Failed to delete user: %v", err)
		}

		// Check if user still exists
		exists, err := auth.UserExists(ctx, "testuser")
		if err != nil {
			t.Fatalf("Failed to check if user exists: %v", err)
		}
		if exists {
			t.Fatal("Expected user to be deleted, but it still exists")
		}

		// Try to delete non-existent user
		err = auth.DeleteUser(ctx, "nonexistentuser")
		if err == nil {
			t.Fatal("Expected error when deleting non-existent user, got nil")
		}
		if err != ErrUserNotFound {
			t.Fatalf("Expected ErrUserNotFound, got: %v", err)
		}
	})
}

func TestAuthWithLDAP(t *testing.T) {
	// Create a mock LDAP datasource
	mockLDAP := NewMockLDAP()

	// Create an Auth instance with the mock LDAP datasource
	auth, err := New(Config{
		DataSource: mockLDAP,
	})
	if err != nil {
		t.Fatalf("Failed to create Auth instance: %v", err)
	}

	ctx := context.Background()

	// Test user creation with LDAP
	t.Run("CreateUserLDAP", func(t *testing.T) {
		err := auth.CreateUser(ctx, "ldapuser", "ldappass", "ldap@example.com", "LDAP User", false)
		if err != nil {
			t.Fatalf("Failed to create LDAP user: %v", err)
		}

		// Verify the user was created with the correct password (not hashed for LDAP)
		user, err := auth.GetUser(ctx, "ldapuser")
		if err != nil {
			t.Fatalf("Failed to get LDAP user: %v", err)
		}

		if user.Password != "ldappass" {
			t.Fatalf("Expected password to be stored as-is for LDAP, got: %s", user.Password)
		}

		// Try to create the same user again, should fail
		err = auth.CreateUser(ctx, "ldapuser", "ldappass", "ldap@example.com", "LDAP User", false)
		if err == nil {
			t.Fatal("Expected error when creating duplicate LDAP user, got nil")
		}
	})

	// Test LDAP authentication
	t.Run("AuthenticateLDAP", func(t *testing.T) {
		// Test with correct credentials
		authenticated, err := auth.Authenticate(ctx, "ldapuser", "ldappass")
		if err != nil {
			t.Fatalf("LDAP authentication failed with error: %v", err)
		}
		if !authenticated {
			t.Fatal("Expected LDAP authentication to succeed, but it failed")
		}

		// Test with incorrect password
		authenticated, err = auth.Authenticate(ctx, "ldapuser", "wrongpass")
		if err != nil {
			t.Fatalf("LDAP authentication check failed with error: %v", err)
		}
		if authenticated {
			t.Fatal("Expected LDAP authentication to fail with wrong password, but it succeeded")
		}
	})

	// Test password update with LDAP
	t.Run("UpdatePasswordLDAP", func(t *testing.T) {
		// Update password
		err := auth.UpdatePassword(ctx, "ldapuser", "ldappass", "newldappass")
		if err != nil {
			t.Fatalf("Failed to update LDAP password: %v", err)
		}

		// Verify the password was updated correctly (not hashed for LDAP)
		user, err := auth.GetUser(ctx, "ldapuser")
		if err != nil {
			t.Fatalf("Failed to get LDAP user after password update: %v", err)
		}

		if user.Password != "newldappass" {
			t.Fatalf("Expected updated password to be stored as-is for LDAP, got: %s", user.Password)
		}

		// Test authentication with new password
		authenticated, err := auth.Authenticate(ctx, "ldapuser", "newldappass")
		if err != nil {
			t.Fatalf("LDAP authentication with new password failed with error: %v", err)
		}
		if !authenticated {
			t.Fatal("Expected LDAP authentication with new password to succeed, but it failed")
		}
	})

	// Test admin password update with LDAP
	t.Run("AdminUpdatePasswordLDAP", func(t *testing.T) {
		// Update password as admin
		err := auth.AdminUpdatePassword(ctx, "ldapuser", "adminldappass")
		if err != nil {
			t.Fatalf("Failed to update LDAP password as admin: %v", err)
		}

		// Verify the password was updated correctly (not hashed for LDAP)
		user, err := auth.GetUser(ctx, "ldapuser")
		if err != nil {
			t.Fatalf("Failed to get LDAP user after admin password update: %v", err)
		}

		if user.Password != "adminldappass" {
			t.Fatalf("Expected admin-updated password to be stored as-is for LDAP, got: %s", user.Password)
		}

		// Test authentication with new password
		authenticated, err := auth.Authenticate(ctx, "ldapuser", "adminldappass")
		if err != nil {
			t.Fatalf("LDAP authentication with admin-set password failed with error: %v", err)
		}
		if !authenticated {
			t.Fatal("Expected LDAP authentication with admin-set password to succeed, but it failed")
		}
	})

	// Test user deletion with LDAP
	t.Run("DeleteUserLDAP", func(t *testing.T) {
		// Delete the LDAP user
		err := auth.DeleteUser(ctx, "ldapuser")
		if err != nil {
			t.Fatalf("Failed to delete LDAP user: %v", err)
		}

		// Verify the user was deleted
		exists, err := auth.UserExists(ctx, "ldapuser")
		if err != nil {
			t.Fatalf("Failed to check if LDAP user exists: %v", err)
		}
		if exists {
			t.Fatal("Expected LDAP user to be deleted, but it still exists")
		}
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("ValidPassword", func(t *testing.T) {
		password := "securepassword123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}
		if hash == "" {
			t.Fatal("Expected non-empty hash")
		}
		if hash == password {
			t.Fatal("Hash should not be the same as the original password")
		}

		// Verify the hash
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			t.Fatalf("Failed to verify password hash: %v", err)
		}
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		_, err := HashPassword("")
		if err == nil {
			t.Fatal("Expected error with empty password, got nil")
		}
		if err != ErrInvalidPassword {
			t.Fatalf("Expected ErrInvalidPassword, got: %v", err)
		}
	})
}

func TestComparePasswords(t *testing.T) {
	password := "securepassword123"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate password hash: %v", err)
	}

	t.Run("CorrectPassword", func(t *testing.T) {
		err := ComparePasswords(string(hash), password)
		if err != nil {
			t.Fatalf("Failed to compare passwords: %v", err)
		}
	})

	t.Run("IncorrectPassword", func(t *testing.T) {
		err := ComparePasswords(string(hash), "wrongpassword")
		if err == nil {
			t.Fatal("Expected error with incorrect password, got nil")
		}
	})
}

func TestNewAuth(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir, err := os.MkdirTemp("", "elemta-auth-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "auth-test.db")

	t.Run("ValidConfig", func(t *testing.T) {
		// Create SQLite datasource
		dsConfig := datasource.Config{
			Type:     "sqlite",
			Name:     "auth-test",
			Database: "auth.db",
			Options: map[string]interface{}{
				"db_path": dbPath,
			},
		}

		ds := datasource.NewSQLite(dsConfig)
		if err := ds.Connect(); err != nil {
			t.Fatalf("Failed to connect to SQLite datasource: %v", err)
		}
		defer ds.Close()

		// Create Auth with valid config
		config := Config{
			DataSource: ds,
		}

		auth, err := New(config)
		if err != nil {
			t.Fatalf("Failed to create Auth instance: %v", err)
		}
		defer auth.Close()

		if auth == nil {
			t.Fatal("Expected non-nil Auth instance")
		}
	})

	t.Run("NilDataSource", func(t *testing.T) {
		// Create Auth with nil datasource
		config := Config{
			DataSource: nil,
		}

		_, err := New(config)
		if err == nil {
			t.Fatal("Expected error with nil datasource, got nil")
		}
	})
}

func TestNewWithSQLite(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir, err := os.MkdirTemp("", "elemta-auth-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "auth-test.db")

	t.Run("ValidPath", func(t *testing.T) {
		auth, err := NewWithSQLite(dbPath)
		if err != nil {
			t.Fatalf("Failed to create Auth instance: %v", err)
		}
		defer auth.Close()

		if auth == nil {
			t.Fatal("Expected non-nil Auth instance")
		}
	})

	t.Run("InvalidPath", func(t *testing.T) {
		// Use a path that should not be writable
		invalidPath := "/root/nonexistent/directory/auth.db"
		_, err := NewWithSQLite(invalidPath)
		if err == nil {
			t.Fatal("Expected error with invalid path, got nil")
		}
	})
}

func TestGetDataSourceType(t *testing.T) {
	// Test with SQLite
	t.Run("SQLiteType", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "elemta-auth-test")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tempDir)

		dbPath := filepath.Join(tempDir, "auth-test.db")

		auth, err := NewWithSQLite(dbPath)
		if err != nil {
			t.Fatalf("Failed to create Auth instance: %v", err)
		}
		defer auth.Close()

		dsType := auth.GetDataSourceType()
		if dsType != "sqlite" {
			t.Fatalf("Expected datasource type 'sqlite', got: %s", dsType)
		}
	})

	// Test with LDAP
	t.Run("LDAPType", func(t *testing.T) {
		mockLDAP := NewMockLDAP()

		auth, err := New(Config{
			DataSource: mockLDAP,
		})
		if err != nil {
			t.Fatalf("Failed to create Auth instance: %v", err)
		}

		dsType := auth.GetDataSourceType()
		if dsType != "ldap" {
			t.Fatalf("Expected datasource type 'ldap', got: %s", dsType)
		}
	})

	// Test with nil datasource
	t.Run("NilDataSource", func(t *testing.T) {
		auth := &Auth{ds: nil}

		dsType := auth.GetDataSourceType()
		if dsType != "" {
			t.Fatalf("Expected empty datasource type, got: %s", dsType)
		}
	})
}
