package datasource

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestSQLInjectionPrevention tests comprehensive SQL injection prevention
func TestSQLInjectionPrevention(t *testing.T) {
	// Create logger for testing
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise during testing
	}))

	// Initialize security manager
	securityManager := NewSQLSecurityManager(logger)
	
	// Register test table
	securityManager.RegisterTable("users", []string{
		"username", "password", "email", "full_name", "is_active", "is_admin",
	})

	t.Run("Username Validation", func(t *testing.T) {
		testCases := []struct {
			name     string
			username string
			wantErr  bool
		}{
			{"Valid username", "testuser", false},
			{"Valid email username", "test@example.com", false},
			{"Valid with underscore", "test_user", false},
			{"Valid with hyphen", "test-user", false},
			{"Valid with dot", "test.user", false},
			{"Empty username", "", true},
			{"SQL injection attempt", "admin'; DROP TABLE users; --", true},
			{"Union injection", "user' UNION SELECT * FROM users --", true},
			{"Boolean injection", "user' OR 1=1 --", true},
			{"Comment injection", "user/* comment */", true},
			{"Control character injection", "user\x00admin", true},
			{"Too long username", strings.Repeat("a", 256), true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := securityManager.ValidateUsername(tc.username)
				if (err != nil) != tc.wantErr {
					t.Errorf("ValidateUsername() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Email Validation", func(t *testing.T) {
		testCases := []struct {
			name    string
			email   string
			wantErr bool
		}{
			{"Valid email", "test@example.com", false},
			{"Valid complex email", "test.user+tag@example.co.uk", false},
			{"Empty email (allowed)", "", false},
			{"Invalid format", "notanemail", true},
			{"SQL injection in email", "test@example.com'; DROP TABLE users; --", true},
			{"Too long email", strings.Repeat("a", 300) + "@example.com", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := securityManager.ValidateEmail(tc.email)
				if (err != nil) != tc.wantErr {
					t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Input Sanitization", func(t *testing.T) {
		testCases := []struct {
			name    string
			input   string
			wantErr bool
		}{
			{"Normal text", "Hello World", false},
			{"Empty string", "", false},
			{"Numbers", "12345", false},
			{"Special chars (safe)", "test@example.com", false},
			{"SQL SELECT injection", "SELECT * FROM users", true},
			{"SQL UNION injection", "' UNION SELECT password FROM users --", true},
			{"SQL INSERT injection", "'; INSERT INTO users VALUES ('hacker', 'pass'); --", true},
			{"SQL DROP injection", "'; DROP TABLE users; --", true},
			{"Boolean injection", "' OR 1=1 --", true},
			{"Function injection", "'; EXEC xp_cmdshell('dir'); --", true},
			{"Time-based injection", "'; WAITFOR DELAY '00:00:10'; --", true},
			{"Schema injection", "'; SELECT * FROM information_schema.tables; --", true},
			{"Control character injection", "test\x00\x1a", true},
			{"Comment injection", "test /* comment */ --", true},
			{"Dollar quote injection", "test $tag$SELECT * FROM users$tag$", true},
			{"Buffer overflow attempt", strings.Repeat("A", 10001), true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := securityManager.SanitizeInput(tc.input)
				if (err != nil) != tc.wantErr {
					t.Errorf("SanitizeInput() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Table Name Validation", func(t *testing.T) {
		testCases := []struct {
			name      string
			tableName string
			wantErr   bool
		}{
			{"Valid registered table", "users", false},
			{"Invalid unregistered table", "admin_secrets", true},
			{"SQL injection in table name", "users; DROP TABLE users; --", true},
			{"Invalid characters", "users'", true},
			{"Invalid characters quotes", "users\"", true},
			{"Invalid characters semicolon", "users;", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := securityManager.ValidateTableName(tc.tableName)
				if (err != nil) != tc.wantErr {
					t.Errorf("ValidateTableName() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Column Name Validation", func(t *testing.T) {
		testCases := []struct {
			name       string
			tableName  string
			columnName string
			wantErr    bool
		}{
			{"Valid column", "users", "username", false},
			{"Valid column", "users", "email", false},
			{"Invalid unregistered column", "users", "secret_data", true},
			{"SQL injection in column", "users", "username; DROP TABLE users; --", true},
			{"Invalid characters", "users", "username'", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := securityManager.ValidateColumnName(tc.tableName, tc.columnName)
				if (err != nil) != tc.wantErr {
					t.Errorf("ValidateColumnName() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Filter Map Validation", func(t *testing.T) {
		testCases := []struct {
			name      string
			tableName string
			filter    map[string]interface{}
			wantErr   bool
		}{
			{
				"Valid filter",
				"users",
				map[string]interface{}{"username": "test", "is_active": 1},
				false,
			},
			{
				"Invalid column in filter",
				"users",
				map[string]interface{}{"secret_column": "value"},
				true,
			},
			{
				"SQL injection in filter value",
				"users",
				map[string]interface{}{"username": "test'; DROP TABLE users; --"},
				true,
			},
			{
				"Invalid data type",
				"users",
				map[string]interface{}{"username": []string{"test"}},
				true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := securityManager.ValidateFilterMap(tc.tableName, tc.filter)
				if (err != nil) != tc.wantErr {
					t.Errorf("ValidateFilterMap() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Secure Query Building", func(t *testing.T) {
		testCases := []struct {
			name         string
			operation    string
			tableName    string
			columns      []string
			whereColumns []string
			wantErr      bool
		}{
			{
				"Valid SELECT query",
				"SELECT",
				"users",
				[]string{"username", "email"},
				[]string{"is_active"},
				false,
			},
			{
				"Valid INSERT query",
				"INSERT",
				"users",
				[]string{"username", "password", "email"},
				[]string{},
				false,
			},
			{
				"Invalid table name",
				"SELECT",
				"malicious_table",
				[]string{"username"},
				[]string{},
				true,
			},
			{
				"Invalid column name",
				"SELECT",
				"users",
				[]string{"malicious_column"},
				[]string{},
				true,
			},
			{
				"Unsupported operation",
				"TRUNCATE",
				"users",
				[]string{},
				[]string{},
				true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := securityManager.BuildSecureQuery(tc.operation, tc.tableName, tc.columns, tc.whereColumns)
				if (err != nil) != tc.wantErr {
					t.Errorf("BuildSecureQuery() error = %v, wantErr %v", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("Debug Mode", func(t *testing.T) {
		// Test debug mode toggle
		if securityManager.IsDebugMode() {
			t.Error("Debug mode should be disabled by default")
		}

		securityManager.EnableDebugMode(true)
		if !securityManager.IsDebugMode() {
			t.Error("Debug mode should be enabled after EnableDebugMode(true)")
		}

		securityManager.EnableDebugMode(false)
		if securityManager.IsDebugMode() {
			t.Error("Debug mode should be disabled after EnableDebugMode(false)")
		}
	})

	t.Run("Error Handling", func(t *testing.T) {
		// Test secure error handling
		testErr := securityManager.HandleSecureError("SELECT", "users", "testuser", 
			context.DeadlineExceeded, "Operation timed out")
		
		if testErr == nil {
			t.Error("HandleSecureError should return an error")
		}
		
		if !strings.Contains(testErr.Error(), "Operation timed out") {
			t.Errorf("HandleSecureError should return user message, got: %v", testErr)
		}
		
		// Test generic error message
		genericErr := securityManager.HandleSecureError("SELECT", "users", "testuser", 
			context.DeadlineExceeded, "")
		
		if genericErr == nil || genericErr.Error() != "database operation failed" {
			t.Errorf("HandleSecureError should return generic message, got: %v", genericErr)
		}
	})
}

// TestSQLiteSecurityIntegration tests SQLite with security enhancements
func TestSQLiteSecurityIntegration(t *testing.T) {
	// Create temporary SQLite database for testing
	config := Config{
		Type:     "sqlite",
		Name:     "test-sqlite-security",
		Database: ":memory:", // In-memory database for testing
	}

	sqlite := NewSQLite(config)
	if err := sqlite.Connect(); err != nil {
		t.Fatalf("Failed to connect to SQLite: %v", err)
	}
	defer sqlite.Close()

	ctx := context.Background()

	t.Run("Secure Authentication", func(t *testing.T) {
		// Test with valid inputs
		_, err := sqlite.Authenticate(ctx, "testuser", "testpass")
		if err == nil {
			t.Error("Authentication should fail for non-existent user")
		}

		// Test with SQL injection attempts
		injectionAttempts := []struct {
			username string
			password string
		}{
			{"admin'; DROP TABLE users; --", "password"},
			{"admin", "' OR 1=1 --"},
			{"admin' UNION SELECT * FROM users --", "password"},
			{"admin", "'; INSERT INTO users VALUES ('hacker', 'pass'); --"},
		}

		for _, attempt := range injectionAttempts {
			_, err := sqlite.Authenticate(ctx, attempt.username, attempt.password)
			if err == nil {
				t.Errorf("Authentication should reject SQL injection attempt: %s / %s", 
					attempt.username, attempt.password)
			}
		}
	})

	t.Run("Secure GetUser", func(t *testing.T) {
		// Test with SQL injection attempts
		injectionUsernames := []string{
			"admin'; DROP TABLE users; --",
			"admin' UNION SELECT password FROM users --",
			"admin' OR 1=1 --",
			strings.Repeat("A", 1000), // Buffer overflow attempt
		}

		for _, username := range injectionUsernames {
			_, err := sqlite.GetUser(ctx, username)
			if err == nil {
				t.Errorf("GetUser should reject SQL injection attempt: %s", username)
			}
		}
	})

	t.Run("Secure ListUsers", func(t *testing.T) {
		// Test with malicious filter
		maliciousFilters := []map[string]interface{}{
			{"username": "'; DROP TABLE users; --"},
			{"malicious_column": "value"},
			{"username": []string{"injection"}}, // Invalid type
		}

		for i, filter := range maliciousFilters {
			_, err := sqlite.ListUsers(ctx, filter, 10, 0)
			if err == nil {
				t.Errorf("ListUsers should reject malicious filter %d: %v", i, filter)
			}
		}
	})
}

// BenchmarkSecurityValidation benchmarks the security validation performance
func BenchmarkSecurityValidation(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	securityManager := NewSQLSecurityManager(logger)
	securityManager.RegisterTable("users", []string{"username", "password", "email"})

	b.Run("ValidateUsername", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = securityManager.ValidateUsername("testuser")
		}
	})

	b.Run("SanitizeInput", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = securityManager.SanitizeInput("normal input text")
		}
	})

	b.Run("BuildSecureQuery", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = securityManager.BuildSecureQuery("SELECT", "users", 
				[]string{"username", "email"}, []string{"is_active"})
		}
	})
}
