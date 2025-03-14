package datasource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteDataSource(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir, err := os.MkdirTemp("", "elemta-sqlite-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")

	// Create a new SQLite datasource with test configuration
	config := Config{
		Name: "test-sqlite",
		Type: "sqlite",
		Options: map[string]interface{}{
			"db_path": dbPath,
		},
	}

	sqlite := NewSQLite(config)

	// Ensure the connection is closed at the end of the test
	defer func() {
		if sqlite.IsConnected() {
			sqlite.Close()
		}
	}()

	// Test connection
	t.Run("Connect", func(t *testing.T) {
		err := sqlite.Connect()
		if err != nil {
			t.Fatalf("Failed to connect to SQLite database: %v", err)
		}

		if !sqlite.IsConnected() {
			t.Fatal("Expected IsConnected() to return true after Connect()")
		}

		// Check if the database file was created
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Fatal("Database file was not created")
		}
	})

	// Test user operations
	ctx := context.Background()

	// Create a test user
	testUser := User{
		Username: "testuser",
		FullName: "Test User",
		Email:    "testuser@example.com",
		Password: "password123",
		IsActive: true,
		IsAdmin:  false,
		Groups:   []string{"users"},
		Attributes: map[string]interface{}{
			"phone": "123-456-7890",
			"title": "Test Engineer",
		},
	}

	t.Run("CreateUser", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		err := sqlite.CreateUser(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Try to create the same user again, should fail with ErrAlreadyExists
		err = sqlite.CreateUser(ctx, testUser)
		if err == nil {
			t.Fatal("Expected error when creating duplicate user, got nil")
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		user, err := sqlite.GetUser(ctx, testUser.Username)
		if err != nil {
			t.Fatalf("Failed to get user: %v", err)
		}

		if user.Username != testUser.Username {
			t.Errorf("Expected username %s, got %s", testUser.Username, user.Username)
		}

		if user.FullName != testUser.FullName {
			t.Errorf("Expected full name %s, got %s", testUser.FullName, user.FullName)
		}

		if user.Email != testUser.Email {
			t.Errorf("Expected email %s, got %s", testUser.Email, user.Email)
		}

		if !user.IsActive {
			t.Error("Expected user to be active")
		}

		if user.IsAdmin {
			t.Error("Expected user not to be admin")
		}

		// Check if user is in the correct group
		foundGroup := false
		for _, group := range user.Groups {
			if group == "users" {
				foundGroup = true
				break
			}
		}

		if !foundGroup {
			t.Errorf("User is not in the 'users' group")
		}

		// Check attributes
		if phone, ok := user.Attributes["phone"].(string); !ok || phone != "123-456-7890" {
			t.Errorf("Expected phone attribute '123-456-7890', got %v", user.Attributes["phone"])
		}

		if title, ok := user.Attributes["title"].(string); !ok || title != "Test Engineer" {
			t.Errorf("Expected title attribute 'Test Engineer', got %v", user.Attributes["title"])
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		// Test with correct password
		authenticated, err := sqlite.Authenticate(ctx, testUser.Username, testUser.Password)
		if err != nil {
			t.Fatalf("Authentication failed with error: %v", err)
		}

		if !authenticated {
			t.Error("Authentication failed with correct password")
		}

		// Test with incorrect password
		authenticated, err = sqlite.Authenticate(ctx, testUser.Username, "wrongpassword")
		if err != nil {
			t.Fatalf("Authentication check failed with error: %v", err)
		}

		if authenticated {
			t.Error("Authentication succeeded with incorrect password")
		}

		// Test with non-existent user
		authenticated, err = sqlite.Authenticate(ctx, "nonexistentuser", "password")
		if err != nil {
			t.Fatalf("Authentication check failed with error: %v", err)
		}

		if authenticated {
			t.Error("Authentication succeeded with non-existent user")
		}
	})

	t.Run("UpdateUser", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		// Update the user
		updatedUser := testUser
		updatedUser.FullName = "Updated Test User"
		updatedUser.Email = "updated@example.com"
		updatedUser.IsAdmin = true
		updatedUser.Groups = []string{"users", "admins"}
		updatedUser.Attributes["title"] = "Senior Test Engineer"
		updatedUser.Attributes["department"] = "Engineering"

		err := sqlite.UpdateUser(ctx, updatedUser)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		// Verify the update
		user, err := sqlite.GetUser(ctx, testUser.Username)
		if err != nil {
			t.Fatalf("Failed to get updated user: %v", err)
		}

		if user.FullName != updatedUser.FullName {
			t.Errorf("Expected updated full name %s, got %s", updatedUser.FullName, user.FullName)
		}

		if user.Email != updatedUser.Email {
			t.Errorf("Expected updated email %s, got %s", updatedUser.Email, user.Email)
		}

		if !user.IsAdmin {
			t.Error("Expected user to be admin after update")
		}

		// Check if user is in both groups
		foundUsers := false
		foundAdmins := false
		for _, group := range user.Groups {
			if group == "users" {
				foundUsers = true
			}
			if group == "admins" {
				foundAdmins = true
			}
		}

		if !foundUsers {
			t.Errorf("User is not in the 'users' group after update")
		}

		if !foundAdmins {
			t.Errorf("User is not in the 'admins' group after update")
		}

		// Check updated attributes
		if title, ok := user.Attributes["title"].(string); !ok || title != "Senior Test Engineer" {
			t.Errorf("Expected updated title attribute 'Senior Test Engineer', got %v", user.Attributes["title"])
		}

		if dept, ok := user.Attributes["department"].(string); !ok || dept != "Engineering" {
			t.Errorf("Expected new department attribute 'Engineering', got %v", user.Attributes["department"])
		}
	})

	t.Run("ListUsers", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		// Create another test user
		anotherUser := User{
			Username: "anotheruser",
			FullName: "Another User",
			Email:    "another@example.com",
			Password: "password456",
			IsActive: true,
			Groups:   []string{"users"},
		}

		err := sqlite.CreateUser(ctx, anotherUser)
		if err != nil {
			t.Fatalf("Failed to create another user: %v", err)
		}

		// List all users
		users, err := sqlite.ListUsers(ctx, nil, 0, 0)
		if err != nil {
			t.Fatalf("Failed to list users: %v", err)
		}

		if len(users) < 2 {
			t.Errorf("Expected at least 2 users, got %d", len(users))
		}

		// List users with filter by username
		users, err = sqlite.ListUsers(ctx, map[string]interface{}{
			"username": testUser.Username,
		}, 0, 0)
		if err != nil {
			t.Fatalf("Failed to list users with username filter: %v", err)
		}

		if len(users) != 1 {
			t.Errorf("Expected 1 user with username filter, got %d", len(users))
		}

		if len(users) > 0 && users[0].Username != testUser.Username {
			t.Errorf("Expected filtered user %s, got %s", testUser.Username, users[0].Username)
		}

		// List users with filter by admin status
		users, err = sqlite.ListUsers(ctx, map[string]interface{}{
			"is_admin": true,
		}, 0, 0)
		if err != nil {
			t.Fatalf("Failed to list users with admin filter: %v", err)
		}

		if len(users) != 1 {
			t.Errorf("Expected 1 admin user, got %d", len(users))
		}

		if len(users) > 0 && !users[0].IsAdmin {
			t.Errorf("Expected filtered user to be admin")
		}

		// Test pagination
		users, err = sqlite.ListUsers(ctx, nil, 1, 0)
		if err != nil {
			t.Fatalf("Failed to list users with pagination: %v", err)
		}

		if len(users) != 1 {
			t.Errorf("Expected 1 user with limit=1, got %d", len(users))
		}

		// Get the first user for comparison
		firstUser := users[0].Username

		users, err = sqlite.ListUsers(ctx, nil, 1, 1)
		if err != nil {
			t.Fatalf("Failed to list users with pagination: %v", err)
		}

		if len(users) != 1 {
			t.Errorf("Expected 1 user with limit=1, offset=1, got %d", len(users))
		}

		if len(users) > 0 && users[0].Username == firstUser {
			t.Errorf("Expected different user with offset=1, got the same user: %s", users[0].Username)
		}
	})

	t.Run("Query", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		// Execute a custom query
		result, err := sqlite.Query(ctx, "SELECT username, email FROM users")
		if err != nil {
			t.Fatalf("Failed to execute query: %v", err)
		}

		rows, ok := result.([]map[string]interface{})
		if !ok {
			t.Fatalf("Expected result to be []map[string]interface{}, got %T", result)
		}

		if len(rows) < 2 {
			t.Errorf("Expected at least 2 rows in query result, got %d", len(rows))
		}

		// Check if the result contains the expected columns
		if len(rows) > 0 {
			row := rows[0]
			if _, ok := row["username"]; !ok {
				t.Error("Expected 'username' column in query result")
			}
			if _, ok := row["email"]; !ok {
				t.Error("Expected 'email' column in query result")
			}
		}
	})

	t.Run("DeleteUser", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		// Delete the test users
		err := sqlite.DeleteUser(ctx, testUser.Username)
		if err != nil {
			t.Fatalf("Failed to delete test user: %v", err)
		}

		err = sqlite.DeleteUser(ctx, "anotheruser")
		if err != nil {
			t.Fatalf("Failed to delete another user: %v", err)
		}

		// Verify the users are deleted
		_, err = sqlite.GetUser(ctx, testUser.Username)
		if err != ErrNotFound {
			t.Errorf("Expected ErrNotFound for deleted user, got %v", err)
		}

		_, err = sqlite.GetUser(ctx, "anotheruser")
		if err != ErrNotFound {
			t.Errorf("Expected ErrNotFound for deleted user, got %v", err)
		}

		// Try to delete a non-existent user
		err = sqlite.DeleteUser(ctx, "nonexistentuser")
		if err != ErrNotFound {
			t.Errorf("Expected ErrNotFound when deleting non-existent user, got %v", err)
		}
	})

	t.Run("Close", func(t *testing.T) {
		if !sqlite.IsConnected() {
			t.Fatal("SQLite is not connected")
		}

		err := sqlite.Close()
		if err != nil {
			t.Fatalf("Failed to close connection: %v", err)
		}

		if sqlite.IsConnected() {
			t.Fatal("Expected IsConnected() to return false after Close()")
		}
	})
}
