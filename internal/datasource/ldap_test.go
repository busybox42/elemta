package datasource

import (
	"context"
	"testing"
)

func TestLDAPDataSource(t *testing.T) {
	// Skip this test by default since it requires an actual LDAP server
	t.Skip("Skipping LDAP test as it requires an actual LDAP server")

	// Create a new LDAP datasource with test configuration
	config := Config{
		Name:     "test-ldap",
		Type:     "ldap",
		Host:     "localhost",
		Port:     389,
		Username: "cn=admin,dc=example,dc=com",
		Password: "admin",
		Options: map[string]interface{}{
			"base_dn":  "dc=example,dc=com",
			"user_dn":  "ou=users",
			"group_dn": "ou=groups",
		},
	}

	ldap := NewLDAP(config)

	// Test connection
	t.Run("Connect", func(t *testing.T) {
		err := ldap.Connect()
		if err != nil {
			t.Fatalf("Failed to connect to LDAP server: %v", err)
		}

		if !ldap.IsConnected() {
			t.Fatal("Expected IsConnected() to return true after Connect()")
		}

		defer ldap.Close()
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
			"telephoneNumber": "123-456-7890",
			"title":           "Test Engineer",
		},
	}

	t.Run("CreateUser", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		// Delete the user if it already exists
		_ = ldap.DeleteUser(ctx, testUser.Username)

		err := ldap.CreateUser(ctx, testUser)
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		user, err := ldap.GetUser(ctx, testUser.Username)
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
	})

	t.Run("Authenticate", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		// Test with correct password
		authenticated, err := ldap.Authenticate(ctx, testUser.Username, testUser.Password)
		if err != nil {
			t.Fatalf("Authentication failed with error: %v", err)
		}

		if !authenticated {
			t.Error("Authentication failed with correct password")
		}

		// Test with incorrect password
		authenticated, err = ldap.Authenticate(ctx, testUser.Username, "wrongpassword")
		if err != nil {
			t.Fatalf("Authentication check failed with error: %v", err)
		}

		if authenticated {
			t.Error("Authentication succeeded with incorrect password")
		}
	})

	t.Run("UpdateUser", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		// Update the user
		updatedUser := testUser
		updatedUser.FullName = "Updated Test User"
		updatedUser.Email = "updated@example.com"
		updatedUser.Groups = []string{"users", "developers"}
		updatedUser.Attributes["title"] = "Senior Test Engineer"

		err := ldap.UpdateUser(ctx, updatedUser)
		if err != nil {
			t.Fatalf("Failed to update user: %v", err)
		}

		// Verify the update
		user, err := ldap.GetUser(ctx, testUser.Username)
		if err != nil {
			t.Fatalf("Failed to get updated user: %v", err)
		}

		if user.FullName != updatedUser.FullName {
			t.Errorf("Expected updated full name %s, got %s", updatedUser.FullName, user.FullName)
		}

		if user.Email != updatedUser.Email {
			t.Errorf("Expected updated email %s, got %s", updatedUser.Email, user.Email)
		}

		// Check if user is in both groups
		foundUsers := false
		foundDevelopers := false
		for _, group := range user.Groups {
			if group == "users" {
				foundUsers = true
			}
			if group == "developers" {
				foundDevelopers = true
			}
		}

		if !foundUsers {
			t.Errorf("User is not in the 'users' group after update")
		}

		if !foundDevelopers {
			t.Errorf("User is not in the 'developers' group after update")
		}
	})

	t.Run("ListUsers", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
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

		// Delete the user if it already exists
		_ = ldap.DeleteUser(ctx, anotherUser.Username)

		err := ldap.CreateUser(ctx, anotherUser)
		if err != nil {
			t.Fatalf("Failed to create another user: %v", err)
		}

		// List all users
		users, err := ldap.ListUsers(ctx, nil, 0, 0)
		if err != nil {
			t.Fatalf("Failed to list users: %v", err)
		}

		if len(users) < 2 {
			t.Errorf("Expected at least 2 users, got %d", len(users))
		}

		// List users with filter
		users, err = ldap.ListUsers(ctx, map[string]interface{}{
			"username": testUser.Username,
		}, 0, 0)
		if err != nil {
			t.Fatalf("Failed to list users with filter: %v", err)
		}

		if len(users) != 1 {
			t.Errorf("Expected 1 user with filter, got %d", len(users))
		}

		if len(users) > 0 && users[0].Username != testUser.Username {
			t.Errorf("Expected filtered user %s, got %s", testUser.Username, users[0].Username)
		}
	})

	t.Run("DeleteUser", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		// Delete the test users
		err := ldap.DeleteUser(ctx, testUser.Username)
		if err != nil {
			t.Fatalf("Failed to delete test user: %v", err)
		}

		err = ldap.DeleteUser(ctx, "anotheruser")
		if err != nil {
			t.Fatalf("Failed to delete another user: %v", err)
		}

		// Verify the users are deleted
		_, err = ldap.GetUser(ctx, testUser.Username)
		if err != ErrNotFound {
			t.Errorf("Expected ErrNotFound for deleted user, got %v", err)
		}

		_, err = ldap.GetUser(ctx, "anotheruser")
		if err != ErrNotFound {
			t.Errorf("Expected ErrNotFound for deleted user, got %v", err)
		}
	})

	t.Run("Query", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		// Execute a custom query
		result, err := ldap.Query(ctx, "||sub||(objectClass=*)||cn,dn")
		if err != nil {
			t.Fatalf("Failed to execute query: %v", err)
		}

		entries, ok := result.([]map[string]interface{})
		if !ok {
			t.Fatalf("Expected result to be []map[string]interface{}, got %T", result)
		}

		if len(entries) == 0 {
			t.Error("Expected at least one entry in query result")
		}
	})

	t.Run("Close", func(t *testing.T) {
		if !ldap.IsConnected() {
			if err := ldap.Connect(); err != nil {
				t.Fatalf("Failed to connect to LDAP server: %v", err)
			}
		}

		err := ldap.Close()
		if err != nil {
			t.Fatalf("Failed to close connection: %v", err)
		}

		if ldap.IsConnected() {
			t.Fatal("Expected IsConnected() to return false after Close()")
		}
	})
}
