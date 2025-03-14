package datasource

import (
	"context"
	"testing"
)

func TestMockDataSource(t *testing.T) {
	// Create a mock datasource
	ds := NewMockDataSource("test-mock")

	// Test basic properties
	if ds.Name() != "test-mock" {
		t.Errorf("Expected name to be 'test-mock', got '%s'", ds.Name())
	}

	if ds.Type() != "mock" {
		t.Errorf("Expected type to be 'mock', got '%s'", ds.Type())
	}

	if ds.IsConnected() {
		t.Error("Expected datasource to be disconnected initially")
	}

	// Test connection
	if err := ds.Connect(); err != nil {
		t.Errorf("Failed to connect: %v", err)
	}

	if !ds.IsConnected() {
		t.Error("Expected datasource to be connected after Connect()")
	}

	// Test user operations
	ctx := context.Background()

	// Test with non-existent user
	_, err := ds.GetUser(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound for nonexistent user, got %v", err)
	}

	// Create a test user
	testUser := User{
		Username:   "testuser",
		Password:   "password123",
		Email:      "test@example.com",
		FullName:   "Test User",
		IsActive:   true,
		IsAdmin:    false,
		Groups:     []string{"users"},
		Attributes: map[string]interface{}{"department": "IT"},
	}

	// Test CreateUser
	if err := ds.CreateUser(ctx, testUser); err != nil {
		t.Errorf("Failed to create user: %v", err)
	}

	// Test GetUser
	retrievedUser, err := ds.GetUser(ctx, "testuser")
	if err != nil {
		t.Errorf("Failed to get user: %v", err)
	}

	if retrievedUser.Username != testUser.Username {
		t.Errorf("Expected username '%s', got '%s'", testUser.Username, retrievedUser.Username)
	}

	if retrievedUser.Email != testUser.Email {
		t.Errorf("Expected email '%s', got '%s'", testUser.Email, retrievedUser.Email)
	}

	// Test Authenticate
	authenticated, err := ds.Authenticate(ctx, "testuser", "password123")
	if err != nil {
		t.Errorf("Authentication failed with error: %v", err)
	}
	if !authenticated {
		t.Error("Expected authentication to succeed with correct password")
	}

	authenticated, err = ds.Authenticate(ctx, "testuser", "wrongpassword")
	if err != nil {
		t.Errorf("Authentication failed with error: %v", err)
	}
	if authenticated {
		t.Error("Expected authentication to fail with incorrect password")
	}

	// Test UpdateUser
	updatedUser := retrievedUser
	updatedUser.Email = "updated@example.com"
	updatedUser.IsAdmin = true

	if err := ds.UpdateUser(ctx, updatedUser); err != nil {
		t.Errorf("Failed to update user: %v", err)
	}

	retrievedUser, err = ds.GetUser(ctx, "testuser")
	if err != nil {
		t.Errorf("Failed to get updated user: %v", err)
	}

	if retrievedUser.Email != "updated@example.com" {
		t.Errorf("Expected updated email 'updated@example.com', got '%s'", retrievedUser.Email)
	}

	if !retrievedUser.IsAdmin {
		t.Error("Expected user to be admin after update")
	}

	// Test ListUsers
	users, err := ds.ListUsers(ctx, nil, 0, 0)
	if err != nil {
		t.Errorf("Failed to list users: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}

	// Test ListUsers with filter
	users, err = ds.ListUsers(ctx, map[string]interface{}{"is_admin": true}, 0, 0)
	if err != nil {
		t.Errorf("Failed to list users with filter: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected 1 admin user, got %d", len(users))
	}

	users, err = ds.ListUsers(ctx, map[string]interface{}{"is_admin": false}, 0, 0)
	if err != nil {
		t.Errorf("Failed to list users with filter: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("Expected 0 non-admin users, got %d", len(users))
	}

	// Test DeleteUser
	if err := ds.DeleteUser(ctx, "testuser"); err != nil {
		t.Errorf("Failed to delete user: %v", err)
	}

	_, err = ds.GetUser(ctx, "testuser")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound after deletion, got %v", err)
	}

	// Test Close
	if err := ds.Close(); err != nil {
		t.Errorf("Failed to close connection: %v", err)
	}

	if ds.IsConnected() {
		t.Error("Expected datasource to be disconnected after Close()")
	}
}

func TestDataSourceManager(t *testing.T) {
	// Create a manager
	manager := NewManager()

	// Create mock datasources
	ds1 := NewMockDataSource("mock1")
	ds2 := NewMockDataSource("mock2")

	// Test Register
	if err := manager.Register(ds1); err != nil {
		t.Errorf("Failed to register datasource 1: %v", err)
	}

	if err := manager.Register(ds2); err != nil {
		t.Errorf("Failed to register datasource 2: %v", err)
	}

	// Test registering duplicate
	if err := manager.Register(NewMockDataSource("mock1")); err == nil {
		t.Error("Expected error when registering duplicate datasource")
	}

	// Test Get
	retrievedDS, err := manager.Get("mock1")
	if err != nil {
		t.Errorf("Failed to get datasource: %v", err)
	}

	if retrievedDS.Name() != "mock1" {
		t.Errorf("Expected name 'mock1', got '%s'", retrievedDS.Name())
	}

	// Test Get nonexistent
	_, err = manager.Get("nonexistent")
	if err == nil {
		t.Error("Expected error when getting nonexistent datasource")
	}

	// Test List
	dsList := manager.List()
	if len(dsList) != 2 {
		t.Errorf("Expected 2 datasources, got %d", len(dsList))
	}

	// Test Remove
	if err := manager.Remove("mock1"); err != nil {
		t.Errorf("Failed to remove datasource: %v", err)
	}

	dsList = manager.List()
	if len(dsList) != 1 {
		t.Errorf("Expected 1 datasource after removal, got %d", len(dsList))
	}

	// Test CloseAll
	if err := ds2.Connect(); err != nil {
		t.Errorf("Failed to connect datasource: %v", err)
	}

	if err := manager.CloseAll(); err != nil {
		t.Errorf("Failed to close all datasources: %v", err)
	}

	if ds2.IsConnected() {
		t.Error("Expected datasource to be disconnected after CloseAll()")
	}
}

func TestFactoryWithMock(t *testing.T) {
	// Since we can't test the real database implementations without dependencies,
	// we'll create a mock factory function for testing
	mockFactory := func(config Config) (DataSource, error) {
		return NewMockDataSource(config.Name), nil
	}

	// Test the mock factory
	config := Config{
		Type: "mock",
		Name: "factory-test",
	}

	ds, err := mockFactory(config)
	if err != nil {
		t.Errorf("Factory failed: %v", err)
	}

	if ds.Name() != "factory-test" {
		t.Errorf("Expected name 'factory-test', got '%s'", ds.Name())
	}

	if ds.Type() != "mock" {
		t.Errorf("Expected type 'mock', got '%s'", ds.Type())
	}
}

func TestUserLifecycle(t *testing.T) {
	// Create a mock datasource
	ds := NewMockDataSource("user-lifecycle")
	if err := ds.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	ctx := context.Background()

	// Create multiple users
	users := []User{
		{
			Username:   "user1",
			Password:   "pass1",
			Email:      "user1@example.com",
			FullName:   "User One",
			IsActive:   true,
			IsAdmin:    false,
			Groups:     []string{"users"},
			Attributes: map[string]interface{}{"department": "IT"},
		},
		{
			Username:   "user2",
			Password:   "pass2",
			Email:      "user2@example.com",
			FullName:   "User Two",
			IsActive:   true,
			IsAdmin:    true,
			Groups:     []string{"users", "admins"},
			Attributes: map[string]interface{}{"department": "HR"},
		},
		{
			Username:   "user3",
			Password:   "pass3",
			Email:      "user3@example.com",
			FullName:   "User Three",
			IsActive:   false, // Inactive user
			IsAdmin:    false,
			Groups:     []string{"users"},
			Attributes: map[string]interface{}{"department": "Finance"},
		},
	}

	// Create users
	for _, user := range users {
		if err := ds.CreateUser(ctx, user); err != nil {
			t.Errorf("Failed to create user %s: %v", user.Username, err)
		}
	}

	// Test ListUsers with pagination
	listedUsers, err := ds.ListUsers(ctx, nil, 2, 0)
	if err != nil {
		t.Errorf("Failed to list users with pagination: %v", err)
	}

	if len(listedUsers) != 2 {
		t.Errorf("Expected 2 users with limit=2, got %d", len(listedUsers))
	}

	listedUsers, err = ds.ListUsers(ctx, nil, 2, 1)
	if err != nil {
		t.Errorf("Failed to list users with pagination and offset: %v", err)
	}

	if len(listedUsers) != 2 {
		t.Errorf("Expected 2 users with limit=2, offset=1, got %d", len(listedUsers))
	}

	// Test authentication for inactive user
	authenticated, err := ds.Authenticate(ctx, "user3", "pass3")
	if err != nil {
		t.Errorf("Authentication failed with error: %v", err)
	}
	if authenticated {
		t.Error("Expected authentication to fail for inactive user")
	}

	// Test filtering by multiple criteria
	listedUsers, err = ds.ListUsers(ctx, map[string]interface{}{
		"is_active": true,
		"is_admin":  true,
	}, 0, 0)
	if err != nil {
		t.Errorf("Failed to list users with multiple filters: %v", err)
	}

	if len(listedUsers) != 1 {
		t.Errorf("Expected 1 active admin user, got %d", len(listedUsers))
	}

	if len(listedUsers) > 0 && listedUsers[0].Username != "user2" {
		t.Errorf("Expected user2 to be the active admin, got %s", listedUsers[0].Username)
	}

	// Test batch operations
	// Update all users to a new department
	for _, username := range []string{"user1", "user2", "user3"} {
		user, err := ds.GetUser(ctx, username)
		if err != nil {
			t.Errorf("Failed to get user %s: %v", username, err)
			continue
		}

		user.Attributes["department"] = "NewDept"
		if err := ds.UpdateUser(ctx, user); err != nil {
			t.Errorf("Failed to update user %s: %v", username, err)
		}
	}

	// Verify updates
	for _, username := range []string{"user1", "user2", "user3"} {
		user, err := ds.GetUser(ctx, username)
		if err != nil {
			t.Errorf("Failed to get updated user %s: %v", username, err)
			continue
		}

		if dept, ok := user.Attributes["department"].(string); !ok || dept != "NewDept" {
			t.Errorf("Expected department 'NewDept' for user %s, got '%v'", username, user.Attributes["department"])
		}
	}

	// Test error cases
	// Try to create a duplicate user
	if err := ds.CreateUser(ctx, users[0]); err != ErrAlreadyExists {
		t.Errorf("Expected ErrAlreadyExists when creating duplicate user, got %v", err)
	}

	// Try to update a nonexistent user
	nonexistentUser := User{
		Username: "nonexistent",
		Email:    "nonexistent@example.com",
	}
	if err := ds.UpdateUser(ctx, nonexistentUser); err != ErrNotFound {
		t.Errorf("Expected ErrNotFound when updating nonexistent user, got %v", err)
	}

	// Try to delete a nonexistent user
	if err := ds.DeleteUser(ctx, "nonexistent"); err != ErrNotFound {
		t.Errorf("Expected ErrNotFound when deleting nonexistent user, got %v", err)
	}

	// Close the connection and try operations
	if err := ds.Close(); err != nil {
		t.Errorf("Failed to close connection: %v", err)
	}

	_, err = ds.GetUser(ctx, "user1")
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected when using closed datasource, got %v", err)
	}
}
