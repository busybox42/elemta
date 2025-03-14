package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/busybox42/elemta/internal/datasource"
)

// TestIntegrationSQLite tests the SQLite datasource with a real database
func TestIntegrationSQLite(t *testing.T) {
	// Create a temporary directory for the test database
	tempDir, err := os.MkdirTemp("", "elemta-integration-sqlite")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a SQLite datasource
	config := datasource.Config{
		Name: "integration-sqlite",
		Type: "sqlite",
		Options: map[string]interface{}{
			"db_path": tempDir + "/test.db",
		},
	}

	ds, err := datasource.Factory(config)
	if err != nil {
		t.Fatalf("Failed to create SQLite datasource: %v", err)
	}

	// Run the integration tests
	runIntegrationTests(t, ds)
}

// TestIntegrationMySQL tests the MySQL datasource with a real database
func TestIntegrationMySQL(t *testing.T) {
	// Skip the test if no MySQL server is available
	mysqlHost := os.Getenv("TEST_MYSQL_HOST")
	if mysqlHost == "" {
		t.Skip("Skipping MySQL integration test as TEST_MYSQL_HOST environment variable is not set")
	}

	// Get MySQL connection details from environment variables or use defaults
	mysqlPort := 3306
	mysqlUser := os.Getenv("TEST_MYSQL_USER")
	if mysqlUser == "" {
		mysqlUser = "root"
	}
	mysqlPassword := os.Getenv("TEST_MYSQL_PASSWORD")
	mysqlDatabase := os.Getenv("TEST_MYSQL_DATABASE")
	if mysqlDatabase == "" {
		mysqlDatabase = "elemta_test"
	}

	// Create a MySQL datasource
	config := datasource.Config{
		Name:     "integration-mysql",
		Type:     "mysql",
		Host:     mysqlHost,
		Port:     mysqlPort,
		Database: mysqlDatabase,
		Username: mysqlUser,
		Password: mysqlPassword,
	}

	ds, err := datasource.Factory(config)
	if err != nil {
		t.Fatalf("Failed to create MySQL datasource: %v", err)
	}

	// Run the integration tests
	runIntegrationTests(t, ds)
}

// TestIntegrationPostgres tests the PostgreSQL datasource with a real database
func TestIntegrationPostgres(t *testing.T) {
	// Skip the test if no PostgreSQL server is available
	pgHost := os.Getenv("TEST_PG_HOST")
	if pgHost == "" {
		t.Skip("Skipping PostgreSQL integration test as TEST_PG_HOST environment variable is not set")
	}

	// Get PostgreSQL connection details from environment variables or use defaults
	pgPort := 5432
	pgUser := os.Getenv("TEST_PG_USER")
	if pgUser == "" {
		pgUser = "postgres"
	}
	pgPassword := os.Getenv("TEST_PG_PASSWORD")
	pgDatabase := os.Getenv("TEST_PG_DATABASE")
	if pgDatabase == "" {
		pgDatabase = "elemta_test"
	}

	// Create a PostgreSQL datasource
	config := datasource.Config{
		Name:     "integration-postgres",
		Type:     "postgres",
		Host:     pgHost,
		Port:     pgPort,
		Database: pgDatabase,
		Username: pgUser,
		Password: pgPassword,
	}

	ds, err := datasource.Factory(config)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL datasource: %v", err)
	}

	// Run the integration tests
	runIntegrationTests(t, ds)
}

// runIntegrationTests runs a series of integration tests on the provided datasource
func runIntegrationTests(t *testing.T, ds datasource.DataSource) {
	// Ensure the datasource is closed at the end of the test
	defer func() {
		if ds.IsConnected() {
			ds.Close()
		}
	}()

	// Connect to the datasource
	err := ds.Connect()
	if err != nil {
		t.Fatalf("Failed to connect to datasource: %v", err)
	}

	if !ds.IsConnected() {
		t.Fatal("Expected IsConnected() to return true after Connect()")
	}

	// Create a context for operations
	ctx := context.Background()

	// Test user operations
	testUserOperations(t, ctx, ds)

	// Test group operations
	testGroupOperations(t, ctx, ds)

	// Test query operations
	testQueryOperations(t, ctx, ds)

	// Close the datasource
	err = ds.Close()
	if err != nil {
		t.Fatalf("Failed to close datasource: %v", err)
	}

	if ds.IsConnected() {
		t.Fatal("Expected IsConnected() to return false after Close()")
	}
}

// testUserOperations tests user-related operations on the datasource
func testUserOperations(t *testing.T, ctx context.Context, ds datasource.DataSource) {
	t.Logf("Testing user operations on %s datasource", ds.Type())

	// Create a test user
	testUser := datasource.User{
		Username: "integration-test-user",
		FullName: "Integration Test User",
		Email:    "integration@example.com",
		Password: "integration-password",
		IsActive: true,
		IsAdmin:  false,
		Groups:   []string{"users"},
		Attributes: map[string]interface{}{
			"department": "Testing",
			"location":   "Integration",
		},
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}

	// Delete the user if it already exists
	_ = ds.DeleteUser(ctx, testUser.Username)

	// Create the user
	err := ds.CreateUser(ctx, testUser)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Try to create the same user again, should fail with ErrAlreadyExists
	err = ds.CreateUser(ctx, testUser)
	if err == nil {
		t.Fatal("Expected error when creating duplicate user, got nil")
	}

	// Get the user
	user, err := ds.GetUser(ctx, testUser.Username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if user.Username != testUser.Username {
		t.Errorf("Expected username %s, got %s", testUser.Username, user.Username)
	}

	// Authenticate the user
	authenticated, err := ds.Authenticate(ctx, testUser.Username, testUser.Password)
	if err != nil {
		t.Fatalf("Authentication failed with error: %v", err)
	}

	if !authenticated {
		t.Error("Authentication failed with correct password")
	}

	// Update the user
	updatedUser := testUser
	updatedUser.FullName = "Updated Integration Test User"
	updatedUser.Email = "updated-integration@example.com"
	updatedUser.IsAdmin = true
	updatedUser.Groups = []string{"users", "admins"}
	updatedUser.Attributes["title"] = "Senior Test Engineer"
	updatedUser.UpdatedAt = time.Now().Unix()

	err = ds.UpdateUser(ctx, updatedUser)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	// Get the updated user
	updatedUserFromDB, err := ds.GetUser(ctx, testUser.Username)
	if err != nil {
		t.Fatalf("Failed to get updated user: %v", err)
	}

	if updatedUserFromDB.FullName != updatedUser.FullName {
		t.Errorf("Expected updated full name %s, got %s", updatedUser.FullName, updatedUserFromDB.FullName)
	}

	// Create another user
	anotherUser := datasource.User{
		Username:  "another-integration-user",
		FullName:  "Another Integration User",
		Email:     "another-integration@example.com",
		Password:  "another-password",
		IsActive:  true,
		IsAdmin:   false,
		Groups:    []string{"users"},
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}

	// Delete the user if it already exists
	_ = ds.DeleteUser(ctx, anotherUser.Username)

	err = ds.CreateUser(ctx, anotherUser)
	if err != nil {
		t.Fatalf("Failed to create another user: %v", err)
	}

	// List all users
	users, err := ds.ListUsers(ctx, nil, 0, 0)
	if err != nil {
		t.Fatalf("Failed to list users: %v", err)
	}

	if len(users) < 2 {
		t.Errorf("Expected at least 2 users, got %d", len(users))
	}

	// List users with filter
	filteredUsers, err := ds.ListUsers(ctx, map[string]interface{}{
		"username": testUser.Username,
	}, 0, 0)
	if err != nil {
		t.Fatalf("Failed to list users with filter: %v", err)
	}

	if len(filteredUsers) != 1 {
		t.Errorf("Expected 1 user with filter, got %d", len(filteredUsers))
	}

	// Delete the users
	err = ds.DeleteUser(ctx, testUser.Username)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}

	err = ds.DeleteUser(ctx, anotherUser.Username)
	if err != nil {
		t.Fatalf("Failed to delete another user: %v", err)
	}

	// Verify the users are deleted
	_, err = ds.GetUser(ctx, testUser.Username)
	if err != datasource.ErrNotFound {
		t.Errorf("Expected ErrNotFound for deleted user, got %v", err)
	}
}

// testGroupOperations tests group-related operations on the datasource
func testGroupOperations(t *testing.T, ctx context.Context, ds datasource.DataSource) {
	t.Logf("Testing group operations on %s datasource", ds.Type())

	// Create a test user with groups
	testUser := datasource.User{
		Username:  "group-test-user",
		FullName:  "Group Test User",
		Email:     "group-test@example.com",
		Password:  "group-password",
		IsActive:  true,
		IsAdmin:   false,
		Groups:    []string{"group1", "group2"},
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}

	// Delete the user if it already exists
	_ = ds.DeleteUser(ctx, testUser.Username)

	// Create the user
	err := ds.CreateUser(ctx, testUser)
	if err != nil {
		t.Fatalf("Failed to create user with groups: %v", err)
	}

	// Get the user and check groups
	user, err := ds.GetUser(ctx, testUser.Username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	// Check if user is in the correct groups
	foundGroup1 := false
	foundGroup2 := false
	for _, group := range user.Groups {
		if group == "group1" {
			foundGroup1 = true
		}
		if group == "group2" {
			foundGroup2 = true
		}
	}

	if !foundGroup1 {
		t.Errorf("User is not in 'group1'")
	}

	if !foundGroup2 {
		t.Errorf("User is not in 'group2'")
	}

	// Update user groups
	updatedUser := user
	updatedUser.Groups = []string{"group1", "group3"}
	updatedUser.UpdatedAt = time.Now().Unix()

	err = ds.UpdateUser(ctx, updatedUser)
	if err != nil {
		t.Fatalf("Failed to update user groups: %v", err)
	}

	// Get the updated user and check groups
	updatedUserFromDB, err := ds.GetUser(ctx, testUser.Username)
	if err != nil {
		t.Fatalf("Failed to get updated user: %v", err)
	}

	// Check if user is in the correct groups after update
	foundGroup1 = false
	foundGroup2 = false
	foundGroup3 := false
	for _, group := range updatedUserFromDB.Groups {
		if group == "group1" {
			foundGroup1 = true
		}
		if group == "group2" {
			foundGroup2 = true
		}
		if group == "group3" {
			foundGroup3 = true
		}
	}

	if !foundGroup1 {
		t.Errorf("User is not in 'group1' after update")
	}

	if foundGroup2 {
		t.Errorf("User is still in 'group2' after update")
	}

	if !foundGroup3 {
		t.Errorf("User is not in 'group3' after update")
	}

	// Delete the user
	err = ds.DeleteUser(ctx, testUser.Username)
	if err != nil {
		t.Fatalf("Failed to delete test user: %v", err)
	}
}

// testQueryOperations tests custom query operations on the datasource
func testQueryOperations(t *testing.T, ctx context.Context, ds datasource.DataSource) {
	t.Logf("Testing query operations on %s datasource", ds.Type())

	// Create test users
	for i := 1; i <= 5; i++ {
		user := datasource.User{
			Username:  fmt.Sprintf("query-test-user-%d", i),
			FullName:  fmt.Sprintf("Query Test User %d", i),
			Email:     fmt.Sprintf("query-test-%d@example.com", i),
			Password:  "query-password",
			IsActive:  true,
			IsAdmin:   i == 1, // Make the first user an admin
			Groups:    []string{"query-users"},
			CreatedAt: time.Now().Unix(),
			UpdatedAt: time.Now().Unix(),
		}

		// Delete the user if it already exists
		_ = ds.DeleteUser(ctx, user.Username)

		// Create the user
		err := ds.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("Failed to create query test user: %v", err)
		}
	}

	// Execute a custom query
	var query string
	switch ds.Type() {
	case "sqlite":
		query = "SELECT username, email FROM users WHERE username LIKE 'query-test-user-%'"
	case "mysql":
		query = "SELECT username, email FROM users WHERE username LIKE 'query-test-user-%'"
	case "postgres":
		query = "SELECT username, email FROM users WHERE username LIKE 'query-test-user-%'"
	default:
		t.Skipf("Query not supported for datasource type: %s", ds.Type())
		return
	}

	result, err := ds.Query(ctx, query)
	if err != nil {
		t.Fatalf("Failed to execute query: %v", err)
	}

	rows, ok := result.([]map[string]interface{})
	if !ok {
		t.Fatalf("Expected result to be []map[string]interface{}, got %T", result)
	}

	if len(rows) != 5 {
		t.Errorf("Expected 5 rows in query result, got %d", len(rows))
	}

	// Clean up test users
	for i := 1; i <= 5; i++ {
		username := fmt.Sprintf("query-test-user-%d", i)
		err := ds.DeleteUser(ctx, username)
		if err != nil {
			t.Fatalf("Failed to delete query test user: %v", err)
		}
	}
}
