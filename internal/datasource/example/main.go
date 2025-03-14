package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/busybox42/elemta/internal/datasource"
)

func main() {
	// Create a temporary directory for the SQLite database
	tempDir, err := os.MkdirTemp("", "elemta-example")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "elemta.db")

	// Create a datasource manager
	manager := datasource.NewManager()

	// Create a SQLite datasource for testing
	sqliteConfig := datasource.Config{
		Name: "local-db",
		Type: "sqlite",
		Options: map[string]interface{}{
			"db_path": dbPath,
		},
	}

	// Create the datasource using the factory
	sqliteDS, err := datasource.Factory(sqliteConfig)
	if err != nil {
		log.Fatalf("Failed to create SQLite datasource: %v", err)
	}

	// Connect to the datasource
	if err := sqliteDS.Connect(); err != nil {
		log.Fatalf("Failed to connect to SQLite datasource: %v", err)
	}

	// Register the datasource with the manager
	manager.Register(sqliteDS)

	// Create a mock datasource for testing
	mockConfig := datasource.Config{
		Name: "mock-db",
		Type: "mock",
	}

	mockDS, err := datasource.Factory(mockConfig)
	if err != nil {
		log.Fatalf("Failed to create mock datasource: %v", err)
	}

	// Connect to the mock datasource
	if err := mockDS.Connect(); err != nil {
		log.Fatalf("Failed to connect to mock datasource: %v", err)
	}

	// Register the mock datasource with the manager
	manager.Register(mockDS)

	// List all registered datasources
	fmt.Println("Registered datasources:")
	datasources := manager.List()
	for _, ds := range datasources {
		fmt.Printf("- %s (%s): connected=%v\n", ds.Name(), ds.Type(), ds.IsConnected())
	}

	// Create a context for operations
	ctx := context.Background()

	// Create a test user in the SQLite datasource
	testUser := datasource.User{
		Username: "testuser",
		FullName: "Test User",
		Email:    "testuser@example.com",
		Password: "password123",
		IsActive: true,
		IsAdmin:  false,
		Groups:   []string{"users"},
		Attributes: map[string]interface{}{
			"department": "Engineering",
			"location":   "New York",
		},
	}

	var ds datasource.DataSource
	ds, err = manager.Get("local-db")
	if err != nil {
		log.Fatalf("SQLite datasource not found: %v", err)
	}
	sqliteDS = ds

	fmt.Println("\nCreating test user in SQLite datasource...")
	if err := sqliteDS.CreateUser(ctx, testUser); err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	// Authenticate the user
	fmt.Println("Authenticating user...")
	authenticated, err := sqliteDS.Authenticate(ctx, testUser.Username, testUser.Password)
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}

	if authenticated {
		fmt.Println("Authentication successful")
	} else {
		fmt.Println("Authentication failed")
	}

	// Get user information
	fmt.Println("\nRetrieving user information...")
	user, err := sqliteDS.GetUser(ctx, testUser.Username)
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}

	fmt.Printf("User: %s\n", user.Username)
	fmt.Printf("Full Name: %s\n", user.FullName)
	fmt.Printf("Email: %s\n", user.Email)
	fmt.Printf("Active: %v\n", user.IsActive)
	fmt.Printf("Admin: %v\n", user.IsAdmin)
	fmt.Printf("Groups: %v\n", user.Groups)
	fmt.Printf("Attributes: %v\n", user.Attributes)

	// Update the user
	fmt.Println("\nUpdating user...")
	user.FullName = "Updated Test User"
	user.Email = "updated@example.com"
	user.IsAdmin = true
	user.Groups = append(user.Groups, "admins")
	user.Attributes["title"] = "Senior Engineer"

	if err := sqliteDS.UpdateUser(ctx, user); err != nil {
		log.Fatalf("Failed to update user: %v", err)
	}

	// Get updated user information
	fmt.Println("Retrieving updated user information...")
	updatedUser, err := sqliteDS.GetUser(ctx, testUser.Username)
	if err != nil {
		log.Fatalf("Failed to get updated user: %v", err)
	}

	fmt.Printf("User: %s\n", updatedUser.Username)
	fmt.Printf("Full Name: %s\n", updatedUser.FullName)
	fmt.Printf("Email: %s\n", updatedUser.Email)
	fmt.Printf("Active: %v\n", updatedUser.IsActive)
	fmt.Printf("Admin: %v\n", updatedUser.IsAdmin)
	fmt.Printf("Groups: %v\n", updatedUser.Groups)
	fmt.Printf("Attributes: %v\n", updatedUser.Attributes)

	// Create another user
	anotherUser := datasource.User{
		Username: "anotheruser",
		FullName: "Another User",
		Email:    "another@example.com",
		Password: "password456",
		IsActive: true,
		Groups:   []string{"users"},
	}

	fmt.Println("\nCreating another user...")
	if err := sqliteDS.CreateUser(ctx, anotherUser); err != nil {
		log.Fatalf("Failed to create another user: %v", err)
	}

	// List all users
	fmt.Println("\nListing all users...")
	users, err := sqliteDS.ListUsers(ctx, nil, 0, 0)
	if err != nil {
		log.Fatalf("Failed to list users: %v", err)
	}

	for i, u := range users {
		fmt.Printf("%d. %s (%s)\n", i+1, u.Username, u.Email)
	}

	// List admin users
	fmt.Println("\nListing admin users...")
	adminUsers, err := sqliteDS.ListUsers(ctx, map[string]interface{}{
		"is_admin": true,
	}, 0, 0)
	if err != nil {
		log.Fatalf("Failed to list admin users: %v", err)
	}

	for i, u := range adminUsers {
		fmt.Printf("%d. %s (%s)\n", i+1, u.Username, u.Email)
	}

	// Execute a custom query
	fmt.Println("\nExecuting custom query...")
	result, err := sqliteDS.Query(ctx, "SELECT username, email FROM users")
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}

	// Type assertion for the result
	rows, ok := result.([]map[string]interface{})
	if !ok {
		log.Fatalf("Unexpected result type: %T", result)
	}

	for i, row := range rows {
		fmt.Printf("%d. Username: %s, Email: %s\n", i+1, row["username"], row["email"])
	}

	// Delete users
	fmt.Println("\nDeleting users...")
	if err := sqliteDS.DeleteUser(ctx, testUser.Username); err != nil {
		log.Fatalf("Failed to delete test user: %v", err)
	}

	if err := sqliteDS.DeleteUser(ctx, anotherUser.Username); err != nil {
		log.Fatalf("Failed to delete another user: %v", err)
	}

	// Verify users are deleted
	fmt.Println("Verifying users are deleted...")
	_, err = sqliteDS.GetUser(ctx, testUser.Username)
	if err == datasource.ErrNotFound {
		fmt.Printf("User %s was successfully deleted\n", testUser.Username)
	} else if err != nil {
		log.Fatalf("Error checking deleted user: %v", err)
	} else {
		fmt.Printf("User %s still exists\n", testUser.Username)
	}

	// Close all datasources
	fmt.Println("\nClosing all datasources...")
	manager.CloseAll()

	fmt.Println("Example completed successfully")
}
