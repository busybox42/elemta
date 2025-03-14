# Elemta Datasource System

The Elemta Datasource System provides a flexible and extensible way to integrate with various data sources for authentication and user management. This system allows Elemta to connect to different types of databases and directories, including LDAP, MySQL, PostgreSQL, and SQLite.

## Features

- **Unified Interface**: All datasources implement a common interface, making it easy to switch between different backends.
- **Multiple Datasource Support**: Connect to multiple datasources simultaneously and manage them through a central manager.
- **Authentication**: Verify user credentials against the configured datasource.
- **User Management**: Create, retrieve, update, and delete users in the datasource.
- **Group Management**: Manage user group memberships.
- **Custom Queries**: Execute custom queries against the datasource.

## Supported Datasources

- **LDAP**: Connect to LDAP directories for authentication and user management.
- **MySQL**: Use MySQL databases for storing user information.
- **PostgreSQL**: Use PostgreSQL databases for storing user information.
- **SQLite**: Use SQLite for testing or small deployments.
- **Mock**: In-memory datasource for testing purposes.

## Usage

### Configuration

Each datasource requires specific configuration parameters:

```go
// Example configuration for LDAP
ldapConfig := datasource.Config{
    Name:     "company-ldap",
    Type:     "ldap",
    Host:     "ldap.example.com",
    Port:     389,
    Username: "cn=admin,dc=example,dc=com",
    Password: "admin_password",
    Options: map[string]interface{}{
        "base_dn": "dc=example,dc=com",
        "user_dn": "ou=users",
        "group_dn": "ou=groups",
    },
}

// Example configuration for MySQL
mysqlConfig := datasource.Config{
    Name:     "user-db",
    Type:     "mysql",
    Host:     "db.example.com",
    Port:     3306,
    Username: "dbuser",
    Password: "dbpassword",
    Database: "userdb",
    Options: map[string]interface{}{
        "users_table": "users",
        "groups_table": "groups",
    },
}

// Example configuration for SQLite
sqliteConfig := datasource.Config{
    Name: "local-db",
    Type: "sqlite",
    Options: map[string]interface{}{
        "db_path": "/path/to/elemta.db",
    },
}
```

### Creating a Datasource

```go
// Create a datasource using the factory function
ds, err := datasource.Factory(config)
if err != nil {
    log.Fatalf("Failed to create datasource: %v", err)
}

// Connect to the datasource
if err := ds.Connect(); err != nil {
    log.Fatalf("Failed to connect to datasource: %v", err)
}
defer ds.Close()
```

### Using the Datasource Manager

```go
// Create a datasource manager
manager := datasource.NewManager()

// Register datasources
manager.Register("ldap", ldapDS)
manager.Register("mysql", mysqlDS)

// Get a datasource by name
ds, exists := manager.Get("ldap")
if !exists {
    log.Fatal("LDAP datasource not found")
}

// List all registered datasources
datasources := manager.List()
for name, ds := range datasources {
    fmt.Printf("Datasource: %s, Type: %s\n", name, ds.Type())
}

// Remove a datasource
manager.Remove("mysql")

// Close all datasources
manager.CloseAll()
```

### Authentication

```go
// Authenticate a user
authenticated, err := ds.Authenticate(ctx, "username", "password")
if err != nil {
    log.Fatalf("Authentication error: %v", err)
}

if authenticated {
    fmt.Println("Authentication successful")
} else {
    fmt.Println("Authentication failed")
}
```

### User Management

```go
// Create a new user
newUser := datasource.User{
    Username: "newuser",
    FullName: "New User",
    Email:    "newuser@example.com",
    Password: "password123",
    IsActive: true,
    IsAdmin:  false,
    Groups:   []string{"users"},
    Attributes: map[string]interface{}{
        "department": "Engineering",
        "location": "New York",
    },
}

if err := ds.CreateUser(ctx, newUser); err != nil {
    log.Fatalf("Failed to create user: %v", err)
}

// Get user information
user, err := ds.GetUser(ctx, "username")
if err != nil {
    log.Fatalf("Failed to get user: %v", err)
}
fmt.Printf("User: %s, Email: %s\n", user.Username, user.Email)

// Update a user
user.Email = "updated@example.com"
user.Groups = append(user.Groups, "developers")
if err := ds.UpdateUser(ctx, user); err != nil {
    log.Fatalf("Failed to update user: %v", err)
}

// List users
users, err := ds.ListUsers(ctx, nil, 10, 0)
if err != nil {
    log.Fatalf("Failed to list users: %v", err)
}
for _, user := range users {
    fmt.Printf("User: %s, Email: %s\n", user.Username, user.Email)
}

// List users with filter
adminUsers, err := ds.ListUsers(ctx, map[string]interface{}{
    "is_admin": true,
}, 0, 0)
if err != nil {
    log.Fatalf("Failed to list admin users: %v", err)
}
fmt.Printf("Found %d admin users\n", len(adminUsers))

// Delete a user
if err := ds.DeleteUser(ctx, "username"); err != nil {
    log.Fatalf("Failed to delete user: %v", err)
}
```

### Custom Queries

```go
// Execute a custom query
result, err := ds.Query(ctx, "SELECT * FROM users WHERE department = ?", "Engineering")
if err != nil {
    log.Fatalf("Query failed: %v", err)
}

// Process the result
rows, ok := result.([]map[string]interface{})
if ok {
    for _, row := range rows {
        fmt.Printf("Username: %s, Email: %s\n", row["username"], row["email"])
    }
}
```

## Error Handling

The datasource system defines several common errors:

- `ErrNotConnected`: The datasource is not connected.
- `ErrNotFound`: The requested resource was not found.
- `ErrAlreadyExists`: The resource already exists.
- `ErrInvalidCredentials`: The provided credentials are invalid.

Example error handling:

```go
user, err := ds.GetUser(ctx, "nonexistentuser")
if err == datasource.ErrNotFound {
    fmt.Println("User does not exist")
} else if err != nil {
    log.Fatalf("Error: %v", err)
}
```

## Testing

The datasource system includes a mock implementation for testing purposes:

```go
// Create a mock datasource
mockDS := datasource.NewMockDataSource("test-mock")

// Add test users
mockDS.AddMockUser(datasource.User{
    Username: "testuser",
    Password: "password",
    IsActive: true,
})

// Use the mock datasource in tests
authenticated, err := mockDS.Authenticate(ctx, "testuser", "password")
if err != nil || !authenticated {
    t.Fatal("Authentication failed")
}
```

## Extending the System

To add a new datasource type:

1. Implement the `DataSource` interface
2. Update the `Factory` function to recognize the new type
3. Add appropriate configuration options

Example of a new datasource implementation:

```go
type CustomDataSource struct {
    config    Config
    connected bool
    // Other fields as needed
}

func NewCustomDataSource(config Config) *CustomDataSource {
    return &CustomDataSource{
        config:    config,
        connected: false,
    }
}

// Implement all methods required by the DataSource interface
func (c *CustomDataSource) Connect() error {
    // Implementation
}

// Add to the Factory function
func Factory(config Config) (DataSource, error) {
    switch config.Type {
    // Existing cases
    case "custom":
        return NewCustomDataSource(config), nil
    default:
        return nil, fmt.Errorf("unknown datasource type: %s", config.Type)
    }
}
``` 