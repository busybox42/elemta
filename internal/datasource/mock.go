package datasource

import (
	"context"
	"sync"
	"time"
)

// MockDataSource implements the DataSource interface for testing
type MockDataSource struct {
	name       string
	connected  bool
	users      map[string]User
	usersMutex sync.RWMutex
}

// NewMockDataSource creates a new mock datasource
func NewMockDataSource(name string) *MockDataSource {
	return &MockDataSource{
		name:      name,
		connected: false,
		users:     make(map[string]User),
	}
}

// Connect establishes a connection to the mock datasource
func (m *MockDataSource) Connect() error {
	m.connected = true
	return nil
}

// Close closes the connection to the mock datasource
func (m *MockDataSource) Close() error {
	m.connected = false
	return nil
}

// IsConnected returns true if the datasource is connected
func (m *MockDataSource) IsConnected() bool {
	return m.connected
}

// Name returns the name of the datasource
func (m *MockDataSource) Name() string {
	return m.name
}

// Type returns the type of the datasource
func (m *MockDataSource) Type() string {
	return "mock"
}

// Authenticate verifies credentials against the mock datasource
func (m *MockDataSource) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !m.connected {
		return false, ErrNotConnected
	}

	m.usersMutex.RLock()
	defer m.usersMutex.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return false, nil
	}

	// In a real implementation, you would use a secure password hashing algorithm
	// This is a simplified example for testing
	return user.Password == password && user.IsActive, nil
}

// GetUser retrieves user information from the mock datasource
func (m *MockDataSource) GetUser(ctx context.Context, username string) (User, error) {
	if !m.connected {
		return User{}, ErrNotConnected
	}

	m.usersMutex.RLock()
	defer m.usersMutex.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return User{}, ErrNotFound
	}

	return user, nil
}

// ListUsers retrieves a list of users from the mock datasource
func (m *MockDataSource) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !m.connected {
		return nil, ErrNotConnected
	}

	m.usersMutex.RLock()
	defer m.usersMutex.RUnlock()

	var users []User
	var count int

	// Apply filters (simplified)
	for _, user := range m.users {
		// Skip users that don't match the filter
		if filter != nil {
			match := true
			for key, value := range filter {
				switch key {
				case "username":
					if user.Username != value.(string) {
						match = false
					}
				case "email":
					if user.Email != value.(string) {
						match = false
					}
				case "is_active":
					if user.IsActive != value.(bool) {
						match = false
					}
				case "is_admin":
					if user.IsAdmin != value.(bool) {
						match = false
					}
				}
			}
			if !match {
				continue
			}
		}

		// Apply pagination
		if offset > 0 && count < offset {
			count++
			continue
		}

		users = append(users, user)
		count++

		// Apply limit
		if limit > 0 && len(users) >= limit {
			break
		}
	}

	return users, nil
}

// CreateUser creates a new user in the mock datasource
func (m *MockDataSource) CreateUser(ctx context.Context, user User) error {
	if !m.connected {
		return ErrNotConnected
	}

	m.usersMutex.Lock()
	defer m.usersMutex.Unlock()

	if _, exists := m.users[user.Username]; exists {
		return ErrAlreadyExists
	}

	// Set timestamps if not provided
	now := time.Now().Unix()
	if user.CreatedAt == 0 {
		user.CreatedAt = now
	}
	if user.UpdatedAt == 0 {
		user.UpdatedAt = now
	}

	m.users[user.Username] = user
	return nil
}

// UpdateUser updates an existing user in the mock datasource
func (m *MockDataSource) UpdateUser(ctx context.Context, user User) error {
	if !m.connected {
		return ErrNotConnected
	}

	m.usersMutex.Lock()
	defer m.usersMutex.Unlock()

	if _, exists := m.users[user.Username]; !exists {
		return ErrNotFound
	}

	// Update timestamp
	user.UpdatedAt = time.Now().Unix()

	m.users[user.Username] = user
	return nil
}

// DeleteUser deletes a user from the mock datasource
func (m *MockDataSource) DeleteUser(ctx context.Context, username string) error {
	if !m.connected {
		return ErrNotConnected
	}

	m.usersMutex.Lock()
	defer m.usersMutex.Unlock()

	if _, exists := m.users[username]; !exists {
		return ErrNotFound
	}

	delete(m.users, username)
	return nil
}

// Query executes a custom query against the mock datasource
func (m *MockDataSource) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	// For the mock implementation, we'll just return a simple response
	return map[string]interface{}{
		"success": true,
		"message": "Mock query executed",
	}, nil
}

// AddMockUser adds a user to the mock datasource for testing
func (m *MockDataSource) AddMockUser(user User) {
	m.usersMutex.Lock()
	defer m.usersMutex.Unlock()

	// Set timestamps if not provided
	now := time.Now().Unix()
	if user.CreatedAt == 0 {
		user.CreatedAt = now
	}
	if user.UpdatedAt == 0 {
		user.UpdatedAt = now
	}

	m.users[user.Username] = user
}
