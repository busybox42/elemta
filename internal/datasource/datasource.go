package datasource

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Common errors
var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrNotConnected  = errors.New("not connected to datasource")
	ErrNotSupported  = errors.New("operation not supported by this datasource")
)

// DataSource defines the interface that all datasource implementations must satisfy
type DataSource interface {
	// Connect establishes a connection to the datasource
	Connect() error

	// Close closes the connection to the datasource
	Close() error

	// IsConnected returns true if the datasource is connected
	IsConnected() bool

	// Name returns the name of the datasource
	Name() string

	// Type returns the type of the datasource (e.g., "mysql", "ldap", etc.)
	Type() string

	// Authenticate verifies credentials against the datasource
	Authenticate(ctx context.Context, username, password string) (bool, error)

	// GetUser retrieves user information from the datasource
	GetUser(ctx context.Context, username string) (User, error)

	// ListUsers retrieves a list of users from the datasource
	ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error)

	// CreateUser creates a new user in the datasource
	CreateUser(ctx context.Context, user User) error

	// UpdateUser updates an existing user in the datasource
	UpdateUser(ctx context.Context, user User) error

	// DeleteUser deletes a user from the datasource
	DeleteUser(ctx context.Context, username string) error

	// Query executes a custom query against the datasource
	Query(ctx context.Context, query string, args ...interface{}) (interface{}, error)
}

// User represents a user in the system
type User struct {
	Username    string
	Password    string // Hashed password, not stored in clear text
	Email       string
	FullName    string
	IsActive    bool
	IsAdmin     bool
	Groups      []string
	Attributes  map[string]interface{}
	CreatedAt   int64
	UpdatedAt   int64
	LastLoginAt int64
}

// Config represents the configuration for a datasource
type Config struct {
	Type     string                 // Type of datasource (mysql, postgres, ldap, etc.)
	Name     string                 // Name of this datasource instance
	Host     string                 // Hostname or IP address
	Port     int                    // Port number
	Database string                 // Database name (for SQL datasources)
	Username string                 // Username for authentication
	Password string                 // Password for authentication
	Options  map[string]interface{} // Additional options specific to the datasource type
}

// Manager manages multiple datasources
type Manager struct {
	datasources map[string]DataSource
	mu          sync.RWMutex
}

// NewManager creates a new datasource manager
func NewManager() *Manager {
	return &Manager{
		datasources: make(map[string]DataSource),
	}
}

// Register adds a datasource to the manager
func (m *Manager) Register(ds DataSource) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := ds.Name()
	if _, exists := m.datasources[name]; exists {
		return fmt.Errorf("datasource with name '%s' already registered", name)
	}

	m.datasources[name] = ds
	return nil
}

// Get retrieves a datasource by name
func (m *Manager) Get(name string) (DataSource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ds, exists := m.datasources[name]
	if !exists {
		return nil, fmt.Errorf("datasource '%s' not found", name)
	}

	return ds, nil
}

// List returns all registered datasources
func (m *Manager) List() []DataSource {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]DataSource, 0, len(m.datasources))
	for _, ds := range m.datasources {
		result = append(result, ds)
	}

	return result
}

// Remove removes a datasource from the manager
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ds, exists := m.datasources[name]
	if !exists {
		return fmt.Errorf("datasource '%s' not found", name)
	}

	if ds.IsConnected() {
		if err := ds.Close(); err != nil {
			return fmt.Errorf("failed to close datasource '%s': %w", name, err)
		}
	}

	delete(m.datasources, name)
	return nil
}

// CloseAll closes all datasources
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, ds := range m.datasources {
		if ds.IsConnected() {
			if err := ds.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close datasource '%s': %w", name, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing datasources: %v", errs)
	}

	return nil
}

// Factory creates datasources based on configuration
func Factory(config Config) (DataSource, error) {
	switch config.Type {
	case "mysql":
		return NewMySQL(config), nil
	case "postgres":
		return NewPostgres(config), nil
	case "sqlite":
		return NewSQLite(config), nil
	case "ldap":
		return NewLDAP(config), nil
	case "mock":
		return NewMockDataSource(config.Name), nil
	default:
		return nil, fmt.Errorf("unsupported datasource type: %s", config.Type)
	}
}
