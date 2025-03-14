package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/busybox42/elemta/internal/datasource"
	"golang.org/x/crypto/bcrypt"
)

// Common errors
var (
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserExists             = errors.New("user already exists")
	ErrDataSourceNotConnected = errors.New("datasource not connected")
	ErrInvalidPassword        = errors.New("invalid password format")
)

// Auth provides authentication functionality using SQLite datasource
type Auth struct {
	ds datasource.DataSource
}

// Config represents the configuration for the Auth module
type Config struct {
	// DataSource is the datasource to use for authentication
	DataSource datasource.DataSource
}

// New creates a new Auth instance with the provided configuration
func New(config Config) (*Auth, error) {
	if config.DataSource == nil {
		return nil, errors.New("datasource is required")
	}

	// Ensure the datasource is connected
	if !config.DataSource.IsConnected() {
		if err := config.DataSource.Connect(); err != nil {
			return nil, fmt.Errorf("failed to connect to datasource: %w", err)
		}
	}

	return &Auth{
		ds: config.DataSource,
	}, nil
}

// NewWithSQLite creates a new Auth instance with a SQLite datasource
func NewWithSQLite(dbPath string) (*Auth, error) {
	// Create SQLite datasource
	config := datasource.Config{
		Type:     "sqlite",
		Name:     "auth-sqlite",
		Database: "auth.db",
		Options: map[string]interface{}{
			"db_path": dbPath,
		},
	}

	ds := datasource.NewSQLite(config)
	if err := ds.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite datasource: %w", err)
	}

	return &Auth{
		ds: ds,
	}, nil
}

// Close closes the underlying datasource connection
func (a *Auth) Close() error {
	if a.ds != nil {
		return a.ds.Close()
	}
	return nil
}

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrInvalidPassword
	}

	// Generate bcrypt hash with default cost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// ComparePasswords compares a hashed password with a plain-text password
func ComparePasswords(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

// Authenticate verifies a username and password
func (a *Auth) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !a.ds.IsConnected() {
		return false, ErrDataSourceNotConnected
	}

	// Get the user from the datasource
	user, err := a.ds.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, datasource.ErrNotFound) {
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	// Compare the provided password with the stored hash
	err = ComparePasswords(user.Password, password)
	if err != nil {
		return false, ErrInvalidCredentials
	}

	// Update last login time
	user.LastLoginAt = time.Now().Unix()
	if err := a.ds.UpdateUser(ctx, user); err != nil {
		// Non-critical error, just log it in a real application
		// For now, we'll ignore it and continue
	}

	return true, nil
}

// CreateUser creates a new user with a hashed password
func (a *Auth) CreateUser(ctx context.Context, username, password, email, fullName string, isAdmin bool) error {
	if !a.ds.IsConnected() {
		return ErrDataSourceNotConnected
	}

	// Check if user already exists
	_, err := a.ds.GetUser(ctx, username)
	if err == nil {
		return ErrUserExists
	} else if !errors.Is(err, datasource.ErrNotFound) {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	// Hash the password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	// Create the user
	now := time.Now().Unix()
	user := datasource.User{
		Username:    username,
		Password:    hashedPassword,
		Email:       email,
		FullName:    fullName,
		IsActive:    true,
		IsAdmin:     isAdmin,
		Groups:      []string{},
		Attributes:  make(map[string]interface{}),
		CreatedAt:   now,
		UpdatedAt:   now,
		LastLoginAt: 0,
	}

	if err := a.ds.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password
func (a *Auth) UpdatePassword(ctx context.Context, username, currentPassword, newPassword string) error {
	if !a.ds.IsConnected() {
		return ErrDataSourceNotConnected
	}

	// First authenticate the user with the current password
	authenticated, err := a.Authenticate(ctx, username, currentPassword)
	if err != nil {
		return err
	}
	if !authenticated {
		return ErrInvalidCredentials
	}

	// Get the user
	user, err := a.ds.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, datasource.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Hash the new password
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update the user
	user.Password = hashedPassword
	user.UpdatedAt = time.Now().Unix()

	if err := a.ds.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// AdminUpdatePassword allows an admin to update a user's password without knowing the current password
func (a *Auth) AdminUpdatePassword(ctx context.Context, username, newPassword string) error {
	if !a.ds.IsConnected() {
		return ErrDataSourceNotConnected
	}

	// Get the user
	user, err := a.ds.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, datasource.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Hash the new password
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update the user
	user.Password = hashedPassword
	user.UpdatedAt = time.Now().Unix()

	if err := a.ds.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UserExists checks if a user exists
func (a *Auth) UserExists(ctx context.Context, username string) (bool, error) {
	if !a.ds.IsConnected() {
		return false, ErrDataSourceNotConnected
	}

	_, err := a.ds.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, datasource.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if user exists: %w", err)
	}

	return true, nil
}

// DeleteUser deletes a user
func (a *Auth) DeleteUser(ctx context.Context, username string) error {
	if !a.ds.IsConnected() {
		return ErrDataSourceNotConnected
	}

	// Check if user exists
	exists, err := a.UserExists(ctx, username)
	if err != nil {
		return err
	}
	if !exists {
		return ErrUserNotFound
	}

	// Delete the user
	if err := a.ds.DeleteUser(ctx, username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// GetUser retrieves a user's information
func (a *Auth) GetUser(ctx context.Context, username string) (datasource.User, error) {
	if !a.ds.IsConnected() {
		return datasource.User{}, ErrDataSourceNotConnected
	}

	user, err := a.ds.GetUser(ctx, username)
	if err != nil {
		if errors.Is(err, datasource.ErrNotFound) {
			return datasource.User{}, ErrUserNotFound
		}
		return datasource.User{}, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}
