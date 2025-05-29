package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"strings"

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

// Auth provides authentication functionality using various datasources
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

// NewWithLDAP creates a new Auth instance with an LDAP datasource
func NewWithLDAP(host string, port int, bindDN, bindPassword, userDN, groupDN string, options map[string]interface{}) (*Auth, error) {
	// Create LDAP datasource
	config := datasource.Config{
		Type:     "ldap",
		Name:     "auth-ldap",
		Host:     host,
		Port:     port,
		Username: bindDN,
		Password: bindPassword,
		Options:  options,
	}

	// Add user and group DNs to options if not already present
	if config.Options == nil {
		config.Options = make(map[string]interface{})
	}

	if _, ok := config.Options["user_dn"]; !ok && userDN != "" {
		config.Options["user_dn"] = userDN
	}

	if _, ok := config.Options["group_dn"]; !ok && groupDN != "" {
		config.Options["group_dn"] = groupDN
	}

	ds := datasource.NewLDAP(config)
	if err := ds.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP datasource: %w", err)
	}

	return &Auth{
		ds: ds,
	}, nil
}

// NewFromEnv creates a new Auth instance using environment variables
func NewFromEnv() (*Auth, error) {
	// Get datasource type from environment
	dsType := os.Getenv("AUTH_DATASOURCE_TYPE")
	if dsType == "" {
		dsType = "sqlite" // Default to SQLite if not specified
	}

	switch dsType {
	case "sqlite":
		// Get SQLite path from environment
		sqlitePath := os.Getenv("AUTH_SQLITE_PATH")
		if sqlitePath == "" {
			sqlitePath = "/app/config/auth.db" // Default path
		}
		return NewWithSQLite(sqlitePath)

	case "ldap":
		// Get LDAP configuration from environment
		host := os.Getenv("AUTH_LDAP_HOST")
		if host == "" {
			return nil, errors.New("LDAP host not specified in environment")
		}

		portStr := os.Getenv("AUTH_LDAP_PORT")
		port := 389 // Default LDAP port
		if portStr != "" {
			var err error
			port, err = strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid LDAP port: %w", err)
			}
		}

		bindDN := os.Getenv("AUTH_LDAP_BIND_DN")
		bindPassword := os.Getenv("AUTH_LDAP_BIND_PASSWORD")
		userDN := os.Getenv("AUTH_LDAP_USER_DN")
		groupDN := os.Getenv("AUTH_LDAP_GROUP_DN")

		options := make(map[string]interface{})
		return NewWithLDAP(host, port, bindDN, bindPassword, userDN, groupDN, options)

	case "file":
		filePath := os.Getenv("AUTH_FILE_PATH")
		if filePath == "" {
			filePath = "/app/config/users.txt"
		}
		return NewWithFile(filePath)

	default:
		return nil, fmt.Errorf("unsupported datasource type: %s", dsType)
	}
}

// NewWithFile creates a new Auth instance with a flat file datasource
func NewWithFile(filePath string) (*Auth, error) {
	config := datasource.Config{
		Type:    "file",
		Name:    "auth-file",
		Options: map[string]interface{}{"file": filePath},
	}

	ds := datasource.NewFile(config)
	if err := ds.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to file datasource: %w", err)
	}
	return &Auth{ds: ds}, nil
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
	if strings.HasPrefix(hashedPassword, "$2") {
		// bcrypt
		return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	}
	if strings.HasPrefix(hashedPassword, "{SHA}") {
		// OpenLDAP SHA-1
		hash := sha1.Sum([]byte(plainPassword))
		b64 := base64.StdEncoding.EncodeToString(hash[:])
		if hashedPassword == "{SHA}"+b64 {
			return nil
		}
		return ErrInvalidCredentials
	}
	if strings.HasPrefix(hashedPassword, "{SHA256}") {
		// OpenLDAP SHA-256
		hash := sha256.Sum256([]byte(plainPassword))
		b64 := base64.StdEncoding.EncodeToString(hash[:])
		if hashedPassword == "{SHA256}"+b64 {
			return nil
		}
		return ErrInvalidCredentials
	}
	if strings.HasPrefix(hashedPassword, "{SHA512}") {
		// OpenLDAP SHA-512
		hash := sha512.Sum512([]byte(plainPassword))
		b64 := base64.StdEncoding.EncodeToString(hash[:])
		if hashedPassword == "{SHA512}"+b64 {
			return nil
		}
		return ErrInvalidCredentials
	}
	if strings.HasPrefix(hashedPassword, "{SSHA}") {
		// OpenLDAP SSHA (SHA-1 + salt)
		b, err := base64.StdEncoding.DecodeString(hashedPassword[6:])
		if err != nil || len(b) < 20 {
			return ErrInvalidCredentials
		}
		hash := b[:20]
		salt := b[20:]
		h := sha1.New()
		h.Write([]byte(plainPassword))
		h.Write(salt)
		if string(h.Sum(nil)) == string(hash) {
			return nil
		}
		return ErrInvalidCredentials
	}
	// fallback: plain text
	if hashedPassword == plainPassword {
		return nil
	}
	return ErrInvalidCredentials
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

	// For LDAP or file, we'll use the datasource's Authenticate method directly
	if a.ds.Type() == "ldap" || a.ds.Type() == "file" {
		return a.ds.Authenticate(ctx, username, password)
	}

	// For other datasources, compare the provided password with the stored hash
	err = ComparePasswords(user.Password, password)
	if err != nil {
		return false, ErrInvalidCredentials
	}

	// Update last login time
	user.LastLoginAt = time.Now().Unix()
	if err := a.ds.UpdateUser(ctx, user); err != nil {
		// Non-critical error, just log it in a real application
		// For now, we'll ignore it and continue
		_ = err // Explicitly ignore the error
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

	// Hash the password if not using LDAP
	// LDAP will handle the password differently
	var hashedPassword string
	if a.ds.Type() != "ldap" {
		hashedPassword, err = HashPassword(password)
		if err != nil {
			return err
		}
	} else {
		// For LDAP, we'll use the plain password as the datasource will handle it
		hashedPassword = password
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

	// Hash the new password if not using LDAP
	if a.ds.Type() != "ldap" {
		hashedPassword, err := HashPassword(newPassword)
		if err != nil {
			return err
		}
		user.Password = hashedPassword
	} else {
		// For LDAP, we'll use the plain password as the datasource will handle it
		user.Password = newPassword
	}

	// Update the user
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

	// Hash the new password if not using LDAP
	if a.ds.Type() != "ldap" {
		hashedPassword, err := HashPassword(newPassword)
		if err != nil {
			return err
		}
		user.Password = hashedPassword
	} else {
		// For LDAP, we'll use the plain password as the datasource will handle it
		user.Password = newPassword
	}

	// Update the user
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

// GetDataSourceType returns the type of the underlying datasource
func (a *Auth) GetDataSourceType() string {
	if a.ds == nil {
		return ""
	}
	return a.ds.Type()
}
