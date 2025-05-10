package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/busybox42/elemta/internal/datasource"
)

// AuthMethod represents the SMTP authentication method
type AuthMethod string

const (
	// AuthMethodPlain represents PLAIN authentication
	AuthMethodPlain AuthMethod = "PLAIN"
	// AuthMethodLogin represents LOGIN authentication
	AuthMethodLogin AuthMethod = "LOGIN"
	// AuthMethodCramMD5 represents CRAM-MD5 authentication
	AuthMethodCramMD5 AuthMethod = "CRAM-MD5"
)

// Authenticator is the interface for SMTP authentication
type Authenticator interface {
	// Authenticate authenticates a user with the given credentials
	Authenticate(ctx context.Context, username, password string) (bool, error)
	// IsEnabled returns true if authentication is enabled
	IsEnabled() bool
	// IsRequired returns true if authentication is required
	IsRequired() bool
	// GetSupportedMethods returns the supported authentication methods
	GetSupportedMethods() []AuthMethod
}

// SMTPAuthenticator implements the Authenticator interface
type SMTPAuthenticator struct {
	config     *AuthConfig
	dataSource datasource.DataSource
	logger     *slog.Logger
	mu         sync.RWMutex
}

// NewAuthenticator creates a new SMTP authenticator
func NewAuthenticator(config *AuthConfig) (*SMTPAuthenticator, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	auth := &SMTPAuthenticator{
		config: config,
		logger: logger,
	}

	// If authentication is not enabled, return early
	if !config.Enabled {
		return auth, nil
	}

	// Create and connect to the datasource
	dsConfig := datasource.Config{
		Type:     config.DataSourceName,
		Name:     config.DataSourceName,
		Host:     config.DataSourceHost,
		Port:     config.DataSourcePort,
		Database: config.DataSourceDB,
		Username: config.DataSourceUser,
		Password: config.DataSourcePass,
		Options:  make(map[string]interface{}),
	}

	// Set both file and db_path options to ensure backward compatibility
	if config.DataSourcePath != "" {
		dsConfig.Options["file"] = config.DataSourcePath
		dsConfig.Options["db_path"] = config.DataSourcePath
	}

	ds, err := datasource.Factory(dsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create datasource: %w", err)
	}

	if err := ds.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to datasource: %w", err)
	}

	auth.dataSource = ds
	return auth, nil
}

// Authenticate authenticates a user with the given credentials
func (a *SMTPAuthenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// If authentication is not enabled, return success
	if !a.config.Enabled {
		return true, nil
	}

	// If no datasource is configured, return error
	if a.dataSource == nil {
		return false, fmt.Errorf("no datasource configured for authentication")
	}

	// Authenticate against the datasource
	authenticated, err := a.dataSource.Authenticate(ctx, username, password)
	if err != nil {
		a.logger.Error("authentication failed", "username", username, "error", err)
		return false, err
	}

	if authenticated {
		a.logger.Info("authentication successful", "username", username)
	} else {
		a.logger.Warn("authentication failed", "username", username)
	}

	return authenticated, nil
}

// IsEnabled returns true if authentication is enabled
func (a *SMTPAuthenticator) IsEnabled() bool {
	return a.config != nil && a.config.Enabled
}

// IsRequired returns true if authentication is required
func (a *SMTPAuthenticator) IsRequired() bool {
	return a.config != nil && a.config.Enabled && a.config.Required
}

// GetSupportedMethods returns the supported authentication methods
func (a *SMTPAuthenticator) GetSupportedMethods() []AuthMethod {
	return []AuthMethod{AuthMethodPlain, AuthMethodLogin}
}

// Close closes the authenticator and releases resources
func (a *SMTPAuthenticator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dataSource != nil && a.dataSource.IsConnected() {
		return a.dataSource.Close()
	}
	return nil
}
