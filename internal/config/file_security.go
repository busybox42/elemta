package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ConfigFileSecurity provides secure configuration file handling
type ConfigFileSecurity struct {
	securityValidator *SecurityValidator
}

// NewConfigFileSecurity creates a new configuration file security handler
func NewConfigFileSecurity() *ConfigFileSecurity {
	return &ConfigFileSecurity{
		securityValidator: NewSecurityValidator(),
	}
}

// SecureFilePermissions ensures configuration files have secure permissions
func (cfs *ConfigFileSecurity) SecureFilePermissions(filePath string) error {
	if filePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Validate the file path for security issues (basic validation)
	if err := cfs.validateBasicPathSecurity(filePath); err != nil {
		return fmt.Errorf("invalid config file path: %w", err)
	}

	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat config file: %w", err)
	}

	// Get current permissions
	currentMode := info.Mode()

	// Check if file contains sensitive data
	containsSensitiveData, err := cfs.ContainsSensitiveData(filePath)
	if err != nil {
		return fmt.Errorf("cannot check file content: %w", err)
	}

	// Set appropriate permissions based on content
	var targetMode os.FileMode
	if containsSensitiveData {
		targetMode = 0600 // Owner read/write only for sensitive files
	} else {
		targetMode = 0644 // Owner read/write, group/other read for non-sensitive files
	}

	// Only change permissions if they're not already secure
	if currentMode.Perm() != targetMode {
		if err := os.Chmod(filePath, targetMode); err != nil {
			return fmt.Errorf("failed to set secure permissions on %s: %w", filePath, err)
		}

		// Log the security improvement
		fmt.Fprintf(os.Stderr, "SECURITY: Set secure permissions on %s (%s -> %s)\n",
			filePath, currentMode.Perm(), targetMode)
	}

	// Validate file ownership (should be owned by current user)
	if err := cfs.validateFileOwnership(filePath); err != nil {
		return fmt.Errorf("file ownership validation failed: %w", err)
	}

	return nil
}

// ContainsSensitiveData checks if a configuration file contains sensitive information
func (cfs *ConfigFileSecurity) ContainsSensitiveData(filePath string) (bool, error) {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	contentStr := strings.ToLower(string(content))

	// Check for sensitive data patterns
	sensitivePatterns := []string{
		"password",
		"pass",
		"secret",
		"key",
		"token",
		"credential",
		"auth",
		"datasource_pass",
		"bind_password",
		"api_key",
		"private_key",
		"certificate",
		"tls_key",
		"ssl_key",
		"database_password",
		"db_password",
		"mysql_password",
		"postgres_password",
		"ldap_password",
		"redis_password",
		"jwt_secret",
		"encryption_key",
		"signing_key",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(contentStr, pattern) {
			return true, nil
		}
	}

	// Check for common sensitive file extensions
	ext := strings.ToLower(filepath.Ext(filePath))
	sensitiveExtensions := []string{".key", ".pem", ".p12", ".pfx", ".jks", ".db", ".sqlite", ".sqlite3"}
	for _, sensitiveExt := range sensitiveExtensions {
		if ext == sensitiveExt {
			return true, nil
		}
	}

	// Check for common sensitive filenames
	baseName := strings.ToLower(filepath.Base(filePath))
	sensitiveNames := []string{"users.txt", "passwords.txt", "secrets.txt", "credentials.txt", "auth.txt"}
	for _, sensitiveName := range sensitiveNames {
		if baseName == sensitiveName {
			return true, nil
		}
	}

	return false, nil
}

// validateFileOwnership validates that the file is owned by the current user
func (cfs *ConfigFileSecurity) validateFileOwnership(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	// Get current user ID
	currentUID := os.Getuid()

	// Get file owner (Unix-specific)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != currentUID {
			return fmt.Errorf("file %s is not owned by current user (owner: %d, current: %d)",
				filePath, stat.Uid, currentUID)
		}
	}

	return nil
}

// validateBasicPathSecurity performs basic path security validation without strict prefix checking
func (cfs *ConfigFileSecurity) validateBasicPathSecurity(filePath string) error {
	// Check for path traversal attacks
	if err := cfs.securityValidator.CheckPathTraversal(filePath); err != nil {
		return fmt.Errorf("path traversal detected: %w", err)
	}

	// Check for blocked patterns
	if err := cfs.securityValidator.CheckBlockedPatterns(filePath); err != nil {
		return fmt.Errorf("blocked path pattern: %w", err)
	}

	// Check for symlink attacks
	if err := cfs.securityValidator.CheckSymlinkAttack(filePath); err != nil {
		return fmt.Errorf("symlink attack detected: %w", err)
	}

	// Validate path length
	if len(filePath) > 4096 {
		return fmt.Errorf("path too long: %d characters (max 4096)", len(filePath))
	}

	return nil
}

// ValidateConfigFileSecurity performs comprehensive security validation on config files
func (cfs *ConfigFileSecurity) ValidateConfigFileSecurity(filePath string) error {
	if filePath == "" {
		return fmt.Errorf("config file path cannot be empty")
	}

	// Basic path validation (check for path traversal, but allow more flexible paths)
	if err := cfs.validateBasicPathSecurity(filePath); err != nil {
		return fmt.Errorf("config file path validation failed: %w", err)
	}

	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("config file does not exist: %w", err)
	}

	// Validate file size
	if err := cfs.securityValidator.ValidateFileSize(filePath, "config_file"); err != nil {
		return fmt.Errorf("config file size validation failed: %w", err)
	}

	// Check file permissions
	currentMode := info.Mode()
	containsSensitiveData, err := cfs.ContainsSensitiveData(filePath)
	if err != nil {
		return fmt.Errorf("cannot check file content for sensitive data: %w", err)
	}

	// Validate permissions based on content
	if containsSensitiveData {
		// Sensitive files should be 0600 (owner read/write only)
		if currentMode.Perm()&0077 != 0 {
			return fmt.Errorf("config file %s contains sensitive data but has world/group readable permissions (%s)",
				filePath, currentMode.Perm())
		}
	} else {
		// Non-sensitive files can be 0644 (owner read/write, group/other read)
		if currentMode.Perm()&0002 != 0 {
			return fmt.Errorf("config file %s is world-writable (%s)", filePath, currentMode.Perm())
		}
	}

	// Validate file ownership
	if err := cfs.validateFileOwnership(filePath); err != nil {
		return fmt.Errorf("config file ownership validation failed: %w", err)
	}

	// Check for symlink attacks
	if err := cfs.securityValidator.CheckSymlinkAttack(filePath); err != nil {
		return fmt.Errorf("config file symlink attack detected: %w", err)
	}

	return nil
}

// CreateSecureConfigFile creates a configuration file with secure permissions
func (cfs *ConfigFileSecurity) CreateSecureConfigFile(filePath string, content []byte, containsSensitiveData bool) error {
	if filePath == "" {
		return fmt.Errorf("config file path cannot be empty")
	}

	// Validate the file path for security issues
	if err := cfs.securityValidator.ValidatePath(filePath, "config_file"); err != nil {
		return fmt.Errorf("invalid config file path: %w", err)
	}

	// Create directory if it doesn't exist
	configDir := filepath.Dir(filePath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Set appropriate permissions based on content
	var fileMode os.FileMode
	if containsSensitiveData {
		fileMode = 0600 // Owner read/write only
	} else {
		fileMode = 0644 // Owner read/write, group/other read
	}

	// Write file with secure permissions
	if err := os.WriteFile(filePath, content, fileMode); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Ensure ownership is correct
	if err := cfs.validateFileOwnership(filePath); err != nil {
		return fmt.Errorf("config file ownership validation failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "SECURITY: Created secure config file %s with permissions %s\n", filePath, fileMode)

	return nil
}

// SanitizeConfigContent sanitizes configuration content to remove sensitive data from logs
func (cfs *ConfigFileSecurity) SanitizeConfigContent(content string) string {
	lines := strings.Split(content, "\n")
	var sanitizedLines []string

	for _, line := range lines {
		// Check if line contains sensitive data
		lowerLine := strings.ToLower(line)
		containsSensitive := false

		sensitivePatterns := []string{
			"password",
			"pass",
			"secret",
			"key",
			"token",
			"credential",
			"auth",
			"datasource_pass",
			"bind_password",
			"api_key",
			"private_key",
		}

		for _, pattern := range sensitivePatterns {
			if strings.Contains(lowerLine, pattern) {
				containsSensitive = true
				break
			}
		}

		if containsSensitive {
			// Replace sensitive values with [REDACTED]
			sanitizedLine := cfs.redactSensitiveValue(line)
			sanitizedLines = append(sanitizedLines, sanitizedLine)
		} else {
			sanitizedLines = append(sanitizedLines, line)
		}
	}

	return strings.Join(sanitizedLines, "\n")
}

// redactSensitiveValue redacts sensitive values in configuration lines
func (cfs *ConfigFileSecurity) redactSensitiveValue(line string) string {
	// Look for key = value patterns
	if strings.Contains(line, "=") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			_ = strings.TrimSpace(parts[1]) // value not used, just checking format

			// Check if key indicates sensitive data
			lowerKey := strings.ToLower(key)
			sensitiveKeys := []string{
				"password", "pass", "secret", "key", "token",
				"credential", "auth", "datasource_pass", "bind_password",
				"api_key", "private_key", "certificate", "tls_key",
				"ssl_key", "database_password", "db_password",
				"mysql_password", "postgres_password", "ldap_password",
				"redis_password", "jwt_secret", "encryption_key", "signing_key",
			}

			for _, sensitiveKey := range sensitiveKeys {
				if strings.Contains(lowerKey, sensitiveKey) {
					// Redact the value
					return fmt.Sprintf("%s = [REDACTED]", key)
				}
			}
		}
	}

	return line
}

// ValidateAllConfigFiles validates security of all configuration files in a directory
func (cfs *ConfigFileSecurity) ValidateAllConfigFiles(configDir string) error {
	if configDir == "" {
		return fmt.Errorf("config directory path cannot be empty")
	}

	// Validate the directory path with basic security checks
	if err := cfs.validateBasicPathSecurity(configDir); err != nil {
		return fmt.Errorf("invalid config directory path: %w", err)
	}

	// Read directory contents
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return fmt.Errorf("cannot read config directory: %w", err)
	}

	var errors []string
	var warnings []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories for now
		}

		filePath := filepath.Join(configDir, entry.Name())

		// Skip non-config files
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext != ".toml" && ext != ".conf" && ext != ".txt" && ext != ".db" && ext != ".key" && ext != ".crt" {
			continue
		}

		// Validate file security
		if err := cfs.ValidateConfigFileSecurity(filePath); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", filePath, err))
		} else {
			// Check if file needs permission updates
			info, err := entry.Info()
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: cannot get file info: %v", filePath, err))
				continue
			}

			containsSensitiveData, err := cfs.ContainsSensitiveData(filePath)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: cannot check for sensitive data: %v", filePath, err))
				continue
			}

			currentMode := info.Mode()
			if containsSensitiveData && currentMode.Perm()&0077 != 0 {
				warnings = append(warnings, fmt.Sprintf("%s: contains sensitive data but has world/group readable permissions", filePath))
			}
		}
	}

	// Report results
	if len(errors) > 0 {
		return fmt.Errorf("config file security validation failed:\n%s", strings.Join(errors, "\n"))
	}

	if len(warnings) > 0 {
		fmt.Println("Config file security warnings:")
		for _, warning := range warnings {
			fmt.Fprintf(os.Stderr, "  WARNING: %s\n", warning)
		}
	}

	return nil
}
