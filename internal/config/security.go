package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SecurityConfig holds security validation settings
type SecurityConfig struct {
	MaxFileSize         int64    // Maximum file size in bytes
	MaxWorkers          int      // Maximum number of workers
	MaxConnections      int      // Maximum connections
	MaxQueueSize        int64    // Maximum queue size
	MaxLogFileSize      int64    // Maximum log file size
	MaxConfigFileSize   int64    // Maximum config file size
	AllowedPathPrefixes []string // Allowed path prefixes for security
	BlockedPathPatterns []string // Blocked path patterns
}

// DefaultSecurityConfig returns secure default security settings
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxFileSize:       100 * 1024 * 1024, // 100MB
		MaxWorkers:        1000,
		MaxConnections:    10000,
		MaxQueueSize:      10 * 1024 * 1024 * 1024, // 10GB
		MaxLogFileSize:    100 * 1024 * 1024,       // 100MB
		MaxConfigFileSize: 1024 * 1024,             // 1MB
		AllowedPathPrefixes: []string{
			"/app/",
			"/var/",
			"/tmp/",
			"/opt/",
			"/etc/",
			"./",
			"../",
		},
		BlockedPathPatterns: []string{
			"../",
			"..\\",
			"/etc/passwd",
			"/etc/shadow",
			"/proc/",
			"/sys/",
			"/dev/",
			"~/.ssh/",
			"/root/",
		},
	}
}

// SecurityValidator provides comprehensive security validation
type SecurityValidator struct {
	config *SecurityConfig
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{
		config: DefaultSecurityConfig(),
	}
}

// ValidatePath validates file paths for security issues
func (sv *SecurityValidator) ValidatePath(path, fieldName string) error {
	if path == "" {
		return nil // Empty paths are handled by other validators
	}

	// Check for path traversal attacks
	if err := sv.CheckPathTraversal(path); err != nil {
		return fmt.Errorf("path traversal detected in %s: %w", fieldName, err)
	}

	// Check for blocked patterns
	if err := sv.CheckBlockedPatterns(path); err != nil {
		return fmt.Errorf("blocked path pattern in %s: %w", fieldName, err)
	}

	// Check for allowed prefixes (if configured)
	if err := sv.checkAllowedPrefixes(path); err != nil {
		return fmt.Errorf("path not in allowed prefixes for %s: %w", fieldName, err)
	}

	// Check for symlink attacks
	if err := sv.CheckSymlinkAttack(path); err != nil {
		return fmt.Errorf("symlink attack detected in %s: %w", fieldName, err)
	}

	// Validate path length
	if len(path) > 4096 {
		return fmt.Errorf("path too long in %s: %d characters (max 4096)", fieldName, len(path))
	}

	return nil
}

// ValidateNumericBounds validates numeric values for resource exhaustion
func (sv *SecurityValidator) ValidateNumericBounds(value int64, fieldName string, min, max int64) error {
	if value < min {
		return fmt.Errorf("value too small for %s: %d (minimum: %d)", fieldName, value, min)
	}
	if value > max {
		return fmt.Errorf("value too large for %s: %d (maximum: %d)", fieldName, value, max)
	}
	return nil
}

// ValidatePort validates port numbers
func (sv *SecurityValidator) ValidatePort(port int, fieldName string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port for %s: %d (must be 1-65535)", fieldName, port)
	}
	return nil
}

// ValidateNetworkAddress validates network addresses
func (sv *SecurityValidator) ValidateNetworkAddress(addr, fieldName string) error {
	if addr == "" {
		return fmt.Errorf("network address cannot be empty for %s", fieldName)
	}

	// Check for injection patterns
	if err := sv.checkInjectionPatterns(addr); err != nil {
		return fmt.Errorf("injection pattern detected in %s: %w", fieldName, err)
	}

	// Validate address format
	if err := sv.validateAddressFormat(addr); err != nil {
		return fmt.Errorf("invalid address format for %s: %w", fieldName, err)
	}

	return nil
}

// ValidateHostname validates hostnames for security
func (sv *SecurityValidator) ValidateHostname(hostname, fieldName string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty for %s", fieldName)
	}

	// Check for injection patterns
	if err := sv.checkInjectionPatterns(hostname); err != nil {
		return fmt.Errorf("injection pattern detected in %s: %w", fieldName, err)
	}

	// Validate hostname format
	if err := sv.validateHostnameFormat(hostname); err != nil {
		return fmt.Errorf("invalid hostname format for %s: %w", fieldName, err)
	}

	return nil
}

// ValidateStringLength validates string lengths to prevent memory exhaustion
func (sv *SecurityValidator) ValidateStringLength(str, fieldName string, maxLength int) error {
	if !utf8.ValidString(str) {
		return fmt.Errorf("invalid UTF-8 encoding in %s", fieldName)
	}

	if len(str) > maxLength {
		return fmt.Errorf("string too long for %s: %d characters (max: %d)", fieldName, len(str), maxLength)
	}

	return nil
}

// ValidateFileSize validates file sizes
func (sv *SecurityValidator) ValidateFileSize(filePath, fieldName string) error {
	if filePath == "" {
		return nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil // File doesn't exist, that's handled elsewhere
	}

	if info.Size() > sv.config.MaxFileSize {
		return fmt.Errorf("file too large for %s: %d bytes (max: %d)", fieldName, info.Size(), sv.config.MaxFileSize)
	}

	return nil
}

// CheckPathTraversal checks for directory traversal attacks
func (sv *SecurityValidator) CheckPathTraversal(path string) error {
	// Normalize the path
	cleanPath := filepath.Clean(path)

	// Check for parent directory references
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("parent directory reference detected: %s", path)
	}

	// Check for absolute path escapes
	if filepath.IsAbs(path) && !strings.HasPrefix(cleanPath, "/") {
		return fmt.Errorf("absolute path escape detected: %s", path)
	}

	return nil
}

// CheckBlockedPatterns checks for blocked path patterns
func (sv *SecurityValidator) CheckBlockedPatterns(path string) error {
	lowerPath := strings.ToLower(path)

	for _, pattern := range sv.config.BlockedPathPatterns {
		if strings.Contains(lowerPath, strings.ToLower(pattern)) {
			return fmt.Errorf("blocked pattern detected: %s", pattern)
		}
	}

	return nil
}

// checkAllowedPrefixes checks if path is in allowed prefixes
func (sv *SecurityValidator) checkAllowedPrefixes(path string) error {
	if len(sv.config.AllowedPathPrefixes) == 0 {
		return nil // No restrictions
	}

	// Convert to absolute path for comparison
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path // Use original if abs fails
	}

	for _, prefix := range sv.config.AllowedPathPrefixes {
		if strings.HasPrefix(absPath, prefix) {
			return nil // Path is allowed
		}
	}

	return fmt.Errorf("path not in allowed prefixes: %s", path)
}

// CheckSymlinkAttack checks for symlink attacks
func (sv *SecurityValidator) CheckSymlinkAttack(path string) error {
	// Check if path exists and is a symlink
	info, err := os.Lstat(path)
	if err != nil {
		return nil // Path doesn't exist, that's fine
	}

	if info.Mode()&os.ModeSymlink != 0 {
		// It's a symlink, check if it points to a safe location
		target, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("cannot read symlink target: %w", err)
		}

		// Validate the target path for security issues
		if err := sv.CheckPathTraversal(target); err != nil {
			return fmt.Errorf("symlink target contains path traversal: %w", err)
		}

		if err := sv.CheckBlockedPatterns(target); err != nil {
			return fmt.Errorf("symlink target contains blocked pattern: %w", err)
		}

		// Recursively check the target for more symlinks
		return sv.CheckSymlinkAttack(target)
	}

	return nil
}

// checkInjectionPatterns checks for injection patterns
func (sv *SecurityValidator) checkInjectionPatterns(input string) error {
	// Common injection patterns
	injectionPatterns := []string{
		"../",
		"..\\",
		"<script",
		"javascript:",
		"data:",
		"vbscript:",
		"onload=",
		"onerror=",
		"${",
		"$(",
		"`",
		";",
		"|",
		"&",
		"&&",
		"||",
		"$(",
		"$((",
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lowerInput, pattern) {
			return fmt.Errorf("injection pattern detected: %s", pattern)
		}
	}

	return nil
}

// validateAddressFormat validates network address format
func (sv *SecurityValidator) validateAddressFormat(addr string) error {
	// Handle :port format
	if strings.HasPrefix(addr, ":") {
		portStr := addr[1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port format: %s", portStr)
		}
		return sv.ValidatePort(port, "port")
	}

	// Handle host:port format
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}
	if err := sv.ValidatePort(port, "port"); err != nil {
		return err
	}

	// Validate host
	if host != "" && host != "0.0.0.0" && host != "::" {
		if net.ParseIP(host) == nil {
			// Not an IP, validate as hostname
			return sv.ValidateHostname(host, "hostname")
		}
	}

	return nil
}

// validateHostnameFormat validates hostname format
func (sv *SecurityValidator) validateHostnameFormat(hostname string) error {
	if len(hostname) == 0 || len(hostname) > 253 {
		return fmt.Errorf("hostname length invalid: %d (must be 1-253)", len(hostname))
	}

	// Allow localhost and IP addresses
	if hostname == "localhost" || net.ParseIP(hostname) != nil {
		return nil
	}

	// Validate domain name format
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format: %s", hostname)
	}

	return nil
}

// ValidateConfigFileSize validates the size of the configuration file
func (sv *SecurityValidator) ValidateConfigFileSize(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat config file: %w", err)
	}

	if info.Size() > sv.config.MaxConfigFileSize {
		return fmt.Errorf("config file too large: %d bytes (max: %d)", info.Size(), sv.config.MaxConfigFileSize)
	}

	return nil
}

// SanitizePath sanitizes a file path for safe use
func (sv *SecurityValidator) SanitizePath(path string) string {
	// Remove any null bytes
	path = strings.ReplaceAll(path, "\x00", "")

	// Normalize path separators
	path = filepath.Clean(path)

	// Remove any trailing slashes (except root)
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	return path
}

// SanitizeString sanitizes a string for safe use
func (sv *SecurityValidator) SanitizeString(str string) string {
	// Remove null bytes
	str = strings.ReplaceAll(str, "\x00", "")

	// Remove control characters except newlines and tabs
	var result strings.Builder
	for _, r := range str {
		if r >= 32 || r == '\n' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}
