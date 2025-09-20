package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// PluginValidator provides comprehensive validation for plugin inputs and outputs
type PluginValidator struct {
	logger           *slog.Logger
	maxMessageSize   int64
	maxHeaderCount   int
	maxHeaderLength  int
	allowedActions   map[PluginAction]bool
	trustedChecksums map[string]bool
}

// ValidationError represents a validation error with detailed information
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Reason  string `json:"reason"`
	Code    string `json:"code"`
}

// Error implements the error interface
func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation error in %s: %s (%s)", ve.Field, ve.Reason, ve.Code)
}

// ValidationResult contains the result of a validation operation
type ValidationResult struct {
	Valid   bool               `json:"valid"`
	Errors  []*ValidationError `json:"errors,omitempty"`
	Warnings []*ValidationError `json:"warnings,omitempty"`
}

// NewPluginValidator creates a new plugin validator with secure defaults
func NewPluginValidator(logger *slog.Logger) *PluginValidator {
	return &PluginValidator{
		logger:          logger,
		maxMessageSize:  50 * 1024 * 1024, // 50MB max message size
		maxHeaderCount:  100,               // Max 100 headers
		maxHeaderLength: 1024,              // Max 1KB per header
		allowedActions: map[PluginAction]bool{
			PluginActionAccept:     true,
			PluginActionReject:     true,
			PluginActionQuarantine: true,
			PluginActionModify:     true,
			PluginActionContinue:   true,
			PluginActionDefer:      true,
		},
		trustedChecksums: make(map[string]bool),
	}
}

// ValidatePlugin validates a plugin before loading
func (v *PluginValidator) ValidatePlugin(info *SecurePluginInfo, pluginPath string) error {
	result := &ValidationResult{Valid: true}
	
	// Validate plugin info
	v.validatePluginInfo(info, result)
	
	// Validate plugin files
	v.validatePluginFiles(pluginPath, result)
	
	// Validate plugin checksum
	v.validatePluginChecksum(info, pluginPath, result)
	
	// Check if validation passed
	if !result.Valid {
		return fmt.Errorf("plugin validation failed: %d errors", len(result.Errors))
	}
	
	return nil
}

// ValidateInput validates plugin input data
func (v *PluginValidator) ValidateInput(input *SecurePluginInput) error {
	result := &ValidationResult{Valid: true}
	
	// Validate message ID
	v.validateMessageID(input.MessageID, result)
	
	// Validate email addresses
	v.validateEmailAddress("from", input.From, result)
	v.validateEmailAddresses("to", input.To, result)
	
	// Validate subject
	v.validateSubject(input.Subject, result)
	
	// Validate headers
	v.validateHeaders(input.Headers, result)
	
	// Validate body
	v.validateBody(input.Body, result)
	
	// Validate metadata
	v.validateMetadata(input.Metadata, result)
	
	// Validate remote address
	v.validateRemoteAddr(input.RemoteAddr, result)
	
	// Validate timestamp
	v.validateTimestamp(input.Timestamp, result)
	
	// Check if validation passed
	if !result.Valid {
		v.logger.Error("Plugin input validation failed",
			"errors", len(result.Errors),
			"warnings", len(result.Warnings),
		)
		return fmt.Errorf("input validation failed: %d errors", len(result.Errors))
	}
	
	if len(result.Warnings) > 0 {
		v.logger.Warn("Plugin input validation warnings",
			"warnings", len(result.Warnings),
		)
	}
	
	return nil
}

// ValidateOutput validates plugin output data
func (v *PluginValidator) ValidateOutput(output *SecurePluginOutput) error {
	result := &ValidationResult{Valid: true}
	
	// Validate action
	v.validateAction(output.Action, result)
	
	// Validate score
	v.validateScore(output.Score, result)
	
	// Validate message
	v.validateMessage(output.Message, result)
	
	// Validate headers
	v.validateHeaders(output.Headers, result)
	
	// Validate modified body
	v.validateModifiedBody(output.ModifiedBody, result)
	
	// Validate metadata
	v.validateMetadata(output.Metadata, result)
	
	// Validate errors and warnings
	v.validateStringArray("errors", output.Errors, result)
	v.validateStringArray("warnings", output.Warnings, result)
	
	// Check if validation passed
	if !result.Valid {
		v.logger.Error("Plugin output validation failed",
			"errors", len(result.Errors),
			"warnings", len(result.Warnings),
		)
		return fmt.Errorf("output validation failed: %d errors", len(result.Errors))
	}
	
	if len(result.Warnings) > 0 {
		v.logger.Warn("Plugin output validation warnings",
			"warnings", len(result.Warnings),
		)
	}
	
	return nil
}

// validatePluginInfo validates plugin information
func (v *PluginValidator) validatePluginInfo(info *SecurePluginInfo, result *ValidationResult) {
	// Validate name
	if info.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "name",
			Reason: "plugin name cannot be empty",
			Code:   "EMPTY_NAME",
		})
	} else if !v.isValidPluginName(info.Name) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "name",
			Value:  info.Name,
			Reason: "plugin name contains invalid characters",
			Code:   "INVALID_NAME",
		})
	}
	
	// Validate version
	if info.Version == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "version",
			Reason: "plugin version cannot be empty",
			Code:   "EMPTY_VERSION",
		})
	} else if !v.isValidVersion(info.Version) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "version",
			Value:  info.Version,
			Reason: "plugin version format is invalid",
			Code:   "INVALID_VERSION",
		})
	}
	
	// Validate type
	if info.Type == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "type",
			Reason: "plugin type cannot be empty",
			Code:   "EMPTY_TYPE",
		})
	}
	
	// Validate API version
	if info.APIVersion == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "api_version",
			Reason: "API version cannot be empty",
			Code:   "EMPTY_API_VERSION",
		})
	} else if !v.isCompatibleAPIVersion(info.APIVersion) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "api_version",
			Value:  info.APIVersion,
			Reason: "API version is not compatible",
			Code:   "INCOMPATIBLE_API_VERSION",
		})
	}
	
	// Validate capabilities
	for _, capability := range info.Capabilities {
		if !v.isValidCapability(capability) {
			result.Warnings = append(result.Warnings, &ValidationError{
				Field:  "capabilities",
				Value:  capability,
				Reason: "unknown capability",
				Code:   "UNKNOWN_CAPABILITY",
			})
		}
	}
}

// validatePluginFiles validates plugin files and structure
func (v *PluginValidator) validatePluginFiles(pluginPath string, result *ValidationResult) {
	// Check if plugin directory exists
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "path",
			Value:  pluginPath,
			Reason: "plugin directory does not exist",
			Code:   "DIRECTORY_NOT_FOUND",
		})
		return
	}
	
	// Check for required files
	requiredFiles := []string{"plugin.json", "plugin"}
	for _, file := range requiredFiles {
		filePath := filepath.Join(pluginPath, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "files",
				Value:  file,
				Reason: "required file is missing",
				Code:   "MISSING_FILE",
			})
		}
	}
	
	// Check plugin binary permissions
	binaryPath := filepath.Join(pluginPath, "plugin")
	if info, err := os.Stat(binaryPath); err == nil {
		if info.Mode().Perm()&0111 == 0 {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "binary",
				Value:  binaryPath,
				Reason: "plugin binary is not executable",
				Code:   "NOT_EXECUTABLE",
			})
		}
	}
}

// validatePluginChecksum validates plugin integrity using checksums
func (v *PluginValidator) validatePluginChecksum(info *SecurePluginInfo, pluginPath string, result *ValidationResult) {
	if info.Checksum == "" {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "checksum",
			Reason: "no checksum provided for integrity verification",
			Code:   "NO_CHECKSUM",
		})
		return
	}
	
	// Calculate actual checksum
	binaryPath := filepath.Join(pluginPath, "plugin")
	actualChecksum, err := v.calculateFileChecksum(binaryPath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "checksum",
			Reason: fmt.Sprintf("failed to calculate checksum: %v", err),
			Code:   "CHECKSUM_ERROR",
		})
		return
	}
	
	// Compare checksums
	if actualChecksum != info.Checksum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "checksum",
			Value:  actualChecksum,
			Reason: "checksum mismatch - plugin may be corrupted or tampered",
			Code:   "CHECKSUM_MISMATCH",
		})
	}
	
	// Check if checksum is in trusted list
	if !v.trustedChecksums[info.Checksum] {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "checksum",
			Value:  info.Checksum,
			Reason: "plugin checksum is not in trusted list",
			Code:   "UNTRUSTED_CHECKSUM",
		})
	}
}

// validateMessageID validates message ID format
func (v *PluginValidator) validateMessageID(messageID string, result *ValidationResult) {
	if messageID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "message_id",
			Reason: "message ID cannot be empty",
			Code:   "EMPTY_MESSAGE_ID",
		})
		return
	}
	
	if len(messageID) > 255 {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "message_id",
			Value:  messageID,
			Reason: "message ID too long",
			Code:   "MESSAGE_ID_TOO_LONG",
		})
	}
	
	// Check for valid characters (alphanumeric, dash, underscore)
	if !regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`).MatchString(messageID) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "message_id",
			Value:  messageID,
			Reason: "message ID contains invalid characters",
			Code:   "INVALID_MESSAGE_ID",
		})
	}
}

// validateEmailAddress validates a single email address
func (v *PluginValidator) validateEmailAddress(field, email string, result *ValidationResult) {
	if email == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  field,
			Reason: "email address cannot be empty",
			Code:   "EMPTY_EMAIL",
		})
		return
	}
	
	// Use Go's mail package for basic validation
	if _, err := mail.ParseAddress(email); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  field,
			Value:  email,
			Reason: "invalid email address format",
			Code:   "INVALID_EMAIL",
		})
		return
	}
	
	// Additional security checks
	if len(email) > 320 { // RFC 5321 limit
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  field,
			Value:  email,
			Reason: "email address too long",
			Code:   "EMAIL_TOO_LONG",
		})
	}
	
	// Check for suspicious patterns
	if v.containsSuspiciousPatterns(email) {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  field,
			Value:  email,
			Reason: "email address contains suspicious patterns",
			Code:   "SUSPICIOUS_EMAIL",
		})
	}
}

// validateEmailAddresses validates multiple email addresses
func (v *PluginValidator) validateEmailAddresses(field string, emails []string, result *ValidationResult) {
	if len(emails) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  field,
			Reason: "email address list cannot be empty",
			Code:   "EMPTY_EMAIL_LIST",
		})
		return
	}
	
	if len(emails) > 100 { // Reasonable limit
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  field,
			Reason: "too many email addresses",
			Code:   "TOO_MANY_EMAILS",
		})
	}
	
	for i, email := range emails {
		fieldName := fmt.Sprintf("%s[%d]", field, i)
		v.validateEmailAddress(fieldName, email, result)
	}
}

// validateSubject validates email subject
func (v *PluginValidator) validateSubject(subject string, result *ValidationResult) {
	if len(subject) > 998 { // RFC 5322 limit
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "subject",
			Value:  subject,
			Reason: "subject line too long",
			Code:   "SUBJECT_TOO_LONG",
		})
	}
	
	// Check for valid UTF-8
	if !utf8.ValidString(subject) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "subject",
			Reason: "subject contains invalid UTF-8",
			Code:   "INVALID_UTF8",
		})
	}
	
	// Check for suspicious patterns
	if v.containsSuspiciousPatterns(subject) {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "subject",
			Value:  subject,
			Reason: "subject contains suspicious patterns",
			Code:   "SUSPICIOUS_SUBJECT",
		})
	}
}

// validateHeaders validates email headers
func (v *PluginValidator) validateHeaders(headers map[string]string, result *ValidationResult) {
	if len(headers) > v.maxHeaderCount {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "headers",
			Reason: fmt.Sprintf("too many headers (max %d)", v.maxHeaderCount),
			Code:   "TOO_MANY_HEADERS",
		})
	}
	
	for name, value := range headers {
		// Validate header name
		if name == "" {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "headers",
				Reason: "header name cannot be empty",
				Code:   "EMPTY_HEADER_NAME",
			})
			continue
		}
		
		if len(name) > 78 { // RFC 5322 recommendation
			result.Warnings = append(result.Warnings, &ValidationError{
				Field:  "headers",
				Value:  name,
				Reason: "header name is very long",
				Code:   "LONG_HEADER_NAME",
			})
		}
		
		// Validate header value
		if len(value) > v.maxHeaderLength {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "headers",
				Value:  fmt.Sprintf("%s: %s", name, value),
				Reason: "header value too long",
				Code:   "HEADER_TOO_LONG",
			})
		}
		
		// Check for valid UTF-8
		if !utf8.ValidString(value) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "headers",
				Value:  name,
				Reason: "header value contains invalid UTF-8",
				Code:   "INVALID_UTF8",
			})
		}
		
		// Check for injection attempts
		if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "headers",
				Value:  name,
				Reason: "header value contains line breaks (injection attempt)",
				Code:   "HEADER_INJECTION",
			})
		}
	}
}

// validateBody validates message body
func (v *PluginValidator) validateBody(body []byte, result *ValidationResult) {
	if len(body) > int(v.maxMessageSize) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "body",
			Reason: fmt.Sprintf("message body too large (max %d bytes)", v.maxMessageSize),
			Code:   "BODY_TOO_LARGE",
		})
	}
	
	// Check for valid UTF-8 in text content
	if len(body) > 0 && !utf8.Valid(body) {
		// Could be binary content, which is acceptable
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "body",
			Reason: "message body contains non-UTF-8 content",
			Code:   "NON_UTF8_BODY",
		})
	}
}

// validateModifiedBody validates modified message body
func (v *PluginValidator) validateModifiedBody(body []byte, result *ValidationResult) {
	if len(body) == 0 {
		return // Empty is acceptable for non-modifying plugins
	}
	
	// Apply same validation as regular body
	v.validateBody(body, result)
}

// validateMetadata validates metadata object
func (v *PluginValidator) validateMetadata(metadata map[string]interface{}, result *ValidationResult) {
	if len(metadata) > 50 { // Reasonable limit
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "metadata",
			Reason: "metadata has many entries",
			Code:   "LARGE_METADATA",
		})
	}
	
	for key, value := range metadata {
		if len(key) > 100 {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "metadata",
				Value:  key,
				Reason: "metadata key too long",
				Code:   "METADATA_KEY_TOO_LONG",
			})
		}
		
		// Check for suspicious keys
		if v.containsSuspiciousPatterns(key) {
			result.Warnings = append(result.Warnings, &ValidationError{
				Field:  "metadata",
				Value:  key,
				Reason: "metadata key contains suspicious patterns",
				Code:   "SUSPICIOUS_METADATA_KEY",
			})
		}
		
		// Validate value size (prevent memory exhaustion)
		if str, ok := value.(string); ok && len(str) > 10000 {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  "metadata",
				Value:  key,
				Reason: "metadata value too large",
				Code:   "METADATA_VALUE_TOO_LARGE",
			})
		}
	}
}

// validateRemoteAddr validates remote address
func (v *PluginValidator) validateRemoteAddr(remoteAddr string, result *ValidationResult) {
	if remoteAddr == "" {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "remote_addr",
			Reason: "remote address is empty",
			Code:   "EMPTY_REMOTE_ADDR",
		})
		return
	}
	
	// Basic format validation (IP:port)
	if !regexp.MustCompile(`^[^\s:]+:\d+$`).MatchString(remoteAddr) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "remote_addr",
			Value:  remoteAddr,
			Reason: "invalid remote address format",
			Code:   "INVALID_REMOTE_ADDR",
		})
	}
}

// validateTimestamp validates timestamp
func (v *PluginValidator) validateTimestamp(timestamp time.Time, result *ValidationResult) {
	now := time.Now()
	
	// Check if timestamp is too far in the past (more than 24 hours)
	if now.Sub(timestamp) > 24*time.Hour {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "timestamp",
			Value:  timestamp.String(),
			Reason: "timestamp is very old",
			Code:   "OLD_TIMESTAMP",
		})
	}
	
	// Check if timestamp is in the future (more than 1 hour)
	if timestamp.Sub(now) > time.Hour {
		result.Warnings = append(result.Warnings, &ValidationError{
			Field:  "timestamp",
			Value:  timestamp.String(),
			Reason: "timestamp is in the future",
			Code:   "FUTURE_TIMESTAMP",
		})
	}
}

// validateAction validates plugin action
func (v *PluginValidator) validateAction(action PluginAction, result *ValidationResult) {
	if action == "" {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "action",
			Reason: "action cannot be empty",
			Code:   "EMPTY_ACTION",
		})
		return
	}
	
	if !v.allowedActions[action] {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "action",
			Value:  string(action),
			Reason: "action is not allowed",
			Code:   "INVALID_ACTION",
		})
	}
}

// validateScore validates plugin score
func (v *PluginValidator) validateScore(score float64, result *ValidationResult) {
	if score < 0 || score > 100 {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "score",
			Value:  fmt.Sprintf("%.2f", score),
			Reason: "score must be between 0 and 100",
			Code:   "INVALID_SCORE",
		})
	}
}

// validateMessage validates plugin message
func (v *PluginValidator) validateMessage(message string, result *ValidationResult) {
	if len(message) > 1000 {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "message",
			Value:  message,
			Reason: "message too long",
			Code:   "MESSAGE_TOO_LONG",
		})
	}
	
	// Check for valid UTF-8
	if !utf8.ValidString(message) {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  "message",
			Reason: "message contains invalid UTF-8",
			Code:   "INVALID_UTF8",
		})
	}
}

// validateStringArray validates arrays of strings
func (v *PluginValidator) validateStringArray(field string, array []string, result *ValidationResult) {
	if len(array) > 100 { // Reasonable limit
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Field:  field,
			Reason: "array has too many elements",
			Code:   "ARRAY_TOO_LARGE",
		})
	}
	
	for i, str := range array {
		if len(str) > 1000 {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  fmt.Sprintf("%s[%d]", field, i),
				Value:  str,
				Reason: "string element too long",
				Code:   "STRING_TOO_LONG",
			})
		}
		
		if !utf8.ValidString(str) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Field:  fmt.Sprintf("%s[%d]", field, i),
				Reason: "string contains invalid UTF-8",
				Code:   "INVALID_UTF8",
			})
		}
	}
}

// Helper methods

// isValidPluginName checks if plugin name is valid
func (v *PluginValidator) isValidPluginName(name string) bool {
	return regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\-_]*$`).MatchString(name)
}

// isValidVersion checks if version string is valid
func (v *PluginValidator) isValidVersion(version string) bool {
	return regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9\-_]+)?$`).MatchString(version)
}

// isCompatibleAPIVersion checks if API version is compatible
func (v *PluginValidator) isCompatibleAPIVersion(apiVersion string) bool {
	// For now, only support v1.0.0
	return apiVersion == "1.0.0"
}

// isValidCapability checks if capability is valid
func (v *PluginValidator) isValidCapability(capability string) bool {
	validCapabilities := map[string]bool{
		"scan_message":    true,
		"modify_headers":  true,
		"modify_body":     true,
		"quarantine":      true,
		"network_access":  true,
		"file_access":     true,
		"external_api":    true,
	}
	
	return validCapabilities[capability]
}

// containsSuspiciousPatterns checks for suspicious patterns in strings
func (v *PluginValidator) containsSuspiciousPatterns(str string) bool {
	suspiciousPatterns := []string{
		"<script", "javascript:", "vbscript:",
		"../", "..\\", "/etc/passwd", "/proc/",
		"SELECT ", "INSERT ", "UPDATE ", "DELETE ",
		"UNION ", "DROP ", "CREATE ", "ALTER ",
		"exec(", "eval(", "system(",
	}
	
	lowerStr := strings.ToLower(str)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerStr, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// calculateFileChecksum calculates SHA256 checksum of a file
func (v *PluginValidator) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// AddTrustedChecksum adds a checksum to the trusted list
func (v *PluginValidator) AddTrustedChecksum(checksum string) {
	v.trustedChecksums[checksum] = true
}
