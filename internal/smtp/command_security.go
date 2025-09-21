package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode/utf8"
)

// CommandSecurityManager provides comprehensive SMTP command injection prevention
type CommandSecurityManager struct {
	logger *slog.Logger
	config *CommandSecurityConfig
}

// CommandSecurityConfig defines security policies for command validation
type CommandSecurityConfig struct {
	// Maximum command line length
	MaxCommandLength int
	// Maximum parameter length
	MaxParameterLength int
	// Allowed command characters (regex pattern)
	AllowedCommandChars string
	// Allowed parameter characters (regex pattern)
	AllowedParameterChars string
	// Blocked command patterns
	BlockedCommandPatterns []string
	// Blocked parameter patterns
	BlockedParameterPatterns []string
	// Enable strict mode (more aggressive filtering)
	StrictMode bool
	// Enable logging of suspicious commands
	LogSuspiciousCommands bool
}

// DefaultCommandSecurityConfig returns a secure default configuration
func DefaultCommandSecurityConfig() *CommandSecurityConfig {
	return &CommandSecurityConfig{
		MaxCommandLength:    512,  // RFC 5321 limit
		MaxParameterLength:  320,  // RFC 5321 email address limit
		AllowedCommandChars: `^[A-Za-z0-9\-_]+$`,
		AllowedParameterChars: `^[A-Za-z0-9\-_@\.:<>=\s]+$`,
		BlockedCommandPatterns: []string{
			// SQL injection patterns
			`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
			// Command injection patterns
			`[;&|` + "`" + `$]`,
			// Script injection patterns
			`(?i)(script|javascript|vbscript|onload|onerror)`,
			// Path traversal patterns
			`\.\./|\.\.\\`,
			// Control characters
			`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`,
		},
		BlockedParameterPatterns: []string{
			// SQL injection patterns
			`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
			// Command injection patterns
			`[;&|` + "`" + `$]`,
			// Script injection patterns
			`(?i)(script|javascript|vbscript|onload|onerror)`,
			// Path traversal patterns
			`\.\./|\.\.\\`,
			// Control characters
			`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`,
			// CRLF injection
			`\r\n|\r|\n`,
		},
		StrictMode:             true,
		LogSuspiciousCommands:  true,
	}
}

// NewCommandSecurityManager creates a new command security manager
func NewCommandSecurityManager(logger *slog.Logger) *CommandSecurityManager {
	return &CommandSecurityManager{
		logger: logger.With("component", "command-security"),
		config: DefaultCommandSecurityConfig(),
	}
}

// ValidateCommand performs comprehensive command validation
func (csm *CommandSecurityManager) ValidateCommand(ctx context.Context, line string) error {
	// Step 1: Basic length validation
	if err := csm.validateLength(ctx, line); err != nil {
		return err
	}

	// Step 2: UTF-8 validation
	if err := csm.validateUTF8(ctx, line); err != nil {
		return err
	}

	// Step 3: Control character filtering
	if err := csm.filterControlCharacters(ctx, line); err != nil {
		return err
	}

	// Step 4: Command canonicalization
	canonicalLine, err := csm.canonicalizeCommand(ctx, line)
	if err != nil {
		return err
	}

	// Step 5: Parse command and arguments
	cmd, args := csm.parseCommand(canonicalLine)

	// Step 6: Validate command structure
	if err := csm.validateCommandStructure(ctx, cmd, args); err != nil {
		return err
	}

	// Step 7: Validate command name
	if err := csm.validateCommandName(ctx, cmd); err != nil {
		return err
	}

	// Step 8: Validate command parameters
	if err := csm.validateCommandParameters(ctx, cmd, args); err != nil {
		return err
	}

	// Step 9: Check for blocked patterns
	if err := csm.checkBlockedPatterns(ctx, cmd, args); err != nil {
		return err
	}

	// Step 10: Log suspicious activity if enabled
	if csm.config.LogSuspiciousCommands {
		csm.logSuspiciousActivity(ctx, line, cmd, args)
	}

	return nil
}

// validateLength checks command line length
func (csm *CommandSecurityManager) validateLength(ctx context.Context, line string) error {
	if len(line) > csm.config.MaxCommandLength {
		csm.logger.WarnContext(ctx, "Command line too long",
			"length", len(line),
			"max_length", csm.config.MaxCommandLength,
		)
		return fmt.Errorf("500 5.5.2 Line too long")
	}
	return nil
}

// validateUTF8 ensures the line contains valid UTF-8
func (csm *CommandSecurityManager) validateUTF8(ctx context.Context, line string) error {
	if !utf8.ValidString(line) {
		csm.logger.WarnContext(ctx, "Invalid UTF-8 in command line")
		return fmt.Errorf("500 5.5.2 Invalid character encoding")
	}
	return nil
}

// filterControlCharacters removes or flags control characters
func (csm *CommandSecurityManager) filterControlCharacters(ctx context.Context, line string) error {
	// Check for null bytes and other dangerous control characters
	for i, r := range line {
		if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, LF, CR
			csm.logger.WarnContext(ctx, "Control character detected in command",
				"position", i,
				"character", fmt.Sprintf("\\x%02X", r),
			)
			return fmt.Errorf("500 5.5.2 Invalid control character")
		}
		if r == 127 { // DEL character
			csm.logger.WarnContext(ctx, "DEL character detected in command",
				"position", i,
			)
			return fmt.Errorf("500 5.5.2 Invalid control character")
		}
	}
	return nil
}

// canonicalizeCommand normalizes the command for consistent processing
func (csm *CommandSecurityManager) canonicalizeCommand(ctx context.Context, line string) (string, error) {
	// Trim whitespace
	canonical := strings.TrimSpace(line)

	// Normalize whitespace (replace multiple spaces with single space)
	whitespaceRegex := regexp.MustCompile(`\s+`)
	canonical = whitespaceRegex.ReplaceAllString(canonical, " ")

	// Remove any trailing whitespace
	canonical = strings.TrimSpace(canonical)

	// Check for empty command
	if canonical == "" {
		return "", fmt.Errorf("500 5.5.2 Empty command")
	}

	return canonical, nil
}

// parseCommand splits command into command name and arguments
func (csm *CommandSecurityManager) parseCommand(line string) (string, string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}
	return cmd, args
}

// validateCommandStructure validates the basic command structure
func (csm *CommandSecurityManager) validateCommandStructure(ctx context.Context, cmd, args string) error {
	// Command name must not be empty
	if cmd == "" {
		return fmt.Errorf("500 5.5.2 Invalid command structure")
	}

	// Command name must contain only allowed characters
	cmdRegex := regexp.MustCompile(csm.config.AllowedCommandChars)
	if !cmdRegex.MatchString(cmd) {
		csm.logger.WarnContext(ctx, "Command name contains invalid characters",
			"command", cmd,
		)
		return fmt.Errorf("500 5.5.2 Invalid command name")
	}

	// Check parameter length if present
	if args != "" && len(args) > csm.config.MaxParameterLength {
		csm.logger.WarnContext(ctx, "Command parameters too long",
			"length", len(args),
			"max_length", csm.config.MaxParameterLength,
		)
		return fmt.Errorf("500 5.5.2 Parameters too long")
	}

	return nil
}

// validateCommandName validates the command name against known commands
func (csm *CommandSecurityManager) validateCommandName(ctx context.Context, cmd string) error {
	// List of valid SMTP commands
	validCommands := map[string]bool{
		"HELO":     true,
		"EHLO":     true,
		"MAIL":     true,
		"RCPT":     true,
		"DATA":     true,
		"RSET":     true,
		"NOOP":     true,
		"QUIT":     true,
		"AUTH":     true,
		"STARTTLS": true,
		"HELP":     true,
		"VRFY":     true,
		"EXPN":     true,
		"XDEBUG":   true, // Development only
	}

	if !validCommands[cmd] {
		csm.logger.WarnContext(ctx, "Unknown command received",
			"command", cmd,
		)
		return fmt.Errorf("502 5.5.1 Command not recognized")
	}

	return nil
}

// validateCommandParameters validates command parameters
func (csm *CommandSecurityManager) validateCommandParameters(ctx context.Context, cmd, args string) error {
	if args == "" {
		return nil // No parameters to validate
	}

	// Validate parameter characters
	paramRegex := regexp.MustCompile(csm.config.AllowedParameterChars)
	if !paramRegex.MatchString(args) {
		csm.logger.WarnContext(ctx, "Command parameters contain invalid characters",
			"command", cmd,
			"parameters", args,
		)
		return fmt.Errorf("500 5.5.2 Invalid parameter characters")
	}

	// Command-specific parameter validation
	switch cmd {
	case "HELO", "EHLO":
		return csm.validateHostnameParameter(ctx, args)
	case "MAIL":
		return csm.validateMailFromParameter(ctx, args)
	case "RCPT":
		return csm.validateRcptToParameter(ctx, args)
	case "AUTH":
		return csm.validateAuthParameter(ctx, args)
	case "VRFY", "EXPN":
		return csm.validateEmailParameter(ctx, args)
	}

	return nil
}

// validateHostnameParameter validates hostname parameters
func (csm *CommandSecurityManager) validateHostnameParameter(ctx context.Context, hostname string) error {
	// Check for empty hostname
	if hostname == "" {
		return fmt.Errorf("501 5.0.0 Hostname required")
	}

	// Basic hostname validation
	if len(hostname) > 255 {
		return fmt.Errorf("501 5.0.0 Hostname too long")
	}

	// Check for valid hostname characters
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostnameRegex.MatchString(hostname) {
		csm.logger.WarnContext(ctx, "Invalid hostname format",
			"hostname", hostname,
		)
		return fmt.Errorf("501 5.0.0 Invalid hostname format")
	}

	return nil
}

// validateMailFromParameter validates MAIL FROM parameters
func (csm *CommandSecurityManager) validateMailFromParameter(ctx context.Context, args string) error {
	// Check for proper MAIL FROM syntax
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Extract and validate email address
	addr := strings.TrimPrefix(args, "FROM:")
	addr = strings.TrimPrefix(addr, "from:")
	addr = strings.TrimSpace(addr)

	// Check if address is empty after FROM:
	if addr == "" {
		return fmt.Errorf("501 5.5.4 Syntax: MAIL FROM:<address>")
	}

	// Remove angle brackets if present
	if strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}

	return csm.validateEmailAddress(ctx, addr)
}

// validateRcptToParameter validates RCPT TO parameters
func (csm *CommandSecurityManager) validateRcptToParameter(ctx context.Context, args string) error {
	// Check for proper RCPT TO syntax
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Extract and validate email address
	addr := strings.TrimPrefix(args, "TO:")
	addr = strings.TrimPrefix(addr, "to:")
	addr = strings.TrimSpace(addr)

	// Check if address is empty after TO:
	if addr == "" {
		return fmt.Errorf("501 5.5.4 Syntax: RCPT TO:<address>")
	}

	// Remove angle brackets if present
	if strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		addr = addr[1 : len(addr)-1]
	}

	return csm.validateEmailAddress(ctx, addr)
}

// validateAuthParameter validates AUTH parameters
func (csm *CommandSecurityManager) validateAuthParameter(ctx context.Context, args string) error {
	// AUTH command should have a mechanism
	if args == "" {
		return fmt.Errorf("501 5.5.4 Syntax: AUTH <mechanism>")
	}

	// Split args and get the first part (mechanism)
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return fmt.Errorf("501 5.5.4 Syntax: AUTH <mechanism>")
	}

	// Check for valid auth mechanisms
	validMechanisms := []string{"PLAIN", "LOGIN"}
	mechanism := strings.ToUpper(fields[0])
	
	valid := false
	for _, vm := range validMechanisms {
		if mechanism == vm {
			valid = true
			break
		}
	}

	if !valid {
		csm.logger.WarnContext(ctx, "Invalid AUTH mechanism",
			"mechanism", mechanism,
		)
		return fmt.Errorf("504 5.7.4 Unrecognized authentication type")
	}

	return nil
}

// validateEmailParameter validates email address parameters
func (csm *CommandSecurityManager) validateEmailParameter(ctx context.Context, email string) error {
	return csm.validateEmailAddress(ctx, email)
}

// validateEmailAddress validates an email address
func (csm *CommandSecurityManager) validateEmailAddress(ctx context.Context, addr string) error {
	// Allow empty address for null sender
	if addr == "" {
		return nil
	}

	// Basic length check
	if len(addr) > 320 { // RFC 5321 limit
		return fmt.Errorf("501 5.1.3 Address too long")
	}

	// Basic email validation
	if !strings.Contains(addr, "@") || len(addr) < 3 {
		csm.logger.WarnContext(ctx, "Invalid email address format",
			"address", addr,
		)
		return fmt.Errorf("501 5.1.3 Invalid email address format")
	}

	// Check for valid email characters (more strict)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(addr) {
		csm.logger.WarnContext(ctx, "Invalid email address format",
			"address", addr,
		)
		return fmt.Errorf("501 5.1.3 Invalid email address format")
	}

	return nil
}

// checkBlockedPatterns checks for blocked patterns in command and parameters
func (csm *CommandSecurityManager) checkBlockedPatterns(ctx context.Context, cmd, args string) error {
	// Check command for blocked patterns
	for _, pattern := range csm.config.BlockedCommandPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(cmd) {
			csm.logger.WarnContext(ctx, "Blocked pattern detected in command",
				"command", cmd,
				"pattern", pattern,
			)
			return fmt.Errorf("554 5.7.1 Command rejected: security violation")
		}
	}

	// Check parameters for blocked patterns
	if args != "" {
		for _, pattern := range csm.config.BlockedParameterPatterns {
			regex := regexp.MustCompile(pattern)
			if regex.MatchString(args) {
				csm.logger.WarnContext(ctx, "Blocked pattern detected in parameters",
					"command", cmd,
					"parameters", args,
					"pattern", pattern,
				)
				return fmt.Errorf("554 5.7.1 Parameters rejected: security violation")
			}
		}
	}

	return nil
}

// logSuspiciousActivity logs potentially suspicious command activity
func (csm *CommandSecurityManager) logSuspiciousActivity(ctx context.Context, originalLine, cmd, args string) {
	// Check for suspicious patterns that might indicate attack attempts
	suspiciousPatterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter)`,
		`[;&|` + "`" + `$]`,
		`(?i)(script|javascript|vbscript)`,
		`\.\./|\.\.\\`,
		`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F`,
	}

	for _, pattern := range suspiciousPatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(originalLine) {
			csm.logger.WarnContext(ctx, "Suspicious command pattern detected",
				"original_line", originalLine,
				"command", cmd,
				"parameters", args,
				"pattern", pattern,
			)
			break
		}
	}
}

// SanitizeCommand sanitizes a command for safe logging
func (csm *CommandSecurityManager) SanitizeCommand(line string) string {
	// Remove control characters for safe logging
	sanitized := ""
	for _, r := range line {
		if r >= 32 && r != 127 { // Keep printable characters except DEL
			sanitized += string(r)
		} else {
			sanitized += fmt.Sprintf("\\x%02X", r)
		}
	}

	// Truncate if too long
	if len(sanitized) > 200 {
		sanitized = sanitized[:200] + "..."
	}

	return sanitized
}

// GetSecurityStats returns security statistics
func (csm *CommandSecurityManager) GetSecurityStats() map[string]interface{} {
	return map[string]interface{}{
		"max_command_length":     csm.config.MaxCommandLength,
		"max_parameter_length":   csm.config.MaxParameterLength,
		"strict_mode":           csm.config.StrictMode,
		"log_suspicious":        csm.config.LogSuspiciousCommands,
		"blocked_patterns":      len(csm.config.BlockedCommandPatterns) + len(csm.config.BlockedParameterPatterns),
	}
}
