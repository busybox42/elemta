package smtp

import (
	"fmt"
	"log/slog"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// EnhancedValidationResult contains comprehensive validation results with security analysis
type EnhancedValidationResult struct {
	Valid             bool
	ErrorType         string
	ErrorMessage      string
	SecurityThreat    string
	SanitizedValue    string
	NormalizedValue   string
	ValidationDetails map[string]interface{}
	RFCCompliant      bool
	SecurityScore     int // 0-100, higher is more secure
}

// SMTPParameterLimits defines RFC 5321 parameter limits
type SMTPParameterLimits struct {
	MaxCommandLength   int   // RFC 5321: 512 octets including CRLF
	MaxLocalPartLength int   // RFC 5321: 64 octets
	MaxDomainLength    int   // RFC 5321: 255 octets
	MaxPathLength      int   // RFC 5321: 256 octets
	MaxLineLength      int   // RFC 5321: 1000 octets including CRLF
	MaxHeaderLength    int   // RFC 5322: 998 octets
	MaxHeaderCount     int   // Reasonable limit
	MaxParameterLength int   // For SMTP extensions
	MaxSizeValue       int64 // Maximum SIZE parameter value
}

// DefaultSMTPParameterLimits returns RFC-compliant parameter limits
func DefaultSMTPParameterLimits() *SMTPParameterLimits {
	return &SMTPParameterLimits{
		MaxCommandLength:   512,
		MaxLocalPartLength: 64,
		MaxDomainLength:    255,
		MaxPathLength:      256,
		MaxLineLength:      1000,
		MaxHeaderLength:    998,
		MaxHeaderCount:     100,
		MaxParameterLength: 256,
		MaxSizeValue:       50 * 1024 * 1024, // 50MB
	}
}

// EnhancedValidator provides comprehensive input validation with security analysis
type EnhancedValidator struct {
	limits                   *SMTPParameterLimits
	logger                   *slog.Logger
	unicodeNormalizer        norm.Form
	suspiciousPatterns       []*regexp.Regexp
	sqlInjectionPatterns     []*regexp.Regexp
	commandInjectionPatterns []*regexp.Regexp
	headerInjectionPatterns  []*regexp.Regexp
}

// NewEnhancedValidator creates a new enhanced validator with security patterns
func NewEnhancedValidator(logger *slog.Logger) *EnhancedValidator {
	validator := &EnhancedValidator{
		limits:            DefaultSMTPParameterLimits(),
		logger:            logger,
		unicodeNormalizer: norm.NFC, // Canonical decomposition followed by canonical composition
	}

	// Initialize security patterns
	validator.initializeSecurityPatterns()

	return validator
}

// initializeSecurityPatterns initializes regex patterns for security threat detection
func (v *EnhancedValidator) initializeSecurityPatterns() {
	// Suspicious patterns for general threat detection
	v.suspiciousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)vbscript:`),
		regexp.MustCompile(`(?i)data:.*base64`),
		regexp.MustCompile(`(?i)eval\s*\(`),
		regexp.MustCompile(`(?i)expression\s*\(`),
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F`), // Control characters
	}

	// SQL injection patterns
	v.sqlInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(union\s+select|select\s+.*\s+from)\b`),
		regexp.MustCompile(`(?i)\b(insert\s+into|delete\s+from|update\s+.*\s+set)\b`),
		regexp.MustCompile(`(?i)\b(drop\s+table|alter\s+table|create\s+table)\b`),
		regexp.MustCompile(`(?i)\b(exec\s*\(|execute\s*\(|sp_|xp_)\b`),
		regexp.MustCompile(`(?i)\b(@@|char\s*\(|cast\s*\(|convert\s*\()\b`),
		regexp.MustCompile(`(?i)\b(waitfor\s+delay|benchmark\s*\(|sleep\s*\()\b`),
		regexp.MustCompile(`(?i)\b(information_schema|sys\.tables|sysobjects)\b`),
		regexp.MustCompile(`(?i)('|\"|;|--|\|\|)`), // Basic SQL metacharacters
	}

	// Command injection patterns
	v.commandInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[|&;` + "`" + `$]`),                         // Shell metacharacters
		regexp.MustCompile(`\$\{.*\}`),                                  // Variable expansion
		regexp.MustCompile(`\$\(.*\)`),                                  // Command substitution
		regexp.MustCompile(`\.\.[\\/]`),                                 // Path traversal
		regexp.MustCompile(`(?i)\b(rm\s+|del\s+|format\s+|fdisk\s+)\b`), // Dangerous commands
	}

	// Header injection patterns (CRLF injection) - more specific to avoid false positives
	v.headerInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F`),                       // Control chars
		regexp.MustCompile(`(?i)\r?\n\r?\n.*\r?\n\s*(to|from|cc|bcc|subject|reply-to|return-path|message-id|date):`), // Header injection after message body
		regexp.MustCompile(`(?i)\r?\n\r?\n.*\r?\n\s*x-`),                                                             // X- header injection after message body
	}
}

// ValidateAndNormalizeUnicode performs Unicode normalization and validation
func (v *EnhancedValidator) ValidateAndNormalizeUnicode(input string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Check if input is valid UTF-8
	if !utf8.ValidString(input) {
		result.Valid = false
		result.ErrorType = "invalid_utf8"
		result.ErrorMessage = "Input contains invalid UTF-8 sequences"
		result.SecurityThreat = "encoding_attack"
		result.SecurityScore = 0
		return result
	}

	// Normalize Unicode using NFC (Canonical Decomposition followed by Canonical Composition)
	normalized := v.unicodeNormalizer.String(input)
	result.NormalizedValue = normalized

	// Check for Unicode security issues
	if v.containsDangerousUnicode(normalized) {
		result.Valid = false
		result.ErrorType = "dangerous_unicode"
		result.ErrorMessage = "Input contains potentially dangerous Unicode characters"
		result.SecurityThreat = "unicode_attack"
		result.SecurityScore = 10
		return result
	}

	// Check for homograph attacks
	if v.containsHomographAttack(normalized) {
		result.Valid = false
		result.ErrorType = "homograph_attack"
		result.ErrorMessage = "Input contains characters that may be used for homograph attacks"
		result.SecurityThreat = "homograph_attack"
		result.SecurityScore = 20
		return result
	}

	result.Valid = true
	result.SanitizedValue = v.sanitizeUnicode(normalized)
	result.ValidationDetails["original_length"] = len(input)
	result.ValidationDetails["normalized_length"] = len(normalized)
	result.ValidationDetails["sanitized_length"] = len(result.SanitizedValue)

	return result
}

// containsDangerousUnicode checks for dangerous Unicode characters
func (v *EnhancedValidator) containsDangerousUnicode(input string) bool {
	for _, r := range input {
		// Check for dangerous Unicode categories
		if unicode.Is(unicode.Cc, r) && r != '\t' && r != '\n' && r != '\r' {
			return true // Control characters (except tab, LF, CR)
		}
		if unicode.Is(unicode.Cf, r) {
			return true // Format characters
		}
		if unicode.Is(unicode.Co, r) {
			return true // Private use characters
		}
		if unicode.Is(unicode.Cs, r) {
			return true // Surrogate characters
		}

		// Check for specific dangerous characters
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u200E', '\u200F': // Zero-width characters
			return true
		case '\uFEFF': // Byte order mark
			return true
		case '\u2028', '\u2029': // Line/paragraph separators
			return true
		}
	}
	return false
}

// containsHomographAttack checks for potential homograph attacks
func (v *EnhancedValidator) containsHomographAttack(input string) bool {
	// Basic check for mixed scripts that could indicate homograph attacks
	hasLatin := false
	hasCyrillic := false
	hasGreek := false

	for _, r := range input {
		// Check for specific script ranges
		if (r >= 0x0041 && r <= 0x005A) || (r >= 0x0061 && r <= 0x007A) {
			hasLatin = true
		} else if r >= 0x0400 && r <= 0x04FF {
			hasCyrillic = true
		} else if r >= 0x0370 && r <= 0x03FF {
			hasGreek = true
		}
	}

	// If we have Latin mixed with other potentially confusing scripts
	if hasLatin && (hasCyrillic || hasGreek) {
		return true
	}

	return false
}

// sanitizeUnicode removes or replaces dangerous Unicode characters
func (v *EnhancedValidator) sanitizeUnicode(input string) string {
	var result strings.Builder

	for _, r := range input {
		// Allow only safe characters
		if unicode.IsPrint(r) || r == '\t' || r == '\n' || r == '\r' {
			// Additional check for dangerous characters
			if !v.isDangerousUnicodeChar(r) {
				result.WriteRune(r)
			}
		}
	}

	return result.String()
}

// isDangerousUnicodeChar checks if a specific Unicode character is dangerous
func (v *EnhancedValidator) isDangerousUnicodeChar(r rune) bool {
	// Zero-width characters
	if r >= '\u200B' && r <= '\u200F' {
		return true
	}
	// Byte order mark
	if r == '\uFEFF' {
		return true
	}
	// Line/paragraph separators
	if r == '\u2028' || r == '\u2029' {
		return true
	}
	return false
}

// ValidateSMTPParameter validates SMTP command parameters with length limits and security checks
func (v *EnhancedValidator) ValidateSMTPParameter(paramType, paramValue string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// First, perform Unicode normalization
	unicodeResult := v.ValidateAndNormalizeUnicode(paramValue)
	if !unicodeResult.Valid {
		return unicodeResult
	}

	normalizedValue := unicodeResult.NormalizedValue
	result.NormalizedValue = normalizedValue

	// Parameter-specific validation
	switch strings.ToUpper(paramType) {
	case "MAIL_FROM", "RCPT_TO":
		return v.validateEmailParameter(normalizedValue)
	case "HELO", "EHLO":
		return v.validateHostnameParameter(normalizedValue)
	case "AUTH_TYPE":
		return v.validateAuthTypeParameter(normalizedValue)
	case "SIZE":
		return v.validateSizeParameter(normalizedValue)
	case "DATA_LINE":
		return v.validateDataLineParameter(normalizedValue)
	case "HEADER":
		return v.validateHeaderParameter(normalizedValue)
	default:
		return v.validateGenericParameter(normalizedValue)
	}
}

// validateEmailParameter validates email address parameters
func (v *EnhancedValidator) validateEmailParameter(email string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation according to RFC 5321
	if len(email) > v.limits.MaxPathLength {
		result.Valid = false
		result.ErrorType = "parameter_too_long"
		result.ErrorMessage = fmt.Sprintf("Email parameter exceeds RFC 5321 limit (%d characters)", v.limits.MaxPathLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Parse email address for detailed validation
	if email != "" && email != "<>" { // Allow null sender
		// Remove angle brackets if present
		cleanEmail := strings.Trim(email, "<>")

		// Validate using Go's mail package
		addr, err := mail.ParseAddress(cleanEmail)
		if err != nil {
			result.Valid = false
			result.ErrorType = "invalid_email_format"
			result.ErrorMessage = "Email address does not conform to RFC 5322"
			result.SecurityScore = 30
			return result
		}

		// Additional validation
		parts := strings.Split(addr.Address, "@")
		if len(parts) != 2 {
			result.Valid = false
			result.ErrorType = "invalid_email_structure"
			result.ErrorMessage = "Email address must contain exactly one @ symbol"
			result.SecurityScore = 20
			return result
		}

		localPart, domain := parts[0], parts[1]

		// Validate local part length
		if len(localPart) > v.limits.MaxLocalPartLength {
			result.Valid = false
			result.ErrorType = "local_part_too_long"
			result.ErrorMessage = fmt.Sprintf("Local part exceeds RFC 5321 limit (%d characters)", v.limits.MaxLocalPartLength)
			result.SecurityScore = 10
			return result
		}

		// Validate domain length
		if len(domain) > v.limits.MaxDomainLength {
			result.Valid = false
			result.ErrorType = "domain_too_long"
			result.ErrorMessage = fmt.Sprintf("Domain exceeds RFC 5321 limit (%d characters)", v.limits.MaxDomainLength)
			result.SecurityScore = 10
			return result
		}

		// Security pattern validation
		if securityResult := v.validateSecurityPatterns(email); !securityResult.Valid {
			return securityResult
		}
	}

	result.Valid = true
	result.RFCCompliant = true
	result.SanitizedValue = v.sanitizeEmailParameter(email)
	result.ValidationDetails["local_part_length"] = len(strings.Split(email, "@")[0])
	result.ValidationDetails["domain_length"] = len(strings.Split(email, "@")[1])

	return result
}

// validateHostnameParameter validates HELO/EHLO hostname parameters
func (v *EnhancedValidator) validateHostnameParameter(hostname string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(hostname) > v.limits.MaxDomainLength {
		result.Valid = false
		result.ErrorType = "hostname_too_long"
		result.ErrorMessage = fmt.Sprintf("Hostname exceeds RFC 5321 limit (%d characters)", v.limits.MaxDomainLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Basic hostname format validation
	if !v.isValidHostnameFormat(hostname) {
		result.Valid = false
		result.ErrorType = "invalid_hostname_format"
		result.ErrorMessage = "Hostname does not conform to RFC standards"
		result.SecurityScore = 30
		return result
	}

	// Security pattern validation
	if securityResult := v.validateSecurityPatterns(hostname); !securityResult.Valid {
		return securityResult
	}

	result.Valid = true
	result.RFCCompliant = true
	result.SanitizedValue = v.sanitizeHostname(hostname)
	result.ValidationDetails["label_count"] = len(strings.Split(hostname, "."))

	return result
}

// validateAuthTypeParameter validates AUTH command type parameters
func (v *EnhancedValidator) validateAuthTypeParameter(authType string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(authType) > v.limits.MaxParameterLength {
		result.Valid = false
		result.ErrorType = "auth_type_too_long"
		result.ErrorMessage = fmt.Sprintf("AUTH type exceeds maximum length (%d characters)", v.limits.MaxParameterLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Validate against known AUTH types
	validAuthTypes := map[string]bool{
		"PLAIN":      true,
		"LOGIN":      true,
		"CRAM-MD5":   false, // Disabled for security
		"DIGEST-MD5": false, // Disabled for security
		"NTLM":       false, // Disabled for security
	}

	upperAuthType := strings.ToUpper(authType)
	if allowed, exists := validAuthTypes[upperAuthType]; !exists {
		result.Valid = false
		result.ErrorType = "unknown_auth_type"
		result.ErrorMessage = "Unknown authentication type"
		result.SecurityScore = 40
		return result
	} else if !allowed {
		result.Valid = false
		result.ErrorType = "disabled_auth_type"
		result.ErrorMessage = "Authentication type disabled for security reasons"
		result.SecurityThreat = "weak_authentication"
		result.SecurityScore = 20
		return result
	}

	result.Valid = true
	result.RFCCompliant = true
	result.SanitizedValue = upperAuthType
	result.ValidationDetails["auth_type"] = upperAuthType

	return result
}

// validateSizeParameter validates SIZE parameter values
func (v *EnhancedValidator) validateSizeParameter(sizeStr string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(sizeStr) > 20 { // Reasonable limit for numeric values
		result.Valid = false
		result.ErrorType = "size_param_too_long"
		result.ErrorMessage = "SIZE parameter too long"
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Numeric validation
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		result.Valid = false
		result.ErrorType = "invalid_size_format"
		result.ErrorMessage = "SIZE parameter must be a valid integer"
		result.SecurityScore = 30
		return result
	}

	// Range validation
	if size < 0 {
		result.Valid = false
		result.ErrorType = "negative_size"
		result.ErrorMessage = "SIZE parameter cannot be negative"
		result.SecurityScore = 20
		return result
	}

	if size > v.limits.MaxSizeValue {
		result.Valid = false
		result.ErrorType = "size_too_large"
		result.ErrorMessage = fmt.Sprintf("SIZE parameter exceeds maximum allowed value (%d bytes)", v.limits.MaxSizeValue)
		result.SecurityThreat = "resource_exhaustion"
		result.SecurityScore = 10
		return result
	}

	result.Valid = true
	result.RFCCompliant = true
	result.SanitizedValue = sizeStr
	result.ValidationDetails["size_bytes"] = size

	return result
}

// validateHeaderParameter validates email headers (more permissive than data lines)
func (v *EnhancedValidator) validateHeaderParameter(headers string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(headers) > v.limits.MaxLineLength*10 { // Allow longer headers
		result.Valid = false
		result.ErrorType = "headers_too_long"
		result.ErrorMessage = fmt.Sprintf("Headers exceed maximum length (%d characters)", v.limits.MaxLineLength*10)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Check for dangerous Unicode characters
	if v.containsDangerousUnicode(headers) {
		result.Valid = false
		result.ErrorType = "dangerous_unicode"
		result.ErrorMessage = "Headers contain dangerous Unicode characters"
		result.SecurityThreat = "unicode_attack"
		result.SecurityScore = 0
		return result
	}

	// Check for homograph attacks
	if v.containsHomographAttack(headers) {
		result.Valid = false
		result.ErrorType = "homograph_attack"
		result.ErrorMessage = "Headers contain potential homograph attack patterns"
		result.SecurityThreat = "homograph_attack"
		result.SecurityScore = 0
		return result
	}

	// Only check for obvious header injection patterns (not legitimate headers)
	// This is more permissive than DATA_LINE validation
	if v.containsObviousHeaderInjection(headers) {
		result.Valid = false
		result.ErrorType = "header_injection"
		result.ErrorMessage = "Headers contain obvious injection patterns"
		result.SecurityThreat = "header_injection_attack"
		result.SecurityScore = 0
		return result
	}

	result.Valid = true
	result.SecurityScore = 100
	return result
}

// containsObviousHeaderInjection checks for obvious header injection patterns (more permissive)
func (v *EnhancedValidator) containsObviousHeaderInjection(input string) bool {
	// Only check for obvious injection patterns, not legitimate headers
	obviousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F`), // Control chars
		regexp.MustCompile(`(?i)\r?\n\r?\n.*\r?\n\s*(to|from|cc|bcc|subject|reply-to|return-path|message-id|date):`), // Header injection after body
		regexp.MustCompile(`(?i)\r?\n\r?\n.*\r?\n\s*x-`), // X- header injection after body
	}

	for _, pattern := range obviousPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// validateDataLineParameter validates individual lines in DATA command
func (v *EnhancedValidator) validateDataLineParameter(line string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation according to RFC 5321
	if len(line) > v.limits.MaxLineLength {
		result.Valid = false
		result.ErrorType = "line_too_long"
		result.ErrorMessage = fmt.Sprintf("Line exceeds RFC 5321 limit (%d characters)", v.limits.MaxLineLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Check if this looks like a legitimate email header
	if v.looksLikeHeader(line) {
		// For legitimate headers, use more relaxed validation
		return v.validateHeaderLineRelaxed(line)
	}

	// For non-header lines, check for header injection patterns
	// But only if the line doesn't look like a legitimate email header
	if !v.looksLikeHeader(line) && v.containsHeaderInjection(line) {
		result.Valid = false
		result.ErrorType = "header_injection"
		result.ErrorMessage = "Line contains header injection patterns"
		result.SecurityThreat = "header_injection_attack"
		result.SecurityScore = 0
		return result
	}

	// Security pattern validation for non-header content
	if securityResult := v.validateSecurityPatterns(line); !securityResult.Valid {
		return securityResult
	}

	result.Valid = true
	result.SanitizedValue = v.sanitizeDataLine(line)
	result.ValidationDetails["line_length"] = len(line)
	result.ValidationDetails["contains_headers"] = v.looksLikeHeader(line)

	return result
}

// validateGenericParameter validates generic SMTP parameters
func (v *EnhancedValidator) validateGenericParameter(param string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(param) > v.limits.MaxParameterLength {
		result.Valid = false
		result.ErrorType = "parameter_too_long"
		result.ErrorMessage = fmt.Sprintf("Parameter exceeds maximum length (%d characters)", v.limits.MaxParameterLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Security pattern validation
	if securityResult := v.validateSecurityPatterns(param); !securityResult.Valid {
		return securityResult
	}

	result.Valid = true
	result.SanitizedValue = v.sanitizeGenericParameter(param)
	result.ValidationDetails["parameter_length"] = len(param)

	return result
}

// validateHeaderSecurityPatterns checks header values against security threats with header-specific exceptions
func (v *EnhancedValidator) validateHeaderSecurityPatterns(headerName, headerValue string) *EnhancedValidationResult {
	// Convert header name to lowercase for comparison
	headerNameLower := strings.ToLower(headerName)

	// Headers that commonly contain semicolons and other characters that might trigger false positives
	safeHeaders := map[string]bool{
		"content-type":               true,
		"content-disposition":        true,
		"content-transfer-encoding":  true,
		"mime-version":               true,
		"user-agent":                 true,
		"x-mailer":                   true,
		"x-originating-ip":           true,
		"received":                   true,
		"authentication-results":     true,
		"dkim-signature":             true,
		"arc-seal":                   true,
		"arc-message-signature":      true,
		"arc-authentication-results": true,
	}

	// For safe headers, use relaxed validation (only check for actual injection patterns)
	if safeHeaders[headerNameLower] {
		return v.validateHeaderValueRelaxed(headerValue)
	}

	// For other headers, use standard security validation
	return v.validateSecurityPatterns(headerValue)
}

// validateHeaderValueRelaxed performs relaxed validation for safe headers
func (v *EnhancedValidator) validateHeaderValueRelaxed(headerValue string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Only check for actual dangerous patterns, not legitimate header syntax
	dangerousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\r\n|\n\r|\r|\n`),                                              // Line breaks (header injection)
		regexp.MustCompile(`\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F`), // Control chars
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),                                    // Script tags
		regexp.MustCompile(`(?i)javascript:`),                                                  // JavaScript protocol
		regexp.MustCompile(`(?i)eval\s*\(`),                                                    // eval() function
		regexp.MustCompile(`(?i)\b(union\s+select.*from|drop\s+table|delete\s+from)\b`),        // Obvious SQL injection
		regexp.MustCompile(`[|&` + "`" + `$]\s*[a-zA-Z/]`),                                     // Command injection (but not legitimate syntax)
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(headerValue) {
			result.Valid = false
			result.ErrorType = "header_security_violation"
			result.ErrorMessage = "Header contains dangerous patterns"
			result.SecurityThreat = "header_injection_attack"
			result.SecurityScore = 0
			return result
		}
	}

	result.Valid = true
	return result
}

// validateHeaderLineRelaxed performs relaxed validation for individual header lines
func (v *EnhancedValidator) validateHeaderLineRelaxed(line string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(line) > v.limits.MaxHeaderLength {
		result.Valid = false
		result.ErrorType = "header_too_long"
		result.ErrorMessage = fmt.Sprintf("Header exceeds RFC 5322 limit (%d characters)", v.limits.MaxHeaderLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Check for header format: "Name: Value"
	colonIndex := strings.Index(line, ":")
	if colonIndex == -1 {
		// Not a header line, treat as regular content
		result.Valid = true
		result.SanitizedValue = v.sanitizeDataLine(line)
		return result
	}

	headerName := strings.TrimSpace(line[:colonIndex])
	headerValue := strings.TrimSpace(line[colonIndex+1:])

	// Validate header name
	if len(headerName) == 0 {
		result.Valid = false
		result.ErrorType = "empty_header_name"
		result.ErrorMessage = "Header name cannot be empty"
		result.SecurityScore = 30
		return result
	}

	// Check for valid header name characters
	for _, r := range headerName {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			result.Valid = false
			result.ErrorType = "invalid_header_name"
			result.ErrorMessage = "Header name contains invalid characters"
			result.SecurityScore = 20
			return result
		}
	}

	// Use relaxed validation for header value
	headerValueResult := v.validateHeaderValueRelaxed(headerValue)
	if !headerValueResult.Valid {
		result.Valid = false
		result.ErrorType = headerValueResult.ErrorType
		result.ErrorMessage = "Header value: " + headerValueResult.ErrorMessage
		result.SecurityThreat = headerValueResult.SecurityThreat
		result.SecurityScore = headerValueResult.SecurityScore
		return result
	}

	result.Valid = true
	result.SanitizedValue = line
	result.ValidationDetails["header_name"] = headerName
	result.ValidationDetails["header_value_length"] = len(headerValue)

	return result
}

// validateSecurityPatterns checks input against various security threat patterns
func (v *EnhancedValidator) validateSecurityPatterns(input string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Check for suspicious patterns
	for _, pattern := range v.suspiciousPatterns {
		if pattern.MatchString(input) {
			result.Valid = false
			result.ErrorType = "suspicious_pattern"
			result.ErrorMessage = "Input contains suspicious patterns"
			result.SecurityThreat = "general_attack"
			result.SecurityScore = 10
			return result
		}
	}

	// Check for SQL injection patterns
	for _, pattern := range v.sqlInjectionPatterns {
		if pattern.MatchString(input) {
			result.Valid = false
			result.ErrorType = "sql_injection"
			result.ErrorMessage = "Input contains SQL injection patterns"
			result.SecurityThreat = "sql_injection_attack"
			result.SecurityScore = 0
			return result
		}
	}

	// Check for command injection patterns
	for _, pattern := range v.commandInjectionPatterns {
		if pattern.MatchString(input) {
			result.Valid = false
			result.ErrorType = "command_injection"
			result.ErrorMessage = "Input contains command injection patterns"
			result.SecurityThreat = "command_injection_attack"
			result.SecurityScore = 0
			return result
		}
	}

	result.Valid = true
	return result
}

// containsHeaderInjection checks for header injection patterns
func (v *EnhancedValidator) containsHeaderInjection(input string) bool {
	for _, pattern := range v.headerInjectionPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// looksLikeHeader checks if a line looks like an email header
func (v *EnhancedValidator) looksLikeHeader(line string) bool {
	// Basic header pattern: "HeaderName: value"
	colonIndex := strings.Index(line, ":")
	if colonIndex == -1 {
		return false
	}

	headerName := strings.TrimSpace(line[:colonIndex])

	// Check if header name contains only valid characters
	for _, r := range headerName {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}

	return len(headerName) > 0
}

// isValidHostnameFormat validates hostname format according to RFC standards
func (v *EnhancedValidator) isValidHostnameFormat(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Check for valid characters and structure
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// Label must start and end with alphanumeric
		if !unicode.IsLetter(rune(label[0])) && !unicode.IsDigit(rune(label[0])) {
			return false
		}
		if !unicode.IsLetter(rune(label[len(label)-1])) && !unicode.IsDigit(rune(label[len(label)-1])) {
			return false
		}

		// Check all characters in label
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}

	return true
}

// Sanitization functions

// sanitizeEmailParameter sanitizes email parameters
func (v *EnhancedValidator) sanitizeEmailParameter(email string) string {
	// Remove any null bytes and control characters except tab, LF, CR
	var result strings.Builder
	for _, r := range email {
		if r == 0 {
			continue // Remove null bytes
		}
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			continue // Remove control characters
		}
		result.WriteRune(r)
	}
	return result.String()
}

// sanitizeHostname sanitizes hostname parameters
func (v *EnhancedValidator) sanitizeHostname(hostname string) string {
	var result strings.Builder
	for _, r := range hostname {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// sanitizeDataLine sanitizes individual data lines
func (v *EnhancedValidator) sanitizeDataLine(line string) string {
	// Remove null bytes and most control characters, keep tab, LF, CR
	var result strings.Builder
	for _, r := range line {
		if r == 0 {
			continue
		}
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

// sanitizeGenericParameter sanitizes generic parameters
func (v *EnhancedValidator) sanitizeGenericParameter(param string) string {
	var result strings.Builder
	for _, r := range param {
		if r == 0 {
			continue
		}
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		if unicode.IsPrint(r) || r == ' ' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// SafeLogString sanitizes strings for safe logging to prevent log injection
func SafeLogString(input string) string {
	if input == "" {
		return ""
	}

	var result strings.Builder
	result.Grow(len(input)) // Pre-allocate capacity

	for _, r := range input {
		switch {
		case r == 0:
			result.WriteString("\\0") // Null byte
		case r == '\r':
			result.WriteString("\\r") // Carriage return
		case r == '\n':
			result.WriteString("\\n") // Line feed
		case r == '\t':
			result.WriteString("\\t") // Tab
		case r == '\\':
			result.WriteString("\\\\") // Backslash
		case r == '"':
			result.WriteString("\\\"") // Quote
		case unicode.IsControl(r):
			result.WriteString(fmt.Sprintf("\\u%04x", r)) // Other control characters
		case unicode.IsPrint(r):
			result.WriteRune(r) // Printable characters
		default:
			result.WriteString(fmt.Sprintf("\\u%04x", r)) // Non-printable characters
		}
	}

	// Truncate if too long for logging
	if result.Len() > 1000 {
		truncated := result.String()[:997] + "..."
		return truncated
	}

	return result.String()
}

// ValidateEmailHeaders validates email headers during DATA command processing
func (v *EnhancedValidator) ValidateEmailHeaders(headers string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Unfold headers first (handle continuation lines per RFC 5322)
	unfoldedHeaders := v.unfoldHeaders(headers)

	// Split into individual header lines
	headerLines := strings.Split(unfoldedHeaders, "\n")
	headerCount := 0
	suspiciousHeaders := 0

	for i, line := range headerLines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		headerCount++

		// Check header count limit
		if headerCount > v.limits.MaxHeaderCount {
			result.Valid = false
			result.ErrorType = "too_many_headers"
			result.ErrorMessage = fmt.Sprintf("Too many headers (limit: %d)", v.limits.MaxHeaderCount)
			result.SecurityThreat = "resource_exhaustion"
			result.SecurityScore = 20
			return result
		}

		// Validate individual header
		headerResult := v.validateSingleHeader(line)
		if !headerResult.Valid {
			result.Valid = false
			result.ErrorType = headerResult.ErrorType
			result.ErrorMessage = fmt.Sprintf("Header %d: %s", i+1, headerResult.ErrorMessage)
			result.SecurityThreat = headerResult.SecurityThreat
			result.SecurityScore = headerResult.SecurityScore
			return result
		}

		if headerResult.SecurityScore < 80 {
			suspiciousHeaders++
		}
	}

	// Check for suspicious header patterns
	if suspiciousHeaders > 5 {
		result.SecurityScore = 30
		result.ValidationDetails["suspicious_header_count"] = suspiciousHeaders
	}

	result.Valid = true
	result.ValidationDetails["header_count"] = headerCount
	result.ValidationDetails["suspicious_headers"] = suspiciousHeaders

	return result
}

// unfoldHeaders handles RFC 5322 header folding (continuation lines)
func (v *EnhancedValidator) unfoldHeaders(headers string) string {
	// Split by lines
	lines := strings.Split(headers, "\n")
	var unfoldedLines []string

	for _, line := range lines {
		// Remove \r if present
		line = strings.TrimRight(line, "\r")

		// If this line starts with space or tab, it's a continuation of the previous header
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(unfoldedLines) > 0 {
			// Append to the previous line (with a single space)
			lastIdx := len(unfoldedLines) - 1
			unfoldedLines[lastIdx] = unfoldedLines[lastIdx] + " " + strings.TrimSpace(line)
		} else {
			// New header line
			unfoldedLines = append(unfoldedLines, line)
		}
	}

	return strings.Join(unfoldedLines, "\n")
}

// validateSingleHeader validates a single email header
func (v *EnhancedValidator) validateSingleHeader(header string) *EnhancedValidationResult {
	result := &EnhancedValidationResult{
		ValidationDetails: make(map[string]interface{}),
		SecurityScore:     100,
	}

	// Length validation
	if len(header) > v.limits.MaxHeaderLength {
		result.Valid = false
		result.ErrorType = "header_too_long"
		result.ErrorMessage = fmt.Sprintf("Header exceeds RFC 5322 limit (%d characters)", v.limits.MaxHeaderLength)
		result.SecurityThreat = "buffer_overflow_attempt"
		result.SecurityScore = 0
		return result
	}

	// Header format validation
	colonIndex := strings.Index(header, ":")
	if colonIndex == -1 {
		result.Valid = false
		result.ErrorType = "invalid_header_format"
		result.ErrorMessage = "Header must contain a colon"
		result.SecurityScore = 40
		return result
	}

	headerName := strings.TrimSpace(header[:colonIndex])
	headerValue := strings.TrimSpace(header[colonIndex+1:])

	// Validate header name
	if len(headerName) == 0 {
		result.Valid = false
		result.ErrorType = "empty_header_name"
		result.ErrorMessage = "Header name cannot be empty"
		result.SecurityScore = 30
		return result
	}

	// Check for valid header name characters
	for _, r := range headerName {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			result.Valid = false
			result.ErrorType = "invalid_header_name"
			result.ErrorMessage = "Header name contains invalid characters"
			result.SecurityScore = 20
			return result
		}
	}

	// Header injection validation
	if v.containsHeaderInjection(headerValue) {
		result.Valid = false
		result.ErrorType = "header_injection"
		result.ErrorMessage = "Header value contains injection patterns"
		result.SecurityThreat = "header_injection_attack"
		result.SecurityScore = 0
		return result
	}

	// Security pattern validation for header value (with header-specific exceptions)
	if securityResult := v.validateHeaderSecurityPatterns(headerName, headerValue); !securityResult.Valid {
		result.Valid = false
		result.ErrorType = securityResult.ErrorType
		result.ErrorMessage = "Header value: " + securityResult.ErrorMessage
		result.SecurityThreat = securityResult.SecurityThreat
		result.SecurityScore = securityResult.SecurityScore
		return result
	}

	result.Valid = true
	result.ValidationDetails["header_name"] = headerName
	result.ValidationDetails["header_value_length"] = len(headerValue)

	return result
}

// LogSecurityEvent logs security events with sanitized input
func LogSecurityEvent(logger *slog.Logger, eventType, threat, message, input, remoteAddr string) {
	logger.Warn("smtp_security_event",
		"event_type", eventType,
		"security_threat", threat,
		"message", message,
		"sanitized_input", SafeLogString(input),
		"remote_addr", SafeLogString(remoteAddr),
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)
}
