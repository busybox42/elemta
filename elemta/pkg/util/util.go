package util

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Email validation constants and patterns
const (
	// MaxEmailLength is the maximum allowed length for an email address
	MaxEmailLength = 254

	// LocalPartMaxLength is the maximum allowed length for the local part of an email address
	LocalPartMaxLength = 64

	// DomainMaxLength is the maximum allowed length for the domain part of an email address
	DomainMaxLength = 255
)

var (
	// emailRegex is a simple regex for validating email format
	// Note: This is a basic check, use ValidateEmail for more thorough validation
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

	// ipv4Regex matches IPv4 addresses
	ipv4Regex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)

	// domainRegex matches valid domain names
	domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]$`)
)

// String Manipulation Functions

// TrimString trims a string to a maximum length and adds an ellipsis if truncated
func TrimString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// NormalizeString normalizes a string by trimming whitespace and converting to lowercase
func NormalizeString(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// RemoveWhitespace removes all whitespace from a string
func RemoveWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// SanitizeHeader sanitizes a header value by removing CR, LF, and other control characters
func SanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || (r < 32 && r != '\t') {
			return -1
		}
		return r
	}, s)
}

// QuoteString quotes a string if it contains whitespace or special characters
func QuoteString(s string) string {
	if strings.ContainsAny(s, " \t\r\n\"\\(),:;<>@[]") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// UnwrapText unwraps text that has been wrapped with newlines
func UnwrapText(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, " ")
}

// Email Address Functions

// ValidateEmail validates an email address format and structure
func ValidateEmail(email string) (bool, error) {
	if len(email) > MaxEmailLength {
		return false, fmt.Errorf("email exceeds maximum length of %d characters", MaxEmailLength)
	}

	// Basic format check
	if !emailRegex.MatchString(email) {
		return false, fmt.Errorf("email format is invalid")
	}

	// More thorough validation using mail.ParseAddress
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false, err
	}

	// Check if parsed address matches original
	if addr.Address != email {
		return false, fmt.Errorf("email address parsed differently than input")
	}

	// Check local part and domain lengths
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false, fmt.Errorf("email must contain exactly one @ symbol")
	}

	localPart, domain := parts[0], parts[1]
	if len(localPart) > LocalPartMaxLength {
		return false, fmt.Errorf("local part exceeds maximum length of %d characters", LocalPartMaxLength)
	}

	if len(domain) > DomainMaxLength {
		return false, fmt.Errorf("domain exceeds maximum length of %d characters", DomainMaxLength)
	}

	// Validate domain
	if !domainRegex.MatchString(domain) {
		return false, fmt.Errorf("domain part is invalid")
	}

	return true, nil
}

// NormalizeEmail normalizes an email address (lowercase, trim)
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ExtractDomain extracts the domain part from an email address
func ExtractDomain(email string) (string, error) {
	email = NormalizeEmail(email)
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid email address format")
	}
	return parts[1], nil
}

// ExtractLocalPart extracts the local part from an email address
func ExtractLocalPart(email string) (string, error) {
	email = NormalizeEmail(email)
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid email address format")
	}
	return parts[0], nil
}

// IP Address Functions

// IsIPv4 checks if a string is a valid IPv4 address
func IsIPv4(ip string) bool {
	return ipv4Regex.MatchString(ip)
}

// IsIPv6 checks if a string is a valid IPv6 address
func IsIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// IsValidIP checks if a string is a valid IP address (IPv4 or IPv6)
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsPrivateIP checks if an IP address is in private ranges
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check against private IP ranges
	privateIPv4Blocks := []string{
		"10.0.0.0/8",     // RFC 1918 private network
		"172.16.0.0/12",  // RFC 1918 private network
		"192.168.0.0/16", // RFC 1918 private network
		"127.0.0.0/8",    // RFC 1122 localhost
		"169.254.0.0/16", // RFC 3927 link-local
	}

	privateIPv6Blocks := []string{
		"fc00::/7",  // RFC 4193 unique local addresses
		"fe80::/10", // RFC 4291 link-local addresses
		"::1/128",   // RFC 4291 loopback address
	}

	// Check IPv4
	if ip.To4() != nil {
		for _, block := range privateIPv4Blocks {
			_, ipnet, _ := net.ParseCIDR(block)
			if ipnet.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Check IPv6
	for _, block := range privateIPv6Blocks {
		_, ipnet, _ := net.ParseCIDR(block)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// ReverseIPv4 reverses an IPv4 address for RBL lookups
func ReverseIPv4(ip string) (string, error) {
	if !IsIPv4(ip) {
		return "", fmt.Errorf("invalid IPv4 address")
	}

	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return strings.Join(parts, "."), nil
}

// GetHostname gets the hostname of the current machine
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return hostname
}

// Domain Functions

// IsValidDomain checks if a string is a valid domain name
func IsValidDomain(domain string) bool {
	return domainRegex.MatchString(domain)
}

// HasMXRecord checks if a domain has MX records
func HasMXRecord(domain string) (bool, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return false, err
	}
	return len(mxRecords) > 0, nil
}

// GetMXRecords gets the MX records for a domain
func GetMXRecords(domain string) ([]*net.MX, error) {
	return net.LookupMX(domain)
}

// GetTXTRecords gets the TXT records for a domain
func GetTXTRecords(domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

// Time and Date Functions

// FormatRFC2822 formats a time according to RFC2822 (email date format)
func FormatRFC2822(t time.Time) string {
	return t.Format("Mon, 02 Jan 2006 15:04:05 -0700")
}

// ParseRFC2822 parses a time string in RFC2822 format
func ParseRFC2822(s string) (time.Time, error) {
	formats := []string{
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"02 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("could not parse time: %s", s)
}

// Random Generation Functions

// GenerateRandomBytes generates random bytes of the specified length
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(n int) (string, error) {
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:n], nil
}

// GenerateMessageID generates a unique Message-ID for an email
func GenerateMessageID(domain string) string {
	randomPart, _ := GenerateRandomString(12)
	timestamp := time.Now().Unix()
	return fmt.Sprintf("<%d.%s@%s>", timestamp, randomPart, domain)
}

// GenerateRandomToken generates a random token suitable for authentication
func GenerateRandomToken(length int) (string, error) {
	bytes, err := GenerateRandomBytes((length*3)/4 + 1)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// MIME and Content Type Functions

// GetMIMEType returns the MIME type for common file extensions
func GetMIMEType(filename string) string {
	ext := strings.ToLower(strings.TrimPrefix(filename[strings.LastIndex(filename, "."):], "."))

	mimeTypes := map[string]string{
		"txt":  "text/plain",
		"html": "text/html",
		"htm":  "text/html",
		"css":  "text/css",
		"js":   "application/javascript",
		"json": "application/json",
		"xml":  "application/xml",
		"jpg":  "image/jpeg",
		"jpeg": "image/jpeg",
		"png":  "image/png",
		"gif":  "image/gif",
		"webp": "image/webp",
		"svg":  "image/svg+xml",
		"pdf":  "application/pdf",
		"doc":  "application/msword",
		"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"xls":  "application/vnd.ms-excel",
		"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"zip":  "application/zip",
		"gz":   "application/gzip",
		"tar":  "application/x-tar",
		"mp3":  "audio/mpeg",
		"mp4":  "video/mp4",
		"wav":  "audio/wav",
		"eml":  "message/rfc822",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}

	return "application/octet-stream"
}

// IsTextMIMEType checks if a MIME type is a text type
func IsTextMIMEType(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") ||
		mimeType == "application/json" ||
		mimeType == "application/xml" ||
		mimeType == "application/javascript"
}

// Encoding and Decoding Functions

// EncodeBase64 encodes a string to base64
func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// DecodeBase64 decodes a base64 string
func DecodeBase64(s string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// EncodeQuotedPrintable encodes a string in quoted-printable format
func EncodeQuotedPrintable(s string) string {
	// Simple implementation - for a full implementation, use the mime/quotedprintable package
	var result strings.Builder

	for _, r := range s {
		if r > 127 || r == '=' || r == '\r' || r == '\n' {
			result.WriteString(fmt.Sprintf("=%02X", r))
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// Logging Utilities

// LogLevels represents different log levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	FATAL
)

// LogLevelToString converts a log level to a string
func LogLevelToString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// FormatLogMessage formats a log message with timestamp, level, and message
func FormatLogMessage(level LogLevel, message string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	hostname := GetHostname()
	return fmt.Sprintf("%s [%s] [%s] %s", timestamp, LogLevelToString(level), hostname, message)
}

// Validation Functions

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

// ContainsAny checks if a string contains any of the specified substrings
func ContainsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// IsASCII checks if a string contains only ASCII characters
func IsASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// HasValidSenderPolicy checks if an email domain has valid sender policy records
func HasValidSenderPolicy(domain string) (bool, error) {
	// Check for SPF record
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return false, err
	}

	hasSPF := false
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1 ") {
			hasSPF = true
			break
		}
	}

	// Check for DMARC record
	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		// DMARC record might not exist, which is not an error
		return hasSPF, nil
	}

	hasDMARC := false
	for _, txt := range dmarcRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			hasDMARC = true
			break
		}
	}

	return hasSPF && hasDMARC, nil
}

// File and Path Functions

// SanitizeFilename sanitizes a filename by removing invalid characters
func SanitizeFilename(filename string) string {
	// Replace invalid characters with underscores
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	result := filename

	for _, char := range invalidChars {
		result = strings.ReplaceAll(result, char, "_")
	}

	return result
}

// EnsureDirectoryExists ensures that a directory exists, creating it if necessary
func EnsureDirectoryExists(path string) error {
	return os.MkdirAll(path, 0755)
}

// IsFileExists checks if a file exists
func IsFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Email Header Functions

// FormatEmailAddressList formats a list of email addresses for a header
func FormatEmailAddressList(addresses []*mail.Address) string {
	if len(addresses) == 0 {
		return ""
	}

	parts := make([]string, len(addresses))
	for i, addr := range addresses {
		parts[i] = addr.String()
	}

	return strings.Join(parts, ", ")
}

// ParseEmailAddressList parses a list of email addresses from a header
func ParseEmailAddressList(list string) ([]*mail.Address, error) {
	return mail.ParseAddressList(list)
}

// FormatMessageID formats a Message-ID header value
func FormatMessageID(id string) string {
	if !strings.HasPrefix(id, "<") {
		id = "<" + id
	}
	if !strings.HasSuffix(id, ">") {
		id = id + ">"
	}
	return id
}

// ParseMessageID parses a Message-ID header value
func ParseMessageID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.Trim(id, "<>")
	return id
}
