package util

import (
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStringManipulation(t *testing.T) {
	// Test TrimString
	if TrimString("Hello, world!", 5) != "He..." {
		t.Errorf("TrimString failed")
	}
	if TrimString("Short", 10) != "Short" {
		t.Errorf("TrimString failed for short string")
	}

	// Test NormalizeString
	if NormalizeString("  Hello, WORLD!  ") != "hello, world!" {
		t.Errorf("NormalizeString failed")
	}

	// Test RemoveWhitespace
	if RemoveWhitespace("Hello, \t\n world!") != "Hello,world!" {
		t.Errorf("RemoveWhitespace failed")
	}

	// Test SanitizeHeader
	if SanitizeHeader("Subject: \r\nTest") != "Subject: Test" {
		t.Errorf("SanitizeHeader failed")
	}

	// Test QuoteString
	if QuoteString("Hello") != "Hello" {
		t.Errorf("QuoteString failed for simple string")
	}
	if QuoteString("Hello, world!") != "\"Hello, world!\"" {
		t.Errorf("QuoteString failed for string with special chars")
	}

	// Test UnwrapText
	if UnwrapText("Line 1\nLine 2\nLine 3") != "Line 1 Line 2 Line 3" {
		t.Errorf("UnwrapText failed")
	}
}

func TestEmailValidation(t *testing.T) {
	// Test ValidateEmail
	validEmails := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.com",
		"user-name@example.co.uk",
	}

	invalidEmails := []string{
		"",
		"user",
		"user@",
		"@example.com",
		"user@.com",
		"user@example.",
		"user@example..com",
		strings.Repeat("a", 65) + "@example.com", // Local part too long
		strings.Repeat("a", 255) + "@example.com",   // Email too long
		"user@" + strings.Repeat("a", 256) + ".com", // Domain too long
	}

	for _, email := range validEmails {
		valid, err := ValidateEmail(email)
		if !valid || err != nil {
			t.Errorf("ValidateEmail failed for valid email: %s, error: %v", email, err)
		}
	}

	for _, email := range invalidEmails {
		valid, _ := ValidateEmail(email)
		if valid {
			t.Errorf("ValidateEmail failed for invalid email: %s", email)
		}
	}

	// Test with invalid address format that mail.ParseAddress would reject
	_, err := ValidateEmail("user@example.com (comment)")
	if err == nil {
		t.Errorf("ValidateEmail should have failed for email with comment")
	}

	// Test NormalizeEmail
	if NormalizeEmail("  User@Example.COM  ") != "user@example.com" {
		t.Errorf("NormalizeEmail failed")
	}

	// Test ExtractDomain
	domain, err := ExtractDomain("user@example.com")
	if err != nil || domain != "example.com" {
		t.Errorf("ExtractDomain failed: %v", err)
	}

	// Test ExtractDomain with invalid email
	_, err = ExtractDomain("invalid-email")
	if err == nil {
		t.Errorf("ExtractDomain should have failed for invalid email")
	}

	// Test ExtractLocalPart
	localPart, err := ExtractLocalPart("user@example.com")
	if err != nil || localPart != "user" {
		t.Errorf("ExtractLocalPart failed: %v", err)
	}

	// Test ExtractLocalPart with invalid email
	_, err = ExtractLocalPart("invalid-email")
	if err == nil {
		t.Errorf("ExtractLocalPart should have failed for invalid email")
	}
}

func TestIPFunctions(t *testing.T) {
	// Test IsIPv4
	if !IsIPv4("192.168.1.1") {
		t.Errorf("IsIPv4 failed for valid IPv4")
	}
	if IsIPv4("2001:db8::1") {
		t.Errorf("IsIPv4 failed for IPv6")
	}
	if IsIPv4("not-an-ip") {
		t.Errorf("IsIPv4 failed for invalid IP")
	}

	// Test IsIPv6
	if !IsIPv6("2001:db8::1") {
		t.Errorf("IsIPv6 failed for valid IPv6")
	}
	if IsIPv6("192.168.1.1") {
		t.Errorf("IsIPv6 failed for IPv4")
	}
	if IsIPv6("not-an-ip") {
		t.Errorf("IsIPv6 failed for invalid IP")
	}

	// Test IsValidIP
	if !IsValidIP("192.168.1.1") {
		t.Errorf("IsValidIP failed for valid IPv4")
	}
	if !IsValidIP("2001:db8::1") {
		t.Errorf("IsValidIP failed for valid IPv6")
	}
	if IsValidIP("not-an-ip") {
		t.Errorf("IsValidIP failed for invalid IP")
	}

	// Test IsPrivateIP
	if !IsPrivateIP("192.168.1.1") {
		t.Errorf("IsPrivateIP failed for private IPv4")
	}
	if !IsPrivateIP("127.0.0.1") {
		t.Errorf("IsPrivateIP failed for localhost IPv4")
	}
	if IsPrivateIP("8.8.8.8") {
		t.Errorf("IsPrivateIP failed for public IPv4")
	}

	// Test IsPrivateIP with invalid IP
	if IsPrivateIP("not-an-ip") {
		t.Errorf("IsPrivateIP failed for invalid IP")
	}

	// Test IsPrivateIP with IPv6 loopback
	if !IsPrivateIP("::1") {
		t.Errorf("IsPrivateIP failed for IPv6 loopback")
	}

	// Test IsPrivateIP with public IPv6
	if IsPrivateIP("2001:db8::1") {
		t.Errorf("IsPrivateIP failed for public IPv6")
	}

	// Test ReverseIPv4
	reversed, err := ReverseIPv4("192.168.1.1")
	if err != nil || reversed != "1.1.168.192" {
		t.Errorf("ReverseIPv4 failed: %v, got %s", err, reversed)
	}

	// Test ReverseIPv4 with invalid IP
	_, err = ReverseIPv4("not-an-ip")
	if err == nil {
		t.Errorf("ReverseIPv4 should have failed for invalid IP")
	}
}

func TestDomainFunctions(t *testing.T) {
	// Test IsValidDomain
	if !IsValidDomain("example.com") {
		t.Errorf("IsValidDomain failed for valid domain")
	}
	if !IsValidDomain("sub.example.co.uk") {
		t.Errorf("IsValidDomain failed for valid subdomain")
	}
	if IsValidDomain("invalid..domain") {
		t.Errorf("IsValidDomain failed for invalid domain")
	}
	if IsValidDomain("domain.") {
		t.Errorf("IsValidDomain failed for domain with trailing dot")
	}

	// Note: The following tests require network access and may fail in some environments
	// To run these tests, uncomment the code below and ensure you have internet connectivity
	// These tests are disabled by default to avoid test failures in CI/CD environments
	// or when running tests without internet access
	/*
		// Test HasMXRecord
		hasMX, err := HasMXRecord("gmail.com")
		if err != nil {
			t.Errorf("HasMXRecord failed with error: %v", err)
		}
		if !hasMX {
			t.Errorf("HasMXRecord failed for domain with MX records")
		}

		// Test with invalid domain
		hasMX, err = HasMXRecord("invalid-domain-that-does-not-exist.example")
		if err == nil {
			t.Logf("HasMXRecord did not return error for invalid domain, which might be environment-dependent")
		}
		if hasMX {
			t.Errorf("HasMXRecord returned true for invalid domain")
		}

		// Test GetMXRecords
		mxRecords, err := GetMXRecords("gmail.com")
		if err != nil {
			t.Errorf("GetMXRecords failed with error: %v", err)
		}
		if len(mxRecords) == 0 {
			t.Errorf("GetMXRecords failed to find MX records")
		}

		// Test with invalid domain
		mxRecords, err = GetMXRecords("invalid-domain-that-does-not-exist.example")
		if err == nil {
			t.Logf("GetMXRecords did not return error for invalid domain, which might be environment-dependent")
		}
		if len(mxRecords) > 0 {
			t.Errorf("GetMXRecords found MX records for invalid domain")
		}

		// Test GetTXTRecords
		txtRecords, err := GetTXTRecords("gmail.com")
		if err != nil {
			t.Errorf("GetTXTRecords failed with error: %v", err)
		}
		if len(txtRecords) == 0 {
			t.Errorf("GetTXTRecords failed to find TXT records")
		}

		// Test with invalid domain
		txtRecords, err = GetTXTRecords("invalid-domain-that-does-not-exist.example")
		if err == nil {
			t.Logf("GetTXTRecords did not return error for invalid domain, which might be environment-dependent")
		}
		if len(txtRecords) > 0 {
			t.Errorf("GetTXTRecords found TXT records for invalid domain")
		}
	*/
}

func TestTimeAndDateFunctions(t *testing.T) {
	// Test FormatRFC2822
	testTime := time.Date(2023, 1, 15, 12, 30, 45, 0, time.UTC)
	formatted := FormatRFC2822(testTime)
	expected := "Sun, 15 Jan 2023 12:30:45 +0000"
	if formatted != expected {
		t.Errorf("FormatRFC2822 failed, got: %s, expected: %s", formatted, expected)
	}

	// Test ParseRFC2822
	parsed, err := ParseRFC2822("Sun, 15 Jan 2023 12:30:45 +0000")
	if err != nil || parsed.Year() != 2023 || parsed.Month() != time.January || parsed.Day() != 15 {
		t.Errorf("ParseRFC2822 failed: %v", err)
	}

	// Test ParseRFC2822 with alternative formats
	formats := []string{
		"Mon, 2 Jan 2023 12:30:45 +0000",
		"02 Jan 2023 12:30:45 +0000",
		"2 Jan 2023 12:30:45 +0000",
	}

	for _, format := range formats {
		parsed, err := ParseRFC2822(format)
		if err != nil || parsed.Year() != 2023 || parsed.Month() != time.January {
			t.Errorf("ParseRFC2822 failed for format %s: %v", format, err)
		}
	}

	// Test ParseRFC2822 with invalid format
	_, err = ParseRFC2822("Invalid date format")
	if err == nil {
		t.Errorf("ParseRFC2822 should have failed for invalid format")
	}
}

func TestRandomGenerationFunctions(t *testing.T) {
	// Test GenerateRandomBytes
	bytes, err := GenerateRandomBytes(16)
	if err != nil || len(bytes) != 16 {
		t.Errorf("GenerateRandomBytes failed: %v", err)
	}

	// Test GenerateRandomString
	str, err := GenerateRandomString(10)
	if err != nil || len(str) != 10 {
		t.Errorf("GenerateRandomString failed: %v", err)
	}

	// Test GenerateMessageID
	msgID := GenerateMessageID("example.com")
	if !strings.HasSuffix(msgID, "@example.com>") || !strings.HasPrefix(msgID, "<") {
		t.Errorf("GenerateMessageID failed, got: %s", msgID)
	}

	// Test GenerateRandomToken
	token, err := GenerateRandomToken(20)
	if err != nil || len(token) != 20 {
		t.Errorf("GenerateRandomToken failed: %v", err)
	}

	// Test GenerateRandomBytes with zero length
	bytes, err = GenerateRandomBytes(0)
	if err != nil || len(bytes) != 0 {
		t.Errorf("GenerateRandomBytes failed for zero length: %v", err)
	}

	// Note: We don't test negative lengths for GenerateRandomString and GenerateRandomToken
	// as they would cause runtime panics. In a real implementation, these functions should
	// validate their input parameters to prevent such panics.
}

func TestMIMEFunctions(t *testing.T) {
	// Test GetMIMEType
	if GetMIMEType("test.txt") != "text/plain" {
		t.Errorf("GetMIMEType failed for txt")
	}
	if GetMIMEType("test.html") != "text/html" {
		t.Errorf("GetMIMEType failed for html")
	}
	if GetMIMEType("test.jpg") != "image/jpeg" {
		t.Errorf("GetMIMEType failed for jpg")
	}
	if GetMIMEType("test.unknown") != "application/octet-stream" {
		t.Errorf("GetMIMEType failed for unknown extension")
	}

	// Test IsTextMIMEType
	if !IsTextMIMEType("text/plain") {
		t.Errorf("IsTextMIMEType failed for text/plain")
	}
	if !IsTextMIMEType("text/html") {
		t.Errorf("IsTextMIMEType failed for text/html")
	}
	if !IsTextMIMEType("application/json") {
		t.Errorf("IsTextMIMEType failed for application/json")
	}
	if IsTextMIMEType("image/jpeg") {
		t.Errorf("IsTextMIMEType failed for image/jpeg")
	}
}

func TestEncodingFunctions(t *testing.T) {
	// Test EncodeBase64 and DecodeBase64
	original := "Hello, world!"
	encoded := EncodeBase64(original)
	decoded, err := DecodeBase64(encoded)
	if err != nil || decoded != original {
		t.Errorf("Base64 encoding/decoding failed: %v", err)
	}

	// Test EncodeQuotedPrintable
	if EncodeQuotedPrintable("Hello, world!") != "Hello, world!" {
		t.Errorf("EncodeQuotedPrintable failed for ASCII string")
	}
	if EncodeQuotedPrintable("Hello\r\nWorld") != "Hello=0D=0AWorld" {
		t.Errorf("EncodeQuotedPrintable failed for string with CR/LF")
	}

	// Test DecodeBase64 with invalid input
	_, err = DecodeBase64("Invalid base64 input!")
	if err == nil {
		t.Errorf("DecodeBase64 should have failed for invalid input")
	}
}

func TestLoggingFunctions(t *testing.T) {
	// Test LogLevelToString
	if LogLevelToString(DEBUG) != "DEBUG" {
		t.Errorf("LogLevelToString failed for DEBUG")
	}
	if LogLevelToString(INFO) != "INFO" {
		t.Errorf("LogLevelToString failed for INFO")
	}
	if LogLevelToString(WARNING) != "WARNING" {
		t.Errorf("LogLevelToString failed for WARNING")
	}
	if LogLevelToString(ERROR) != "ERROR" {
		t.Errorf("LogLevelToString failed for ERROR")
	}
	if LogLevelToString(FATAL) != "FATAL" {
		t.Errorf("LogLevelToString failed for FATAL")
	}

	// Test FormatLogMessage
	msg := FormatLogMessage(INFO, "Test message")
	if !strings.Contains(msg, "INFO") || !strings.Contains(msg, "Test message") {
		t.Errorf("FormatLogMessage failed, got: %s", msg)
	}

	// Test LogLevelToString with invalid level
	if LogLevelToString(LogLevel(99)) != "UNKNOWN" {
		t.Errorf("LogLevelToString failed for invalid level")
	}
}

func TestValidationFunctions(t *testing.T) {
	// Test IsEmpty
	if !IsEmpty("   ") {
		t.Errorf("IsEmpty failed for whitespace string")
	}
	if IsEmpty("Hello") {
		t.Errorf("IsEmpty failed for non-empty string")
	}

	// Test ContainsAny
	if !ContainsAny("Hello, world!", "world", "universe") {
		t.Errorf("ContainsAny failed for matching substring")
	}
	if ContainsAny("Hello, world!", "universe", "galaxy") {
		t.Errorf("ContainsAny failed for non-matching substrings")
	}

	// Test IsASCII
	if !IsASCII("Hello, world!") {
		t.Errorf("IsASCII failed for ASCII string")
	}
	if IsASCII("Hello, 世界!") {
		t.Errorf("IsASCII failed for non-ASCII string")
	}
}

func TestFileAndPathFunctions(t *testing.T) {
	// Test SanitizeFilename
	if SanitizeFilename("file:name?.txt") != "file_name_.txt" {
		t.Errorf("SanitizeFilename failed")
	}
	if SanitizeFilename("normal.txt") != "normal.txt" {
		t.Errorf("SanitizeFilename failed for normal filename")
	}

	// Test EnsureDirectoryExists
	tempDir := filepath.Join(os.TempDir(), "elemta_test_"+time.Now().Format("20060102150405"))
	defer os.RemoveAll(tempDir) // Clean up after test

	err := EnsureDirectoryExists(tempDir)
	if err != nil {
		t.Errorf("EnsureDirectoryExists failed: %v", err)
	}

	// Check if directory was created
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		t.Errorf("EnsureDirectoryExists did not create directory")
	}

	// Test IsFileExists
	testFile := filepath.Join(tempDir, "test.txt")
	if IsFileExists(testFile) {
		t.Errorf("IsFileExists returned true for non-existent file")
	}

	// Create test file
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	f.Close()

	if !IsFileExists(testFile) {
		t.Errorf("IsFileExists returned false for existing file")
	}
}

func TestGetHostname(t *testing.T) {
	hostname := GetHostname()
	if hostname == "" {
		t.Errorf("GetHostname returned empty string")
	}
	if hostname == "unknown-host" {
		// This is acceptable but log it for awareness
		t.Logf("GetHostname returned fallback value 'unknown-host'")
	}
}

func TestHasValidSenderPolicy(t *testing.T) {
	// Note: This test requires network access and may fail in some environments
	// We'll just test the function signature and error handling

	// Test with invalid domain
	_, err := HasValidSenderPolicy("invalid-domain-that-does-not-exist.example")
	if err == nil {
		t.Logf("HasValidSenderPolicy did not return error for invalid domain, which might be environment-dependent")
	}

	// Test with valid domain but skip actual validation
	// Just ensure the function doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("HasValidSenderPolicy panicked: %v", r)
		}
	}()

	// This call might succeed or fail depending on network and the domain's actual configuration
	// We're just testing that the function runs without panicking
	HasValidSenderPolicy("example.com")
}

func TestEmailHeaderFunctions(t *testing.T) {
	// Test FormatEmailAddressList
	addr1, _ := mail.ParseAddress("user1@example.com")
	addr2, _ := mail.ParseAddress("User Two <user2@example.com>")
	addresses := []*mail.Address{addr1, addr2}
	formatted := FormatEmailAddressList(addresses)
	if !strings.Contains(formatted, "user1@example.com") || !strings.Contains(formatted, "user2@example.com") {
		t.Errorf("FormatEmailAddressList failed, got: %s", formatted)
	}

	// Test ParseEmailAddressList
	list := "user1@example.com, User Two <user2@example.com>"
	parsed, err := ParseEmailAddressList(list)
	if err != nil || len(parsed) != 2 {
		t.Errorf("ParseEmailAddressList failed: %v", err)
	}

	// Test FormatMessageID
	if FormatMessageID("123.abc@example.com") != "<123.abc@example.com>" {
		t.Errorf("FormatMessageID failed")
	}
	if FormatMessageID("<123.abc@example.com>") != "<123.abc@example.com>" {
		t.Errorf("FormatMessageID failed for already formatted ID")
	}

	// Test ParseMessageID
	if ParseMessageID("<123.abc@example.com>") != "123.abc@example.com" {
		t.Errorf("ParseMessageID failed")
	}
	if ParseMessageID("123.abc@example.com") != "123.abc@example.com" {
		t.Errorf("ParseMessageID failed for unformatted ID")
	}

	// Test FormatEmailAddressList with empty list
	if FormatEmailAddressList([]*mail.Address{}) != "" {
		t.Errorf("FormatEmailAddressList failed for empty list")
	}
}
