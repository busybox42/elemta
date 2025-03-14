package main

import (
	"fmt"
	"log"
	"time"

	"github.com/elemta/elemta/pkg/util"
)

func main() {
	// Set up logging
	log.SetFlags(0) // Remove timestamp from log output for clarity

	fmt.Println("Elemta Utility Package Examples")
	fmt.Println("===============================")

	// String manipulation examples
	fmt.Println("\n## String Manipulation")
	fmt.Printf("TrimString: %q\n", util.TrimString("This is a very long string that needs to be trimmed", 20))
	fmt.Printf("NormalizeString: %q\n", util.NormalizeString("  Hello, WORLD!  "))
	fmt.Printf("RemoveWhitespace: %q\n", util.RemoveWhitespace("Hello, \t\n world!"))
	fmt.Printf("SanitizeHeader: %q\n", util.SanitizeHeader("Subject: \r\nTest"))
	fmt.Printf("QuoteString: %s\n", util.QuoteString("Hello, world!"))
	fmt.Printf("UnwrapText: %q\n", util.UnwrapText("Line 1\nLine 2\nLine 3"))

	// Email validation examples
	fmt.Println("\n## Email Validation")
	email := "user@example.com"
	valid, err := util.ValidateEmail(email)
	fmt.Printf("ValidateEmail(%q): valid=%v, err=%v\n", email, valid, err)

	invalidEmail := "invalid@email@example.com"
	valid, err = util.ValidateEmail(invalidEmail)
	fmt.Printf("ValidateEmail(%q): valid=%v, err=%v\n", invalidEmail, valid, err)

	fmt.Printf("NormalizeEmail: %q\n", util.NormalizeEmail("  User@Example.COM  "))

	domain, err := util.ExtractDomain(email)
	fmt.Printf("ExtractDomain: domain=%q, err=%v\n", domain, err)

	localPart, err := util.ExtractLocalPart(email)
	fmt.Printf("ExtractLocalPart: localPart=%q, err=%v\n", localPart, err)

	// IP address examples
	fmt.Println("\n## IP Address Functions")
	ip := "192.168.1.1"
	fmt.Printf("IsIPv4(%q): %v\n", ip, util.IsIPv4(ip))
	fmt.Printf("IsIPv6(%q): %v\n", ip, util.IsIPv6(ip))
	fmt.Printf("IsValidIP(%q): %v\n", ip, util.IsValidIP(ip))
	fmt.Printf("IsPrivateIP(%q): %v\n", ip, util.IsPrivateIP(ip))

	reversedIP, err := util.ReverseIPv4(ip)
	fmt.Printf("ReverseIPv4: reversedIP=%q, err=%v\n", reversedIP, err)

	fmt.Printf("GetHostname: %s\n", util.GetHostname())

	// Domain functions
	fmt.Println("\n## Domain Functions")
	fmt.Printf("IsValidDomain(%q): %v\n", domain, util.IsValidDomain(domain))

	// Note: The following functions make actual DNS queries
	// Uncomment if you want to test with real DNS lookups
	/*
		hasMX, err := util.HasMXRecord(domain)
		fmt.Printf("HasMXRecord: hasMX=%v, err=%v\n", hasMX, err)

		mxRecords, err := util.GetMXRecords(domain)
		fmt.Printf("GetMXRecords: count=%d, err=%v\n", len(mxRecords), err)

		txtRecords, err := util.GetTXTRecords(domain)
		fmt.Printf("GetTXTRecords: count=%d, err=%v\n", len(txtRecords), err)
	*/

	// Time and date functions
	fmt.Println("\n## Time and Date Functions")
	now := time.Now()
	formatted := util.FormatRFC2822(now)
	fmt.Printf("FormatRFC2822: %s\n", formatted)

	parsed, err := util.ParseRFC2822(formatted)
	fmt.Printf("ParseRFC2822: parsed=%v, err=%v\n", parsed, err)

	// Random generation functions
	fmt.Println("\n## Random Generation Functions")
	randomBytes, err := util.GenerateRandomBytes(8)
	fmt.Printf("GenerateRandomBytes: bytes=%v, err=%v\n", randomBytes, err)

	randomString, err := util.GenerateRandomString(10)
	fmt.Printf("GenerateRandomString: string=%q, err=%v\n", randomString, err)

	messageID := util.GenerateMessageID(domain)
	fmt.Printf("GenerateMessageID: %s\n", messageID)

	token, err := util.GenerateRandomToken(16)
	fmt.Printf("GenerateRandomToken: token=%q, err=%v\n", token, err)

	// MIME and content type functions
	fmt.Println("\n## MIME and Content Type Functions")
	fmt.Printf("GetMIMEType(%q): %s\n", "document.pdf", util.GetMIMEType("document.pdf"))
	fmt.Printf("GetMIMEType(%q): %s\n", "image.jpg", util.GetMIMEType("image.jpg"))
	fmt.Printf("GetMIMEType(%q): %s\n", "page.html", util.GetMIMEType("page.html"))
	fmt.Printf("GetMIMEType(%q): %s\n", "unknown.xyz", util.GetMIMEType("unknown.xyz"))

	fmt.Printf("IsTextMIMEType(%q): %v\n", "text/plain", util.IsTextMIMEType("text/plain"))
	fmt.Printf("IsTextMIMEType(%q): %v\n", "application/json", util.IsTextMIMEType("application/json"))
	fmt.Printf("IsTextMIMEType(%q): %v\n", "image/jpeg", util.IsTextMIMEType("image/jpeg"))

	// Encoding and decoding functions
	fmt.Println("\n## Encoding and Decoding Functions")
	original := "Hello, world!"
	encoded := util.EncodeBase64(original)
	fmt.Printf("EncodeBase64: %q -> %q\n", original, encoded)

	decoded, err := util.DecodeBase64(encoded)
	fmt.Printf("DecodeBase64: %q -> %q, err=%v\n", encoded, decoded, err)

	qpEncoded := util.EncodeQuotedPrintable("Hello\r\nWorld")
	fmt.Printf("EncodeQuotedPrintable: %q -> %q\n", "Hello\r\nWorld", qpEncoded)

	// Logging utilities
	fmt.Println("\n## Logging Utilities")
	for _, level := range []util.LogLevel{util.DEBUG, util.INFO, util.WARNING, util.ERROR, util.FATAL} {
		fmt.Printf("LogLevelToString(%d): %s\n", level, util.LogLevelToString(level))
	}

	logMessage := util.FormatLogMessage(util.INFO, "This is a test message")
	fmt.Printf("FormatLogMessage: %s\n", logMessage)

	// Validation functions
	fmt.Println("\n## Validation Functions")
	fmt.Printf("IsEmpty(%q): %v\n", "   ", util.IsEmpty("   "))
	fmt.Printf("IsEmpty(%q): %v\n", "Hello", util.IsEmpty("Hello"))

	fmt.Printf("ContainsAny(%q, %q, %q): %v\n", "Hello, world!", "world", "universe",
		util.ContainsAny("Hello, world!", "world", "universe"))
	fmt.Printf("ContainsAny(%q, %q, %q): %v\n", "Hello, world!", "universe", "galaxy",
		util.ContainsAny("Hello, world!", "universe", "galaxy"))

	fmt.Printf("IsASCII(%q): %v\n", "Hello, world!", util.IsASCII("Hello, world!"))
	fmt.Printf("IsASCII(%q): %v\n", "Hello, 世界!", util.IsASCII("Hello, 世界!"))

	// File and path functions
	fmt.Println("\n## File and Path Functions")
	fmt.Printf("SanitizeFilename(%q): %q\n", "file:name?.txt", util.SanitizeFilename("file:name?.txt"))
	fmt.Printf("SanitizeFilename(%q): %q\n", "normal.txt", util.SanitizeFilename("normal.txt"))

	// Email header functions
	fmt.Println("\n## Email Header Functions")
	fmt.Printf("FormatMessageID(%q): %q\n", "123.abc@example.com", util.FormatMessageID("123.abc@example.com"))
	fmt.Printf("ParseMessageID(%q): %q\n", "<123.abc@example.com>", util.ParseMessageID("<123.abc@example.com>"))
}
