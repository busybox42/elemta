# Elemta Utility Package

This package provides a comprehensive set of utility functions for the Elemta email server project. It contains helper functions for common operations used across the codebase, including string manipulation, email address validation, IP address handling, logging utilities, and other general-purpose helpers.

## Categories of Utilities

### String Manipulation
- `TrimString`: Trims a string to a maximum length with ellipsis
- `NormalizeString`: Normalizes a string (lowercase, trim whitespace)
- `RemoveWhitespace`: Removes all whitespace from a string
- `SanitizeHeader`: Sanitizes email header values
- `QuoteString`: Quotes a string if it contains special characters
- `UnwrapText`: Unwraps text that has been wrapped with newlines

### Email Address Functions
- `ValidateEmail`: Validates an email address format and structure
- `NormalizeEmail`: Normalizes an email address
- `ExtractDomain`: Extracts the domain part from an email address
- `ExtractLocalPart`: Extracts the local part from an email address

### IP Address Functions
- `IsIPv4`: Checks if a string is a valid IPv4 address
- `IsIPv6`: Checks if a string is a valid IPv6 address
- `IsValidIP`: Checks if a string is a valid IP address (IPv4 or IPv6)
- `IsPrivateIP`: Checks if an IP address is in private ranges
- `ReverseIPv4`: Reverses an IPv4 address for RBL lookups
- `GetHostname`: Gets the hostname of the current machine

### Domain Functions
- `IsValidDomain`: Checks if a string is a valid domain name
- `HasMXRecord`: Checks if a domain has MX records
- `GetMXRecords`: Gets the MX records for a domain
- `GetTXTRecords`: Gets the TXT records for a domain

### Time and Date Functions
- `FormatRFC2822`: Formats a time according to RFC2822 (email date format)
- `ParseRFC2822`: Parses a time string in RFC2822 format

### Random Generation Functions
- `GenerateRandomBytes`: Generates random bytes of the specified length
- `GenerateRandomString`: Generates a random string of the specified length
- `GenerateMessageID`: Generates a unique Message-ID for an email
- `GenerateRandomToken`: Generates a random token suitable for authentication

### MIME and Content Type Functions
- `GetMIMEType`: Returns the MIME type for common file extensions
- `IsTextMIMEType`: Checks if a MIME type is a text type

### Encoding and Decoding Functions
- `EncodeBase64`: Encodes a string to base64
- `DecodeBase64`: Decodes a base64 string
- `EncodeQuotedPrintable`: Encodes a string in quoted-printable format

### Logging Utilities
- `LogLevel`: Enum for different log levels (DEBUG, INFO, WARNING, ERROR, FATAL)
- `LogLevelToString`: Converts a log level to a string
- `FormatLogMessage`: Formats a log message with timestamp, level, and message

### Validation Functions
- `IsEmpty`: Checks if a string is empty or contains only whitespace
- `ContainsAny`: Checks if a string contains any of the specified substrings
- `IsASCII`: Checks if a string contains only ASCII characters
- `HasValidSenderPolicy`: Checks if an email domain has valid sender policy records

### File and Path Functions
- `SanitizeFilename`: Sanitizes a filename by removing invalid characters
- `EnsureDirectoryExists`: Ensures that a directory exists, creating it if necessary
- `IsFileExists`: Checks if a file exists

### Email Header Functions
- `FormatEmailAddressList`: Formats a list of email addresses for a header
- `ParseEmailAddressList`: Parses a list of email addresses from a header
- `FormatMessageID`: Formats a Message-ID header value
- `ParseMessageID`: Parses a Message-ID header value

## Usage Examples

### Email Validation

```go
// Validate an email address
valid, err := util.ValidateEmail("user@example.com")
if err != nil {
    log.Printf("Email validation error: %v", err)
}
if valid {
    log.Println("Email is valid")
}

// Extract domain from email
domain, err := util.ExtractDomain("user@example.com")
if err != nil {
    log.Printf("Error extracting domain: %v", err)
}
log.Printf("Domain: %s", domain)
```

### IP Address Handling

```go
// Check if an IP is valid
if util.IsValidIP("192.168.1.1") {
    log.Println("Valid IP address")
}

// Check if an IP is private
if util.IsPrivateIP("192.168.1.1") {
    log.Println("Private IP address")
}

// Reverse an IP for RBL lookups
reversed, err := util.ReverseIPv4("192.168.1.1")
if err != nil {
    log.Printf("Error reversing IP: %v", err)
}
log.Printf("Reversed IP: %s", reversed)
```

### Message ID Generation

```go
// Generate a unique Message-ID
messageID := util.GenerateMessageID("example.com")
log.Printf("Generated Message-ID: %s", messageID)
```

### Logging

```go
// Format a log message
logMessage := util.FormatLogMessage(util.INFO, "Email processed successfully")
log.Println(logMessage)
```

## Testing

The package includes comprehensive tests for all utility functions. Run the tests with:

```bash
cd pkg/util
go test -v
``` 