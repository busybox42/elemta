package arc

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elemta/elemta/pkg/dkim"
)

// Status represents the ARC chain validation status
type Status string

const (
	// StatusNone indicates no ARC chain is present
	StatusNone Status = "none"
	// StatusPass indicates the ARC chain is valid
	StatusPass Status = "pass"
	// StatusFail indicates the ARC chain is invalid
	StatusFail Status = "fail"
)

// SignOptions represents options for ARC signing
type SignOptions struct {
	Domain                 string            // Domain to sign for
	Selector               string            // Selector to use
	PrivateKey             *rsa.PrivateKey   // Private key to sign with
	Headers                []string          // Headers to sign
	AuthenticationResults  string            // Authentication-Results header value
	ChainValidationStatus  Status            // Status of the existing chain (if any)
	SignatureAlgo          string            // Signature algorithm (rsa-sha1 or rsa-sha256)
	CanonicalizationHeader string            // Header canonicalization (simple or relaxed)
	CanonicalizationBody   string            // Body canonicalization (simple or relaxed)
	AdditionalTags         map[string]string // Additional tags to include in the signature
}

// VerifyOptions represents options for ARC verification
type VerifyOptions struct {
	AllowUnsafeDNS bool          // Allow unsafe DNS (no DNSSEC)
	DNSTimeout     time.Duration // DNS timeout
	MaxDNSQueries  int           // Maximum number of DNS queries
}

// VerifyResult represents the result of an ARC verification
type VerifyResult struct {
	Status      Status // Status (pass, fail, none)
	Error       error  // Error (if any)
	InstanceIDs []int  // Instance IDs found in the message
}

// Sign signs a message with ARC
func Sign(message []byte, options SignOptions) ([]byte, error) {
	// Validate options
	if options.Domain == "" {
		return nil, errors.New("domain is required")
	}
	if options.Selector == "" {
		return nil, errors.New("selector is required")
	}
	if options.PrivateKey == nil {
		return nil, errors.New("private key is required")
	}
	if options.AuthenticationResults == "" {
		return nil, errors.New("authentication results are required")
	}
	if len(options.Headers) == 0 {
		// Default headers to sign
		options.Headers = []string{"From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"}
	}
	if options.SignatureAlgo == "" {
		options.SignatureAlgo = "rsa-sha256"
	}
	if options.CanonicalizationHeader == "" {
		options.CanonicalizationHeader = "relaxed"
	}
	if options.CanonicalizationBody == "" {
		options.CanonicalizationBody = "relaxed"
	}

	// Parse message
	headers, body, err := parseMessage(message)
	if err != nil {
		return nil, err
	}

	// Determine instance number
	instanceID := 1
	for _, header := range headers {
		if strings.HasPrefix(strings.ToLower(header), "arc-seal:") {
			// Extract instance ID
			re := regexp.MustCompile(`i=(\d+)`)
			matches := re.FindStringSubmatch(header)
			if len(matches) > 1 {
				id, err := strconv.Atoi(matches[1])
				if err == nil && id >= instanceID {
					instanceID = id + 1
				}
			}
		}
	}

	// Create Authentication-Results header
	aarHeader := fmt.Sprintf("ARC-Authentication-Results: i=%d; %s", instanceID, options.AuthenticationResults)

	// Create ARC-Message-Signature
	dkimOptions := dkim.SignOptions{
		Domain:                 options.Domain,
		Selector:               options.Selector,
		PrivateKey:             options.PrivateKey,
		Headers:                append(options.Headers, fmt.Sprintf("ARC-Authentication-Results:i=%d", instanceID)),
		SignatureAlgo:          options.SignatureAlgo,
		CanonicalizationHeader: options.CanonicalizationHeader,
		CanonicalizationBody:   options.CanonicalizationBody,
	}

	// Create a temporary message with the AAR header
	var tempMessage bytes.Buffer
	tempMessage.WriteString(aarHeader)
	tempMessage.WriteString("\r\n")
	for _, header := range headers {
		tempMessage.WriteString(header)
		tempMessage.WriteString("\r\n")
	}
	tempMessage.WriteString("\r\n")
	tempMessage.Write(body)

	// Sign the message with DKIM
	signedMessage, err := dkim.Sign(tempMessage.Bytes(), dkimOptions)
	if err != nil {
		return nil, err
	}

	// Extract the DKIM-Signature header
	signedHeaders, _, err := parseMessage(signedMessage)
	if err != nil {
		return nil, err
	}

	var dkimSignature string
	for _, header := range signedHeaders {
		if strings.HasPrefix(strings.ToLower(header), "dkim-signature:") {
			dkimSignature = header
			break
		}
	}

	if dkimSignature == "" {
		return nil, errors.New("failed to extract DKIM signature")
	}

	// Convert DKIM-Signature to ARC-Message-Signature
	amsHeader := strings.Replace(dkimSignature, "DKIM-Signature:", fmt.Sprintf("ARC-Message-Signature: i=%d;", instanceID), 1)

	// Create ARC-Seal
	// Headers to include in the ARC-Seal
	sealHeaders := []string{
		fmt.Sprintf("ARC-Authentication-Results:i=%d", instanceID),
		fmt.Sprintf("ARC-Message-Signature:i=%d", instanceID),
	}

	// If there's a previous instance, include its ARC-Seal
	if instanceID > 1 {
		sealHeaders = append(sealHeaders, fmt.Sprintf("ARC-Seal:i=%d", instanceID-1))
	}

	// Create a temporary message with the AAR and AMS headers
	var sealMessage bytes.Buffer
	sealMessage.WriteString(aarHeader)
	sealMessage.WriteString("\r\n")
	sealMessage.WriteString(amsHeader)
	sealMessage.WriteString("\r\n")
	for _, header := range headers {
		sealMessage.WriteString(header)
		sealMessage.WriteString("\r\n")
	}
	sealMessage.WriteString("\r\n")
	sealMessage.Write(body)

	// Sign the seal
	dkimSealOptions := dkim.SignOptions{
		Domain:                 options.Domain,
		Selector:               options.Selector,
		PrivateKey:             options.PrivateKey,
		Headers:                sealHeaders,
		SignatureAlgo:          options.SignatureAlgo,
		CanonicalizationHeader: options.CanonicalizationHeader,
		CanonicalizationBody:   options.CanonicalizationBody,
	}

	sealedMessage, err := dkim.Sign(sealMessage.Bytes(), dkimSealOptions)
	if err != nil {
		return nil, err
	}

	// Extract the DKIM-Signature header for the seal
	sealedHeaders, _, err := parseMessage(sealedMessage)
	if err != nil {
		return nil, err
	}

	var sealSignature string
	for _, header := range sealedHeaders {
		if strings.HasPrefix(strings.ToLower(header), "dkim-signature:") {
			sealSignature = header
			break
		}
	}

	if sealSignature == "" {
		return nil, errors.New("failed to extract seal signature")
	}

	// Convert DKIM-Signature to ARC-Seal
	asHeader := strings.Replace(sealSignature, "DKIM-Signature:", fmt.Sprintf("ARC-Seal: i=%d; cv=%s;", instanceID, options.ChainValidationStatus), 1)

	// Create the final message with all ARC headers
	var result bytes.Buffer
	result.WriteString(asHeader)
	result.WriteString("\r\n")
	result.WriteString(amsHeader)
	result.WriteString("\r\n")
	result.WriteString(aarHeader)
	result.WriteString("\r\n")
	for _, header := range headers {
		result.WriteString(header)
		result.WriteString("\r\n")
	}
	result.WriteString("\r\n")
	result.Write(body)

	return result.Bytes(), nil
}

// Verify verifies an ARC chain
func Verify(message []byte, options VerifyOptions) (*VerifyResult, error) {
	// Set default options
	if options.DNSTimeout == 0 {
		options.DNSTimeout = 5 * time.Second
	}
	if options.MaxDNSQueries == 0 {
		options.MaxDNSQueries = 10
	}

	// Parse message
	headers, body, err := parseMessage(message)
	if err != nil {
		return nil, err
	}

	// Find ARC headers
	var arcSeals []string
	var arcMessageSignatures []string
	var arcAuthResults []string
	var otherHeaders []string

	for _, header := range headers {
		headerLower := strings.ToLower(header)
		if strings.HasPrefix(headerLower, "arc-seal:") {
			arcSeals = append(arcSeals, header)
		} else if strings.HasPrefix(headerLower, "arc-message-signature:") {
			arcMessageSignatures = append(arcMessageSignatures, header)
		} else if strings.HasPrefix(headerLower, "arc-authentication-results:") {
			arcAuthResults = append(arcAuthResults, header)
		} else {
			otherHeaders = append(otherHeaders, header)
		}
	}

	// Check if ARC chain exists
	if len(arcSeals) == 0 || len(arcMessageSignatures) == 0 || len(arcAuthResults) == 0 {
		return &VerifyResult{
			Status: StatusNone,
		}, nil
	}

	// Extract instance IDs
	instanceIDs, err := extractInstanceIDs(arcSeals)
	if err != nil {
		return &VerifyResult{
			Status: StatusFail,
			Error:  err,
		}, nil
	}

	// Verify the chain
	for i := 1; i <= len(instanceIDs); i++ {
		// Find headers for this instance
		seal, err := findHeaderByInstance(arcSeals, i)
		if err != nil {
			return &VerifyResult{
				Status:      StatusFail,
				Error:       err,
				InstanceIDs: instanceIDs,
			}, nil
		}

		msgSig, err := findHeaderByInstance(arcMessageSignatures, i)
		if err != nil {
			return &VerifyResult{
				Status:      StatusFail,
				Error:       err,
				InstanceIDs: instanceIDs,
			}, nil
		}

		authRes, err := findHeaderByInstance(arcAuthResults, i)
		if err != nil {
			return &VerifyResult{
				Status:      StatusFail,
				Error:       err,
				InstanceIDs: instanceIDs,
			}, nil
		}

		// For the first instance, verify the seal
		if i == 1 {
			if err := verifyFirstSeal(seal, msgSig, authRes, otherHeaders, body, options); err != nil {
				return &VerifyResult{
					Status:      StatusFail,
					Error:       err,
					InstanceIDs: instanceIDs,
				}, nil
			}
		} else {
			// For subsequent instances, verify the seal and check the chain validation status
			prevSeal, err := findHeaderByInstance(arcSeals, i-1)
			if err != nil {
				return &VerifyResult{
					Status:      StatusFail,
					Error:       err,
					InstanceIDs: instanceIDs,
				}, nil
			}

			if err := verifySubsequentSeal(seal, msgSig, authRes, prevSeal, otherHeaders, body, options); err != nil {
				return &VerifyResult{
					Status:      StatusFail,
					Error:       err,
					InstanceIDs: instanceIDs,
				}, nil
			}
		}
	}

	// If we get here, the chain is valid
	return &VerifyResult{
		Status:      StatusPass,
		InstanceIDs: instanceIDs,
	}, nil
}

// extractInstanceIDs extracts instance IDs from ARC-Seal headers
func extractInstanceIDs(seals []string) ([]int, error) {
	var ids []int
	re := regexp.MustCompile(`i=(\d+)`)

	for _, seal := range seals {
		matches := re.FindStringSubmatch(seal)
		if len(matches) < 2 {
			return nil, errors.New("invalid ARC-Seal header: missing instance ID")
		}

		id, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid instance ID: %s", matches[1])
		}

		ids = append(ids, id)
	}

	// Check for missing instances
	for i := 1; i <= len(ids); i++ {
		found := false
		for _, id := range ids {
			if id == i {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("missing instance ID: %d", i)
		}
	}

	return ids, nil
}

// findHeaderByInstance finds a header with a specific instance ID
func findHeaderByInstance(headers []string, instance int) (string, error) {
	re := regexp.MustCompile(fmt.Sprintf(`i=%d`, instance))

	for _, header := range headers {
		if re.MatchString(header) {
			return header, nil
		}
	}

	return "", fmt.Errorf("header with instance ID %d not found", instance)
}

// verifyFirstSeal verifies the first seal in the chain
func verifyFirstSeal(seal, msgSig, authRes string, otherHeaders []string, body []byte, options VerifyOptions) error {
	// Extract the chain validation status
	cvRe := regexp.MustCompile(`cv=([^;]+)`)
	cvMatches := cvRe.FindStringSubmatch(seal)
	if len(cvMatches) < 2 {
		return errors.New("invalid ARC-Seal: missing cv tag")
	}

	cv := cvMatches[1]
	if cv != "none" {
		return fmt.Errorf("invalid cv value for first instance: %s", cv)
	}

	// Verify the seal signature
	if err := verifySignature(seal, []string{msgSig, authRes}, otherHeaders, body, options); err != nil {
		return err
	}

	// Verify the message signature
	if err := verifySignature(msgSig, []string{authRes}, otherHeaders, body, options); err != nil {
		return err
	}

	return nil
}

// verifySubsequentSeal verifies a subsequent seal in the chain
func verifySubsequentSeal(seal, msgSig, authRes, prevSeal string, otherHeaders []string, body []byte, options VerifyOptions) error {
	// Extract the chain validation status
	cvRe := regexp.MustCompile(`cv=([^;]+)`)
	cvMatches := cvRe.FindStringSubmatch(seal)
	if len(cvMatches) < 2 {
		return errors.New("invalid ARC-Seal: missing cv tag")
	}

	cv := cvMatches[1]
	if cv != "pass" {
		return fmt.Errorf("invalid cv value for subsequent instance: %s", cv)
	}

	// Verify the seal signature
	if err := verifySignature(seal, []string{msgSig, authRes, prevSeal}, otherHeaders, body, options); err != nil {
		return err
	}

	// Verify the message signature
	if err := verifySignature(msgSig, []string{authRes}, otherHeaders, body, options); err != nil {
		return err
	}

	return nil
}

// verifySignature verifies a signature (ARC-Seal or ARC-Message-Signature)
func verifySignature(sigHeader string, includedHeaders []string, otherHeaders []string, body []byte, options VerifyOptions) error {
	// Convert ARC-Seal or ARC-Message-Signature to DKIM-Signature
	dkimHeader := convertToDKIMHeader(sigHeader)

	// Create a temporary message with the included headers
	var tempMessage bytes.Buffer
	for _, header := range includedHeaders {
		tempMessage.WriteString(header)
		tempMessage.WriteString("\r\n")
	}
	for _, header := range otherHeaders {
		tempMessage.WriteString(header)
		tempMessage.WriteString("\r\n")
	}
	tempMessage.WriteString("\r\n")
	tempMessage.Write(body)

	// Verify with DKIM
	dkimOptions := dkim.VerifyOptions{
		AllowUnsafeDNS: options.AllowUnsafeDNS,
		DNSTimeout:     options.DNSTimeout,
		MaxDNSQueries:  options.MaxDNSQueries,
	}

	// Add the DKIM-Signature header
	var verifyMessage bytes.Buffer
	verifyMessage.WriteString(dkimHeader)
	verifyMessage.WriteString("\r\n")
	verifyMessage.Write(tempMessage.Bytes())

	results, err := dkim.Verify(verifyMessage.Bytes(), dkimOptions)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		return errors.New("no DKIM verification results")
	}

	for _, result := range results {
		if result.Status != "pass" {
			return fmt.Errorf("DKIM verification failed: %s", result.Error)
		}
	}

	return nil
}

// convertToDKIMHeader converts an ARC header to a DKIM-Signature header
func convertToDKIMHeader(arcHeader string) string {
	// Remove instance tag
	header := regexp.MustCompile(`i=\d+;`).ReplaceAllString(arcHeader, "")

	// Remove cv tag if present
	header = regexp.MustCompile(`cv=[^;]+;`).ReplaceAllString(header, "")

	// Replace header name
	if strings.HasPrefix(strings.ToLower(header), "arc-seal:") {
		header = strings.Replace(header, "ARC-Seal:", "DKIM-Signature:", 1)
		header = strings.Replace(header, "arc-seal:", "DKIM-Signature:", 1)
	} else if strings.HasPrefix(strings.ToLower(header), "arc-message-signature:") {
		header = strings.Replace(header, "ARC-Message-Signature:", "DKIM-Signature:", 1)
		header = strings.Replace(header, "arc-message-signature:", "DKIM-Signature:", 1)
	}

	return header
}

// parseMessage parses a message into headers and body
func parseMessage(message []byte) ([]string, []byte, error) {
	// Split message into headers and body
	parts := bytes.SplitN(message, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		return nil, nil, errors.New("invalid message format")
	}

	// Parse headers
	headerLines := bytes.Split(parts[0], []byte("\r\n"))
	var headers []string
	var currentHeader string

	for _, line := range headerLines {
		if len(line) == 0 {
			continue
		}

		// Check if line is a continuation of the previous header
		if line[0] == ' ' || line[0] == '\t' {
			if currentHeader == "" {
				continue
			}
			currentHeader += string(line)
		} else {
			// Add previous header to list
			if currentHeader != "" {
				headers = append(headers, currentHeader)
			}

			// Start new header
			currentHeader = string(line)
		}
	}

	// Add last header
	if currentHeader != "" {
		headers = append(headers, currentHeader)
	}

	return headers, parts[1], nil
}

// LoadPrivateKey loads a private key from PEM format
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	return dkim.LoadPrivateKey(pemData)
}

// GenerateKey generates a new RSA key pair
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	return dkim.GenerateKey(bits)
}

// PrivateKeyToPEM converts a private key to PEM format
func PrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	return dkim.PrivateKeyToPEM(key)
}

// PublicKeyToPEM converts a public key to PEM format
func PublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	return dkim.PublicKeyToPEM(key)
}

// CreateDNSRecord creates a DKIM DNS record for a public key
func CreateDNSRecord(publicKey *rsa.PublicKey, options map[string]string) (string, error) {
	return dkim.CreateDNSRecord(publicKey, options)
}

// ValidateARC validates an ARC chain
func ValidateARC(message []byte) (Status, error) {
	options := VerifyOptions{
		DNSTimeout:    5 * time.Second,
		MaxDNSQueries: 10,
	}

	result, err := Verify(message, options)
	if err != nil {
		return StatusFail, err
	}

	return result.Status, nil
}

// GetAuthenticationResults extracts the Authentication-Results header from an ARC chain
func GetAuthenticationResults(message []byte) (string, error) {
	headers, _, err := parseMessage(message)
	if err != nil {
		return "", err
	}

	// Find the most recent ARC-Authentication-Results header
	var latestAAR string
	var latestInstance int

	for _, header := range headers {
		if strings.HasPrefix(strings.ToLower(header), "arc-authentication-results:") {
			// Extract instance ID
			re := regexp.MustCompile(`i=(\d+)`)
			matches := re.FindStringSubmatch(header)
			if len(matches) > 1 {
				id, err := strconv.Atoi(matches[1])
				if err == nil && id > latestInstance {
					latestInstance = id
					latestAAR = header
				}
			}
		}
	}

	if latestAAR == "" {
		return "", errors.New("no ARC-Authentication-Results header found")
	}

	// Extract the Authentication-Results part
	parts := strings.SplitN(latestAAR, ";", 2)
	if len(parts) < 2 {
		return "", errors.New("invalid ARC-Authentication-Results header")
	}

	return strings.TrimSpace(parts[1]), nil
}

// AddAuthenticationResults adds an Authentication-Results header to a message
func AddAuthenticationResults(message []byte, authResults string, hostname string) ([]byte, error) {
	headers, body, err := parseMessage(message)
	if err != nil {
		return nil, err
	}

	// Create Authentication-Results header
	arHeader := fmt.Sprintf("Authentication-Results: %s; %s", hostname, authResults)

	// Add header to message
	var result bytes.Buffer
	result.WriteString(arHeader)
	result.WriteString("\r\n")
	for _, header := range headers {
		result.WriteString(header)
		result.WriteString("\r\n")
	}
	result.WriteString("\r\n")
	result.Write(body)

	return result.Bytes(), nil
}

// GetSealStatus gets the status of the most recent ARC-Seal
func GetSealStatus(message []byte) (Status, error) {
	headers, _, err := parseMessage(message)
	if err != nil {
		return StatusNone, err
	}

	// Find the most recent ARC-Seal header
	var latestSeal string
	var latestInstance int

	for _, header := range headers {
		if strings.HasPrefix(strings.ToLower(header), "arc-seal:") {
			// Extract instance ID
			re := regexp.MustCompile(`i=(\d+)`)
			matches := re.FindStringSubmatch(header)
			if len(matches) > 1 {
				id, err := strconv.Atoi(matches[1])
				if err == nil && id > latestInstance {
					latestInstance = id
					latestSeal = header
				}
			}
		}
	}

	if latestSeal == "" {
		return StatusNone, nil
	}

	// Extract the cv tag
	re := regexp.MustCompile(`cv=([^;]+)`)
	matches := re.FindStringSubmatch(latestSeal)
	if len(matches) < 2 {
		return StatusNone, errors.New("invalid ARC-Seal: missing cv tag")
	}

	cv := matches[1]
	switch cv {
	case "none":
		return StatusNone, nil
	case "pass":
		return StatusPass, nil
	case "fail":
		return StatusFail, nil
	default:
		return StatusNone, fmt.Errorf("invalid cv value: %s", cv)
	}
}
