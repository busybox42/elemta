package dkim

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// SignOptions represents options for DKIM signing
type SignOptions struct {
	Domain                 string            // Domain to sign for
	Selector               string            // Selector to use
	PrivateKey             *rsa.PrivateKey   // Private key to sign with
	Headers                []string          // Headers to sign
	BodyLength             int               // Body length to sign (0 for entire body)
	Expiration             time.Time         // Expiration time (zero for no expiration)
	SignatureAlgo          string            // Signature algorithm (rsa-sha1 or rsa-sha256)
	Identity               string            // Identity (optional)
	CanonicalizationHeader string            // Header canonicalization (simple or relaxed)
	CanonicalizationBody   string            // Body canonicalization (simple or relaxed)
	AdditionalTags         map[string]string // Additional tags to include in the signature
}

// VerifyOptions represents options for DKIM verification
type VerifyOptions struct {
	AllowUnsignedFromHeader bool          // Allow unsigned From header
	AllowUnsafeDNS          bool          // Allow unsafe DNS (no DNSSEC)
	DNSTimeout              time.Duration // DNS timeout
	MaxDNSQueries           int           // Maximum number of DNS queries
}

// VerifyResult represents the result of a DKIM verification
type VerifyResult struct {
	Domain      string   // Domain that signed the message
	Selector    string   // Selector used
	Identity    string   // Identity (if present)
	HeadersUsed []string // Headers used in the signature
	BodyLength  int      // Body length used in the signature
	Status      string   // Status (pass, fail, neutral, temperror, permerror)
	Error       error    // Error (if any)
}

// Sign signs a message with DKIM
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

	// Ensure "From" header is included
	fromIncluded := false
	for _, h := range options.Headers {
		if strings.EqualFold(h, "From") {
			fromIncluded = true
			break
		}
	}
	if !fromIncluded {
		return nil, errors.New("From header must be included in signed headers")
	}

	// Canonicalize body
	var canonicalizedBody []byte
	if options.CanonicalizationBody == "relaxed" {
		canonicalizedBody = canonicalizeBodyRelaxed(body)
	} else {
		canonicalizedBody = canonicalizeBodySimple(body)
	}

	// Calculate body hash
	var h hash.Hash
	if options.SignatureAlgo == "rsa-sha1" {
		h = sha1.New()
	} else {
		h = sha256.New()
	}

	if options.BodyLength > 0 && options.BodyLength < len(canonicalizedBody) {
		h.Write(canonicalizedBody[:options.BodyLength])
	} else {
		h.Write(canonicalizedBody)
	}
	bodyHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Create DKIM-Signature header
	now := time.Now().Unix()
	dkimHeader := fmt.Sprintf("DKIM-Signature: v=1; a=%s; c=%s/%s; d=%s; s=%s;\r\n\tt=%d; bh=%s;\r\n\th=%s;\r\n\tb=",
		options.SignatureAlgo,
		options.CanonicalizationHeader,
		options.CanonicalizationBody,
		options.Domain,
		options.Selector,
		now,
		bodyHash,
		strings.Join(options.Headers, ":"))

	// Add optional tags
	if options.Identity != "" {
		dkimHeader = fmt.Sprintf("%s\r\n\ti=%s;", dkimHeader, options.Identity)
	}
	if !options.Expiration.IsZero() {
		dkimHeader = fmt.Sprintf("%s\r\n\tx=%d;", dkimHeader, options.Expiration.Unix())
	}
	if options.BodyLength > 0 {
		dkimHeader = fmt.Sprintf("%s\r\n\tl=%d;", dkimHeader, options.BodyLength)
	}
	for k, v := range options.AdditionalTags {
		dkimHeader = fmt.Sprintf("%s\r\n\t%s=%s;", dkimHeader, k, v)
	}

	// Canonicalize headers
	var headerList []string
	headerMap := make(map[string]string)
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		value := parts[1]

		// Store header in map (case-insensitive)
		headerMap[strings.ToLower(name)] = value

		// Add to list
		headerList = append(headerList, header)
	}

	// Create header string to sign
	var headerToSign bytes.Buffer
	for _, h := range options.Headers {
		h = strings.ToLower(h)
		if value, ok := headerMap[h]; ok {
			if options.CanonicalizationHeader == "relaxed" {
				headerToSign.WriteString(canonicalizeHeaderRelaxed(h, value))
			} else {
				headerToSign.WriteString(canonicalizeHeaderSimple(h, value))
			}
			headerToSign.WriteString("\r\n")
		}
	}

	// Add DKIM-Signature header (without signature)
	if options.CanonicalizationHeader == "relaxed" {
		headerToSign.WriteString(canonicalizeHeaderRelaxed("dkim-signature", dkimHeader[15:]))
	} else {
		headerToSign.WriteString(canonicalizeHeaderSimple("dkim-signature", dkimHeader[15:]))
	}

	// Calculate signature
	var signature []byte
	if options.SignatureAlgo == "rsa-sha1" {
		h = sha1.New()
		h.Write(headerToSign.Bytes())
		hashed := h.Sum(nil)
		signature, err = rsa.SignPKCS1v15(rand.Reader, options.PrivateKey, crypto.SHA1, hashed)
	} else {
		h = sha256.New()
		h.Write(headerToSign.Bytes())
		hashed := h.Sum(nil)
		signature, err = rsa.SignPKCS1v15(rand.Reader, options.PrivateKey, crypto.SHA256, hashed)
	}
	if err != nil {
		return nil, err
	}

	// Encode signature
	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	// Add signature to DKIM-Signature header
	dkimHeader = fmt.Sprintf("%s%s", dkimHeader, encodedSignature)

	// Add DKIM-Signature header to message
	var result bytes.Buffer
	result.WriteString(dkimHeader)
	result.WriteString("\r\n")
	for _, header := range headerList {
		result.WriteString(header)
		result.WriteString("\r\n")
	}
	result.WriteString("\r\n")
	result.Write(body)

	return result.Bytes(), nil
}

// Verify verifies a DKIM signature
func Verify(message []byte, options VerifyOptions) ([]VerifyResult, error) {
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

	// Find DKIM-Signature headers
	var dkimHeaders []string
	var otherHeaders []string
	for _, header := range headers {
		if strings.HasPrefix(strings.ToLower(header), "dkim-signature:") {
			dkimHeaders = append(dkimHeaders, header)
		} else {
			otherHeaders = append(otherHeaders, header)
		}
	}

	if len(dkimHeaders) == 0 {
		return nil, errors.New("no DKIM-Signature header found")
	}

	// Verify each signature
	var results []VerifyResult
	for _, dkimHeader := range dkimHeaders {
		result, err := verifySignature(dkimHeader, otherHeaders, body, options)
		if err != nil {
			result.Error = err
			result.Status = "permerror"
		}
		results = append(results, result)
	}

	return results, nil
}

// verifySignature verifies a single DKIM signature
func verifySignature(dkimHeader string, headers []string, body []byte, options VerifyOptions) (VerifyResult, error) {
	result := VerifyResult{}

	// Parse DKIM-Signature header
	tags, err := parseDKIMHeader(dkimHeader)
	if err != nil {
		return result, err
	}

	// Extract required fields
	version, ok := tags["v"]
	if !ok || version != "1" {
		return result, errors.New("invalid DKIM version")
	}

	domain, ok := tags["d"]
	if !ok {
		return result, errors.New("domain not specified")
	}
	result.Domain = domain

	selector, ok := tags["s"]
	if !ok {
		return result, errors.New("selector not specified")
	}
	result.Selector = selector

	algorithm, ok := tags["a"]
	if !ok {
		return result, errors.New("algorithm not specified")
	}

	canonicalization, ok := tags["c"]
	if !ok {
		canonicalization = "simple/simple"
	}
	canonParts := strings.Split(canonicalization, "/")
	headerCanon := canonParts[0]
	bodyCanon := "simple"
	if len(canonParts) > 1 {
		bodyCanon = canonParts[1]
	}

	headerFields, ok := tags["h"]
	if !ok {
		return result, errors.New("header fields not specified")
	}
	headerList := strings.Split(headerFields, ":")
	result.HeadersUsed = headerList

	bodyHash, ok := tags["bh"]
	if !ok {
		return result, errors.New("body hash not specified")
	}

	signature, ok := tags["b"]
	if !ok {
		return result, errors.New("signature not specified")
	}

	// Check if From header is signed
	fromSigned := false
	for _, h := range headerList {
		if strings.EqualFold(h, "From") {
			fromSigned = true
			break
		}
	}
	if !fromSigned && !options.AllowUnsignedFromHeader {
		return result, errors.New("From header not signed")
	}

	// Get body length if specified
	bodyLength := 0
	if l, ok := tags["l"]; ok {
		fmt.Sscanf(l, "%d", &bodyLength)
		result.BodyLength = bodyLength
	}

	// Get identity if specified
	if identity, ok := tags["i"]; ok {
		result.Identity = identity
		// Verify identity is in domain
		if !strings.HasSuffix(identity, "@"+domain) && !strings.HasSuffix(identity, "."+domain) {
			return result, errors.New("identity not in domain")
		}
	}

	// Check expiration
	if expStr, ok := tags["x"]; ok {
		var exp int64
		fmt.Sscanf(expStr, "%d", &exp)
		if exp < time.Now().Unix() {
			return result, errors.New("signature expired")
		}
	}

	// Canonicalize body
	var canonicalizedBody []byte
	if bodyCanon == "relaxed" {
		canonicalizedBody = canonicalizeBodyRelaxed(body)
	} else {
		canonicalizedBody = canonicalizeBodySimple(body)
	}

	// Calculate body hash
	var h hash.Hash
	if algorithm == "rsa-sha1" {
		h = sha1.New()
	} else if algorithm == "rsa-sha256" {
		h = sha256.New()
	} else {
		return result, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if bodyLength > 0 && bodyLength < len(canonicalizedBody) {
		h.Write(canonicalizedBody[:bodyLength])
	} else {
		h.Write(canonicalizedBody)
	}
	calculatedBodyHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Compare body hashes
	if calculatedBodyHash != bodyHash {
		return result, errors.New("body hash mismatch")
	}

	// Get public key
	publicKey, err := getPublicKey(selector, domain, options)
	if err != nil {
		return result, err
	}

	// Create header string to verify
	headerMap := make(map[string]string)
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		value := parts[1]

		// Store header in map (case-insensitive)
		headerMap[strings.ToLower(name)] = value
	}

	// Add DKIM-Signature header (without signature)
	dkimHeaderName := "dkim-signature"
	dkimHeaderValue := dkimHeader[15:] // Remove "DKIM-Signature: "

	// Remove signature value
	re := regexp.MustCompile(`b=([^;]+)`)
	dkimHeaderValue = re.ReplaceAllString(dkimHeaderValue, "b=")

	headerMap[dkimHeaderName] = dkimHeaderValue

	// Create header string to verify
	var headerToVerify bytes.Buffer
	for _, h := range headerList {
		h = strings.ToLower(h)
		if value, ok := headerMap[h]; ok {
			if headerCanon == "relaxed" {
				headerToVerify.WriteString(canonicalizeHeaderRelaxed(h, value))
			} else {
				headerToVerify.WriteString(canonicalizeHeaderSimple(h, value))
			}
			headerToVerify.WriteString("\r\n")
		}
	}

	// Add DKIM-Signature header (without signature)
	if headerCanon == "relaxed" {
		headerToVerify.WriteString(canonicalizeHeaderRelaxed(dkimHeaderName, dkimHeaderValue))
	} else {
		headerToVerify.WriteString(canonicalizeHeaderSimple(dkimHeaderName, dkimHeaderValue))
	}

	// Decode signature
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return result, err
	}

	// Verify signature
	if algorithm == "rsa-sha1" {
		h = sha1.New()
		h.Write(headerToVerify.Bytes())
		hashed := h.Sum(nil)
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, decodedSignature)
	} else {
		h = sha256.New()
		h.Write(headerToVerify.Bytes())
		hashed := h.Sum(nil)
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, decodedSignature)
	}

	if err != nil {
		result.Status = "fail"
		return result, err
	}

	result.Status = "pass"
	return result, nil
}

// parseDKIMHeader parses a DKIM-Signature header into a map of tags
func parseDKIMHeader(header string) (map[string]string, error) {
	// Remove "DKIM-Signature: " prefix
	header = strings.TrimPrefix(header, "DKIM-Signature:")

	// Split into tags
	tags := make(map[string]string)
	for _, tag := range strings.Split(header, ";") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}

		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		tags[name] = value
	}

	return tags, nil
}

// getPublicKey gets the public key for a DKIM selector
func getPublicKey(selector, domain string, options VerifyOptions) (*rsa.PublicKey, error) {
	// Create DNS client
	client := &dns.Client{
		Timeout: options.DNSTimeout,
	}

	// Create DNS query
	query := fmt.Sprintf("%s._domainkey.%s.", selector, domain)
	msg := new(dns.Msg)
	msg.SetQuestion(query, dns.TypeTXT)
	msg.RecursionDesired = true

	// Send DNS query
	resp, _, err := client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	// Check response
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
	}

	// Find TXT record
	var record string
	for _, answer := range resp.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			record = strings.Join(txt.Txt, "")
			break
		}
	}

	if record == "" {
		return nil, errors.New("no DKIM record found")
	}

	// Parse record
	tags, err := parseDKIMRecord(record)
	if err != nil {
		return nil, err
	}

	// Check version
	version, ok := tags["v"]
	if ok && version != "DKIM1" {
		return nil, errors.New("unsupported DKIM version")
	}

	// Check key type
	keyType, ok := tags["k"]
	if ok && keyType != "rsa" {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Check service type
	serviceType, ok := tags["s"]
	if ok && !strings.Contains(serviceType, "*") && !strings.Contains(serviceType, "email") {
		return nil, errors.New("service type does not include email")
	}

	// Get public key
	p, ok := tags["p"]
	if !ok || p == "" {
		return nil, errors.New("no public key found")
	}

	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, err
	}

	// Parse public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		// Try parsing as PEM
		block, _ := pem.Decode(publicKeyBytes)
		if block == nil {
			return nil, errors.New("failed to parse public key")
		}

		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	// Check key type
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPublicKey, nil
}

// parseDKIMRecord parses a DKIM record into a map of tags
func parseDKIMRecord(record string) (map[string]string, error) {
	// Split into tags
	tags := make(map[string]string)
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}

		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		tags[name] = value
	}

	return tags, nil
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

// canonicalizeHeaderSimple canonicalizes a header using the simple algorithm
func canonicalizeHeaderSimple(name, value string) string {
	return name + ":" + value
}

// canonicalizeHeaderRelaxed canonicalizes a header using the relaxed algorithm
func canonicalizeHeaderRelaxed(name, value string) string {
	// Convert header name to lowercase
	name = strings.ToLower(name)

	// Unfold whitespace
	value = regexp.MustCompile(`\r\n\s+`).ReplaceAllString(value, " ")

	// Convert all sequences of WSP to a single SP
	value = regexp.MustCompile(`[ \t]+`).ReplaceAllString(value, " ")

	// Remove WSP at the end of the value
	value = strings.TrimRight(value, " \t")

	// Remove WSP after the colon
	value = strings.TrimLeft(value, " \t")

	return name + ":" + value
}

// canonicalizeBodySimple canonicalizes a body using the simple algorithm
func canonicalizeBodySimple(body []byte) []byte {
	// Remove trailing empty lines
	body = bytes.TrimRight(body, "\r\n")

	// Ensure body ends with CRLF
	if len(body) > 0 {
		body = append(body, '\r', '\n')
	}

	return body
}

// canonicalizeBodyRelaxed canonicalizes a body using the relaxed algorithm
func canonicalizeBodyRelaxed(body []byte) []byte {
	// Convert all CR and LF to CRLF
	body = bytes.ReplaceAll(body, []byte("\r"), []byte(""))
	body = bytes.ReplaceAll(body, []byte("\n"), []byte("\r\n"))

	// Ignore all whitespace at the end of lines
	lines := bytes.Split(body, []byte("\r\n"))
	for i, line := range lines {
		lines[i] = bytes.TrimRight(line, " \t")
	}
	body = bytes.Join(lines, []byte("\r\n"))

	// Remove trailing empty lines
	body = bytes.TrimRight(body, "\r\n")

	// Ensure body ends with CRLF
	if len(body) > 0 {
		body = append(body, '\r', '\n')
	}

	return body
}

// LoadPrivateKey loads a private key from PEM format
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	var privateKey *rsa.PrivateKey
	var err error

	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
	}

	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GenerateKey generates a new RSA key pair
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// PrivateKeyToPEM converts a private key to PEM format
func PrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.EncodeToMemory(block)
}

// PublicKeyToPEM converts a public key to PEM format
func PublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}

	return pem.EncodeToMemory(block), nil
}

// CreateDNSRecord creates a DKIM DNS record for a public key
func CreateDNSRecord(publicKey *rsa.PublicKey, options map[string]string) (string, error) {
	// Marshal public key
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	// Encode public key
	encodedKey := base64.StdEncoding.EncodeToString(bytes)

	// Create record
	record := "v=DKIM1; k=rsa; p=" + encodedKey

	// Add options
	for k, v := range options {
		record += "; " + k + "=" + v
	}

	return record, nil
}
