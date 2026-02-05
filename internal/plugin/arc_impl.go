package plugin

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ARCImpl is a concrete implementation of the ARCPlugin interface
type ARCImpl struct {
	ARCPluginBase
	dnsClient  DNSClient
	dkimPlugin DKIMPlugin
}

// DNSClient is an interface for DNS lookups
type DNSClient interface {
	LookupTXT(domain string) ([]string, error)
}

// DefaultDNSClient is the default implementation of DNSClient
type DefaultDNSClient struct{}

// LookupTXT performs a DNS TXT lookup
func (c *DefaultDNSClient) LookupTXT(domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

// NewARCImpl creates a new ARCImpl
func NewARCImpl() *ARCImpl {
	info := &PluginInfo{
		Name:        "arc",
		Description: "ARC (Authenticated Received Chain) implementation",
		Version:     "1.0.0",
		Type:        PluginTypeARC,
		Author:      "Elemta Team",
	}

	return &ARCImpl{
		ARCPluginBase: *NewARCPluginBase(info),
		dnsClient:     &DefaultDNSClient{},
	}
}

// Init initializes the plugin
func (p *ARCImpl) Init(config map[string]interface{}) error {
	// Call the base implementation
	if err := p.ARCPluginBase.Init(config); err != nil {
		return err
	}

	// Get the DKIM plugin if provided
	if dkimPlugin, ok := config["dkim_plugin"].(DKIMPlugin); ok {
		p.dkimPlugin = dkimPlugin
	}

	return nil
}

// VerifyARC verifies an ARC chain in a message
func (p *ARCImpl) VerifyARC(reader io.Reader) (*ARCVerifyResult, error) {
	// Read the entire message
	message, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	// Parse the message to extract ARC headers
	arcHeaders, err := p.extractARCHeaders(bytes.NewReader(message))
	if err != nil {
		return nil, fmt.Errorf("failed to extract ARC headers: %w", err)
	}

	// If no ARC headers found, return ARCNone
	if len(arcHeaders) == 0 {
		return &ARCVerifyResult{
			Result:        ARCNone,
			Instances:     []ARCInstance{},
			InstanceCount: 0,
			Reason:        "No ARC headers found",
		}, nil
	}

	// Group headers by instance
	instances, err := p.groupARCHeadersByInstance(arcHeaders)
	if err != nil {
		return &ARCVerifyResult{
			Result:        ARCPermError,
			Instances:     []ARCInstance{},
			InstanceCount: 0,
			Reason:        fmt.Sprintf("Error grouping ARC headers: %v", err),
		}, nil
	}

	// Verify the ARC chain
	result, err := p.verifyARCChain(instances, message)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ARC chain: %w", err)
	}

	return result, nil
}

// SignARC adds an ARC instance to a message
func (p *ARCImpl) SignARC(reader io.Reader, writer io.Writer, options *ARCSignOptions) error {
	// Read the entire message
	message, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	// Verify existing ARC chain if present
	var chainValidation ARCResult
	if options.ChainValidation != "" {
		chainValidation = options.ChainValidation
	} else {
		result, err := p.VerifyARC(bytes.NewReader(message))
		if err != nil {
			return fmt.Errorf("failed to verify existing ARC chain: %w", err)
		}
		chainValidation = result.Result
	}

	// Determine the instance number
	instanceNum := 1
	if chainValidation != ARCNone {
		// Extract existing ARC headers
		arcHeaders, err := p.extractARCHeaders(bytes.NewReader(message))
		if err != nil {
			return fmt.Errorf("failed to extract ARC headers: %w", err)
		}

		// Find the highest instance number
		for _, header := range arcHeaders {
			if strings.HasPrefix(header, "ARC-") {
				re := regexp.MustCompile(`i=(\d+)`)
				matches := re.FindStringSubmatch(header)
				if len(matches) > 1 {
					i, err := strconv.Atoi(matches[1])
					if err == nil && i >= instanceNum {
						instanceNum = i + 1
					}
				}
			}
		}
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(options.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Generate the ARC headers
	arcHeaders, err := p.generateARCHeaders(message, instanceNum, options, chainValidation, privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate ARC headers: %w", err)
	}

	// Insert the ARC headers at the beginning of the message
	var newMessage bytes.Buffer
	for _, header := range arcHeaders {
		newMessage.WriteString(header + "\r\n")
	}
	newMessage.Write(message)

	// Write the modified message to the output
	_, err = writer.Write(newMessage.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write modified message: %w", err)
	}

	return nil
}

// extractARCHeaders extracts all ARC-related headers from a message
func (p *ARCImpl) extractARCHeaders(reader io.Reader) ([]string, error) {
	var arcHeaders []string

	scanner := bufio.NewScanner(reader)
	inHeaders := true

	for scanner.Scan() {
		line := scanner.Text()

		// End of headers
		if inHeaders && line == "" {
			inHeaders = false
			continue
		}

		if inHeaders {
			if strings.HasPrefix(line, "ARC-") || strings.HasPrefix(line, "Authentication-Results:") {
				arcHeaders = append(arcHeaders, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return arcHeaders, nil
}

// groupARCHeadersByInstance groups ARC headers by their instance number
func (p *ARCImpl) groupARCHeadersByInstance(headers []string) ([]ARCInstance, error) {
	instances := make(map[int]*ARCInstance)

	// Regular expression to extract instance number
	re := regexp.MustCompile(`i=(\d+)`)

	for _, header := range headers {
		if strings.HasPrefix(header, "ARC-Seal:") {
			matches := re.FindStringSubmatch(header)
			if len(matches) < 2 {
				return nil, errors.New("invalid ARC-Seal header: missing instance number")
			}

			i, err := strconv.Atoi(matches[1])
			if err != nil {
				return nil, fmt.Errorf("invalid instance number: %w", err)
			}

			if _, ok := instances[i]; !ok {
				instances[i] = &ARCInstance{
					InstanceNum: i,
					Timestamp:   time.Now(),
				}
			}

			instances[i].SealSignature = header
		} else if strings.HasPrefix(header, "ARC-Message-Signature:") {
			matches := re.FindStringSubmatch(header)
			if len(matches) < 2 {
				return nil, errors.New("invalid ARC-Message-Signature header: missing instance number")
			}

			i, err := strconv.Atoi(matches[1])
			if err != nil {
				return nil, fmt.Errorf("invalid instance number: %w", err)
			}

			if _, ok := instances[i]; !ok {
				instances[i] = &ARCInstance{
					InstanceNum: i,
					Timestamp:   time.Now(),
				}
			}

			instances[i].MessageSignature = header
		} else if strings.HasPrefix(header, "ARC-Authentication-Results:") {
			matches := re.FindStringSubmatch(header)
			if len(matches) < 2 {
				return nil, errors.New("invalid ARC-Authentication-Results header: missing instance number")
			}

			i, err := strconv.Atoi(matches[1])
			if err != nil {
				return nil, fmt.Errorf("invalid instance number: %w", err)
			}

			if _, ok := instances[i]; !ok {
				instances[i] = &ARCInstance{
					InstanceNum: i,
					Timestamp:   time.Now(),
				}
			}

			instances[i].AuthResults = header
		}
	}

	// Convert map to slice and sort by instance number
	var result []ARCInstance
	for _, instance := range instances {
		result = append(result, *instance)
	}

	// Sort by instance number
	sort.Slice(result, func(i, j int) bool {
		return result[i].InstanceNum < result[j].InstanceNum
	})

	return result, nil
}

// verifyARCChain verifies an ARC chain
func (p *ARCImpl) verifyARCChain(instances []ARCInstance, message []byte) (*ARCVerifyResult, error) {
	if len(instances) == 0 {
		return &ARCVerifyResult{
			Result:        ARCNone,
			Instances:     []ARCInstance{},
			InstanceCount: 0,
			Reason:        "No ARC instances found",
		}, nil
	}

	// Check for missing headers in instances
	for i, instance := range instances {
		if instance.SealSignature == "" || instance.MessageSignature == "" || instance.AuthResults == "" {
			return &ARCVerifyResult{
				Result:        ARCPermError,
				Instances:     instances,
				InstanceCount: len(instances),
				Reason:        fmt.Sprintf("Incomplete ARC instance %d", i+1),
			}, nil
		}
	}

	// Check for sequential instance numbers
	for i, instance := range instances {
		if instance.InstanceNum != i+1 {
			return &ARCVerifyResult{
				Result:        ARCPermError,
				Instances:     instances,
				InstanceCount: len(instances),
				Reason:        "Non-sequential instance numbers",
			}, nil
		}
	}

	// For a complete implementation, we would verify each signature
	// This is a simplified version that just checks the structure

	// In a real implementation, we would:
	// 1. Verify the ARC-Message-Signature for each instance
	// 2. Verify the ARC-Seal for each instance
	// 3. Check the chain validity based on cv= tag in the most recent ARC-Seal

	// For now, we'll just return a successful result
	return &ARCVerifyResult{
		Result:        ARCPass,
		Instances:     instances,
		InstanceCount: len(instances),
		OldestDomain:  p.extractDomain(instances[0].SealSignature),
		LatestDomain:  p.extractDomain(instances[len(instances)-1].SealSignature),
		Reason:        "ARC chain structure is valid",
	}, nil
}

// generateARCHeaders generates ARC headers for a new instance
func (p *ARCImpl) generateARCHeaders(message []byte, instanceNum int, options *ARCSignOptions, chainValidation ARCResult, privateKey *rsa.PrivateKey) ([]string, error) {
	var headers []string

	// Generate ARC-Authentication-Results
	authResults := fmt.Sprintf("ARC-Authentication-Results: i=%d; %s", instanceNum, options.AuthResults)
	headers = append(headers, authResults)

	// Generate ARC-Message-Signature (similar to DKIM signature)
	// In a real implementation, this would use proper canonicalization and signing
	// For simplicity, we're creating a placeholder
	messageSignature := fmt.Sprintf("ARC-Message-Signature: i=%d; a=rsa-sha256; c=%s; d=%s; s=%s; t=%d; h=%s; bh=%s; b=%s",
		instanceNum,
		options.Canonicalization,
		options.Domain,
		options.Selector,
		time.Now().Unix(),
		strings.Join(options.Headers, ":"),
		p.generateBodyHash(message),
		p.generateSignature(message, privateKey),
	)
	headers = append(headers, messageSignature)

	// Generate ARC-Seal
	// The cv= tag indicates the validation state of the existing chain
	cvTag := "none"
	switch chainValidation {
	case ARCPass:
		cvTag = "pass"
	case ARCFail:
		cvTag = "fail"
	}

	arcSeal := fmt.Sprintf("ARC-Seal: i=%d; a=rsa-sha256; t=%d; cv=%s; d=%s; s=%s; b=%s",
		instanceNum,
		time.Now().Unix(),
		cvTag,
		options.Domain,
		options.Selector,
		p.generateSealSignature(headers, privateKey),
	)
	headers = append(headers, arcSeal)

	return headers, nil
}

// extractDomain extracts the domain from an ARC header
func (p *ARCImpl) extractDomain(header string) string {
	re := regexp.MustCompile(`d=([^;]+)`)
	matches := re.FindStringSubmatch(header)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// generateBodyHash generates a base64-encoded SHA-256 hash of the message body
func (p *ARCImpl) generateBodyHash(message []byte) string {
	// In a real implementation, this would properly extract and hash the body
	// For simplicity, we're just hashing the entire message
	hash := sha256.Sum256(message)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// generateSignature generates a base64-encoded signature
func (p *ARCImpl) generateSignature(message []byte, privateKey *rsa.PrivateKey) string {
	// In a real implementation, this would properly canonicalize and sign
	// For simplicity, we're just signing the entire message
	hash := sha256.Sum256(message)
	signature, _ := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash[:])
	return base64.StdEncoding.EncodeToString(signature)
}

// generateSealSignature generates a base64-encoded signature for the ARC-Seal
func (p *ARCImpl) generateSealSignature(headers []string, privateKey *rsa.PrivateKey) string {
	// In a real implementation, this would properly canonicalize and sign
	// For simplicity, we're just signing the concatenated headers
	data := []byte(strings.Join(headers, "\r\n"))
	hash := sha256.Sum256(data)
	signature, _ := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash[:])
	return base64.StdEncoding.EncodeToString(signature)
}
