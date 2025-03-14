package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Result represents the result of an SPF check
type Result string

const (
	// SPF results as defined in RFC 7208
	ResultNone      Result = "none"      // No policy found
	ResultNeutral   Result = "neutral"   // Domain owner explicitly states nothing about the IP
	ResultPass      Result = "pass"      // IP is authorized to send mail
	ResultFail      Result = "fail"      // IP is not authorized to send mail
	ResultSoftFail  Result = "softfail"  // IP is probably not authorized, but not certain
	ResultTempError Result = "temperror" // Temporary error during processing
	ResultPermError Result = "permerror" // Permanent error during processing
)

// Mechanism represents an SPF mechanism
type Mechanism struct {
	Type       string
	Domain     string
	Prefix     string
	PrefixLen  int
	Qualifier  string
	IncludeRes Result
}

// Checker represents an SPF checker
type Checker struct {
	resolver   *dns.Client
	timeout    time.Duration
	maxLookups int
	lookups    int
}

// NewChecker creates a new SPF checker
func NewChecker() *Checker {
	return &Checker{
		resolver: &dns.Client{
			Timeout: 5 * time.Second,
		},
		timeout:    5 * time.Second,
		maxLookups: 10, // RFC 7208 recommends a limit of 10 DNS lookups
	}
}

// SetTimeout sets the timeout for DNS lookups
func (c *Checker) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.resolver.Timeout = timeout
}

// SetMaxLookups sets the maximum number of DNS lookups
func (c *Checker) SetMaxLookups(maxLookups int) {
	c.maxLookups = maxLookups
}

// Check checks if an IP is authorized to send mail from a domain
func (c *Checker) Check(ip net.IP, domain string, sender string, helo string) (Result, error) {
	c.lookups = 0

	// If domain is empty, use the HELO domain
	if domain == "" {
		domain = helo
	}

	// Validate domain
	if domain == "" {
		return ResultPermError, errors.New("domain cannot be empty")
	}

	// Ensure domain ends with a dot for DNS lookups
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	// Get SPF record
	record, err := c.getSPFRecord(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.Temporary() {
			return ResultTempError, err
		}
		return ResultNone, nil
	}

	if record == "" {
		return ResultNone, nil
	}

	// Parse SPF record
	mechanisms, modifiers, err := c.parseSPFRecord(record)
	if err != nil {
		return ResultPermError, err
	}

	// Check mechanisms
	result, err := c.checkMechanisms(ip, domain, mechanisms)
	if err != nil {
		if strings.Contains(err.Error(), "lookup limit exceeded") {
			return ResultPermError, err
		}
		return ResultTempError, err
	}

	// If no mechanisms matched, return default result
	if result == "" {
		return ResultNeutral, nil
	}

	// Check if there's a redirect modifier
	if redirect, ok := modifiers["redirect"]; ok && result == "" {
		// Ensure redirect domain ends with a dot for DNS lookups
		if !strings.HasSuffix(redirect, ".") {
			redirect = redirect + "."
		}

		// Recursive check with redirect domain
		return c.Check(ip, redirect, sender, helo)
	}

	return result, nil
}

// getSPFRecord gets the SPF record for a domain
func (c *Checker) getSPFRecord(domain string) (string, error) {
	// Check if we've exceeded the lookup limit
	if c.lookups >= c.maxLookups {
		return "", errors.New("lookup limit exceeded")
	}
	c.lookups++

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Create DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeTXT)
	msg.RecursionDesired = true

	// Send DNS query
	resp, _, err := c.resolver.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return "", err
	}

	// Check response
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
	}

	// Find SPF record
	for _, answer := range resp.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			record := strings.Join(txt.Txt, "")
			if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
				return record, nil
			}
		}
	}

	return "", nil
}

// parseSPFRecord parses an SPF record
func (c *Checker) parseSPFRecord(record string) ([]Mechanism, map[string]string, error) {
	mechanisms := []Mechanism{}
	modifiers := make(map[string]string)

	// Split record into terms
	terms := strings.Fields(record)

	// Skip the first term (v=spf1)
	for _, term := range terms[1:] {
		// Check if term is a modifier
		if strings.Contains(term, "=") {
			parts := strings.SplitN(term, "=", 2)
			if len(parts) == 2 {
				modifiers[parts[0]] = parts[1]
			}
			continue
		}

		// Parse mechanism
		qualifier := "+"
		if strings.HasPrefix(term, "+") || strings.HasPrefix(term, "-") ||
			strings.HasPrefix(term, "~") || strings.HasPrefix(term, "?") {
			qualifier = term[0:1]
			term = term[1:]
		}

		// Parse mechanism type
		var mechType, domain, prefix string
		var prefixLen int

		if strings.HasPrefix(term, "include:") {
			mechType = "include"
			domain = term[8:]
		} else if strings.HasPrefix(term, "a") {
			mechType = "a"
			if strings.HasPrefix(term, "a:") {
				domain = term[2:]
			}
		} else if strings.HasPrefix(term, "mx") {
			mechType = "mx"
			if strings.HasPrefix(term, "mx:") {
				domain = term[3:]
			}
		} else if strings.HasPrefix(term, "ptr") {
			mechType = "ptr"
			if strings.HasPrefix(term, "ptr:") {
				domain = term[4:]
			}
		} else if strings.HasPrefix(term, "ip4:") {
			mechType = "ip4"
			cidr := term[4:]
			if strings.Contains(cidr, "/") {
				parts := strings.SplitN(cidr, "/", 2)
				prefix = parts[0]
				fmt.Sscanf(parts[1], "%d", &prefixLen)
			} else {
				prefix = cidr
				prefixLen = 32
			}
		} else if strings.HasPrefix(term, "ip6:") {
			mechType = "ip6"
			cidr := term[4:]
			if strings.Contains(cidr, "/") {
				parts := strings.SplitN(cidr, "/", 2)
				prefix = parts[0]
				fmt.Sscanf(parts[1], "%d", &prefixLen)
			} else {
				prefix = cidr
				prefixLen = 128
			}
		} else if term == "all" {
			mechType = "all"
		} else {
			return nil, nil, fmt.Errorf("unknown mechanism: %s", term)
		}

		mechanisms = append(mechanisms, Mechanism{
			Type:      mechType,
			Domain:    domain,
			Prefix:    prefix,
			PrefixLen: prefixLen,
			Qualifier: qualifier,
		})
	}

	return mechanisms, modifiers, nil
}

// checkMechanisms checks if an IP matches any of the mechanisms
func (c *Checker) checkMechanisms(ip net.IP, domain string, mechanisms []Mechanism) (Result, error) {
	for _, mech := range mechanisms {
		match, err := c.checkMechanism(ip, domain, mech)
		if err != nil {
			return "", err
		}

		if match {
			switch mech.Qualifier {
			case "+":
				return ResultPass, nil
			case "-":
				return ResultFail, nil
			case "~":
				return ResultSoftFail, nil
			case "?":
				return ResultNeutral, nil
			}
		}
	}

	return "", nil
}

// checkMechanism checks if an IP matches a mechanism
func (c *Checker) checkMechanism(ip net.IP, domain string, mech Mechanism) (bool, error) {
	switch mech.Type {
	case "all":
		return true, nil

	case "include":
		includeDomain := mech.Domain
		if includeDomain == "" {
			includeDomain = domain
		}

		// Ensure domain ends with a dot for DNS lookups
		if !strings.HasSuffix(includeDomain, ".") {
			includeDomain = includeDomain + "."
		}

		// Recursive check with include domain
		result, err := c.Check(ip, includeDomain, "", "")
		if err != nil {
			return false, err
		}

		// Store the result for later use
		mech.IncludeRes = result

		// Only pass matches
		return result == ResultPass, nil

	case "a":
		aDomain := mech.Domain
		if aDomain == "" {
			aDomain = domain
		}

		// Ensure domain ends with a dot for DNS lookups
		if !strings.HasSuffix(aDomain, ".") {
			aDomain = aDomain + "."
		}

		// Check if we've exceeded the lookup limit
		if c.lookups >= c.maxLookups {
			return false, errors.New("lookup limit exceeded")
		}
		c.lookups++

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()

		// Create DNS message
		msg := new(dns.Msg)
		msg.SetQuestion(aDomain, dns.TypeA)
		msg.RecursionDesired = true

		// Send DNS query
		resp, _, err := c.resolver.ExchangeContext(ctx, msg, "8.8.8.8:53")
		if err != nil {
			return false, err
		}

		// Check response
		if resp.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
		}

		// Check if IP matches any A record
		for _, answer := range resp.Answer {
			if a, ok := answer.(*dns.A); ok {
				if ip.Equal(a.A) {
					return true, nil
				}
			}
		}

		return false, nil

	case "mx":
		mxDomain := mech.Domain
		if mxDomain == "" {
			mxDomain = domain
		}

		// Ensure domain ends with a dot for DNS lookups
		if !strings.HasSuffix(mxDomain, ".") {
			mxDomain = mxDomain + "."
		}

		// Check if we've exceeded the lookup limit
		if c.lookups >= c.maxLookups {
			return false, errors.New("lookup limit exceeded")
		}
		c.lookups++

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()

		// Create DNS message
		msg := new(dns.Msg)
		msg.SetQuestion(mxDomain, dns.TypeMX)
		msg.RecursionDesired = true

		// Send DNS query
		resp, _, err := c.resolver.ExchangeContext(ctx, msg, "8.8.8.8:53")
		if err != nil {
			return false, err
		}

		// Check response
		if resp.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
		}

		// Check if IP matches any MX record
		for _, answer := range resp.Answer {
			if mx, ok := answer.(*dns.MX); ok {
				// Check if we've exceeded the lookup limit
				if c.lookups >= c.maxLookups {
					return false, errors.New("lookup limit exceeded")
				}
				c.lookups++

				// Create DNS message for A record
				msgA := new(dns.Msg)
				msgA.SetQuestion(mx.Mx, dns.TypeA)
				msgA.RecursionDesired = true

				// Send DNS query
				respA, _, err := c.resolver.ExchangeContext(ctx, msgA, "8.8.8.8:53")
				if err != nil {
					return false, err
				}

				// Check response
				if respA.Rcode != dns.RcodeSuccess {
					return false, fmt.Errorf("DNS query failed: %s", dns.RcodeToString[respA.Rcode])
				}

				// Check if IP matches any A record
				for _, answerA := range respA.Answer {
					if a, ok := answerA.(*dns.A); ok {
						if ip.Equal(a.A) {
							return true, nil
						}
					}
				}
			}
		}

		return false, nil

	case "ip4":
		// Only check IPv4 addresses
		if ip.To4() == nil {
			return false, nil
		}

		// Parse CIDR
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", mech.Prefix, mech.PrefixLen))
		if err != nil {
			return false, err
		}

		// Check if IP is in CIDR
		return ipNet.Contains(ip), nil

	case "ip6":
		// Only check IPv6 addresses
		if ip.To4() != nil {
			return false, nil
		}

		// Parse CIDR
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", mech.Prefix, mech.PrefixLen))
		if err != nil {
			return false, err
		}

		// Check if IP is in CIDR
		return ipNet.Contains(ip), nil

	case "ptr":
		// PTR is deprecated in RFC 7208, but we'll implement it anyway
		// This is a simplified implementation

		// Check if we've exceeded the lookup limit
		if c.lookups >= c.maxLookups {
			return false, errors.New("lookup limit exceeded")
		}
		c.lookups++

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()

		// Get PTR domain
		ptrDomain := mech.Domain
		if ptrDomain == "" {
			ptrDomain = domain
		}

		// Ensure domain ends with a dot for DNS lookups
		if !strings.HasSuffix(ptrDomain, ".") {
			ptrDomain = ptrDomain + "."
		}

		// Get reverse IP
		var revIP string
		if ip.To4() != nil {
			// IPv4
			revIP = fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[15], ip[14], ip[13], ip[12])
		} else {
			// IPv6
			revIP = ""
			for i := 0; i < 16; i++ {
				revIP = fmt.Sprintf("%x.%x.%s", ip[i]&0x0F, ip[i]>>4, revIP)
			}
			revIP = revIP + "ip6.arpa."
		}

		// Create DNS message
		msg := new(dns.Msg)
		msg.SetQuestion(revIP, dns.TypePTR)
		msg.RecursionDesired = true

		// Send DNS query
		resp, _, err := c.resolver.ExchangeContext(ctx, msg, "8.8.8.8:53")
		if err != nil {
			return false, err
		}

		// Check response
		if resp.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
		}

		// Check if any PTR record matches the domain
		for _, answer := range resp.Answer {
			if ptr, ok := answer.(*dns.PTR); ok {
				if strings.HasSuffix(ptr.Ptr, ptrDomain) {
					return true, nil
				}
			}
		}

		return false, nil

	default:
		return false, fmt.Errorf("unknown mechanism type: %s", mech.Type)
	}
}

// ValidateSPF validates an SPF record
func ValidateSPF(record string) error {
	// Check if record starts with v=spf1
	if !strings.HasPrefix(strings.ToLower(record), "v=spf1") {
		return errors.New("SPF record must start with v=spf1")
	}

	// Split record into terms
	terms := strings.Fields(record)

	// Skip the first term (v=spf1)
	for _, term := range terms[1:] {
		// Check if term is a modifier
		if strings.Contains(term, "=") {
			parts := strings.SplitN(term, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid modifier: %s", term)
			}

			// Check if modifier is valid
			switch parts[0] {
			case "redirect", "exp":
				// Valid modifiers
			default:
				return fmt.Errorf("unknown modifier: %s", parts[0])
			}

			continue
		}

		// Parse mechanism
		mechTerm := term
		if strings.HasPrefix(term, "+") || strings.HasPrefix(term, "-") ||
			strings.HasPrefix(term, "~") || strings.HasPrefix(term, "?") {
			mechTerm = term[1:]
		}

		// Parse mechanism type
		if strings.HasPrefix(mechTerm, "include:") {
			// Valid
		} else if strings.HasPrefix(mechTerm, "a") {
			// Valid
		} else if strings.HasPrefix(mechTerm, "mx") {
			// Valid
		} else if strings.HasPrefix(mechTerm, "ptr") {
			// Valid
		} else if strings.HasPrefix(mechTerm, "ip4:") {
			// Check if IP is valid
			cidr := mechTerm[4:]
			if strings.Contains(cidr, "/") {
				parts := strings.SplitN(cidr, "/", 2)
				prefix := parts[0]
				var prefixLen int
				fmt.Sscanf(parts[1], "%d", &prefixLen)

				// Check if prefix is a valid IPv4 address
				if net.ParseIP(prefix).To4() == nil {
					return fmt.Errorf("invalid IPv4 address: %s", prefix)
				}

				// Check if prefix length is valid
				if prefixLen < 0 || prefixLen > 32 {
					return fmt.Errorf("invalid IPv4 prefix length: %d", prefixLen)
				}
			} else {
				// Check if IP is a valid IPv4 address
				if net.ParseIP(cidr).To4() == nil {
					return fmt.Errorf("invalid IPv4 address: %s", cidr)
				}
			}
		} else if strings.HasPrefix(mechTerm, "ip6:") {
			// Check if IP is valid
			cidr := mechTerm[4:]
			if strings.Contains(cidr, "/") {
				parts := strings.SplitN(cidr, "/", 2)
				prefix := parts[0]
				var prefixLen int
				fmt.Sscanf(parts[1], "%d", &prefixLen)

				// Check if prefix is a valid IPv6 address
				if net.ParseIP(prefix).To16() == nil {
					return fmt.Errorf("invalid IPv6 address: %s", prefix)
				}

				// Check if prefix length is valid
				if prefixLen < 0 || prefixLen > 128 {
					return fmt.Errorf("invalid IPv6 prefix length: %d", prefixLen)
				}
			} else {
				// Check if IP is a valid IPv6 address
				if net.ParseIP(cidr).To16() == nil {
					return fmt.Errorf("invalid IPv6 address: %s", cidr)
				}
			}
		} else if mechTerm == "all" {
			// Valid
		} else {
			return fmt.Errorf("unknown mechanism: %s", mechTerm)
		}
	}

	return nil
}
