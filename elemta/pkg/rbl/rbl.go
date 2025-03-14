package rbl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/elemta/elemta/pkg/util"
	"github.com/miekg/dns"
)

// Result represents the result of an RBL check
type Result struct {
	Listed     bool              // Whether the IP or domain is listed
	ListName   string            // Name of the list
	ResponseIP string            // Response IP (if listed)
	TXT        string            // TXT record explaining the listing (if available)
	Error      error             // Error (if any)
	QueryTime  time.Duration     // Time taken for the query
	Metadata   map[string]string // Additional metadata
}

// Checker represents an RBL checker
type Checker struct {
	resolver     *dns.Client
	timeout      time.Duration
	maxRetries   int
	dnsServers   []string
	concurrency  int
	defaultLists []string
}

// CheckerOptions represents options for creating a new RBL checker
type CheckerOptions struct {
	Timeout     time.Duration // Timeout for DNS queries
	MaxRetries  int           // Maximum number of retries for DNS queries
	DNSServers  []string      // DNS servers to use
	Concurrency int           // Maximum number of concurrent queries
}

// NewChecker creates a new RBL checker
func NewChecker(options CheckerOptions) *Checker {
	// Set default options
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Second
	}
	if options.MaxRetries == 0 {
		options.MaxRetries = 2
	}
	if len(options.DNSServers) == 0 {
		options.DNSServers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	if options.Concurrency == 0 {
		options.Concurrency = 10
	}

	return &Checker{
		resolver: &dns.Client{
			Timeout: options.Timeout,
		},
		timeout:     options.Timeout,
		maxRetries:  options.MaxRetries,
		dnsServers:  options.DNSServers,
		concurrency: options.Concurrency,
		defaultLists: []string{
			"zen.spamhaus.org",
			"bl.spamcop.net",
			"b.barracudacentral.org",
			"dnsbl.sorbs.net",
		},
	}
}

// CheckIP checks an IP address against an RBL
func (c *Checker) CheckIP(ip string, list string) (*Result, error) {
	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, errors.New("invalid IP address")
	}

	// Reverse the IP address
	var reversed string
	if parsedIP.To4() != nil {
		// IPv4
		parts := strings.Split(ip, ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		reversed = strings.Join(parts, ".")
	} else {
		// IPv6
		return nil, errors.New("IPv6 not supported yet")
	}

	// Create query
	query := fmt.Sprintf("%s.%s.", reversed, list)

	// Start timer
	start := time.Now()

	// Create result
	result := &Result{
		ListName:  list,
		Metadata:  make(map[string]string),
		QueryTime: 0,
	}

	// Query the RBL
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	var response *dns.Msg
	var err error

	// Try each DNS server with retries
	for _, server := range c.dnsServers {
		for retry := 0; retry <= c.maxRetries; retry++ {
			msg := new(dns.Msg)
			msg.SetQuestion(query, dns.TypeA)
			msg.RecursionDesired = true

			response, _, err = c.resolver.ExchangeContext(ctx, msg, server)
			if err == nil && response != nil && response.Rcode == dns.RcodeSuccess {
				break
			}

			// If we've tried all retries, move to the next server
			if retry == c.maxRetries {
				continue
			}

			// Exponential backoff
			time.Sleep(time.Duration(retry+1) * 100 * time.Millisecond)
		}

		// If we got a successful response, break out of the server loop
		if err == nil && response != nil && response.Rcode == dns.RcodeSuccess {
			break
		}
	}

	// Record query time
	result.QueryTime = time.Since(start)

	// Check for errors
	if err != nil {
		result.Error = err
		return result, nil
	}

	// Check if listed
	if response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
		result.Listed = true

		// Get the response IP
		for _, answer := range response.Answer {
			if a, ok := answer.(*dns.A); ok {
				result.ResponseIP = a.A.String()
				break
			}
		}

		// Try to get TXT record
		txtQuery := fmt.Sprintf("%s.%s.", reversed, list)
		txtMsg := new(dns.Msg)
		txtMsg.SetQuestion(txtQuery, dns.TypeTXT)
		txtMsg.RecursionDesired = true

		txtResponse, _, _ := c.resolver.ExchangeContext(ctx, txtMsg, c.dnsServers[0])
		if txtResponse != nil && txtResponse.Rcode == dns.RcodeSuccess {
			for _, answer := range txtResponse.Answer {
				if txt, ok := answer.(*dns.TXT); ok {
					result.TXT = strings.Join(txt.Txt, " ")
					break
				}
			}
		}
	}

	return result, nil
}

// CheckDomain checks a domain against an RBL
func (c *Checker) CheckDomain(domain string, list string) (*Result, error) {
	// Validate domain
	if domain == "" {
		return nil, errors.New("empty domain")
	}

	// Create query
	query := fmt.Sprintf("%s.%s.", domain, list)

	// Start timer
	start := time.Now()

	// Create result
	result := &Result{
		ListName:  list,
		Metadata:  make(map[string]string),
		QueryTime: 0,
	}

	// Query the RBL
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	var response *dns.Msg
	var err error

	// Try each DNS server with retries
	for _, server := range c.dnsServers {
		for retry := 0; retry <= c.maxRetries; retry++ {
			msg := new(dns.Msg)
			msg.SetQuestion(query, dns.TypeA)
			msg.RecursionDesired = true

			response, _, err = c.resolver.ExchangeContext(ctx, msg, server)
			if err == nil && response != nil && response.Rcode == dns.RcodeSuccess {
				break
			}

			// If we've tried all retries, move to the next server
			if retry == c.maxRetries {
				continue
			}

			// Exponential backoff
			time.Sleep(time.Duration(retry+1) * 100 * time.Millisecond)
		}

		// If we got a successful response, break out of the server loop
		if err == nil && response != nil && response.Rcode == dns.RcodeSuccess {
			break
		}
	}

	// Record query time
	result.QueryTime = time.Since(start)

	// Check for errors
	if err != nil {
		result.Error = err
		return result, nil
	}

	// Check if listed
	if response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
		result.Listed = true

		// Get the response IP
		for _, answer := range response.Answer {
			if a, ok := answer.(*dns.A); ok {
				result.ResponseIP = a.A.String()
				break
			}
		}

		// Try to get TXT record
		txtQuery := fmt.Sprintf("%s.%s.", domain, list)
		txtMsg := new(dns.Msg)
		txtMsg.SetQuestion(txtQuery, dns.TypeTXT)
		txtMsg.RecursionDesired = true

		txtResponse, _, _ := c.resolver.ExchangeContext(ctx, txtMsg, c.dnsServers[0])
		if txtResponse != nil && txtResponse.Rcode == dns.RcodeSuccess {
			for _, answer := range txtResponse.Answer {
				if txt, ok := answer.(*dns.TXT); ok {
					result.TXT = strings.Join(txt.Txt, " ")
					break
				}
			}
		}
	}

	return result, nil
}

// CheckIPMulti checks an IP address against multiple RBLs
func (c *Checker) CheckIPMulti(ip string, lists []string) ([]*Result, error) {
	// Use default lists if none provided
	if len(lists) == 0 {
		lists = c.defaultLists
	}

	// Create results slice
	results := make([]*Result, len(lists))

	// Create wait group and semaphore for concurrency control
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.concurrency)

	// Check each list
	for i, list := range lists {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(index int, listName string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			result, err := c.CheckIP(ip, listName)
			if err != nil {
				result = &Result{
					ListName: listName,
					Error:    err,
					Metadata: make(map[string]string),
				}
			}

			results[index] = result
		}(i, list)
	}

	// Wait for all checks to complete
	wg.Wait()

	return results, nil
}

// CheckDomainMulti checks a domain against multiple RBLs
func (c *Checker) CheckDomainMulti(domain string, lists []string) ([]*Result, error) {
	// Use default lists if none provided
	if len(lists) == 0 {
		lists = c.defaultLists
	}

	// Create results slice
	results := make([]*Result, len(lists))

	// Create wait group and semaphore for concurrency control
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.concurrency)

	// Check each list
	for i, list := range lists {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(index int, listName string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			result, err := c.CheckDomain(domain, listName)
			if err != nil {
				result = &Result{
					ListName: listName,
					Error:    err,
					Metadata: make(map[string]string),
				}
			}

			results[index] = result
		}(i, list)
	}

	// Wait for all checks to complete
	wg.Wait()

	return results, nil
}

// IsListed checks if an IP is listed in any of the specified RBLs
func (c *Checker) IsListed(ip string, lists []string) (bool, *Result, error) {
	results, err := c.CheckIPMulti(ip, lists)
	if err != nil {
		return false, nil, err
	}

	for _, result := range results {
		if result.Listed {
			return true, result, nil
		}
	}

	return false, nil, nil
}

// IsDomainListed checks if a domain is listed in any of the specified RBLs
func (c *Checker) IsDomainListed(domain string, lists []string) (bool, *Result, error) {
	results, err := c.CheckDomainMulti(domain, lists)
	if err != nil {
		return false, nil, err
	}

	for _, result := range results {
		if result.Listed {
			return true, result, nil
		}
	}

	return false, nil, nil
}

// SetDefaultLists sets the default RBL lists
func (c *Checker) SetDefaultLists(lists []string) {
	c.defaultLists = lists
}

// GetDefaultLists gets the default RBL lists
func (c *Checker) GetDefaultLists() []string {
	return c.defaultLists
}

// SetTimeout sets the timeout for DNS queries
func (c *Checker) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.resolver.Timeout = timeout
}

// SetMaxRetries sets the maximum number of retries for DNS queries
func (c *Checker) SetMaxRetries(maxRetries int) {
	c.maxRetries = maxRetries
}

// SetDNSServers sets the DNS servers to use
func (c *Checker) SetDNSServers(servers []string) {
	c.dnsServers = servers
}

// SetConcurrency sets the maximum number of concurrent queries
func (c *Checker) SetConcurrency(concurrency int) {
	c.concurrency = concurrency
}

// GetResponseCode gets the meaning of a response code
func GetResponseCode(ip string) string {
	// This is a placeholder. In a real implementation, you would interpret
	// the response code based on the RBL's documentation.
	// For example, Spamhaus uses different octets to indicate different types of listings.
	return "Unknown"
}

// CommonRBLs returns a list of common RBLs
func CommonRBLs() []string {
	return []string{
		"zen.spamhaus.org",
		"bl.spamcop.net",
		"b.barracudacentral.org",
		"dnsbl.sorbs.net",
		"cbl.abuseat.org",
		"xbl.spamhaus.org",
		"pbl.spamhaus.org",
		"sbl.spamhaus.org",
		"dnsbl-1.uceprotect.net",
		"psbl.surriel.com",
	}
}

// SpamhausRBLs returns a list of Spamhaus RBLs
func SpamhausRBLs() []string {
	return []string{
		"zen.spamhaus.org",
		"xbl.spamhaus.org",
		"pbl.spamhaus.org",
		"sbl.spamhaus.org",
	}
}

// SorbsRBLs returns a list of SORBS RBLs
func SorbsRBLs() []string {
	return []string{
		"dnsbl.sorbs.net",
		"spam.dnsbl.sorbs.net",
		"recent.spam.dnsbl.sorbs.net",
		"new.spam.dnsbl.sorbs.net",
		"old.spam.dnsbl.sorbs.net",
		"safe.dnsbl.sorbs.net",
		"http.dnsbl.sorbs.net",
		"socks.dnsbl.sorbs.net",
		"misc.dnsbl.sorbs.net",
		"smtp.dnsbl.sorbs.net",
		"web.dnsbl.sorbs.net",
		"block.dnsbl.sorbs.net",
		"zombie.dnsbl.sorbs.net",
		"dul.dnsbl.sorbs.net",
		"noservers.dnsbl.sorbs.net",
		"rhsbl.sorbs.net",
	}
}

// SURBLs returns a list of SURBL domain blacklists
func SURBLs() []string {
	return []string{
		"multi.surbl.org",
		"multi.uribl.com",
	}
}

// ParseSpamhausResponse parses a Spamhaus response code
func ParseSpamhausResponse(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "Unknown"
	}

	lastOctet := parts[3]
	switch lastOctet {
	case "2":
		return "SBL - Spamhaus Maintained"
	case "3":
		return "SBL - CSS - Snowshoe"
	case "4":
		return "XBL - CBL - 3rd party exploit"
	case "5":
		return "XBL - NJABL - Proxies"
	case "6", "7":
		return "XBL - Spamhaus Maintained"
	case "10":
		return "PBL - ISP Maintained"
	case "11":
		return "PBL - Spamhaus Maintained"
	default:
		return "Unknown"
	}
}

// ParseSorbsResponse parses a SORBS response code
func ParseSorbsResponse(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "Unknown"
	}

	lastOctet := parts[3]
	switch lastOctet {
	case "2":
		return "HTTP Proxy"
	case "3":
		return "SOCKS Proxy"
	case "4":
		return "SMTP Open Relay"
	case "5":
		return "Spam Source"
	case "6":
		return "Old Spam Source"
	case "7":
		return "New Spam Source"
	case "8":
		return "Recent Spam Source"
	case "9":
		return "Probable Spam Source"
	case "10":
		return "Dial-up User"
	case "11":
		return "Block"
	case "12":
		return "Zombie"
	default:
		return "Unknown"
	}
}

// CheckReverseDNS checks the reverse DNS of an IP address
func CheckReverseDNS(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}

	if len(names) == 0 {
		return "", nil
	}

	// Remove trailing dot
	return strings.TrimSuffix(names[0], "."), nil
}

// CheckForwardDNS checks the forward DNS of a domain
func CheckForwardDNS(domain string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

// CheckPTR checks if an IP has a PTR record
func CheckPTR(ip string) (bool, string, error) {
	ptr, err := CheckReverseDNS(ip)
	if err != nil {
		return false, "", err
	}

	if ptr == "" {
		return false, "", nil
	}

	return true, ptr, nil
}

// CheckForwardMatch checks if the forward DNS of a PTR record matches the original IP
func CheckForwardMatch(ip string, ptr string) (bool, error) {
	ips, err := CheckForwardDNS(ptr)
	if err != nil {
		return false, err
	}

	for _, forwardIP := range ips {
		if forwardIP == ip {
			return true, nil
		}
	}

	return false, nil
}

// ValidatePTR validates that an IP has a valid PTR record with forward-confirmed reverse DNS
func ValidatePTR(ip string) (bool, string, error) {
	// Check if IP has a PTR record
	hasPTR, ptr, err := CheckPTR(ip)
	if err != nil {
		return false, "", err
	}

	if !hasPTR {
		return false, "", nil
	}

	// Check if the PTR record resolves back to the original IP
	matches, err := CheckForwardMatch(ip, ptr)
	if err != nil {
		return false, ptr, err
	}

	return matches, ptr, nil
}

// Validate an email address
func ValidateEmail(email string) (bool, error) {
	return util.ValidateEmail(email)
}

// Reverse an IP for RBL lookups
func ReverseIPv4(ip string) (string, error) {
	return util.ReverseIPv4(ip)
}

// Generate a unique Message-ID
func GenerateMessageID(domain string) string {
	return util.GenerateMessageID(domain)
}
