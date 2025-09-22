package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ExternalFeedManager manages external blacklist/whitelist feeds
type ExternalFeedManager struct {
	feeds   []FeedConfig
	client  *http.Client
	logger  *slog.Logger
	mu      sync.RWMutex
}

// NewExternalFeedManager creates a new external feed manager
func NewExternalFeedManager(logger *slog.Logger) *ExternalFeedManager {
	return &ExternalFeedManager{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// AddFeed adds a new external feed
func (efm *ExternalFeedManager) AddFeed(feed FeedConfig) {
	efm.mu.Lock()
	defer efm.mu.Unlock()
	
	efm.feeds = append(efm.feeds, feed)
	efm.logger.Info("External feed added",
		"name", feed.Name,
		"url", feed.URL,
		"type", feed.Type,
	)
}

// UpdateFeed updates an external feed
func (efm *ExternalFeedManager) UpdateFeed(ctx context.Context, feed FeedConfig) error {
	efm.logger.Info("Updating external feed",
		"name", feed.Name,
		"url", feed.URL,
	)
	
	// Fetch feed data
	entries, err := efm.fetchFeedData(ctx, feed)
	if err != nil {
		return fmt.Errorf("failed to fetch feed data: %w", err)
	}
	
	// Parse and convert to rules
	rules, err := efm.parseFeedEntries(entries, feed)
	if err != nil {
		return fmt.Errorf("failed to parse feed entries: %w", err)
	}
	
	efm.logger.Info("External feed updated successfully",
		"name", feed.Name,
		"entries_count", len(entries),
		"rules_count", len(rules),
	)
	
	return nil
}

// fetchFeedData fetches data from an external feed URL
func (efm *ExternalFeedManager) fetchFeedData(ctx context.Context, feed FeedConfig) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set appropriate headers
	req.Header.Set("User-Agent", "Elemta-AllowDeny-Plugin/1.0.0")
	req.Header.Set("Accept", "text/plain, text/csv, application/json")
	
	resp, err := efm.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned status %d", resp.StatusCode)
	}
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Parse based on content type
	contentType := resp.Header.Get("Content-Type")
	return efm.parseFeedContent(string(body), contentType, feed.Format)
}

// parseFeedContent parses feed content based on format
func (efm *ExternalFeedManager) parseFeedContent(content, contentType, format string) ([]string, error) {
	var entries []string
	
	switch format {
	case "ip":
		entries = efm.parseIPFormat(content)
	case "cidr":
		entries = efm.parseCIDRFormat(content)
	case "domain":
		entries = efm.parseDomainFormat(content)
	case "email":
		entries = efm.parseEmailFormat(content)
	default:
		// Try to auto-detect format
		entries = efm.autoDetectFormat(content)
	}
	
	return entries, nil
}

// parseIPFormat parses IP address format
func (efm *ExternalFeedManager) parseIPFormat(content string) []string {
	var entries []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Extract IP address (handle various formats)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			ip := parts[0]
			if efm.isValidIP(ip) {
				entries = append(entries, ip)
			}
		}
	}
	
	return entries
}

// parseCIDRFormat parses CIDR block format
func (efm *ExternalFeedManager) parseCIDRFormat(content string) []string {
	var entries []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Extract CIDR block (handle various formats)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			cidr := parts[0]
			if efm.isValidCIDR(cidr) {
				entries = append(entries, cidr)
			}
		}
	}
	
	return entries
}

// parseDomainFormat parses domain format
func (efm *ExternalFeedManager) parseDomainFormat(content string) []string {
	var entries []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Extract domain (handle various formats)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			domain := parts[0]
			if efm.isValidDomain(domain) {
				entries = append(entries, domain)
			}
		}
	}
	
	return entries
}

// parseEmailFormat parses email format
func (efm *ExternalFeedManager) parseEmailFormat(content string) []string {
	var entries []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Extract email (handle various formats)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			email := parts[0]
			if efm.isValidEmail(email) {
				entries = append(entries, email)
			}
		}
	}
	
	return entries
}

// autoDetectFormat attempts to auto-detect the format
func (efm *ExternalFeedManager) autoDetectFormat(content string) []string {
	// Try different formats and return the one with the most valid entries
	formats := []struct {
		name   string
		parser func(string) []string
	}{
		{"ip", efm.parseIPFormat},
		{"cidr", efm.parseCIDRFormat},
		{"domain", efm.parseDomainFormat},
		{"email", efm.parseEmailFormat},
	}
	
	var bestFormat []string
	maxCount := 0
	
	for _, format := range formats {
		entries := format.parser(content)
		if len(entries) > maxCount {
			maxCount = len(entries)
			bestFormat = entries
		}
	}
	
	return bestFormat
}

// parseFeedEntries converts feed entries to rules
func (efm *ExternalFeedManager) parseFeedEntries(entries []string, feed FeedConfig) ([]Rule, error) {
	var rules []Rule
	now := time.Now()
	
	for i, entry := range entries {
		rule := Rule{
			ID:        fmt.Sprintf("feed-%s-%d", feed.Name, i),
			Action:    feed.Type, // "blacklist" becomes "deny", "whitelist" becomes "allow"
			Priority:  60,        // Medium priority for external feeds
			Source:    fmt.Sprintf("feed:%s", feed.Name),
			CreatedAt: now,
			UpdatedAt: now,
			Description: fmt.Sprintf("External feed rule from %s", feed.Name),
			Tags:        []string{"external", "feed", feed.Name},
		}
		
		// Set appropriate fields based on format
		switch feed.Format {
		case "ip":
			rule.IPAddresses = []string{entry}
		case "cidr":
			rule.CIDRBlocks = []string{entry}
		case "domain":
			rule.Domains = []string{entry}
		case "email":
			rule.EmailPatterns = []string{entry}
		}
		
		// Convert blacklist/whitelist to deny/allow
		if rule.Action == "blacklist" {
			rule.Action = "deny"
		} else if rule.Action == "whitelist" {
			rule.Action = "allow"
		}
		
		rules = append(rules, rule)
	}
	
	return rules, nil
}

// Validation helper functions
func (efm *ExternalFeedManager) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (efm *ExternalFeedManager) isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func (efm *ExternalFeedManager) isValidDomain(domain string) bool {
	// Basic domain validation
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Check for valid characters
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '.' || char == '-') {
			return false
		}
	}
	
	// Must have at least one dot
	return strings.Contains(domain, ".")
}

func (efm *ExternalFeedManager) isValidEmail(email string) bool {
	// Basic email validation
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	
	local, domain := parts[0], parts[1]
	if len(local) == 0 || len(domain) == 0 {
		return false
	}
	
	return efm.isValidDomain(domain)
}

// GetFeedStatus returns the status of all feeds
func (efm *ExternalFeedManager) GetFeedStatus() []FeedStatus {
	efm.mu.RLock()
	defer efm.mu.RUnlock()
	
	var statuses []FeedStatus
	for _, feed := range efm.feeds {
		status := FeedStatus{
			Name:    feed.Name,
			URL:     feed.URL,
			Type:    feed.Type,
			Format:  feed.Format,
			Enabled: feed.Enabled,
		}
		statuses = append(statuses, status)
	}
	
	return statuses
}

// FeedStatus represents the status of an external feed
type FeedStatus struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	Format      string    `json:"format"`
	Enabled     bool      `json:"enabled"`
	LastUpdate  time.Time `json:"last_update,omitempty"`
	EntryCount  int       `json:"entry_count,omitempty"`
	ErrorCount  int       `json:"error_count,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}
