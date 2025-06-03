package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// User represents a Zimbra user account
type User struct {
	DN                  string    `json:"dn"`
	Mail                string    `json:"mail"`
	UID                 string    `json:"uid"`
	CN                  string    `json:"cn"`
	DisplayName         string    `json:"display_name"`
	GivenName           string    `json:"given_name"`
	SN                  string    `json:"sn"`
	MailHost            string    `json:"mail_host"`
	AccountStatus       string    `json:"account_status"`
	MailQuota           int64     `json:"mail_quota"`
	MailDeliveryAddress string    `json:"mail_delivery_address"`
	MailAlias           []string  `json:"mail_alias"`
	LastModified        time.Time `json:"last_modified"`

	// Zimbra-specific attributes
	ZimbraAccountStatus      string   `json:"zimbra_account_status"`
	ZimbraMailHost           string   `json:"zimbra_mail_host"`
	ZimbraMailQuota          string   `json:"zimbra_mail_quota"`
	ZimbraMailAlias          []string `json:"zimbra_mail_alias"`
	ZimbraHideInGAL          string   `json:"zimbra_hide_in_gal"`
	ZimbraPasswordMustChange string   `json:"zimbra_password_must_change"`
}

// UserService handles user-related LDAP operations
type UserService struct {
	client *Client
	logger *slog.Logger
	cache  map[string]*User // Simple in-memory cache
}

// NewUserService creates a new user service
func NewUserService(client *Client, logger *slog.Logger) *UserService {
	return &UserService{
		client: client,
		logger: logger,
		cache:  make(map[string]*User),
	}
}

// AuthenticateUser verifies user credentials against LDAP
func (s *UserService) AuthenticateUser(ctx context.Context, email, password string) (*User, error) {
	s.logger.Debug("Authenticating user",
		slog.String("email", email),
	)

	// First, find the user DN
	user, err := s.FindUser(ctx, email)
	if err != nil {
		s.logger.Warn("User not found during authentication",
			slog.String("email", email),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if account is active
	if !s.isAccountActive(user) {
		s.logger.Warn("User account is not active",
			slog.String("email", email),
			slog.String("status", user.ZimbraAccountStatus),
		)
		return nil, fmt.Errorf("account is not active: %s", user.ZimbraAccountStatus)
	}

	// Get a connection for authentication
	conn, err := s.client.GetConnection(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer s.client.ReturnConnection(conn)

	// Attempt to bind with user credentials
	err = conn.Bind(user.DN, password)
	if err != nil {
		s.logger.Warn("User authentication failed",
			slog.String("email", email),
			slog.String("dn", user.DN),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	s.logger.Info("User authenticated successfully",
		slog.String("email", email),
		slog.String("dn", user.DN),
	)

	return user, nil
}

// FindUser searches for a user by email address
func (s *UserService) FindUser(ctx context.Context, email string) (*User, error) {
	// Check cache first
	if user, exists := s.cache[email]; exists {
		s.logger.Debug("User found in cache",
			slog.String("email", email),
		)
		return user, nil
	}

	conn, err := s.client.GetConnection(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer s.client.ReturnConnection(conn)

	// Build search request
	searchBase := fmt.Sprintf("%s,%s", s.client.config.UserSearchBase, s.client.config.BaseDN)
	searchFilter := fmt.Sprintf(s.client.config.UserSearchFilter, ldap.EscapeFilter(email))

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit
		int(s.client.config.SearchTimeout.Seconds()),
		false,
		searchFilter,
		[]string{
			"dn", "mail", "uid", "cn", "displayName", "givenName", "sn",
			"zimbraAccountStatus", "zimbraMailHost", "zimbraMailQuota",
			"zimbraMailAlias", "zimbraHideInGAL", "zimbraPasswordMustChange",
			"modifyTimestamp",
		},
		nil,
	)

	s.logger.Debug("Searching for user",
		slog.String("email", email),
		slog.String("search_base", searchBase),
		slog.String("search_filter", searchFilter),
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		s.logger.Error("LDAP search failed",
			slog.String("email", email),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", email)
	}

	if len(result.Entries) > 1 {
		s.logger.Warn("Multiple users found for email",
			slog.String("email", email),
			slog.Int("count", len(result.Entries)),
		)
	}

	// Convert LDAP entry to User struct
	entry := result.Entries[0]
	user := s.entryToUser(entry)

	// Cache the user
	s.cache[email] = user

	s.logger.Debug("User found in LDAP",
		slog.String("email", email),
		slog.String("dn", user.DN),
		slog.String("status", user.ZimbraAccountStatus),
	)

	return user, nil
}

// ValidateMailbox checks if a mailbox exists for the given email
func (s *UserService) ValidateMailbox(ctx context.Context, email string) (bool, error) {
	user, err := s.FindUser(ctx, email)
	if err != nil {
		return false, err
	}

	// Check if account is active and has a mailbox
	if !s.isAccountActive(user) {
		return false, fmt.Errorf("account is not active: %s", user.ZimbraAccountStatus)
	}

	// Check if user has a mail host assigned (indicating mailbox exists)
	if user.ZimbraMailHost == "" {
		return false, fmt.Errorf("no mail host assigned to user")
	}

	return true, nil
}

// GetUserAliases returns all aliases for a user
func (s *UserService) GetUserAliases(ctx context.Context, email string) ([]string, error) {
	user, err := s.FindUser(ctx, email)
	if err != nil {
		return nil, err
	}

	return user.ZimbraMailAlias, nil
}

// IsLocalDomain checks if an email domain is handled locally
func (s *UserService) IsLocalDomain(domain string) bool {
	// This would typically check against Zimbra's domain configuration
	// For now, we'll use the configured local domains
	for _, localDomain := range s.client.config.LocalDomains {
		if strings.EqualFold(domain, localDomain) {
			return true
		}
	}
	return false
}

// entryToUser converts an LDAP entry to a User struct
func (s *UserService) entryToUser(entry *ldap.Entry) *User {
	user := &User{
		DN:                       entry.DN,
		Mail:                     entry.GetAttributeValue("mail"),
		UID:                      entry.GetAttributeValue("uid"),
		CN:                       entry.GetAttributeValue("cn"),
		DisplayName:              entry.GetAttributeValue("displayName"),
		GivenName:                entry.GetAttributeValue("givenName"),
		SN:                       entry.GetAttributeValue("sn"),
		ZimbraAccountStatus:      entry.GetAttributeValue("zimbraAccountStatus"),
		ZimbraMailHost:           entry.GetAttributeValue("zimbraMailHost"),
		ZimbraMailQuota:          entry.GetAttributeValue("zimbraMailQuota"),
		ZimbraMailAlias:          entry.GetAttributeValues("zimbraMailAlias"),
		ZimbraHideInGAL:          entry.GetAttributeValue("zimbraHideInGAL"),
		ZimbraPasswordMustChange: entry.GetAttributeValue("zimbraPasswordMustChange"),
	}

	// Parse last modified timestamp
	if modTime := entry.GetAttributeValue("modifyTimestamp"); modTime != "" {
		if t, err := time.Parse("20060102150405Z", modTime); err == nil {
			user.LastModified = t
		}
	}

	// Set convenience fields
	user.MailHost = user.ZimbraMailHost
	user.AccountStatus = user.ZimbraAccountStatus
	user.MailAlias = user.ZimbraMailAlias

	return user
}

// isAccountActive checks if a Zimbra account is in active status
func (s *UserService) isAccountActive(user *User) bool {
	status := strings.ToLower(user.ZimbraAccountStatus)
	return status == "active" || status == ""
}

// ClearCache clears the user cache
func (s *UserService) ClearCache() {
	s.cache = make(map[string]*User)
	s.logger.Debug("User cache cleared")
}

// GetCacheStats returns cache statistics
func (s *UserService) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"cache_size": len(s.cache),
	}
}
