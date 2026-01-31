package datasource

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAP implements the DataSource interface for LDAP directories
type LDAP struct {
	config    Config
	conn      *ldap.Conn
	connected bool
	baseDN    string
	userDN    string
	groupDN   string
}

// NewLDAP creates a new LDAP datasource
func NewLDAP(config Config) *LDAP {
	// Set default values if not provided
	if config.Port == 0 {
		config.Port = 389 // Default LDAP port (use 636 for LDAPS)
	}

	// Get base DNs from options or use defaults
	baseDN := "dc=example,dc=com"
	userDN := "ou=users"
	groupDN := "ou=groups"

	if config.Options != nil {
		if base, ok := config.Options["base_dn"].(string); ok && base != "" {
			baseDN = base
		}
		if user, ok := config.Options["user_dn"].(string); ok && user != "" {
			userDN = user
		}
		if group, ok := config.Options["group_dn"].(string); ok && group != "" {
			groupDN = group
		}
	}

	// Ensure userDN and groupDN are relative to baseDN if they don't contain the baseDN
	// Special case: if userDN is the same as baseDN, don't append it
	if !strings.HasSuffix(userDN, baseDN) && !strings.Contains(userDN, ",") && userDN != baseDN {
		userDN = userDN + "," + baseDN
	}
	if !strings.HasSuffix(groupDN, baseDN) && !strings.Contains(groupDN, ",") && groupDN != baseDN {
		groupDN = groupDN + "," + baseDN
	}

	return &LDAP{
		config:    config,
		connected: false,
		baseDN:    baseDN,
		userDN:    userDN,
		groupDN:   groupDN,
	}
}

// Connect establishes a connection to the LDAP server
func (l *LDAP) Connect() error {
	if l.connected {
		return nil
	}

	// Connect to LDAP server using DialURL (replaces deprecated Dial)
	ldapURL := fmt.Sprintf("ldap://%s:%d", l.config.Host, l.config.Port)
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Set timeout - increase to 30 seconds for better reliability
	conn.SetTimeout(30 * time.Second)

	// Bind with service account if credentials are provided
	if l.config.Username != "" && l.config.Password != "" {
		if err := conn.Bind(l.config.Username, l.config.Password); err != nil {
			_ = conn.Close() // Ignore error on cleanup in error path
			return fmt.Errorf("failed to bind to LDAP server: %w", err)
		}
	}

	l.conn = conn
	l.connected = true
	return nil
}

// Close closes the connection to the LDAP server
func (l *LDAP) Close() error {
	if !l.connected {
		return nil
	}

	l.connected = false
	if err := l.conn.Close(); err != nil {
		return fmt.Errorf("failed to close LDAP connection: %w", err)
	}
	return nil
}

// IsConnected returns true if the datasource is connected
func (l *LDAP) IsConnected() bool {
	return l.connected
}

// Name returns the name of the datasource
func (l *LDAP) Name() string {
	return l.config.Name
}

// Type returns the type of the datasource
func (l *LDAP) Type() string {
	return "ldap"
}

// getUserDN returns the full DN for a user
func (l *LDAP) getUserDN(username string) string {
	return fmt.Sprintf("uid=%s,%s", ldap.EscapeFilter(username), l.userDN)
}

// ensureConnection checks if the LDAP connection is still alive and reconnects if needed
func (l *LDAP) ensureConnection() error {
	// Try a simple search to check if connection is alive
	if l.conn != nil {
		testSearch := ldap.NewSearchRequest(
			l.baseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1, 5, false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)
		_, err := l.conn.Search(testSearch)
		if err == nil {
			// Connection is alive
			return nil
		}
		// Connection is dead, close it
		_ = l.conn.Close() // Ignore error on cleanup
		l.connected = false
	}

	// Reconnect
	return l.Connect()
}

// Authenticate verifies credentials against the LDAP server
func (l *LDAP) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !l.connected {
		return false, ErrNotConnected
	}

	// Check if connection is still alive, reconnect if needed
	if err := l.ensureConnection(); err != nil {
		return false, fmt.Errorf("failed to ensure LDAP connection: %w", err)
	}

	// First, search for the user by email address to get the actual DN
	var userDN string
	var searchFilter string

	// Check if username looks like an email address
	if strings.Contains(username, "@") {
		// Search by email address
		searchFilter = fmt.Sprintf("(mail=%s)", ldap.EscapeFilter(username))
	} else {
		// Search by uid
		searchFilter = fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username))
	}

	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
		searchFilter,
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return false, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return false, nil // User not found
	}

	userDN = searchResult.Entries[0].DN

	// Try to bind with the user's credentials using DialURL (replaces deprecated Dial)
	ldapURL := fmt.Sprintf("ldap://%s:%d", l.config.Host, l.config.Port)
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return false, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer func() {
		if conn != nil {
			_ = conn.Close() // Ignore error in defer cleanup
		}
	}()

	// Set timeout - increase to 30 seconds for better reliability
	conn.SetTimeout(30 * time.Second)

	// Bind with user credentials
	if err := conn.Bind(userDN, password); err != nil {
		// If bind fails, authentication failed
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, fmt.Errorf("authentication failed: %w", err)
	}

	return true, nil
}

// GetUser retrieves user information from the LDAP server
func (l *LDAP) GetUser(ctx context.Context, username string) (User, error) {
	if !l.connected {
		return User{}, ErrNotConnected
	}

	// Ensure connection is alive
	if err := l.ensureConnection(); err != nil {
		return User{}, fmt.Errorf("failed to ensure LDAP connection: %w", err)
	}

	// Search for the user
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail", "objectClass", "createTimestamp", "modifyTimestamp", "shadowLastChange"},
		nil,
	)

	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return User{}, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return User{}, ErrNotFound
	}

	if len(searchResult.Entries) > 1 {
		return User{}, fmt.Errorf("multiple users found with username '%s'", username)
	}

	entry := searchResult.Entries[0]

	// Create user object
	user := User{
		Username:   entry.GetAttributeValue("uid"),
		FullName:   entry.GetAttributeValue("cn"),
		Email:      entry.GetAttributeValue("mail"),
		IsActive:   true, // Assume active unless specified otherwise
		Attributes: make(map[string]interface{}),
	}

	// Parse timestamps
	if createTime := entry.GetAttributeValue("createTimestamp"); createTime != "" {
		if t, err := time.Parse("20060102150405Z", createTime); err == nil {
			user.CreatedAt = t.Unix()
		}
	}

	if modifyTime := entry.GetAttributeValue("modifyTimestamp"); modifyTime != "" {
		if t, err := time.Parse("20060102150405Z", modifyTime); err == nil {
			user.UpdatedAt = t.Unix()
		}
	}

	if lastChange := entry.GetAttributeValue("shadowLastChange"); lastChange != "" {
		if days, err := strconv.ParseInt(lastChange, 10, 64); err == nil {
			// shadowLastChange is in days since Jan 1, 1970
			user.LastLoginAt = days * 86400 // Convert days to seconds
		}
	}

	// Get user groups
	groupSearchRequest := ldap.NewSearchRequest(
		l.groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(entry.DN)),
		[]string{"cn"},
		nil,
	)

	groupResult, err := l.conn.Search(groupSearchRequest)
	if err != nil {
		return user, fmt.Errorf("failed to search for user groups: %w", err)
	}

	for _, groupEntry := range groupResult.Entries {
		groupName := groupEntry.GetAttributeValue("cn")
		user.Groups = append(user.Groups, groupName)

		// Check if user is admin based on group membership
		if strings.ToLower(groupName) == "admins" {
			user.IsAdmin = true
		}
	}

	// Add all attributes to the attributes map
	for _, attr := range entry.Attributes {
		if len(attr.Values) == 1 {
			user.Attributes[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			user.Attributes[attr.Name] = attr.Values
		}
	}

	return user, nil
}

// ListUsers retrieves a list of users from the LDAP server
func (l *LDAP) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !l.connected {
		return nil, ErrNotConnected
	}

	// Build LDAP filter
	ldapFilter := "(objectClass=posixAccount)"

	// Add filters
	for key, value := range filter {
		switch key {
		case "username":
			ldapFilter = fmt.Sprintf("(&%s(uid=%s))", ldapFilter, ldap.EscapeFilter(value.(string)))
		case "email":
			ldapFilter = fmt.Sprintf("(&%s(mail=%s))", ldapFilter, ldap.EscapeFilter(value.(string)))
		case "is_admin":
			// This is a bit tricky in LDAP, we'll handle it after the search
		}
	}

	// Search for users
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapFilter,
		[]string{"uid", "cn", "mail", "objectClass", "createTimestamp", "modifyTimestamp", "shadowLastChange"},
		nil,
	)

	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for users: %w", err)
	}

	var users []User

	// Apply pagination manually
	start := 0
	end := len(searchResult.Entries)

	if offset > 0 && offset < end {
		start = offset
	}

	if limit > 0 && start+limit < end {
		end = start + limit
	}

	// Process each user entry
	for i := start; i < end; i++ {
		entry := searchResult.Entries[i]

		// Create user object
		user := User{
			Username:   entry.GetAttributeValue("uid"),
			FullName:   entry.GetAttributeValue("cn"),
			Email:      entry.GetAttributeValue("mail"),
			IsActive:   true, // Assume active unless specified otherwise
			Attributes: make(map[string]interface{}),
		}

		// Parse timestamps
		if createTime := entry.GetAttributeValue("createTimestamp"); createTime != "" {
			if t, err := time.Parse("20060102150405Z", createTime); err == nil {
				user.CreatedAt = t.Unix()
			}
		}

		if modifyTime := entry.GetAttributeValue("modifyTimestamp"); modifyTime != "" {
			if t, err := time.Parse("20060102150405Z", modifyTime); err == nil {
				user.UpdatedAt = t.Unix()
			}
		}

		// Get user groups
		groupSearchRequest := ldap.NewSearchRequest(
			l.groupDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(member=%s)", ldap.EscapeFilter(entry.DN)),
			[]string{"cn"},
			nil,
		)

		groupResult, err := l.conn.Search(groupSearchRequest)
		if err != nil {
			return users, fmt.Errorf("failed to search for user groups: %w", err)
		}

		for _, groupEntry := range groupResult.Entries {
			groupName := groupEntry.GetAttributeValue("cn")
			user.Groups = append(user.Groups, groupName)

			// Check if user is admin based on group membership
			if strings.ToLower(groupName) == "admins" {
				user.IsAdmin = true
			}
		}

		// Filter by admin status if requested
		if filter != nil {
			if isAdmin, ok := filter["is_admin"].(bool); ok {
				if isAdmin != user.IsAdmin {
					continue // Skip this user if admin status doesn't match
				}
			}
		}

		users = append(users, user)
	}

	return users, nil
}

// CreateUser creates a new user in the LDAP server
func (l *LDAP) CreateUser(ctx context.Context, user User) error {
	if !l.connected {
		return ErrNotConnected
	}

	// Check if user already exists
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(user.Username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for existing user: %w", err)
	}

	if len(searchResult.Entries) > 0 {
		return ErrAlreadyExists
	}

	// Create the user entry
	now := time.Now().Unix()
	if user.CreatedAt == 0 {
		user.CreatedAt = now
	}
	if user.UpdatedAt == 0 {
		user.UpdatedAt = now
	}

	// Create add request
	addRequest := ldap.NewAddRequest(l.getUserDN(user.Username), nil)

	// Add object classes
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"})

	// Add required attributes
	addRequest.Attribute("uid", []string{user.Username})
	addRequest.Attribute("cn", []string{user.FullName})

	if user.Email != "" {
		addRequest.Attribute("mail", []string{user.Email})
	}

	if user.Password != "" {
		// In a real implementation, you would use a secure password hashing algorithm
		// This is a simplified example
		addRequest.Attribute("userPassword", []string{user.Password})
	}

	// Add other attributes
	for key, value := range user.Attributes {
		if key == "objectClass" || key == "uid" || key == "cn" || key == "mail" || key == "userPassword" {
			continue // Skip attributes we've already set
		}

		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []string:
			values = v
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					values = append(values, str)
				}
			}
		default:
			values = []string{fmt.Sprintf("%v", v)}
		}

		if len(values) > 0 {
			addRequest.Attribute(key, values)
		}
	}

	// Execute the add request
	if err := l.conn.Add(addRequest); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Add user to groups
	for _, groupName := range user.Groups {
		// Find the group
		groupSearchRequest := ldap.NewSearchRequest(
			l.groupDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(groupName)),
			[]string{"dn"},
			nil,
		)

		groupResult, err := l.conn.Search(groupSearchRequest)
		if err != nil {
			return fmt.Errorf("failed to search for group: %w", err)
		}

		if len(groupResult.Entries) == 0 {
			// Group doesn't exist, create it
			groupDN := fmt.Sprintf("cn=%s,%s", ldap.EscapeFilter(groupName), l.groupDN)
			groupAddRequest := ldap.NewAddRequest(groupDN, nil)
			groupAddRequest.Attribute("objectClass", []string{"top", "groupOfNames"})
			groupAddRequest.Attribute("cn", []string{groupName})
			groupAddRequest.Attribute("member", []string{l.getUserDN(user.Username)})

			if err := l.conn.Add(groupAddRequest); err != nil {
				return fmt.Errorf("failed to create group: %w", err)
			}
		} else {
			// Group exists, add user to it
			groupDN := groupResult.Entries[0].DN
			modifyRequest := ldap.NewModifyRequest(groupDN, nil)
			modifyRequest.Add("member", []string{l.getUserDN(user.Username)})

			if err := l.conn.Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to add user to group: %w", err)
			}
		}
	}

	return nil
}

// UpdateUser updates an existing user in the LDAP server
func (l *LDAP) UpdateUser(ctx context.Context, user User) error {
	if !l.connected {
		return ErrNotConnected
	}

	// Check if user exists
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(user.Username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for existing user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return ErrNotFound
	}

	userDN := searchResult.Entries[0].DN

	// Create modify request
	modifyRequest := ldap.NewModifyRequest(userDN, nil)

	// Update attributes
	if user.FullName != "" {
		modifyRequest.Replace("cn", []string{user.FullName})
	}

	if user.Email != "" {
		modifyRequest.Replace("mail", []string{user.Email})
	}

	if user.Password != "" {
		// In a real implementation, you would use a secure password hashing algorithm
		modifyRequest.Replace("userPassword", []string{user.Password})
	}

	// Update other attributes
	for key, value := range user.Attributes {
		if key == "objectClass" || key == "uid" {
			continue // Skip attributes we shouldn't modify
		}

		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []string:
			values = v
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					values = append(values, str)
				}
			}
		default:
			values = []string{fmt.Sprintf("%v", v)}
		}

		if len(values) > 0 {
			modifyRequest.Replace(key, values)
		}
	}

	// Execute the modify request
	if err := l.conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Update group memberships
	// First, get current groups
	groupSearchRequest := ldap.NewSearchRequest(
		l.groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN)),
		[]string{"dn", "cn"},
		nil,
	)

	groupResult, err := l.conn.Search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for user groups: %w", err)
	}

	// Create maps for current and desired groups
	currentGroups := make(map[string]string) // map[groupName]groupDN
	desiredGroups := make(map[string]bool)   // map[groupName]true

	for _, groupEntry := range groupResult.Entries {
		groupName := groupEntry.GetAttributeValue("cn")
		currentGroups[groupName] = groupEntry.DN
	}

	for _, groupName := range user.Groups {
		desiredGroups[groupName] = true
	}

	// Remove user from groups they should no longer be in
	for groupName, groupDN := range currentGroups {
		if !desiredGroups[groupName] {
			modifyRequest := ldap.NewModifyRequest(groupDN, nil)
			modifyRequest.Delete("member", []string{userDN})

			if err := l.conn.Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to remove user from group: %w", err)
			}
		}
	}

	// Add user to new groups
	for groupName := range desiredGroups {
		if _, exists := currentGroups[groupName]; !exists {
			// Group doesn't exist in current groups, add user to it
			// First, check if the group exists
			groupSearchRequest := ldap.NewSearchRequest(
				l.groupDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(groupName)),
				[]string{"dn"},
				nil,
			)

			groupResult, err := l.conn.Search(groupSearchRequest)
			if err != nil {
				return fmt.Errorf("failed to search for group: %w", err)
			}

			if len(groupResult.Entries) == 0 {
				// Group doesn't exist, create it
				groupDN := fmt.Sprintf("cn=%s,%s", ldap.EscapeFilter(groupName), l.groupDN)
				groupAddRequest := ldap.NewAddRequest(groupDN, nil)
				groupAddRequest.Attribute("objectClass", []string{"top", "groupOfNames"})
				groupAddRequest.Attribute("cn", []string{groupName})
				groupAddRequest.Attribute("member", []string{userDN})

				if err := l.conn.Add(groupAddRequest); err != nil {
					return fmt.Errorf("failed to create group: %w", err)
				}
			} else {
				// Group exists, add user to it
				groupDN := groupResult.Entries[0].DN
				modifyRequest := ldap.NewModifyRequest(groupDN, nil)
				modifyRequest.Add("member", []string{userDN})

				if err := l.conn.Modify(modifyRequest); err != nil {
					return fmt.Errorf("failed to add user to group: %w", err)
				}
			}
		}
	}

	return nil
}

// DeleteUser deletes a user from the LDAP server
func (l *LDAP) DeleteUser(ctx context.Context, username string) error {
	if !l.connected {
		return ErrNotConnected
	}

	// Check if user exists
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for existing user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return ErrNotFound
	}

	userDN := searchResult.Entries[0].DN

	// Remove user from all groups
	groupSearchRequest := ldap.NewSearchRequest(
		l.groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN)),
		[]string{"dn"},
		nil,
	)

	groupResult, err := l.conn.Search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for user groups: %w", err)
	}

	for _, groupEntry := range groupResult.Entries {
		modifyRequest := ldap.NewModifyRequest(groupEntry.DN, nil)
		modifyRequest.Delete("member", []string{userDN})

		if err := l.conn.Modify(modifyRequest); err != nil {
			return fmt.Errorf("failed to remove user from group: %w", err)
		}
	}

	// Delete the user
	deleteRequest := ldap.NewDelRequest(userDN, nil)
	if err := l.conn.Del(deleteRequest); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// Query executes a custom query against the LDAP server
func (l *LDAP) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	if !l.connected {
		return nil, ErrNotConnected
	}

	// Parse the query as an LDAP search
	// The query should be in the format: "base||scope||filter||attributes"
	// where:
	// - base is the search base DN
	// - scope is one of: base, one, sub
	// - filter is the LDAP filter
	// - attributes is a comma-separated list of attributes to return
	parts := strings.Split(query, "||")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid LDAP query format, expected 'base||scope||filter||attributes'")
	}

	baseDN := parts[0]
	if baseDN == "" {
		baseDN = l.baseDN
	}

	var scope int
	switch strings.ToLower(parts[1]) {
	case "base":
		scope = ldap.ScopeBaseObject
	case "one":
		scope = ldap.ScopeSingleLevel
	case "sub":
		scope = ldap.ScopeWholeSubtree
	default:
		return nil, fmt.Errorf("invalid scope: %s, expected 'base', 'one', or 'sub'", parts[1])
	}

	filter := parts[2]

	var attributes []string
	if len(parts) > 3 && parts[3] != "" {
		attributes = strings.Split(parts[3], ",")
	}

	// Create search request
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	// Execute search
	searchResult, err := l.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP query failed: %w", err)
	}

	// Convert result to a more usable format
	var result []map[string]interface{}

	for _, entry := range searchResult.Entries {
		entryMap := map[string]interface{}{
			"dn": entry.DN,
		}

		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				entryMap[attr.Name] = attr.Values[0]
			} else {
				entryMap[attr.Name] = attr.Values
			}
		}

		result = append(result, entryMap)
	}

	return result, nil
}
