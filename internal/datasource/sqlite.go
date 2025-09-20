package datasource

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLite implements the DataSource interface for SQLite databases
type SQLite struct {
	config          Config
	db              *sql.DB
	connected       bool
	userTable       string
	groupTable      string
	dbPath          string
	securityManager *SQLSecurityManager
	secureDB        *SecureDBConnection
	logger          *slog.Logger
}

// NewSQLite creates a new SQLite datasource
func NewSQLite(config Config) *SQLite {
	// Set default values if not provided
	if config.Database == "" {
		config.Database = "elemta.db"
	}

	// Get table names from options or use defaults
	userTable := "users"
	groupTable := "groups"

	if config.Options != nil {
		if ut, ok := config.Options["user_table"].(string); ok && ut != "" {
			userTable = ut
		}
		if gt, ok := config.Options["group_table"].(string); ok && gt != "" {
			groupTable = gt
		}
	}

	// Determine database path
	dbPath := config.Database
	if config.Options != nil {
		// First check if a full path is provided
		if path, ok := config.Options["db_path"].(string); ok && path != "" {
			dbPath = path
		} else if !filepath.IsAbs(dbPath) {
			// If a directory is specified in the options, use it
			if dir, ok := config.Options["db_dir"].(string); ok && dir != "" {
				dbPath = filepath.Join(dir, config.Database)
			}
		}
	}

	// Create logger for security operations
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "sqlite-datasource",
		"database", dbPath,
	)

	// Initialize security manager
	securityManager := NewSQLSecurityManager(logger)
	
	// Register allowed tables and columns for SQLite
	securityManager.RegisterTable("users", []string{
		"username", "password", "email", "full_name", "is_active", "is_admin",
		"created_at", "updated_at", "last_login_at",
	})
	securityManager.RegisterTable("groups", []string{
		"name", "description", "is_active", "created_at", "updated_at",
	})
	securityManager.RegisterTable("user_attributes", []string{
		"username", "key", "value",
	})
	securityManager.RegisterTable("user_groups", []string{
		"username", "group_name",
	})

	return &SQLite{
		config:          config,
		connected:       false,
		userTable:       userTable,
		groupTable:      groupTable,
		dbPath:          dbPath,
		securityManager: securityManager,
		logger:          logger,
	}
}

// Connect establishes a connection to the SQLite database
func (s *SQLite) Connect() error {
	if s.connected {
		return nil
	}

	// Ensure the directory exists
	dir := filepath.Dir(s.dbPath)
	if dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for SQLite database: %w", err)
		}
	}

	// Connect to the database
	var err error
	s.db, err = sql.Open("sqlite3", s.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Set connection parameters
	s.db.SetMaxOpenConns(1) // SQLite supports only one writer at a time
	s.db.SetMaxIdleConns(1)
	s.db.SetConnMaxLifetime(30 * time.Minute)

	// Test the connection
	if err := s.db.Ping(); err != nil {
		s.db.Close()
		return fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	// Initialize the database schema if it doesn't exist
	if err := s.initSchema(); err != nil {
		s.db.Close()
		return fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Initialize secure database connection wrapper
	s.secureDB = NewSecureDBConnection(s.db, s.securityManager, s.logger)

	s.connected = true
	s.logger.Info("SQLite datasource connected with security enhancements",
		"database", s.dbPath,
		"security_enabled", true,
	)
	return nil
}

// initSchema creates the necessary tables if they don't exist
func (s *SQLite) initSchema() error {
	// Create users table
	userTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			email TEXT,
			full_name TEXT,
			is_active INTEGER NOT NULL DEFAULT 1,
			is_admin INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			last_login_at INTEGER
		)
	`, s.userTable)

	if _, err := s.db.Exec(userTableSQL); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create groups table
	groupTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT,
			created_at INTEGER NOT NULL
		)
	`, s.groupTable)

	if _, err := s.db.Exec(groupTableSQL); err != nil {
		return fmt.Errorf("failed to create groups table: %w", err)
	}

	// Create user_groups table
	userGroupsSQL := `
		CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
		)
	`

	if _, err := s.db.Exec(userGroupsSQL); err != nil {
		return fmt.Errorf("failed to create user_groups table: %w", err)
	}

	// Create user_attributes table
	userAttributesSQL := `
		CREATE TABLE IF NOT EXISTS user_attributes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			attr_key TEXT NOT NULL,
			attr_value TEXT,
			UNIQUE(username, attr_key),
			FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
		)
	`

	if _, err := s.db.Exec(userAttributesSQL); err != nil {
		return fmt.Errorf("failed to create user_attributes table: %w", err)
	}

	return nil
}

// Close closes the connection to the SQLite database
func (s *SQLite) Close() error {
	if !s.connected {
		return nil
	}

	// Close secure database connection (this will cleanup prepared statements)
	if s.secureDB != nil {
		if err := s.secureDB.Close(); err != nil {
			s.logger.Error("Failed to close secure database connection", "error", err)
		}
	}

	s.connected = false
	s.logger.Info("SQLite datasource connection closed")
	return nil
}

// IsConnected returns true if the datasource is connected
func (s *SQLite) IsConnected() bool {
	return s.connected
}

// Name returns the name of the datasource
func (s *SQLite) Name() string {
	return s.config.Name
}

// Type returns the type of the datasource
func (s *SQLite) Type() string {
	return "sqlite"
}

// Authenticate verifies credentials against the SQLite database
func (s *SQLite) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !s.connected {
		return false, ErrNotConnected
	}

	// Log authentication attempt for security monitoring
	s.logger.Info("Authentication attempt",
		"username", username,
		"source", "sqlite",
	)

	// Use secure query execution - check if user exists with valid credentials
	rows, err := s.secureDB.ExecuteSecureQuery(ctx, "SELECT", s.userTable,
		[]string{"username"},
		[]string{"username", "password", "is_active"},
		username, password, 1)
	if err != nil {
		s.logger.Error("Secure authentication query failed",
			"username", username,
			"error", err,
		)
		return false, fmt.Errorf("authentication query failed: %w", err)
	}
	defer rows.Close()

	var foundUsername string
	success := false
	if rows.Next() {
		if err := rows.Scan(&foundUsername); err != nil {
			s.logger.Error("Failed to scan authentication result",
				"username", username,
				"error", err,
			)
			return false, fmt.Errorf("failed to scan authentication result: %w", err)
		}
		success = foundUsername == username
	}
	if success {
		s.logger.Info("Authentication successful",
			"username", username,
			"source", "sqlite",
		)
	} else {
		s.logger.Warn("Authentication failed",
			"username", username,
			"source", "sqlite",
			"reason", "invalid_credentials",
		)
	}

	return success, nil
}

// GetUser retrieves user information from the SQLite database
func (s *SQLite) GetUser(ctx context.Context, username string) (User, error) {
	if !s.connected {
		return User{}, ErrNotConnected
	}

	// Use secure query execution
	rows, err := s.secureDB.ExecuteSecureQuery(ctx, "SELECT", s.userTable,
		[]string{"username", "password", "email", "full_name", "is_active", "is_admin", "created_at", "updated_at", "last_login_at"},
		[]string{"username"},
		username)
	if err != nil {
		s.logger.Error("Secure GetUser query failed",
			"username", username,
			"error", err,
		)
		return User{}, fmt.Errorf("failed to get user: %w", err)
	}
	defer rows.Close()

	var user User
	var createdAt, updatedAt, lastLoginAt sql.NullInt64

	if !rows.Next() {
		return User{}, ErrNotFound
	}

	err = rows.Scan(
		&user.Username,
		&user.Password,
		&user.Email,
		&user.FullName,
		&user.IsActive,
		&user.IsAdmin,
		&createdAt,
		&updatedAt,
		&lastLoginAt,
	)

	if err != nil {
		s.logger.Error("Failed to scan GetUser result",
			"username", username,
			"error", err,
		)
		return User{}, fmt.Errorf("failed to scan user data: %w", err)
	}

	// Convert nullable fields
	if createdAt.Valid {
		user.CreatedAt = createdAt.Int64
	}
	if updatedAt.Valid {
		user.UpdatedAt = updatedAt.Int64
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Int64
	}

	// Get user groups
	groupQuery := fmt.Sprintf(`
		SELECT g.name
		FROM %s g
		JOIN user_groups ug ON g.id = ug.group_id
		JOIN %s u ON u.id = ug.user_id
		WHERE u.username = ?
	`, s.groupTable, s.userTable)

	groupRows, err := s.db.QueryContext(ctx, groupQuery, username)
	if err != nil {
		return user, fmt.Errorf("failed to get user groups: %w", err)
	}
	defer groupRows.Close()

	for groupRows.Next() {
		var groupName string
		if err := groupRows.Scan(&groupName); err != nil {
			return user, fmt.Errorf("failed to scan group name: %w", err)
		}
		user.Groups = append(user.Groups, groupName)
	}

	if err := groupRows.Err(); err != nil {
		return user, fmt.Errorf("error iterating group rows: %w", err)
	}

	// Get user attributes
	attrQuery := `
		SELECT attr_key, attr_value
		FROM user_attributes
		WHERE username = ?
	`

	attrRows, err := s.db.QueryContext(ctx, attrQuery, username)
	if err != nil {
		return user, fmt.Errorf("failed to get user attributes: %w", err)
	}
	defer attrRows.Close()

	user.Attributes = make(map[string]interface{})
	for attrRows.Next() {
		var key, value string
		if err := attrRows.Scan(&key, &value); err != nil {
			return user, fmt.Errorf("failed to scan attribute: %w", err)
		}
		user.Attributes[key] = value
	}

	if err := attrRows.Err(); err != nil {
		return user, fmt.Errorf("error iterating attribute rows: %w", err)
	}

	return user, nil
}

// ListUsers retrieves a list of users from the SQLite database
func (s *SQLite) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !s.connected {
		return nil, ErrNotConnected
	}

	// Build the query
	query := fmt.Sprintf(`
		SELECT username, password, email, full_name, is_active, is_admin, 
		       created_at, updated_at, last_login_at
		FROM %s
		WHERE 1=1
	`, s.userTable)

	// Add filters
	var args []interface{}
	for key, value := range filter {
		// Sanitize the key to prevent SQL injection
		key = strings.ReplaceAll(key, "`", "")
		key = strings.ReplaceAll(key, "'", "")
		key = strings.ReplaceAll(key, "\"", "")

		query += fmt.Sprintf(" AND %s = ?", key)
		args = append(args, value)
	}

	// Add pagination
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)

		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}

	// Execute the query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var createdAt, updatedAt, lastLoginAt sql.NullInt64

		err := rows.Scan(
			&user.Username,
			&user.Password,
			&user.Email,
			&user.FullName,
			&user.IsActive,
			&user.IsAdmin,
			&createdAt,
			&updatedAt,
			&lastLoginAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}

		// Convert nullable fields
		if createdAt.Valid {
			user.CreatedAt = createdAt.Int64
		}
		if updatedAt.Valid {
			user.UpdatedAt = updatedAt.Int64
		}
		if lastLoginAt.Valid {
			user.LastLoginAt = lastLoginAt.Int64
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	// For each user, we could fetch groups and attributes
	// This is simplified for brevity

	return users, nil
}

// CreateUser creates a new user in the SQLite database
func (s *SQLite) CreateUser(ctx context.Context, user User) error {
	if !s.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Insert the user
	query := fmt.Sprintf(`
		INSERT INTO %s (
			username, password, email, full_name, is_active, is_admin,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, s.userTable)

	now := time.Now().Unix()

	_, err = tx.ExecContext(ctx, query,
		user.Username,
		user.Password,
		user.Email,
		user.FullName,
		user.IsActive,
		user.IsAdmin,
		now,
		now,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Insert user groups (simplified)
	if len(user.Groups) > 0 {
		for _, group := range user.Groups {
			// First, ensure the group exists
			_, err = tx.ExecContext(ctx, fmt.Sprintf(`
				INSERT OR IGNORE INTO %s (name, created_at)
				VALUES (?, ?)
			`, s.groupTable), group, now)

			if err != nil {
				return fmt.Errorf("failed to create group: %w", err)
			}

			// Then, add the user to the group
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_groups (user_id, group_id)
				SELECT u.id, g.id
				FROM users u, groups g
				WHERE u.username = ? AND g.name = ?
			`, user.Username, group)

			if err != nil {
				return fmt.Errorf("failed to add user to group: %w", err)
			}
		}
	}

	// Insert user attributes
	if len(user.Attributes) > 0 {
		for key, value := range user.Attributes {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_attributes (username, attr_key, attr_value)
				VALUES (?, ?, ?)
			`, user.Username, key, fmt.Sprintf("%v", value))

			if err != nil {
				return fmt.Errorf("failed to add user attribute: %w", err)
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// UpdateUser updates an existing user in the SQLite database
func (s *SQLite) UpdateUser(ctx context.Context, user User) error {
	if !s.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Update the user
	query := fmt.Sprintf(`
		UPDATE %s SET
			password = ?,
			email = ?,
			full_name = ?,
			is_active = ?,
			is_admin = ?,
			updated_at = ?
		WHERE username = ?
	`, s.userTable)

	now := time.Now().Unix()

	result, err := tx.ExecContext(ctx, query,
		user.Password,
		user.Email,
		user.FullName,
		user.IsActive,
		user.IsAdmin,
		now,
		user.Username,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	// Update user groups
	// First, delete existing group associations
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_groups
		WHERE user_id IN (SELECT id FROM users WHERE username = ?)
	`, user.Username)

	if err != nil {
		return fmt.Errorf("failed to delete user groups: %w", err)
	}

	// Then, add new group associations
	if len(user.Groups) > 0 {
		for _, group := range user.Groups {
			// First, ensure the group exists
			_, err = tx.ExecContext(ctx, fmt.Sprintf(`
				INSERT OR IGNORE INTO %s (name, created_at)
				VALUES (?, ?)
			`, s.groupTable), group, now)

			if err != nil {
				return fmt.Errorf("failed to create group: %w", err)
			}

			// Then, add the user to the group
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_groups (user_id, group_id)
				SELECT u.id, g.id
				FROM users u, groups g
				WHERE u.username = ? AND g.name = ?
			`, user.Username, group)

			if err != nil {
				return fmt.Errorf("failed to add user to group: %w", err)
			}
		}
	}

	// Update user attributes
	// First, delete existing attributes
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_attributes
		WHERE username = ?
	`, user.Username)

	if err != nil {
		return fmt.Errorf("failed to delete user attributes: %w", err)
	}

	// Then, add new attributes
	if len(user.Attributes) > 0 {
		for key, value := range user.Attributes {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_attributes (username, attr_key, attr_value)
				VALUES (?, ?, ?)
			`, user.Username, key, fmt.Sprintf("%v", value))

			if err != nil {
				return fmt.Errorf("failed to add user attribute: %w", err)
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteUser deletes a user from the SQLite database
func (s *SQLite) DeleteUser(ctx context.Context, username string) error {
	if !s.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete the user (cascade will handle related records)
	query := fmt.Sprintf("DELETE FROM %s WHERE username = ?", s.userTable)
	result, err := tx.ExecContext(ctx, query, username)

	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Query executes a custom query against the SQLite database
func (s *SQLite) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	if !s.connected {
		return nil, ErrNotConnected
	}

	// Determine if this is a SELECT query or an action query
	query = strings.TrimSpace(query)
	isSelect := strings.HasPrefix(strings.ToUpper(query), "SELECT")

	if isSelect {
		// For SELECT queries, return rows
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %w", err)
		}
		defer rows.Close()

		// Get column names
		columns, err := rows.Columns()
		if err != nil {
			return nil, fmt.Errorf("failed to get column names: %w", err)
		}

		// Prepare result
		var result []map[string]interface{}

		// Prepare values for scanning
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		// Iterate through rows
		for rows.Next() {
			if err := rows.Scan(valuePtrs...); err != nil {
				return nil, fmt.Errorf("failed to scan row: %w", err)
			}

			// Create a map for this row
			row := make(map[string]interface{})
			for i, col := range columns {
				val := values[i]

				// Handle nil values
				if val == nil {
					row[col] = nil
					continue
				}

				// Convert bytes to string for text data
				switch v := val.(type) {
				case []byte:
					row[col] = string(v)
				default:
					row[col] = v
				}
			}

			result = append(result, row)
		}

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating rows: %w", err)
		}

		return result, nil
	} else {
		// For action queries (INSERT, UPDATE, DELETE), return affected rows
		result, err := s.db.ExecContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("failed to get rows affected: %w", err)
		}

		return map[string]interface{}{
			"rows_affected": rowsAffected,
		}, nil
	}
}
