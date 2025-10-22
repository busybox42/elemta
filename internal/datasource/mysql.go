package datasource

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// MySQL implements the DataSource interface for MySQL databases
type MySQL struct {
	config          Config
	db              *sql.DB
	connected       bool
	userTable       string
	groupTable      string
	securityManager *SQLSecurityManager
	secureDB        *SecureDBConnection
	logger          *slog.Logger
}

// NewMySQL creates a new MySQL datasource
func NewMySQL(config Config) *MySQL {
	// Set default values if not provided
	if config.Port == 0 {
		config.Port = 3306
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

	// Create logger for security operations
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With(
		"component", "mysql-datasource",
		"database", config.Database,
	)

	// Initialize security manager
	securityManager := NewSQLSecurityManager(logger)

	// Register allowed tables and columns for MySQL
	securityManager.RegisterTable(userTable, []string{
		"username", "password", "email", "full_name", "is_active", "is_admin",
		"created_at", "updated_at", "last_login_at",
	})
	securityManager.RegisterTable(groupTable, []string{
		"name", "description", "is_active", "created_at", "updated_at",
	})
	securityManager.RegisterTable("user_attributes", []string{
		"username", "attr_key", "attr_value",
	})
	securityManager.RegisterTable("user_groups", []string{
		"user_id", "group_id",
	})

	return &MySQL{
		config:          config,
		connected:       false,
		userTable:       userTable,
		groupTable:      groupTable,
		securityManager: securityManager,
		logger:          logger,
	}
}

// Connect establishes a connection to the MySQL database
func (m *MySQL) Connect() error {
	if m.connected {
		return nil
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		m.config.Username,
		m.config.Password,
		m.config.Host,
		m.config.Port,
		m.config.Database)

	// Add any additional connection parameters from options
	if m.config.Options != nil {
		if params, ok := m.config.Options["connection_params"].(string); ok && params != "" {
			if !strings.Contains(dsn, "?") {
				dsn += "?"
			} else {
				dsn += "&"
			}
			dsn += params
		}
	}

	var err error
	m.db, err = sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	// Set connection pool parameters
	m.db.SetMaxOpenConns(25)
	m.db.SetMaxIdleConns(5)
	m.db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection
	if err := m.db.Ping(); err != nil {
		m.db.Close()
		return fmt.Errorf("failed to ping MySQL server: %w", err)
	}

	// Initialize secure database connection wrapper
	m.secureDB = NewSecureDBConnection(m.db, m.securityManager, m.logger)

	m.connected = true
	m.logger.Info("MySQL datasource connected with security enhancements",
		"database", m.config.Database,
		"security_enabled", true,
	)
	return nil
}

// Close closes the connection to the MySQL database
func (m *MySQL) Close() error {
	if !m.connected {
		return nil
	}

	// Close secure database connection (this will cleanup prepared statements)
	if m.secureDB != nil {
		if err := m.secureDB.Close(); err != nil {
			m.logger.Error("Failed to close secure database connection", "error", err)
		}
	}

	m.connected = false
	m.logger.Info("MySQL datasource connection closed")
	return nil
}

// IsConnected returns true if the datasource is connected
func (m *MySQL) IsConnected() bool {
	return m.connected
}

// Name returns the name of the datasource
func (m *MySQL) Name() string {
	return m.config.Name
}

// Type returns the type of the datasource
func (m *MySQL) Type() string {
	return "mysql"
}

// Authenticate verifies credentials against the MySQL database
func (m *MySQL) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !m.connected {
		return false, ErrNotConnected
	}

	// Validate inputs first
	if err := m.securityManager.ValidateUsername(username); err != nil {
		m.logger.Warn("Authentication failed: invalid username",
			"username", username,
			"error", err,
		)
		return false, fmt.Errorf("invalid username: %w", err)
	}

	if err := m.securityManager.ValidateStringInput(password, "password", 1000); err != nil {
		m.logger.Warn("Authentication failed: invalid password",
			"username", username,
			"error", err,
		)
		return false, fmt.Errorf("invalid password: %w", err)
	}

	// Log authentication attempt for security monitoring
	m.logger.Info("Authentication attempt",
		"username", username,
		"source", "mysql",
	)

	// Use secure query execution
	rows, err := m.secureDB.ExecuteSecureQuery(ctx, "SELECT", m.userTable,
		[]string{"username"},
		[]string{"username", "password", "is_active"},
		username, password, 1)
	if err != nil {
		m.logger.Error("Secure authentication query failed",
			"username", username,
			"error", err,
		)
		return false, fmt.Errorf("authentication query failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var foundUsername string
	success := false
	if rows.Next() {
		if err := rows.Scan(&foundUsername); err != nil {
			m.logger.Error("Failed to scan authentication result",
				"username", username,
				"error", err,
			)
			return false, fmt.Errorf("failed to scan authentication result: %w", err)
		}
		success = foundUsername == username
	}

	if success {
		m.logger.Info("Authentication successful",
			"username", username,
			"source", "mysql",
		)
	} else {
		m.logger.Warn("Authentication failed",
			"username", username,
			"source", "mysql",
			"reason", "invalid_credentials",
		)
	}

	return success, nil
}

// GetUser retrieves user information from the MySQL database
func (m *MySQL) GetUser(ctx context.Context, username string) (User, error) {
	if !m.connected {
		return User{}, ErrNotConnected
	}

	// Validate username first
	if err := m.securityManager.ValidateUsername(username); err != nil {
		m.logger.Warn("GetUser failed: invalid username",
			"username", username,
			"error", err,
		)
		return User{}, fmt.Errorf("invalid username: %w", err)
	}

	// Use secure query execution
	rows, err := m.secureDB.ExecuteSecureQuery(ctx, "SELECT", m.userTable,
		[]string{"username", "password", "email", "full_name", "is_active", "is_admin", "created_at", "updated_at", "last_login_at"},
		[]string{"username"},
		username)
	if err != nil {
		m.logger.Error("Secure GetUser query failed",
			"username", username,
			"error", err,
		)
		return User{}, fmt.Errorf("failed to get user: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
		m.logger.Error("Failed to scan GetUser result",
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
	`, m.groupTable, m.userTable)

	groupRows, err := m.db.QueryContext(ctx, groupQuery, username)
	if err != nil {
		return user, fmt.Errorf("failed to get user groups: %w", err)
	}
	defer func() { _ = groupRows.Close() }()

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

	// Get user attributes (assuming a separate table for key-value attributes)
	attrQuery := `
		SELECT attr_key, attr_value
		FROM user_attributes
		WHERE username = ?
	`

	attrRows, err := m.db.QueryContext(ctx, attrQuery, username)
	if err != nil {
		return user, fmt.Errorf("failed to get user attributes: %w", err)
	}
	defer func() { _ = attrRows.Close() }()

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

// ListUsers retrieves a list of users from the MySQL database
func (m *MySQL) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !m.connected {
		return nil, ErrNotConnected
	}

	// Validate filter parameters
	validatedFilter, err := m.securityManager.ValidateFilterMap(m.userTable, filter)
	if err != nil {
		m.logger.Warn("ListUsers failed: invalid filter",
			"filter", filter,
			"error", err,
		)
		return nil, fmt.Errorf("invalid filter parameters: %w", err)
	}

	// Validate pagination parameters
	limitValue, err := m.securityManager.ValidateIntegerInput(limit, "limit", 0, 10000)
	if err != nil {
		return nil, fmt.Errorf("invalid limit parameter: %w", err)
	}

	offsetValue, err := m.securityManager.ValidateIntegerInput(offset, "offset", 0, 1000000)
	if err != nil {
		return nil, fmt.Errorf("invalid offset parameter: %w", err)
	}

	// Build secure query using validated parameters
	baseColumns := []string{"username", "password", "email", "full_name", "is_active", "is_admin", "created_at", "updated_at", "last_login_at"}
	whereColumns := make([]string, 0, len(validatedFilter))
	args := make([]interface{}, 0, len(validatedFilter)+2)

	for key, value := range validatedFilter {
		whereColumns = append(whereColumns, key)
		args = append(args, value)
	}

	// Add pagination to args if specified
	if limitValue > 0 {
		args = append(args, limitValue)
		if offsetValue > 0 {
			args = append(args, offsetValue)
		}
	}

	// Build the secure query
	query, queryKey, err := m.securityManager.BuildSecureQuery("SELECT", m.userTable, baseColumns, whereColumns)
	if err != nil {
		return nil, fmt.Errorf("failed to build secure query: %w", err)
	}

	// Add pagination to query if specified
	if limitValue > 0 {
		query += " LIMIT ?"
		if offsetValue > 0 {
			query += " OFFSET ?"
		}
	}

	// Get prepared statement and execute
	stmt, err := m.securityManager.GetPreparedStatement(m.db, queryKey, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get prepared statement: %w", err)
	}

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		m.logger.Error("Secure ListUsers query failed",
			"filter", validatedFilter,
			"limit", limitValue,
			"offset", offsetValue,
			"error", err,
		)
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// CreateUser creates a new user in the MySQL database
func (m *MySQL) CreateUser(ctx context.Context, user User) error {
	if !m.connected {
		return ErrNotConnected
	}

	// Validate all user inputs
	if err := m.securityManager.ValidateUsername(user.Username); err != nil {
		m.logger.Warn("CreateUser failed: invalid username",
			"username", user.Username,
			"error", err,
		)
		return fmt.Errorf("invalid username: %w", err)
	}

	if err := m.securityManager.ValidateStringInput(user.Password, "password", 1000); err != nil {
		m.logger.Warn("CreateUser failed: invalid password",
			"username", user.Username,
			"error", err,
		)
		return fmt.Errorf("invalid password: %w", err)
	}

	if user.Email != "" {
		if err := m.securityManager.ValidateEmail(user.Email); err != nil {
			m.logger.Warn("CreateUser failed: invalid email",
				"username", user.Username,
				"email", user.Email,
				"error", err,
			)
			return fmt.Errorf("invalid email: %w", err)
		}
	}

	if err := m.securityManager.ValidateStringInput(user.FullName, "full_name", 255); err != nil {
		m.logger.Warn("CreateUser failed: invalid full name",
			"username", user.Username,
			"error", err,
		)
		return fmt.Errorf("invalid full name: %w", err)
	}

	// Start a transaction
	tx, err := m.db.BeginTx(ctx, nil)
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
	`, m.userTable)

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
		// This is a simplified example - in a real implementation,
		// you would need to handle the user_groups join table properly
		for _, group := range user.Groups {
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

	// Insert user attributes (simplified)
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

// UpdateUser updates an existing user in the MySQL database
func (m *MySQL) UpdateUser(ctx context.Context, user User) error {
	if !m.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := m.db.BeginTx(ctx, nil)
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
	`, m.userTable)

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

	// Update user groups (simplified - in a real implementation, you would handle this more efficiently)
	// First, delete existing group associations
	_, err = tx.ExecContext(ctx, `
		DELETE ug FROM user_groups ug
		JOIN users u ON ug.user_id = u.id
		WHERE u.username = ?
	`, user.Username)

	if err != nil {
		return fmt.Errorf("failed to delete user groups: %w", err)
	}

	// Then, add new group associations
	if len(user.Groups) > 0 {
		for _, group := range user.Groups {
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

	// Update user attributes (simplified)
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

// DeleteUser deletes a user from the MySQL database
func (m *MySQL) DeleteUser(ctx context.Context, username string) error {
	if !m.connected {
		return ErrNotConnected
	}

	// Validate username first
	if err := m.securityManager.ValidateUsername(username); err != nil {
		m.logger.Warn("DeleteUser failed: invalid username",
			"username", username,
			"error", err,
		)
		return fmt.Errorf("invalid username: %w", err)
	}

	// Start a transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete user attributes
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_attributes
		WHERE username = ?
	`, username)

	if err != nil {
		return fmt.Errorf("failed to delete user attributes: %w", err)
	}

	// Delete user group associations
	_, err = tx.ExecContext(ctx, `
		DELETE ug FROM user_groups ug
		JOIN users u ON ug.user_id = u.id
		WHERE u.username = ?
	`, username)

	if err != nil {
		return fmt.Errorf("failed to delete user groups: %w", err)
	}

	// Delete the user using secure execution
	result, err := m.secureDB.ExecuteSecureExec(ctx, "DELETE", m.userTable, []string{}, []string{"username"}, username)

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

// Query executes a custom query against the MySQL database
func (m *MySQL) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	if !m.connected {
		return nil, ErrNotConnected
	}

	// Determine if this is a SELECT query or an action query
	query = strings.TrimSpace(query)
	isSelect := strings.HasPrefix(strings.ToUpper(query), "SELECT")

	if isSelect {
		// For SELECT queries, return rows
		rows, err := m.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %w", err)
		}
		defer func() { _ = rows.Close() }()

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
		result, err := m.db.ExecContext(ctx, query, args...)
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
