package datasource

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// MySQL implements the DataSource interface for MySQL databases
type MySQL struct {
	config     Config
	db         *sql.DB
	connected  bool
	userTable  string
	groupTable string
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

	return &MySQL{
		config:     config,
		connected:  false,
		userTable:  userTable,
		groupTable: groupTable,
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

	m.connected = true
	return nil
}

// Close closes the connection to the MySQL database
func (m *MySQL) Close() error {
	if !m.connected {
		return nil
	}

	err := m.db.Close()
	if err != nil {
		return fmt.Errorf("failed to close MySQL connection: %w", err)
	}

	m.connected = false
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

	// In a real implementation, you would use a secure password hashing algorithm
	// This is a simplified example that assumes passwords are stored hashed
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE username = ? AND password = ? AND is_active = 1", m.userTable)

	var count int
	err := m.db.QueryRowContext(ctx, query, username, password).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("authentication query failed: %w", err)
	}

	return count > 0, nil
}

// GetUser retrieves user information from the MySQL database
func (m *MySQL) GetUser(ctx context.Context, username string) (User, error) {
	if !m.connected {
		return User{}, ErrNotConnected
	}

	query := fmt.Sprintf(`
		SELECT username, password, email, full_name, is_active, is_admin, 
		       created_at, updated_at, last_login_at
		FROM %s
		WHERE username = ?
	`, m.userTable)

	var user User
	var createdAt, updatedAt, lastLoginAt sql.NullInt64

	err := m.db.QueryRowContext(ctx, query, username).Scan(
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

	if err == sql.ErrNoRows {
		return User{}, ErrNotFound
	} else if err != nil {
		return User{}, fmt.Errorf("failed to get user: %w", err)
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

	rows, err := m.db.QueryContext(ctx, groupQuery, username)
	if err != nil {
		return user, fmt.Errorf("failed to get user groups: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var groupName string
		if err := rows.Scan(&groupName); err != nil {
			return user, fmt.Errorf("failed to scan group name: %w", err)
		}
		user.Groups = append(user.Groups, groupName)
	}

	if err := rows.Err(); err != nil {
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

// ListUsers retrieves a list of users from the MySQL database
func (m *MySQL) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !m.connected {
		return nil, ErrNotConnected
	}

	// Build the query
	query := fmt.Sprintf(`
		SELECT username, password, email, full_name, is_active, is_admin, 
		       created_at, updated_at, last_login_at
		FROM %s
		WHERE 1=1
	`, m.userTable)

	// Add filters
	var args []interface{}
	if filter != nil {
		for key, value := range filter {
			// Sanitize the key to prevent SQL injection
			key = strings.ReplaceAll(key, "`", "")
			key = strings.ReplaceAll(key, "'", "")
			key = strings.ReplaceAll(key, "\"", "")

			query += fmt.Sprintf(" AND %s = ?", key)
			args = append(args, value)
		}
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
	rows, err := m.db.QueryContext(ctx, query, args...)
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

// CreateUser creates a new user in the MySQL database
func (m *MySQL) CreateUser(ctx context.Context, user User) error {
	if !m.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

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
	defer tx.Rollback()

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

	// Start a transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

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

	// Delete the user
	query := fmt.Sprintf("DELETE FROM %s WHERE username = ?", m.userTable)
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
