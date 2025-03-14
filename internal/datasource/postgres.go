package datasource

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Postgres implements the DataSource interface for PostgreSQL databases
type Postgres struct {
	config     Config
	db         *sql.DB
	connected  bool
	userTable  string
	groupTable string
}

// NewPostgres creates a new PostgreSQL datasource
func NewPostgres(config Config) *Postgres {
	// Set default values if not provided
	if config.Port == 0 {
		config.Port = 5432
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

	return &Postgres{
		config:     config,
		connected:  false,
		userTable:  userTable,
		groupTable: groupTable,
	}
}

// Connect establishes a connection to the PostgreSQL database
func (p *Postgres) Connect() error {
	if p.connected {
		return nil
	}

	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		p.config.Host,
		p.config.Port,
		p.config.Username,
		p.config.Password,
		p.config.Database)

	// Add any additional connection parameters from options
	if p.config.Options != nil {
		if params, ok := p.config.Options["connection_params"].(string); ok && params != "" {
			connStr += " " + params
		}
	}

	var err error
	p.db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open PostgreSQL connection: %w", err)
	}

	// Set connection pool parameters
	p.db.SetMaxOpenConns(25)
	p.db.SetMaxIdleConns(5)
	p.db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection
	if err := p.db.Ping(); err != nil {
		p.db.Close()
		return fmt.Errorf("failed to ping PostgreSQL server: %w", err)
	}

	p.connected = true
	return nil
}

// Close closes the connection to the PostgreSQL database
func (p *Postgres) Close() error {
	if !p.connected {
		return nil
	}

	err := p.db.Close()
	if err != nil {
		return fmt.Errorf("failed to close PostgreSQL connection: %w", err)
	}

	p.connected = false
	return nil
}

// IsConnected returns true if the datasource is connected
func (p *Postgres) IsConnected() bool {
	return p.connected
}

// Name returns the name of the datasource
func (p *Postgres) Name() string {
	return p.config.Name
}

// Type returns the type of the datasource
func (p *Postgres) Type() string {
	return "postgres"
}

// Authenticate verifies credentials against the PostgreSQL database
func (p *Postgres) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !p.connected {
		return false, ErrNotConnected
	}

	// In a real implementation, you would use a secure password hashing algorithm
	// This is a simplified example that assumes passwords are stored hashed
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE username = $1 AND password = $2 AND is_active = true", p.userTable)

	var count int
	err := p.db.QueryRowContext(ctx, query, username, password).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("authentication query failed: %w", err)
	}

	return count > 0, nil
}

// GetUser retrieves user information from the PostgreSQL database
func (p *Postgres) GetUser(ctx context.Context, username string) (User, error) {
	if !p.connected {
		return User{}, ErrNotConnected
	}

	query := fmt.Sprintf(`
		SELECT username, password, email, full_name, is_active, is_admin, 
		       created_at, updated_at, last_login_at
		FROM %s
		WHERE username = $1
	`, p.userTable)

	var user User
	var createdAt, updatedAt, lastLoginAt sql.NullInt64

	err := p.db.QueryRowContext(ctx, query, username).Scan(
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
		WHERE u.username = $1
	`, p.groupTable, p.userTable)

	rows, err := p.db.QueryContext(ctx, groupQuery, username)
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
		WHERE username = $1
	`

	attrRows, err := p.db.QueryContext(ctx, attrQuery, username)
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

// ListUsers retrieves a list of users from the PostgreSQL database
func (p *Postgres) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !p.connected {
		return nil, ErrNotConnected
	}

	// Build the query
	query := fmt.Sprintf(`
		SELECT username, password, email, full_name, is_active, is_admin, 
		       created_at, updated_at, last_login_at
		FROM %s
		WHERE 1=1
	`, p.userTable)

	// Add filters
	var args []interface{}
	paramCount := 1

	if filter != nil {
		for key, value := range filter {
			// Sanitize the key to prevent SQL injection
			key = strings.ReplaceAll(key, "\"", "")
			key = strings.ReplaceAll(key, "'", "")
			key = strings.ReplaceAll(key, ";", "")

			query += fmt.Sprintf(" AND %s = $%d", key, paramCount)
			args = append(args, value)
			paramCount++
		}
	}

	// Add pagination
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", paramCount)
		args = append(args, limit)
		paramCount++

		if offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", paramCount)
			args = append(args, offset)
		}
	}

	// Execute the query
	rows, err := p.db.QueryContext(ctx, query, args...)
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

// CreateUser creates a new user in the PostgreSQL database
func (p *Postgres) CreateUser(ctx context.Context, user User) error {
	if !p.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert the user
	query := fmt.Sprintf(`
		INSERT INTO %s (
			username, password, email, full_name, is_active, is_admin,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, p.userTable)

	now := time.Now().Unix()

	var userID int64
	err = tx.QueryRowContext(ctx, query,
		user.Username,
		user.Password,
		user.Email,
		user.FullName,
		user.IsActive,
		user.IsAdmin,
		now,
		now,
	).Scan(&userID)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return ErrAlreadyExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Insert user groups
	if len(user.Groups) > 0 {
		for _, group := range user.Groups {
			// First, ensure the group exists
			var groupID int64
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				INSERT INTO %s (name, created_at)
				VALUES ($1, $2)
				ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
				RETURNING id
			`, p.groupTable), group, now).Scan(&groupID)

			if err != nil {
				return fmt.Errorf("failed to create or get group: %w", err)
			}

			// Then, add the user to the group
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_groups (user_id, group_id)
				VALUES ($1, $2)
				ON CONFLICT (user_id, group_id) DO NOTHING
			`, userID, groupID)

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
				VALUES ($1, $2, $3)
				ON CONFLICT (username, attr_key) DO UPDATE SET attr_value = EXCLUDED.attr_value
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

// UpdateUser updates an existing user in the PostgreSQL database
func (p *Postgres) UpdateUser(ctx context.Context, user User) error {
	if !p.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update the user
	query := fmt.Sprintf(`
		UPDATE %s SET
			password = $1,
			email = $2,
			full_name = $3,
			is_active = $4,
			is_admin = $5,
			updated_at = $6
		WHERE username = $7
		RETURNING id
	`, p.userTable)

	now := time.Now().Unix()

	var userID int64
	err = tx.QueryRowContext(ctx, query,
		user.Password,
		user.Email,
		user.FullName,
		user.IsActive,
		user.IsAdmin,
		now,
		user.Username,
	).Scan(&userID)

	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Update user groups
	// First, delete existing group associations
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_groups
		WHERE user_id = $1
	`, userID)

	if err != nil {
		return fmt.Errorf("failed to delete user groups: %w", err)
	}

	// Then, add new group associations
	if len(user.Groups) > 0 {
		for _, group := range user.Groups {
			// First, ensure the group exists
			var groupID int64
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				INSERT INTO %s (name, created_at)
				VALUES ($1, $2)
				ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
				RETURNING id
			`, p.groupTable), group, now).Scan(&groupID)

			if err != nil {
				return fmt.Errorf("failed to create or get group: %w", err)
			}

			// Then, add the user to the group
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_groups (user_id, group_id)
				VALUES ($1, $2)
				ON CONFLICT (user_id, group_id) DO NOTHING
			`, userID, groupID)

			if err != nil {
				return fmt.Errorf("failed to add user to group: %w", err)
			}
		}
	}

	// Update user attributes
	// First, delete existing attributes
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_attributes
		WHERE username = $1
	`, user.Username)

	if err != nil {
		return fmt.Errorf("failed to delete user attributes: %w", err)
	}

	// Then, add new attributes
	if len(user.Attributes) > 0 {
		for key, value := range user.Attributes {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_attributes (username, attr_key, attr_value)
				VALUES ($1, $2, $3)
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

// DeleteUser deletes a user from the PostgreSQL database
func (p *Postgres) DeleteUser(ctx context.Context, username string) error {
	if !p.connected {
		return ErrNotConnected
	}

	// Start a transaction
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get the user ID first
	var userID int64
	err = tx.QueryRowContext(ctx, fmt.Sprintf("SELECT id FROM %s WHERE username = $1", p.userTable), username).Scan(&userID)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	// Delete user attributes
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_attributes
		WHERE username = $1
	`, username)

	if err != nil {
		return fmt.Errorf("failed to delete user attributes: %w", err)
	}

	// Delete user group associations
	_, err = tx.ExecContext(ctx, `
		DELETE FROM user_groups
		WHERE user_id = $1
	`, userID)

	if err != nil {
		return fmt.Errorf("failed to delete user groups: %w", err)
	}

	// Delete the user
	query := fmt.Sprintf("DELETE FROM %s WHERE username = $1", p.userTable)
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

// Query executes a custom query against the PostgreSQL database
func (p *Postgres) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	if !p.connected {
		return nil, ErrNotConnected
	}

	// Determine if this is a SELECT query or an action query
	query = strings.TrimSpace(query)
	isSelect := strings.HasPrefix(strings.ToUpper(query), "SELECT")

	if isSelect {
		// For SELECT queries, return rows
		rows, err := p.db.QueryContext(ctx, query, args...)
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
		result, err := p.db.ExecContext(ctx, query, args...)
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
