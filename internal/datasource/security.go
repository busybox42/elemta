package datasource

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SQLSecurityManager provides comprehensive SQL injection prevention
type SQLSecurityManager struct {
	preparedStatements map[string]*sql.Stmt
	mutex              sync.RWMutex
	logger             *slog.Logger
	allowedTables      map[string]bool
	allowedColumns     map[string]map[string]bool
	queryWhitelist     map[string]bool
	debugMode          bool
}

// NewSQLSecurityManager creates a new SQL security manager
func NewSQLSecurityManager(logger *slog.Logger) *SQLSecurityManager {
	// Check if debug mode is enabled via environment variable
	debugMode := os.Getenv("ELEMTA_SQL_DEBUG") == "true" || os.Getenv("DEBUG") == "true"

	return &SQLSecurityManager{
		preparedStatements: make(map[string]*sql.Stmt),
		logger:             logger,
		allowedTables:      make(map[string]bool),
		allowedColumns:     make(map[string]map[string]bool),
		queryWhitelist:     make(map[string]bool),
		debugMode:          debugMode,
	}
}

// RegisterTable registers a table as allowed for queries
func (sm *SQLSecurityManager) RegisterTable(tableName string, columns []string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.allowedTables[tableName] = true

	if sm.allowedColumns[tableName] == nil {
		sm.allowedColumns[tableName] = make(map[string]bool)
	}

	for _, column := range columns {
		sm.allowedColumns[tableName][column] = true
	}

	sm.logger.Info("Registered secure table",
		"table", tableName,
		"columns", len(columns),
	)
}

// ValidateTableName validates that a table name is allowed and safe
func (sm *SQLSecurityManager) ValidateTableName(tableName string) error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	if !sm.allowedTables[tableName] {
		sm.logger.Warn("SQL injection attempt: unauthorized table access",
			"table", tableName,
			"threat", "table_name_injection",
		)
		return fmt.Errorf("table '%s' is not authorized for access", tableName)
	}

	// Additional validation: table name must be alphanumeric with underscores only
	if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(tableName) {
		sm.logger.Warn("SQL injection attempt: invalid table name format",
			"table", tableName,
			"threat", "table_name_format_injection",
		)
		return fmt.Errorf("table name '%s' contains invalid characters", tableName)
	}

	return nil
}

// ValidateColumnName validates that a column name is allowed and safe
func (sm *SQLSecurityManager) ValidateColumnName(tableName, columnName string) error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	tableColumns, exists := sm.allowedColumns[tableName]
	if !exists {
		return fmt.Errorf("table '%s' is not registered", tableName)
	}

	if !tableColumns[columnName] {
		sm.logger.Warn("SQL injection attempt: unauthorized column access",
			"table", tableName,
			"column", columnName,
			"threat", "column_name_injection",
		)
		return fmt.Errorf("column '%s' is not authorized for table '%s'", columnName, tableName)
	}

	// Additional validation: column name must be alphanumeric with underscores only
	if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(columnName) {
		sm.logger.Warn("SQL injection attempt: invalid column name format",
			"table", tableName,
			"column", columnName,
			"threat", "column_name_format_injection",
		)
		return fmt.Errorf("column name '%s' contains invalid characters", columnName)
	}

	return nil
}

// SanitizeInput performs comprehensive input sanitization
func (sm *SQLSecurityManager) SanitizeInput(input string) (string, error) {
	if input == "" {
		return "", nil
	}

	// Check for SQL injection patterns
	dangerousPatterns := []struct {
		pattern string
		threat  string
	}{
		{`(?i)(\s|^)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set|drop\s+table|alter\s+table|create\s+table)(\s|$)`, "sql_statement_injection"},
		{`(?i)(\s|^)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'.*'|"\s*or\s*".*")(\s|$)`, "boolean_injection"},
		{`(?i)(\s|^)(exec\s*\(|execute\s*\(|sp_|xp_|@@|char\s*\(|cast\s*\(|convert\s*\()`, "function_injection"},
		{`(?i)(waitfor\s+delay|benchmark\s*\(|sleep\s*\(|pg_sleep\s*\()`, "time_based_injection"},
		{`(?i)(information_schema|sys\.tables|sysobjects|mysql\.user)`, "schema_injection"},
		{`[;\x00\x1a\x0d\x0a]`, "control_character_injection"},
		{`--|\*\/|\/\*`, "comment_injection"},
		{`\$\$|\$[a-zA-Z0-9_]+\$`, "dollar_quote_injection"},
	}

	for _, pattern := range dangerousPatterns {
		matched, err := regexp.MatchString(pattern.pattern, input)
		if err != nil {
			sm.logger.Error("Error checking SQL injection pattern",
				"pattern", pattern.pattern,
				"error", err,
			)
			continue
		}

		if matched {
			sm.logger.Warn("SQL injection attempt detected",
				"input", input[:min(100, len(input))], // Limit log size
				"threat", pattern.threat,
				"pattern_matched", pattern.pattern,
			)
			return "", fmt.Errorf("input contains potentially malicious SQL patterns")
		}
	}

	// Length validation
	if len(input) > 10000 { // Reasonable limit for most inputs
		sm.logger.Warn("SQL injection attempt: input too long",
			"length", len(input),
			"threat", "buffer_overflow_attempt",
		)
		return "", fmt.Errorf("input exceeds maximum allowed length")
	}

	return input, nil
}

// GetPreparedStatement retrieves or creates a prepared statement
func (sm *SQLSecurityManager) GetPreparedStatement(db *sql.DB, queryKey, query string) (*sql.Stmt, error) {
	sm.mutex.RLock()
	stmt, exists := sm.preparedStatements[queryKey]
	sm.mutex.RUnlock()

	if exists && stmt != nil {
		// Verify statement is still valid
		if err := stmt.Close(); err == nil {
			// Statement was closed, need to recreate
			sm.mutex.Lock()
			delete(sm.preparedStatements, queryKey)
			sm.mutex.Unlock()
		} else {
			// Statement is still valid
			return stmt, nil
		}
	}

	// Create new prepared statement
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Double-check pattern to avoid race condition
	if stmt, exists := sm.preparedStatements[queryKey]; exists && stmt != nil {
		return stmt, nil
	}

	stmt, err := db.Prepare(query)
	if err != nil {
		sm.logger.Error("Failed to prepare SQL statement",
			"query_key", queryKey,
			"error", err,
		)
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}

	sm.preparedStatements[queryKey] = stmt

	// Log query in debug mode
	if sm.debugMode {
		sm.logger.Info("SQL Query Prepared (DEBUG MODE)",
			"query_key", queryKey,
			"query", query,
			"total_statements", len(sm.preparedStatements),
		)
	} else {
		sm.logger.Debug("Created prepared statement",
			"query_key", queryKey,
			"total_statements", len(sm.preparedStatements),
		)
	}

	return stmt, nil
}

// CleanupPreparedStatements closes and removes all prepared statements
func (sm *SQLSecurityManager) CleanupPreparedStatements() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for key, stmt := range sm.preparedStatements {
		if stmt != nil {
			if err := stmt.Close(); err != nil {
				sm.logger.Error("Error closing prepared statement",
					"key", key,
					"error", err,
				)
			}
		}
	}

	sm.preparedStatements = make(map[string]*sql.Stmt)

	sm.logger.Info("Cleaned up all prepared statements")
}

// BuildSecureQuery builds a parameterized query with validation
func (sm *SQLSecurityManager) BuildSecureQuery(operation string, tableName string, columns []string, whereColumns []string) (string, string, error) {
	// Validate table name
	if err := sm.ValidateTableName(tableName); err != nil {
		return "", "", err
	}

	// Validate all column names
	for _, column := range columns {
		if err := sm.ValidateColumnName(tableName, column); err != nil {
			return "", "", err
		}
	}

	for _, column := range whereColumns {
		if err := sm.ValidateColumnName(tableName, column); err != nil {
			return "", "", err
		}
	}

	// Generate query key for caching
	queryKey := generateQueryKey(operation, tableName, columns, whereColumns)

	var query string

	switch strings.ToUpper(operation) {
	case "SELECT":
		columnList := strings.Join(columns, ", ")
		query = fmt.Sprintf("SELECT %s FROM %s", columnList, tableName)

		if len(whereColumns) > 0 {
			whereClause := make([]string, len(whereColumns))
			for i, col := range whereColumns {
				whereClause[i] = fmt.Sprintf("%s = ?", col)
			}
			query += " WHERE " + strings.Join(whereClause, " AND ")
		}

	case "INSERT":
		columnList := strings.Join(columns, ", ")
		placeholders := strings.Repeat("?,", len(columns))
		placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma
		query = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tableName, columnList, placeholders)

	case "UPDATE":
		setClause := make([]string, len(columns))
		for i, col := range columns {
			setClause[i] = fmt.Sprintf("%s = ?", col)
		}
		query = fmt.Sprintf("UPDATE %s SET %s", tableName, strings.Join(setClause, ", "))

		if len(whereColumns) > 0 {
			whereClause := make([]string, len(whereColumns))
			for i, col := range whereColumns {
				whereClause[i] = fmt.Sprintf("%s = ?", col)
			}
			query += " WHERE " + strings.Join(whereClause, " AND ")
		}

	case "DELETE":
		query = fmt.Sprintf("DELETE FROM %s", tableName)

		if len(whereColumns) > 0 {
			whereClause := make([]string, len(whereColumns))
			for i, col := range whereColumns {
				whereClause[i] = fmt.Sprintf("%s = ?", col)
			}
			query += " WHERE " + strings.Join(whereClause, " AND ")
		}

	default:
		return "", "", fmt.Errorf("unsupported operation: %s", operation)
	}

	return query, queryKey, nil
}

// generateQueryKey generates a unique key for query caching
func generateQueryKey(operation, tableName string, columns, whereColumns []string) string {
	parts := []string{
		operation,
		tableName,
		strings.Join(columns, ","),
		strings.Join(whereColumns, ","),
	}

	// Add random component to prevent key collisions
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based randomness if crypto/rand fails
		randomBytes = []byte(fmt.Sprintf("%d", time.Now().UnixNano()%10000))
	}
	randomHex := hex.EncodeToString(randomBytes)

	return strings.Join(parts, "|") + "|" + randomHex
}

// SecureDBConnection provides additional security for database connections
type SecureDBConnection struct {
	db                *sql.DB
	securityManager   *SQLSecurityManager
	connectionTimeout time.Duration
	queryTimeout      time.Duration
	logger            *slog.Logger
}

// NewSecureDBConnection creates a new secure database connection wrapper
func NewSecureDBConnection(db *sql.DB, securityManager *SQLSecurityManager, logger *slog.Logger) *SecureDBConnection {
	return &SecureDBConnection{
		db:                db,
		securityManager:   securityManager,
		connectionTimeout: 30 * time.Second,
		queryTimeout:      10 * time.Second,
		logger:            logger,
	}
}

// ExecuteSecureQuery executes a query with comprehensive security checks
func (sdb *SecureDBConnection) ExecuteSecureQuery(ctx context.Context, operation, tableName string, columns, whereColumns []string, args ...interface{}) (*sql.Rows, error) {
	// Build secure query
	query, queryKey, err := sdb.securityManager.BuildSecureQuery(operation, tableName, columns, whereColumns)
	if err != nil {
		return nil, err
	}

	// Sanitize all input arguments
	sanitizedArgs := make([]interface{}, len(args))
	for i, arg := range args {
		if strArg, ok := arg.(string); ok {
			sanitized, err := sdb.securityManager.SanitizeInput(strArg)
			if err != nil {
				return nil, fmt.Errorf("input sanitization failed for argument %d: %w", i, err)
			}
			sanitizedArgs[i] = sanitized
		} else {
			sanitizedArgs[i] = arg
		}
	}

	// Get prepared statement
	stmt, err := sdb.securityManager.GetPreparedStatement(sdb.db, queryKey, query)
	if err != nil {
		return nil, err
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, sdb.queryTimeout)
	defer cancel()

	rows, err := stmt.QueryContext(ctx, sanitizedArgs...)
	if err != nil {
		sdb.logger.Error("Secure query execution failed",
			"operation", operation,
			"table", tableName,
			"error", err,
		)
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	// Log query execution in debug mode
	if sdb.securityManager.debugMode {
		sdb.logger.Info("SQL Query Executed (DEBUG MODE)",
			"operation", operation,
			"table", tableName,
			"query", query,
			"args_count", len(args),
			"sanitized_args", sanitizedArgs,
		)
	} else {
		sdb.logger.Debug("Secure query executed successfully",
			"operation", operation,
			"table", tableName,
			"args_count", len(args),
		)
	}

	return rows, nil
}

// ExecuteSecureExec executes a non-query statement with security checks
func (sdb *SecureDBConnection) ExecuteSecureExec(ctx context.Context, operation, tableName string, columns, whereColumns []string, args ...interface{}) (sql.Result, error) {
	// Build secure query
	query, queryKey, err := sdb.securityManager.BuildSecureQuery(operation, tableName, columns, whereColumns)
	if err != nil {
		return nil, err
	}

	// Sanitize all input arguments
	sanitizedArgs := make([]interface{}, len(args))
	for i, arg := range args {
		if strArg, ok := arg.(string); ok {
			sanitized, err := sdb.securityManager.SanitizeInput(strArg)
			if err != nil {
				return nil, fmt.Errorf("input sanitization failed for argument %d: %w", i, err)
			}
			sanitizedArgs[i] = sanitized
		} else {
			sanitizedArgs[i] = arg
		}
	}

	// Get prepared statement
	stmt, err := sdb.securityManager.GetPreparedStatement(sdb.db, queryKey, query)
	if err != nil {
		return nil, err
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, sdb.queryTimeout)
	defer cancel()

	result, err := stmt.ExecContext(ctx, sanitizedArgs...)
	if err != nil {
		sdb.logger.Error("Secure exec execution failed",
			"operation", operation,
			"table", tableName,
			"error", err,
		)
		return nil, fmt.Errorf("exec execution failed: %w", err)
	}

	// Log exec execution in debug mode
	if sdb.securityManager.debugMode {
		sdb.logger.Info("SQL Exec Executed (DEBUG MODE)",
			"operation", operation,
			"table", tableName,
			"query", query,
			"args_count", len(args),
			"sanitized_args", sanitizedArgs,
		)
	} else {
		sdb.logger.Debug("Secure exec executed successfully",
			"operation", operation,
			"table", tableName,
			"args_count", len(args),
		)
	}

	return result, nil
}

// Close closes the secure database connection and cleans up resources
func (sdb *SecureDBConnection) Close() error {
	sdb.securityManager.CleanupPreparedStatements()

	if sdb.db != nil {
		return sdb.db.Close()
	}

	return nil
}

// ValidateUsername validates username input with strict type checking
func (sm *SQLSecurityManager) ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	// Length validation
	if len(username) > 255 {
		sm.logger.Warn("SQL injection attempt: username too long",
			"length", len(username),
			"threat", "buffer_overflow_attempt",
		)
		return fmt.Errorf("username exceeds maximum allowed length")
	}

	// Character validation - alphanumeric, underscore, hyphen, dot allowed
	if !regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`).MatchString(username) {
		sm.logger.Warn("SQL injection attempt: invalid username format",
			"username", username[:min(50, len(username))],
			"threat", "username_format_injection",
		)
		return fmt.Errorf("username contains invalid characters")
	}

	_, err := sm.SanitizeInput(username)
	return err
}

// ValidateEmail validates email input with strict type checking
func (sm *SQLSecurityManager) ValidateEmail(email string) error {
	if email == "" {
		return nil // Email can be empty
	}

	// Length validation
	if len(email) > 320 { // RFC 5321 limit
		sm.logger.Warn("SQL injection attempt: email too long",
			"length", len(email),
			"threat", "buffer_overflow_attempt",
		)
		return fmt.Errorf("email exceeds maximum allowed length")
	}

	// Basic email format validation
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	if !regexp.MustCompile(emailRegex).MatchString(email) {
		sm.logger.Warn("SQL injection attempt: invalid email format",
			"email", email[:min(50, len(email))],
			"threat", "email_format_injection",
		)
		return fmt.Errorf("email format is invalid")
	}

	_, err := sm.SanitizeInput(email)
	return err
}

// ValidateStringInput validates general string input with type checking
func (sm *SQLSecurityManager) ValidateStringInput(input string, fieldName string, maxLength int) error {
	if input == "" {
		return nil // Allow empty strings
	}

	// Length validation
	if len(input) > maxLength {
		sm.logger.Warn("SQL injection attempt: input too long",
			"field", fieldName,
			"length", len(input),
			"max_length", maxLength,
			"threat", "buffer_overflow_attempt",
		)
		return fmt.Errorf("%s exceeds maximum allowed length of %d characters", fieldName, maxLength)
	}

	_, err := sm.SanitizeInput(input)
	return err
}

// ValidateIntegerInput validates integer input with range checking
func (sm *SQLSecurityManager) ValidateIntegerInput(input interface{}, fieldName string, min, max int64) (int64, error) {
	var value int64

	switch v := input.(type) {
	case int:
		value = int64(v)
	case int32:
		value = int64(v)
	case int64:
		value = v
	case bool:
		if v {
			value = 1
		} else {
			value = 0
		}
	default:
		sm.logger.Warn("SQL injection attempt: invalid integer type",
			"field", fieldName,
			"type", fmt.Sprintf("%T", input),
			"threat", "type_confusion_injection",
		)
		return 0, fmt.Errorf("%s must be an integer value", fieldName)
	}

	// Range validation
	if value < min || value > max {
		sm.logger.Warn("SQL injection attempt: integer out of range",
			"field", fieldName,
			"value", value,
			"min", min,
			"max", max,
			"threat", "range_injection",
		)
		return 0, fmt.Errorf("%s must be between %d and %d", fieldName, min, max)
	}

	return value, nil
}

// ValidateFilterMap validates filter parameters for ListUsers operations
func (sm *SQLSecurityManager) ValidateFilterMap(tableName string, filter map[string]interface{}) (map[string]interface{}, error) {
	if filter == nil {
		return nil, nil
	}

	validatedFilter := make(map[string]interface{})

	for key, value := range filter {
		// Validate column name
		if err := sm.ValidateColumnName(tableName, key); err != nil {
			return nil, err
		}

		// Validate value based on type
		switch v := value.(type) {
		case string:
			if err := sm.ValidateStringInput(v, key, 1000); err != nil {
				return nil, err
			}
			validatedFilter[key] = v
		case int, int32, int64, bool:
			validatedValue, err := sm.ValidateIntegerInput(v, key, -2147483648, 2147483647)
			if err != nil {
				return nil, err
			}
			validatedFilter[key] = validatedValue
		default:
			sm.logger.Warn("SQL injection attempt: unsupported filter value type",
				"field", key,
				"type", fmt.Sprintf("%T", value),
				"threat", "type_confusion_injection",
			)
			return nil, fmt.Errorf("unsupported value type for filter field %s", key)
		}
	}

	return validatedFilter, nil
}

// LogSecureOperation logs database operations for audit purposes
func (sm *SQLSecurityManager) LogSecureOperation(operation, tableName string, username string, success bool, err error) {
	if success {
		sm.logger.Info("Secure database operation completed",
			"operation", operation,
			"table", tableName,
			"username", username,
			"status", "success",
		)
	} else {
		sm.logger.Error("Secure database operation failed",
			"operation", operation,
			"table", tableName,
			"username", username,
			"status", "failed",
			"error", err,
		)
	}
}

// HandleSecureError provides consistent error handling with security logging
func (sm *SQLSecurityManager) HandleSecureError(operation, tableName, username string, internalError error, userMessage string) error {
	// Log detailed error internally for debugging
	sm.logger.Error("Database operation error (internal details)",
		"operation", operation,
		"table", tableName,
		"username", username,
		"internal_error", internalError.Error(),
	)

	// Log security event for monitoring
	sm.LogSecureOperation(operation, tableName, username, false, internalError)

	// Return generic error to user to prevent information disclosure
	if userMessage == "" {
		return fmt.Errorf("database operation failed")
	}
	return fmt.Errorf("%s", userMessage)
}

// EnableDebugMode enables or disables debug mode for SQL query logging
func (sm *SQLSecurityManager) EnableDebugMode(enabled bool) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.debugMode = enabled
	sm.logger.Info("SQL debug mode changed",
		"debug_enabled", enabled,
	)
}

// IsDebugMode returns whether debug mode is currently enabled
func (sm *SQLSecurityManager) IsDebugMode() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.debugMode
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
