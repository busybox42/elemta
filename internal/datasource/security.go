package datasource

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
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
}

// NewSQLSecurityManager creates a new SQL security manager
func NewSQLSecurityManager(logger *slog.Logger) *SQLSecurityManager {
	return &SQLSecurityManager{
		preparedStatements: make(map[string]*sql.Stmt),
		logger:             logger,
		allowedTables:      make(map[string]bool),
		allowedColumns:     make(map[string]map[string]bool),
		queryWhitelist:     make(map[string]bool),
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
	
	sm.logger.Debug("Created prepared statement",
		"query_key", queryKey,
		"total_statements", len(sm.preparedStatements),
	)
	
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
	rand.Read(randomBytes)
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
	
	sdb.logger.Debug("Secure query executed successfully",
		"operation", operation,
		"table", tableName,
		"args_count", len(args),
	)
	
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
	
	sdb.logger.Debug("Secure exec executed successfully",
		"operation", operation,
		"table", tableName,
		"args_count", len(args),
	)
	
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
