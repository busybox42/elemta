# Datasource System

Elemta supports multiple database backends for storing configuration, rules, and other data. This document explains how to configure and use the different datasource options.

## Supported Datasources

Elemta currently supports the following datasources:

- **SQLite**: A file-based database, ideal for development and small deployments
- **MySQL**: A popular open-source relational database
- **PostgreSQL**: A powerful, open-source object-relational database system

## Configuration

The datasource is configured in your application code:

```go
import "github.com/yourusername/elemta/internal/datasource"

// Create a SQLite datasource
sqliteDS, err := datasource.NewSQLiteDataSource("elemta.db")
if err != nil {
    log.Fatalf("Failed to create SQLite datasource: %v", err)
}

// Create a MySQL datasource
mysqlDS, err := datasource.NewMySQLDataSource("user:password@tcp(localhost:3306)/elemta?parseTime=true")
if err != nil {
    log.Fatalf("Failed to create MySQL datasource: %v", err)
}

// Create a PostgreSQL datasource
postgresDS, err := datasource.NewPostgreSQLDataSource("postgres://user:password@localhost:5432/elemta?sslmode=disable")
if err != nil {
    log.Fatalf("Failed to create PostgreSQL datasource: %v", err)
}
```

## Connection Strings

### SQLite

The SQLite connection string is simply the path to the database file:

```
elemta.db
```

If the file doesn't exist, it will be created automatically.

### MySQL

The MySQL connection string follows this format:

```
[username[:password]@][protocol[(address)]]/dbname[?param1=value1&...&paramN=valueN]
```

Example:

```
user:password@tcp(localhost:3306)/elemta?parseTime=true
```

Common parameters:
- `parseTime=true`: Parse time values to Go's `time.Time`
- `charset=utf8mb4`: Use UTF-8 character set
- `loc=Local`: Use local timezone for datetime values

### PostgreSQL

The PostgreSQL connection string follows this format:

```
postgres://[username:password@]host[:port]/dbname[?param1=value1&...&paramN=valueN]
```

Example:

```
postgres://user:password@localhost:5432/elemta?sslmode=disable
```

Common parameters:
- `sslmode=disable`: Disable SSL (not recommended for production)
- `sslmode=require`: Require SSL connection
- `connect_timeout=10`: Connection timeout in seconds

## Usage

Once you have created a datasource, you can use it to interact with the database:

```go
// Create a new rule
rule := &datasource.Rule{
    Name:        "Block Spam",
    Description: "Block emails with spam-like content",
    Condition:   "contains(subject, 'viagra') || contains(body, 'casino')",
    Action:      "reject",
    Enabled:     true,
}

// Save the rule
if err := ds.SaveRule(rule); err != nil {
    log.Fatalf("Failed to save rule: %v", err)
}

// Get all rules
rules, err := ds.GetRules()
if err != nil {
    log.Fatalf("Failed to get rules: %v", err)
}

// Get a specific rule
rule, err := ds.GetRuleByID(1)
if err != nil {
    log.Fatalf("Failed to get rule: %v", err)
}

// Delete a rule
if err := ds.DeleteRule(1); err != nil {
    log.Fatalf("Failed to delete rule: %v", err)
}
```

## Schema Migrations

Elemta automatically handles schema migrations when you create a datasource. The migrations ensure that the database schema is up-to-date with the latest version of the application.

If you need to manually run migrations, you can use the `Migrate` method:

```go
if err := ds.Migrate(); err != nil {
    log.Fatalf("Failed to run migrations: %v", err)
}
```

## Best Practices

- **Use environment variables** for database credentials
- **Use connection pooling** for production deployments
- **Regularly backup** your database
- **Monitor database performance** in production
- **Use transactions** for operations that modify multiple records

## Troubleshooting

### Connection Issues

If you're having trouble connecting to the database:

1. Check that the database server is running
2. Verify that the connection string is correct
3. Ensure that the database user has the necessary permissions
4. Check for network issues or firewall rules

### Performance Issues

If you're experiencing performance issues:

1. Add appropriate indexes to frequently queried columns
2. Optimize your queries
3. Consider using a connection pool
4. Monitor database load and resource usage 