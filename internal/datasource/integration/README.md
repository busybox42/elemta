# Datasource Integration Tests

This package contains integration tests for the datasource implementations. These tests are designed to test the datasources with real databases.

## Running the Tests

The integration tests are skipped by default because they require actual database servers. To run the tests, you need to set the appropriate environment variables:

### SQLite

The SQLite integration test will always run because it creates a temporary database file.

### MySQL

To run the MySQL integration test, set the following environment variables:

- `TEST_MYSQL_HOST`: The hostname or IP address of the MySQL server (required)
- `TEST_MYSQL_USER`: The username for the MySQL server (default: "root")
- `TEST_MYSQL_PASSWORD`: The password for the MySQL server
- `TEST_MYSQL_DATABASE`: The name of the database to use (default: "elemta_test")

Example:

```bash
TEST_MYSQL_HOST=localhost TEST_MYSQL_USER=root TEST_MYSQL_PASSWORD=password TEST_MYSQL_DATABASE=elemta_test go test -v ./internal/datasource/integration
```

### PostgreSQL

To run the PostgreSQL integration test, set the following environment variables:

- `TEST_PG_HOST`: The hostname or IP address of the PostgreSQL server (required)
- `TEST_PG_USER`: The username for the PostgreSQL server (default: "postgres")
- `TEST_PG_PASSWORD`: The password for the PostgreSQL server
- `TEST_PG_DATABASE`: The name of the database to use (default: "elemta_test")

Example:

```bash
TEST_PG_HOST=localhost TEST_PG_USER=postgres TEST_PG_PASSWORD=password TEST_PG_DATABASE=elemta_test go test -v ./internal/datasource/integration
```

## Test Coverage

The integration tests cover the following functionality:

1. **User Operations**:
   - Creating users
   - Retrieving user information
   - Authenticating users
   - Updating users
   - Listing users with filters
   - Deleting users

2. **Group Operations**:
   - Creating users with groups
   - Retrieving user groups
   - Updating user groups

3. **Query Operations**:
   - Executing custom SQL queries
   - Verifying query results

## Adding New Tests

To add new tests, you can:

1. Add new test functions to the existing test file
2. Add new test cases to the existing test functions
3. Create new test files for specific datasource types

## Docker Compose for Testing

For convenience, you can use Docker Compose to set up test databases. Create a `docker-compose.yml` file in the project root:

```yaml
version: '3'

services:
  mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: elemta_test
    ports:
      - "3306:3306"

  postgres:
    image: postgres:14
    environment:
      POSTGRES_PASSWORD: password
      POSTGRES_DB: elemta_test
    ports:
      - "5432:5432"
```

Then run:

```bash
docker-compose up -d
```

And run the tests:

```bash
TEST_MYSQL_HOST=localhost TEST_MYSQL_PASSWORD=password TEST_PG_HOST=localhost TEST_PG_PASSWORD=password go test -v ./internal/datasource/integration
``` 