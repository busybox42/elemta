# Elemta Test Suite

Comprehensive test suite for Elemta MTA, organized by test type and functionality.

## Test Organization

### 🔧 Unit Tests (`internal/`, `plugins/`)
- **Location**: Alongside source code (`*_test.go`)
- **Purpose**: Test individual functions and components
- **Coverage**: Authentication, SMTP, Queue, Delivery, Plugins, Context
- **Run**: `go test -v ./internal/... ./plugins/...`

### 🔄 Integration Tests (`tests/`)
- **Purpose**: Test component interactions and full workflows
- **Categories**: LDAP, SMTP, Roundcube, Docker, ManageSieve
- **Run**: `./tests/integration_test_suite.sh`

### ⚡ Performance Tests (`tests/performance/`)
- **Purpose**: Load testing and performance validation
- **Tools**: Concurrent SMTP load testing, response time analysis
- **Run**: `python3 tests/performance/smtp_load_test.py`

## Quick Start

### Run All Tests
```bash
# Complete test suite
./tests/integration_test_suite.sh

# Unit tests only
go test -v ./internal/... ./plugins/...

# Specific test categories
./tests/integration_test_suite.sh ldap smtp
./tests/integration_test_suite.sh --no-docker
```

### Individual Test Files

#### LDAP Integration
```bash
# Enhanced LDAP features
bash tests/test-enhanced-ldap.sh

# LDAP authentication
python3 tests/test_ldap_success.py
```

#### SMTP Testing
```bash
# SMTP authentication
python3 tests/test_smtp_auth.py

# Complete SMTP session
python3 tests/test_smtp_complete.py

# Relay control
python3 tests/test_relay_control.py

# Load testing
python3 tests/performance/smtp_load_test.py
```

#### ManageSieve Testing
```bash
# ManageSieve integration
python3 tests/test_managesieve_integration.py
```

#### Roundcube Integration
```bash
# Roundcube webmail
bash tests/test-roundcube-webmail.sh

# Login and email sending
bash tests/test-roundcube-login-complete.sh
bash tests/test-roundcube-sending-simple.sh
```

#### Docker Environment
```bash
# Full Docker stack
bash tests/test-elemta-docker.sh
```

## Test Categories

### 🔐 Authentication Tests
- **LDAP Authentication**: Validates LDAP user authentication
- **SMTP Auth**: Tests SMTP authentication with LDAP users
- **Session Management**: Validates authentication sessions
- **Authorization**: Tests user permissions and access control

### 📧 SMTP Protocol Tests
- **Basic SMTP**: Protocol compliance and basic operations
- **STARTTLS**: TLS encryption testing
- **Authentication**: AUTH mechanisms (PLAIN, LOGIN)
- **Relay Control**: Internal vs external relay rules
- **Queue Integration**: Message queuing and processing

### 📂 LDAP Integration Tests
- **User Management**: User creation, modification, filtering
- **Address Book**: Roundcube LDAP address book integration
- **Enhanced Schema**: Email forwarding, aliases, distribution lists
- **Sieve Integration**: LDAP-stored Sieve filter scripts

### 🌐 Roundcube Tests
- **Web Interface**: Login, navigation, basic functionality
- **Email Operations**: Send, receive, folder management
- **Address Book**: LDAP contact integration with filtering
- **ManageSieve**: Sieve filter management through web interface

### 🚀 Performance Tests
- **SMTP Load**: Concurrent connection and email throughput
- **Authentication Load**: LDAP authentication performance
- **Memory Usage**: Resource consumption under load
- **Response Times**: Latency analysis for different operations

### 🐳 Docker Integration Tests
- **Service Startup**: All containers start correctly
- **Inter-service Communication**: Container networking
- **Volume Persistence**: Data persistence across restarts
- **Health Checks**: Service availability validation

## Test Data

### Test Users (LDAP)
- `demo@example.com` / `demo123`
- `john.smith@example.com` / `password123` (CEO)
- `sarah.johnson@example.com` / `password123` (CTO)
- `mike.davis@example.com` / `password123` (Sales)
- `alice.johnson@example.com` / `password123` (Marketing)

### Distribution Lists
- `all@example.com` - All company users
- `executives@example.com` - Management team
- `engineering@example.com` - Engineering team

### Test Configuration
- **SMTP Server**: `localhost:2525` (Docker: `elemta-smtp:2525`)
- **LDAP Server**: `localhost:389` (Docker: `elemta-ldap:389`)
- **Roundcube**: `http://localhost:8025` (Docker: `elemta_roundcube:80`)
- **ManageSieve**: `localhost:4190` (Docker: `elemta-dovecot:4190`)

## Prerequisites

### Development Environment
```bash
# Install dependencies
go version  # Go 1.23+
python3 --version  # Python 3.8+
docker --version  # Docker 20.0+
docker-compose --version  # Docker Compose 1.29+

# Start Elemta stack
docker-compose up -d

# Wait for services (30-60 seconds)
docker-compose ps  # Verify all services are up
```

### Test Environment Variables
```bash
# Optional overrides
export ELEMTA_SMTP_HOST=localhost
export ELEMTA_SMTP_PORT=2525
export ELEMTA_LDAP_HOST=localhost
export ELEMTA_LDAP_PORT=389
export ROUNDCUBE_URL=http://localhost:8025
```

## Continuous Integration

### GitHub Actions (Future)
```yaml
# .github/workflows/test.yml
- Unit Tests: Run on every PR
- Integration Tests: Run on main branch
- Performance Tests: Run nightly
- Docker Tests: Run on release
```

### Local CI Simulation
```bash
# Full CI pipeline simulation
./tests/integration_test_suite.sh
go test -cover ./internal/... ./plugins/...
python3 tests/performance/smtp_load_test.py
```

## Test Results and Reporting

### Coverage Reports
```bash
# Go test coverage
go test -coverprofile=coverage.out ./internal/... ./plugins/...
go tool cover -html=coverage.out

# Integration test results
./tests/integration_test_suite.sh > test_results.log 2>&1
```

### Performance Metrics
- **SMTP Throughput**: Target >100 emails/second
- **Authentication Latency**: Target <100ms per auth
- **Memory Usage**: Target <512MB under normal load
- **Success Rate**: Target >99% under normal conditions

## Troubleshooting

### Common Issues
1. **Docker containers not running**: `docker-compose up -d`
2. **LDAP authentication fails**: Check user credentials in LDAP
3. **ManageSieve connection fails**: Verify port 4190 accessibility
4. **Roundcube login fails**: Check IMAP/LDAP configuration

### Debug Commands
```bash
# Check container logs
docker logs elemta-smtp
docker logs elemta-ldap
docker logs elemta-dovecot
docker logs elemta_roundcube

# Test individual services
telnet localhost 2525  # SMTP
telnet localhost 4190  # ManageSieve
curl http://localhost:8025  # Roundcube

# LDAP search
docker exec elemta-ldap ldapsearch -x -b "dc=example,dc=com" "(mail=demo@example.com)"
```

## Contributing

### Adding New Tests
1. **Unit Tests**: Add `*_test.go` files alongside source code
2. **Integration Tests**: Add to `tests/` directory with descriptive names
3. **Performance Tests**: Add to `tests/performance/` directory
4. **Update Documentation**: Update this README with new test descriptions

### Test Standards
- Use descriptive test names
- Include setup/teardown for integration tests
- Add error handling and meaningful assertions
- Document test purpose and expected behavior
- Include both positive and negative test cases 