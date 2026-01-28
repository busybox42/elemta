# Elemta Changelog

## Latest Improvements (January 2026)

### Enhanced Logging & Monitoring
- **Delivery IP Address Logging**: Added `delivery_ip` and `delivery_host` fields to message delivery logs for enhanced tracking
- **Improved Log Categorization**: Fixed categorization logic for spam/virus/4xx/5xx SMTP responses to ensure proper separation of rejection, deferral, and system logs
- **Comprehensive Log Filtering**: Enhanced web interface log filtering with accurate event type classification

### Web Interface Enhancements
- **Reports Chart Time Scales**: Added time scale selector with Hourly, Daily, Weekly, and Monthly views for delivery trend analysis
- **Chart Y-Axis Fix**: Resolved missing y-axis issue on reports page charts with proper tick marks and value labels
- **Adaptive Chart Rendering**: Charts now automatically adjust label frequency based on data length and time scale

### API Improvements
- **Enhanced Delivery Stats API**: Added `timeScale` parameter to `/api/stats/delivery` endpoint for flexible data aggregation
- **Backward Compatibility**: Maintained existing `by_hour` field while adding new `data` field for generic time-scale responses

## Previous Improvements (June 2025)

### Email Security & Scanning
- **Added ClamAV and Rspamd Integration**: Messages now scanned for viruses and spam
- **Security Headers**: Added proper X-Virus-Scanned, X-Spam-Scanned, X-Spam-Score, X-Spam-Status headers
- **Plugin System**: Enhanced builtin plugin system for antivirus and antispam

### Network-Based Relay Control
- **Smart Relay Logic**: Internal networks can relay without authentication, external networks require auth
- **Private Network Detection**: Automatic recognition of RFC 1918 and RFC 4193 private networks
- **Local Domain Support**: Always allow delivery to configured local domains

### LDAP Authentication
- **Complete LDAP Integration**: Full authentication against LDAP/Active Directory
- **Secure Connection Handling**: Proper LDAP SSL/TLS support
- **User Management**: Dynamic user authentication without local user database

### Email Delivery Pipeline
- **LMTP Integration**: Direct delivery to Dovecot via LMTP protocol
- **Queue Management**: Enhanced message queuing with priority handling
- **Delivery Tracking**: Comprehensive logging and monitoring of message delivery

### Web Interface & Management
- **Roundcube Integration**: Full webmail interface for users
- **Management Dashboard**: Administrative interface for monitoring and control
- **User-Friendly Setup**: Automated configuration and deployment

### Testing & Quality
- **Comprehensive Test Suite**: Organized test files for all major features
- **Automated Testing**: Scripts for validating SMTP, LDAP, relay, and delivery functionality
- **Docker Environment**: Complete containerized testing environment

### Documentation
- **Relay Control Documentation**: Detailed explanation of network-based relay behavior
- **Test Documentation**: Organized test suite with clear instructions
- **Security Documentation**: Guidelines for secure email handling

### Configuration
- **Enhanced Configuration**: Support for local domains, internal networks, and authentication settings
- **Docker Compose**: Complete stack with LDAP, Dovecot, monitoring, and web interface
- **Environment Variables**: Flexible configuration for different deployment scenarios 